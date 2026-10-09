use super::*;
use futures_util::FutureExt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};

/// Bounds every wait in this module. It exceeds `CONTROL_HTTP_TIMEOUT`, so a
/// forward that blocks the worker surfaces as a failed progress assertion
/// once the client times out, never as this guard.
const HANG_GUARD: Duration = Duration::from_secs(30);
const FORWARD_PATH: &str = "/v1/test/leader-forward";
const LEADER_BODY: &str = r#"{"forwardedTo":"leader"}"#;
/// Sorts after every `http://127.0.0.1:<port>` leader, so the leader wins the
/// lowest-URL election and this node forwards.
const FOLLOWER_URL: &str = "http://127.0.0.2:1";

/// A leader that reads each forwarded request in full and withholds the
/// response to every held request until the test releases it.
struct PausedLeader {
    url: String,
    release: std::sync::mpsc::Sender<()>,
    server: std::thread::JoinHandle<()>,
}

impl PausedLeader {
    fn start(requests: usize) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        Self::start_holding(requests, hold_every_request)
    }

    fn start_holding(
        requests: usize,
        hold: fn(&str) -> bool,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        Self::serve(
            TcpListener::bind("127.0.0.1:0").test_unwrap(),
            requests,
            hold,
        )
    }

    /// Holds `requests` requests whose request line `hold` accepts, answering
    /// any other request at once with 404. Each delivery on the returned
    /// receiver means one complete request is held at the leader.
    fn serve(
        listener: TcpListener,
        requests: usize,
        hold: fn(&str) -> bool,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let url = loopback_url(&listener);
        let (received_tx, received) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let mut held = Vec::with_capacity(requests);
            while held.len() < requests {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let Ok((request_line, stream)) = read_request(stream) else {
                    return;
                };
                if !hold(&request_line) {
                    respond(stream, "404 Not Found", r#"{"error":"not held"}"#);
                    continue;
                }
                held.push(stream);
                if received_tx.send(()).is_err() {
                    return;
                }
            }
            if released.recv().is_err() {
                return;
            }
            for stream in held {
                respond(stream, "200 OK", LEADER_BODY);
            }
        });
        (
            Self {
                url,
                release,
                server,
            },
            received,
        )
    }

    fn release(self) {
        self.release.send(()).test_unwrap();
        self.server.join().test_unwrap();
    }
}

fn loopback_url(listener: &TcpListener) -> String {
    format!("http://{}", listener.local_addr().test_unwrap())
}

fn hold_every_request(_request_line: &str) -> bool {
    true
}

fn hold_writes(request_line: &str) -> bool {
    request_line.starts_with("POST ")
}

/// Reads one request in full and returns its request line.
fn read_request(stream: TcpStream) -> std::io::Result<(String, TcpStream)> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().map_err(std::io::Error::other)?;
            }
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    Ok((request_line, reader.into_inner()))
}

fn respond(mut stream: TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(response.as_bytes()).is_ok() {
        let _ = stream.flush();
    }
}

async fn await_requests(received: &mut tokio::sync::mpsc::UnboundedReceiver<()>, count: usize) {
    for _ in 0..count {
        tokio::time::timeout(HANG_GUARD, received.recv())
            .await
            .test_unwrap()
            .test_unwrap();
    }
}

/// A follower whose only peer is the elected leader at `leader_url`.
fn follower_of(leader_url: &str) -> TrustServiceState {
    let state = state_with_cluster(FOLLOWER_URL, &[leader_url], None, None, None);
    update_peer_reachable(&state, leader_url);
    state
}

async fn forwarded_body(response: Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    serde_json::from_slice(&body).test_unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn leader_forward_leaves_the_async_worker_free_while_the_leader_withholds_its_response() {
    let (leader, mut received) = PausedLeader::start(1);
    let state = follower_of(&leader.url);
    let forward_finished = Arc::new(AtomicBool::new(false));
    let forward = tokio::spawn({
        let state = state.clone();
        let forward_finished = Arc::clone(&forward_finished);
        async move {
            let outcome =
                forward_post_to_leader(&state, FORWARD_PATH, &json!({ "write": 1 })).await;
            forward_finished.store(true, Ordering::SeqCst);
            outcome
        }
    });
    // A second task on the same single worker. It can observe the held request
    // while the forward is still outstanding only if the forward yields the
    // worker instead of blocking it on the leader's socket.
    let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
    let observed = Arc::clone(&forward_finished);
    tokio::spawn(async move {
        let held_at_leader = received.recv().await.is_some();
        let _ = progress_tx.send(held_at_leader && !observed.load(Ordering::SeqCst));
    });

    let progressed_while_outstanding = tokio::time::timeout(HANG_GUARD, progress_rx)
        .await
        .test_unwrap()
        .test_unwrap();
    assert!(
        progressed_while_outstanding,
        "a task on the forwarding worker made no progress until the leader forward ended"
    );

    leader.release();
    let response = tokio::time::timeout(HANG_GUARD, forward)
        .await
        .test_unwrap()
        .test_unwrap()
        .test_unwrap()
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        forwarded_body(response).await,
        json!({ "forwardedTo": "leader" })
    );
}

const AT_CAPACITY: &str = "cluster leader forwarding is at capacity for trust-control writes";
const AUTHORITY_AT_CAPACITY: &str = "cluster leader forwarding is at capacity for authority writes";

async fn assert_same_response(actual: Response, expected: Response) {
    assert_eq!(actual.status(), expected.status());
    assert_eq!(
        actual.headers().get(CONTENT_TYPE),
        expected.headers().get(CONTENT_TYPE)
    );
    let actual = to_bytes(actual.into_body(), usize::MAX).await.test_unwrap();
    let expected = to_bytes(expected.into_body(), usize::MAX)
        .await
        .test_unwrap();
    assert_eq!(actual, expected);
}

/// Every forward kind against `state`, each polled exactly once. A forward
/// that would wait for admission is not ready and fails the `test_unwrap`.
fn forwards_polled_once(state: &TrustServiceState) -> [Result<Option<Response>, Response>; 4] {
    let body = json!({ "write": "next" });
    [
        forward_post_to_leader(state, FORWARD_PATH, &body)
            .now_or_never()
            .test_unwrap(),
        forward_authority_post_to_leader(state, FORWARD_PATH, &body)
            .now_or_never()
            .test_unwrap(),
        forward_scim_post_to_leader(state, FORWARD_PATH, &body)
            .now_or_never()
            .test_unwrap(),
        forward_scim_delete_to_leader(state, FORWARD_PATH)
            .now_or_never()
            .test_unwrap(),
    ]
}

#[tokio::test(flavor = "current_thread")]
async fn next_leader_forward_is_refused_at_once_while_paused_forwards_hold_every_permit() {
    const PERMITS: usize = 2;
    let (leader, mut received) = PausedLeader::start(PERMITS);
    let mut state = follower_of(&leader.url);
    state.leader_forward_lane = Arc::new(tokio::sync::Semaphore::new(PERMITS));
    let held = (0..PERMITS)
        .map(|write| {
            let state = state.clone();
            tokio::spawn(async move {
                forward_post_to_leader(&state, FORWARD_PATH, &json!({ "write": write })).await
            })
        })
        .collect::<Vec<_>>();
    await_requests(&mut received, PERMITS).await;
    assert_eq!(state.leader_forward_lane.available_permits(), 0);

    update_peer_reachable(&state, &leader.url);
    let [post, authority, scim_post, scim_delete] = forwards_polled_once(&state);
    assert_same_response(
        post.test_unwrap_err(),
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;
    assert_same_response(
        authority.test_unwrap_err(),
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AUTHORITY_AT_CAPACITY),
    )
    .await;
    assert_same_response(
        scim_post.test_unwrap_err(),
        scim_error_response(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;
    assert_same_response(
        scim_delete.test_unwrap_err(),
        scim_error_response(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;

    leader.release();
    for forward in held {
        let response = tokio::time::timeout(HANG_GUARD, forward)
            .await
            .test_unwrap()
            .test_unwrap()
            .test_unwrap()
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(state.leader_forward_lane.available_permits(), PERMITS);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_leader_forward_keeps_its_permit_until_the_transport_ends() {
    let (leader, mut received) = PausedLeader::start(1);
    let mut state = follower_of(&leader.url);
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    state.leader_forward_lane = Arc::clone(&lane);
    let forward = tokio::spawn({
        let state = state.clone();
        async move { forward_post_to_leader(&state, FORWARD_PATH, &json!({ "write": 1 })).await }
    });
    await_requests(&mut received, 1).await;

    forward.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, forward)
        .await
        .test_unwrap()
        .test_unwrap_err();
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    update_peer_reachable(&state, &leader.url);
    let refused = forward_post_to_leader(&state, FORWARD_PATH, &json!({ "write": 2 }))
        .now_or_never()
        .test_unwrap()
        .test_unwrap_err();
    assert_same_response(
        refused,
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;

    leader.release();
    let returned = tokio::time::timeout(HANG_GUARD, Arc::clone(&lane).acquire_owned())
        .await
        .test_unwrap()
        .test_unwrap();
    drop(returned);
    assert_eq!(lane.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn local_leader_and_standalone_writes_never_take_a_forward_permit() {
    const SELF_URL: &str = "http://127.0.0.1:1";
    const PEER_URL: &str = "http://127.0.0.2:1";
    let leader = state_with_cluster(SELF_URL, &[PEER_URL], None, None, None);
    let standalone = state_with_cluster(SELF_URL, &[], None, None, None);
    assert!(standalone.cluster.is_none());
    for mut state in [leader, standalone] {
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        let _every_permit = Arc::clone(&lane).try_acquire_owned().test_unwrap();
        state.leader_forward_lane = lane;
        update_peer_reachable(&state, PEER_URL);
        for outcome in forwards_polled_once(&state) {
            assert!(matches!(outcome, Ok(None)));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn leader_forward_retry_readmits_under_one_permit_after_a_failed_attempt() {
    // The lower URL wins the first election and refuses connections, so the
    // first attempt fails and the retry follows the election to the other.
    let mut listeners = [
        TcpListener::bind("127.0.0.1:0").test_unwrap(),
        TcpListener::bind("127.0.0.1:0").test_unwrap(),
    ];
    listeners.sort_by_key(loopback_url);
    let [refusing, serving] = listeners;
    let refusing_url = loopback_url(&refusing);
    drop(refusing);
    let (leader, mut received) = PausedLeader::serve(serving, 1, hold_every_request);
    let mut state = state_with_cluster(
        FOLLOWER_URL,
        &[&refusing_url, &leader.url],
        None,
        None,
        None,
    );
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    state.leader_forward_lane = Arc::clone(&lane);
    update_peer_reachable(&state, &refusing_url);
    update_peer_reachable(&state, &leader.url);
    assert_eq!(current_leader_url(&state), Some(refusing_url));

    let forward = tokio::spawn({
        let state = state.clone();
        async move { forward_post_to_leader(&state, FORWARD_PATH, &json!({ "write": 1 })).await }
    });
    await_requests(&mut received, 1).await;
    assert_eq!(lane.available_permits(), 0);

    leader.release();
    let response = tokio::time::timeout(HANG_GUARD, forward)
        .await
        .test_unwrap()
        .test_unwrap()
        .test_unwrap()
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        forwarded_body(response).await,
        json!({ "forwardedTo": "leader" })
    );
    assert_eq!(lane.available_permits(), 1);
}

/// Forwards whose returned response this node builds from the leader's JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizedForward {
    Authority,
    ScimPost,
    ScimDelete,
}

impl FinalizedForward {
    const ALL: [Self; 3] = [Self::Authority, Self::ScimPost, Self::ScimDelete];

    /// The authority forward reads the leader's status before its write, so
    /// only the write is held.
    fn held_requests(self) -> fn(&str) -> bool {
        match self {
            Self::Authority => hold_writes,
            Self::ScimPost | Self::ScimDelete => hold_every_request,
        }
    }

    async fn forward(self, state: &TrustServiceState) -> Result<Option<Response>, Response> {
        let body = json!({ "write": format!("{self:?}") });
        match self {
            Self::Authority => forward_authority_post_to_leader(state, FORWARD_PATH, &body).await,
            Self::ScimPost => forward_scim_post_to_leader(state, FORWARD_PATH, &body).await,
            Self::ScimDelete => forward_scim_delete_to_leader(state, FORWARD_PATH).await,
        }
    }

    /// The response this node returns for the leader's `reply`.
    fn finalized(self, reply: Value) -> Response {
        match self {
            Self::Authority => Json(reply).into_response(),
            Self::ScimPost => scim_json_response(StatusCode::CREATED, &reply),
            Self::ScimDelete => scim_json_response(StatusCode::OK, &reply),
        }
    }

    fn at_capacity(self) -> Response {
        match self {
            Self::Authority => {
                plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AUTHORITY_AT_CAPACITY)
            }
            Self::ScimPost | Self::ScimDelete => {
                scim_error_response(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY)
            }
        }
    }
}

/// Starts `kind` against a leader that holds its write, on a one-permit lane,
/// and returns once the write is held.
async fn held_finalized_forward(
    kind: FinalizedForward,
) -> (
    PausedLeader,
    TrustServiceState,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<Result<Option<Response>, Response>>,
) {
    let (leader, mut received) = PausedLeader::start_holding(1, kind.held_requests());
    let mut state = follower_of(&leader.url);
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    state.leader_forward_lane = Arc::clone(&lane);
    let forward = tokio::spawn({
        let state = state.clone();
        async move { kind.forward(&state).await }
    });
    await_requests(&mut received, 1).await;
    assert_eq!(lane.available_permits(), 0, "{kind:?}");
    (leader, state, lane, forward)
}

async fn assert_refused_at_once(
    kind: FinalizedForward,
    state: &TrustServiceState,
    leader_url: &str,
) {
    update_peer_reachable(state, leader_url);
    let refused = kind
        .forward(state)
        .now_or_never()
        .test_unwrap()
        .test_unwrap_err();
    assert_same_response(refused, kind.at_capacity()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn finalized_leader_forwards_return_the_built_response_under_their_permit() {
    for kind in FinalizedForward::ALL {
        let (leader, state, lane, forward) = held_finalized_forward(kind).await;
        assert_refused_at_once(kind, &state, &leader.url).await;

        leader.release();
        let response = tokio::time::timeout(HANG_GUARD, forward)
            .await
            .test_unwrap()
            .test_unwrap()
            .test_unwrap()
            .test_unwrap();
        assert_same_response(response, kind.finalized(json!({ "forwardedTo": "leader" }))).await;
        assert_eq!(lane.available_permits(), 1, "{kind:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_finalized_leader_forwards_keep_their_permit_until_the_response_is_built() {
    for kind in FinalizedForward::ALL {
        let (leader, state, lane, forward) = held_finalized_forward(kind).await;
        forward.abort();
        let cancelled = tokio::time::timeout(HANG_GUARD, forward)
            .await
            .test_unwrap()
            .test_unwrap_err();
        assert!(cancelled.is_cancelled(), "{kind:?}");
        assert_eq!(lane.available_permits(), 0, "{kind:?}");
        assert_refused_at_once(kind, &state, &leader.url).await;

        leader.release();
        let returned = tokio::time::timeout(HANG_GUARD, Arc::clone(&lane).acquire_owned())
            .await
            .test_unwrap()
            .test_unwrap();
        drop(returned);
        assert_eq!(lane.available_permits(), 1, "{kind:?}");
    }
}

/// A leader that answers its forwarded write at once with `reply`; any other
/// request gets 404. It serves until it has answered one write.
fn answering_leader(write: fn(&str) -> bool, reply: &Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let url = loopback_url(&listener);
    let reply = reply.to_string();
    std::thread::spawn(move || loop {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let Ok((request_line, stream)) = read_request(stream) else {
            return;
        };
        if write(&request_line) {
            respond(stream, "200 OK", &reply);
            return;
        }
        respond(stream, "404 Not Found", r#"{"error":"not a write"}"#);
    });
    url
}

/// A leader reply whose response build pauses on the pause armed for `token`.
fn paused_build_reply(token: &str) -> Value {
    json!({
        "forwardedTo": "leader",
        (forward_finalization_pause::FIELD): token,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn paused_forward_response_build_leaves_the_async_worker_free() {
    let mut stalled = Vec::new();
    for kind in FinalizedForward::ALL {
        let token = format!("worker-free-{kind:?}");
        let reply = paused_build_reply(&token);
        let (pause, mut reached) = forward_finalization_pause::arm(&token);
        let state = follower_of(&answering_leader(kind.held_requests(), &reply));
        let forward_finished = Arc::new(AtomicBool::new(false));
        let forward = tokio::spawn({
            let state = state.clone();
            let forward_finished = Arc::clone(&forward_finished);
            async move {
                let outcome = kind.forward(&state).await;
                forward_finished.store(true, Ordering::SeqCst);
                outcome
            }
        });
        // A second task on the same single worker. It can observe the paused
        // build while the forward is still outstanding only if the build runs
        // off the async worker.
        let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
        let observed = Arc::clone(&forward_finished);
        tokio::spawn(async move {
            let build_paused = reached.recv().await.is_some();
            let _ = progress_tx.send(build_paused && !observed.load(Ordering::SeqCst));
        });

        let progressed_while_paused = tokio::time::timeout(HANG_GUARD, progress_rx)
            .await
            .test_unwrap()
            .test_unwrap();
        pause.release();
        if !progressed_while_paused {
            stalled.push(kind);
        }
        let response = tokio::time::timeout(HANG_GUARD, forward)
            .await
            .test_unwrap()
            .test_unwrap()
            .test_unwrap()
            .test_unwrap();
        assert_same_response(response, kind.finalized(reply)).await;
    }
    assert_eq!(
        stalled,
        Vec::<FinalizedForward>::new(),
        "a task on the forwarding worker made no progress while these forwarded responses were being built"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_forward_response_build_keeps_its_permit_and_refuses_the_next_forward() {
    let mut admission_lost = Vec::new();
    for kind in FinalizedForward::ALL {
        let token = format!("admission-{kind:?}");
        let reply = paused_build_reply(&token);
        let (pause, mut reached) = forward_finalization_pause::arm(&token);
        let leader_url = answering_leader(kind.held_requests(), &reply);
        let mut state = follower_of(&leader_url);
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        state.leader_forward_lane = Arc::clone(&lane);
        let forward = tokio::spawn({
            let state = state.clone();
            async move { kind.forward(&state).await }
        });
        tokio::time::timeout(HANG_GUARD, reached.recv())
            .await
            .test_unwrap()
            .test_unwrap();

        let permit_held = lane.available_permits() == 0;
        update_peer_reachable(&state, &leader_url);
        let next = kind.forward(&state).now_or_never();
        pause.release();
        let next_refused = match next {
            Some(Err(refusal)) => {
                assert_same_response(refusal, kind.at_capacity()).await;
                true
            }
            _ => false,
        };
        if !(permit_held && next_refused) {
            admission_lost.push(kind);
        }
        let response = tokio::time::timeout(HANG_GUARD, forward)
            .await
            .test_unwrap()
            .test_unwrap()
            .test_unwrap()
            .test_unwrap();
        assert_same_response(response, kind.finalized(reply)).await;
        let returned = tokio::time::timeout(HANG_GUARD, Arc::clone(&lane).acquire_owned())
            .await
            .test_unwrap()
            .test_unwrap();
        drop(returned);
    }
    assert_eq!(
        admission_lost,
        Vec::<FinalizedForward>::new(),
        "the forward permit was free, or the next forward was admitted, while these forwarded responses were being built"
    );
}

/// The leader holds public submissions while continuing to answer privileged
/// writes. A watch retains the release signal even if a request has just arrived.
struct PublicForwardLeader {
    url: String,
    release: tokio::sync::watch::Sender<bool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl PublicForwardLeader {
    fn start() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let url = loopback_url(&listener);
        listener.set_nonblocking(true).test_unwrap();
        let (entered_tx, entered) = tokio::sync::mpsc::unbounded_channel();
        let (release, release_rx) = tokio::sync::watch::channel(false);
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let router = Router::new()
            .route(
                PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
                post(move || {
                    let entered_tx = entered_tx.clone();
                    let mut release_rx = release_rx.clone();
                    async move {
                        let _ = entered_tx.send(());
                        let _ = release_rx.wait_for(|released| *released).await;
                        (StatusCode::OK, LEADER_BODY)
                    }
                }),
            )
            .route(REVOCATIONS_PATH, post(Self::privileged_write))
            .route(BUDGET_INCREMENT_PATH, post(Self::privileged_write));
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .test_unwrap()
                .block_on(async move {
                    axum::serve(
                        tokio::net::TcpListener::from_std(listener).test_unwrap(),
                        router,
                    )
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                    })
                    .await
                    .test_unwrap();
                });
        });
        (
            Self {
                url,
                release,
                shutdown: Some(shutdown),
                server: Some(server),
            },
            entered,
        )
    }

    async fn privileged_write(headers: HeaderMap) -> Response {
        match validate_service_auth(&headers, "token") {
            Ok(()) => (StatusCode::OK, LEADER_BODY).into_response(),
            Err(response) => response,
        }
    }
}

impl Drop for PublicForwardLeader {
    fn drop(&mut self) {
        let _ = self.release.send(true);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.join().test_unwrap();
        }
    }
}

/// Valid wire shape; verification belongs to the leader in these follower tests.
fn public_forward_submission() -> VerifyPassportChallengeRequest {
    serde_json::from_value(json!({
        "presentation": {
            "schema": "chio.passport-presentation-response.v1",
            "challenge": {
                "schema": "chio.passport-presentation-challenge.v1",
                "verifier": "https://verifier.example",
                "challengeId": "held-public-submission",
                "nonce": "nonce",
                "issuedAt": "2026-10-09T00:00:00Z",
                "expiresAt": "2026-10-09T00:05:00Z"
            },
            "passport": {
                "schema": "chio.agent-passport.v1",
                "subject": "holder",
                "credentials": [],
                "merkleRoots": [],
                "issuedAt": "2026-10-09T00:00:00Z",
                "validUntil": "2026-10-09T00:05:00Z"
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2026-10-09T00:00:00Z",
                "proofPurpose": "authentication",
                "verificationMethod": "holder",
                "proofValue": "fixture"
            }
        }
    }))
    .test_unwrap()
}

fn start_public_forward(state: &TrustServiceState) -> tokio::task::JoinHandle<Response> {
    let state = state.clone();
    tokio::spawn(async move {
        handle_public_verify_passport_challenge(State(state), Json(public_forward_submission()))
            .await
    })
}

#[tokio::test(flavor = "current_thread")]
async fn final_f10_public_forward_preserves_authenticated_revocation_and_budget_progress() {
    let (leader, mut entered) = PublicForwardLeader::start();
    let mut state = follower_of(&leader.url);
    // One authenticated permit is enough to witness the isolation contract.
    state.leader_forward_lane = Arc::new(tokio::sync::Semaphore::new(1));
    let public = start_public_forward(&state);
    await_requests(&mut entered, 1).await;
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer token".parse().test_unwrap());
    let revoked = handle_revoke_capability(
        State(state.clone()),
        headers.clone(),
        Json(RevokeCapabilityRequest {
            capability_id: "compromised-capability".to_string(),
        }),
    )
    .await;
    let budget = handle_try_increment_budget(
        State(state.clone()),
        headers,
        Json(TryIncrementBudgetRequest {
            capability_id: "active-capability".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
        }),
    )
    .await;
    let statuses = [revoked.status(), budget.status()];
    let _ = leader.release.send(true);
    assert_eq!(public.await.test_unwrap().status(), StatusCode::OK);
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::OK],
        "an unauthenticated public forward consumed authenticated write admission"
    );
    assert_eq!(state.leader_forward_lane.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn final_f10_public_forwards_refuse_the_seventeenth_submission_without_queuing() {
    let (leader, mut entered) = PublicForwardLeader::start();
    let state = follower_of(&leader.url);
    let held = (0..16)
        .map(|_| start_public_forward(&state))
        .collect::<Vec<_>>();
    await_requests(&mut entered, 16).await;
    let next = handle_public_verify_passport_challenge(
        State(state.clone()),
        Json(public_forward_submission()),
    )
    .now_or_never();
    let _ = leader.release.send(true);
    for public in held {
        assert_eq!(public.await.test_unwrap().status(), StatusCode::OK);
    }
    assert_eq!(
        next.map(|response| response.status()),
        Some(StatusCode::SERVICE_UNAVAILABLE),
        "public forwarding admitted or queued a submission beyond its sixteen-worker bound"
    );
    assert_eq!(state.leader_forward_lane.available_permits(), 64);
}
