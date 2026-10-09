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

/// A leader that reads each forwarded request in full and withholds every
/// response until the test releases it.
struct PausedLeader {
    url: String,
    release: std::sync::mpsc::Sender<()>,
    server: std::thread::JoinHandle<()>,
}

impl PausedLeader {
    fn start(requests: usize) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        Self::serve(TcpListener::bind("127.0.0.1:0").test_unwrap(), requests)
    }

    /// Accepts exactly `requests` connections. Each delivery on the returned
    /// receiver means one complete request is held at the leader.
    fn serve(
        listener: TcpListener,
        requests: usize,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let url = loopback_url(&listener);
        let (received_tx, received) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let mut held = Vec::with_capacity(requests);
            for _ in 0..requests {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let Ok(stream) = read_request(stream) else {
                    return;
                };
                held.push(stream);
                if received_tx.send(()).is_err() {
                    return;
                }
            }
            if released.recv().is_err() {
                return;
            }
            for stream in held {
                respond(stream);
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

fn read_request(stream: TcpStream) -> std::io::Result<TcpStream> {
    let mut reader = BufReader::new(stream);
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
    Ok(reader.into_inner())
}

fn respond(mut stream: TcpStream) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{LEADER_BODY}",
        LEADER_BODY.len()
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

async fn assert_same_error(refusal: Response, expected: Response) {
    assert_eq!(refusal.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refusal.status(), expected.status());
    assert_eq!(
        refusal.headers().get(CONTENT_TYPE),
        expected.headers().get(CONTENT_TYPE)
    );
    let refusal = to_bytes(refusal.into_body(), usize::MAX)
        .await
        .test_unwrap();
    let expected = to_bytes(expected.into_body(), usize::MAX)
        .await
        .test_unwrap();
    assert_eq!(refusal, expected);
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
    assert_same_error(
        post.test_unwrap_err(),
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;
    assert_same_error(
        authority.test_unwrap_err(),
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AUTHORITY_AT_CAPACITY),
    )
    .await;
    assert_same_error(
        scim_post.test_unwrap_err(),
        scim_error_response(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;
    assert_same_error(
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
    assert_same_error(
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
    let (leader, mut received) = PausedLeader::serve(serving, 1);
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
