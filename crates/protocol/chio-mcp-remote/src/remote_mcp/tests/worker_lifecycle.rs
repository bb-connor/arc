//! Actual HTTP waits must terminate when their owning worker or response is lost.
use super::*;
use axum::body::{Body, HttpBody};
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::Condvar;
use std::task::Poll;

const TOKEN: &str = "worker-lifecycle-token";
const WAIT: Duration = Duration::from_secs(4);
// The default output sanitizer truncates each string above 1,000,000 bytes, so
// fixture output is split into text items that each stay below that limit.
const TEXT_ITEM_BYTES: usize = 512 * 1024;
// Below the 4 MiB upstream result bound, yet the edge projects it twice (result
// and evidence) with two receipts, which exceeds the 8 MiB session line bound.
const WORKER_KILLING_OUTPUT_BYTES: usize = 4 * 1024 * 1024 - 512;
type DispatchGate = Arc<(StdMutex<bool>, Condvar)>;

struct ReadTransport {
    calls: Arc<AtomicUsize>,
    output_bytes: usize,
    dispatch_gate: Option<DispatchGate>,
    notification_crash_gate: Option<DispatchGate>,
}
impl McpTransport for ReadTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Ok(vec![chio_mcp_adapter::edge::McpToolInfo {
            name: "read".into(),
            title: None,
            description: Some("Read".into()),
            input_schema: json!({"type":"object"}),
            output_schema: None,
            annotations: Some(json!({"readOnlyHint":true,"destructiveHint":false})),
            execution: None,
        }])
    }

    fn call_tool(
        &self,
        tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        assert_eq!(tool_name, "read");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.dispatch_gate {
            let (state, changed) = &**gate;
            let (released, _) = changed
                .wait_timeout_while(state.lock().unwrap(), WAIT, |released| !*released)
                .unwrap();
            if !*released {
                return Err(AdapterError::ConnectionFailed(
                    "test dispatch gate deadline".into(),
                ));
            }
        }
        let mut content = Vec::new();
        let mut remaining = self.output_bytes;
        loop {
            let item_bytes = remaining.min(TEXT_ITEM_BYTES);
            content.push(json!({"type":"text","text":"x".repeat(item_bytes)}));
            remaining -= item_bytes;
            if remaining == 0 {
                break;
            }
        }
        let result = chio_mcp_adapter::edge::McpToolResult {
            content,
            structured_content: None,
            is_error: Some(false),
        };
        assert!(serde_json::to_vec(&result).unwrap().len() < 4 * 1024 * 1024);
        Ok(result)
    }

    fn drain_notifications(&self) -> Vec<Value> {
        if let Some(gate) = &self.notification_crash_gate {
            let (state, changed) = &**gate;
            let (released, _) = changed
                .wait_timeout_while(state.lock().unwrap(), WAIT, |released| !*released)
                .unwrap();
            assert!(
                !*released,
                "test owning worker crash while initialize waits for its reply"
            );
        }
        Vec::new()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    state: RemoteAppState,
    calls: Arc<AtomicUsize>,
}

fn fixture(output_bytes: usize, dispatch_gate: Option<DispatchGate>) -> Fixture {
    fixture_with_crash(output_bytes, dispatch_gate, None)
}

fn fixture_with_crash(
    output_bytes: usize,
    dispatch_gate: Option<DispatchGate>,
    notification_crash_gate: Option<DispatchGate>,
) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config = test_remote_config();
    config.auth_token = Some(TOKEN.into());
    config.wrapped_args.clear();
    config.policy_path = directory.path().join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        r#"
kernel:
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
  durable_admission_mode: off
  allow_unsafe_durable_admission_off: true
capabilities:
  default:
    tools:
      - server: srv
        tool: read
        operations: [invoke]
        ttl: 300
"#,
    )
    .unwrap();
    config.test_transport = Some(Arc::new(ReadTransport {
        calls: calls.clone(),
        output_bytes,
        dispatch_gate,
        notification_crash_gate,
    }));
    configure_signed_manifest(&mut config, directory.path());
    let sessions = Arc::new(
        RemoteSessionLedger::new(config.clock.clone(), config.lifecycle_policy(), None, None)
            .unwrap(),
    );
    let factory = Arc::new(RemoteSessionFactory::new(config).unwrap());
    Fixture {
        _directory: directory,
        state: RemoteAppState {
            sessions,
            factory,
            auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
                token: TOKEN.into(),
            }),
            enterprise_provider_registry: None,
            admin_token: None,
            protected_resource_metadata: None,
            authorization_server_metadata: None,
            local_auth_server: None,
        },
        calls,
    }
}

/// A `read` call the default runtime guard profile admits. That profile
/// classifies `read` as filesystem access and denies it without a path.
fn read_call(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"read","arguments":{"path":"/workspace/notes.txt"}}})
}

fn post_request(session: Option<&str>, message: &Value) -> Request {
    let mut builder = Request::builder()
        .method("POST")
        .uri(MCP_ENDPOINT_PATH)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json");
    if let Some(session) = session {
        builder = builder
            .header(MCP_SESSION_ID_HEADER, session)
            .header(MCP_PROTOCOL_VERSION_HEADER, "2025-11-25");
    }
    builder
        .body(Body::from(serde_json::to_vec(message).unwrap()))
        .unwrap()
}

fn get_request(session: &str) -> Request {
    Request::builder()
        .method("GET")
        .uri(MCP_ENDPOINT_PATH)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("accept", "text/event-stream")
        .header(MCP_SESSION_ID_HEADER, session)
        .header(MCP_PROTOCOL_VERSION_HEADER, "2025-11-25")
        .body(Body::empty())
        .unwrap()
}

async fn post(fixture: &Fixture, session: Option<&str>, message: &Value) -> Response {
    tokio::time::timeout(
        WAIT,
        handle_post(State(fixture.state.clone()), post_request(session, message)),
    )
    .await
    .expect("HTTP request handler exceeded its outer test deadline")
}

async fn initialize(fixture: &Fixture, roots: bool) -> Arc<RemoteSession> {
    let response = post(
        fixture,
        None,
        &json!({"jsonrpc":"2.0","id":1,
        "method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":if roots { json!({"roots":{"listChanged":true}}) } else { json!({}) },
            "clientInfo":{"name":"worker-lifecycle","version":"1"}}}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session_id = response.headers()[MCP_SESSION_ID_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 64 * 1024))
        .await
        .expect("initialize body deadline")
        .unwrap();
    match fixture.state.sessions.lookup(&session_id).await.unwrap() {
        RemoteSessionEntry::Active(session) => session,
        RemoteSessionEntry::Terminal(_) => panic!("new session was terminal"),
    }
}

async fn initialized(fixture: &Fixture, session: &RemoteSession) {
    let response = post(
        fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
}

async fn next_message(body: &mut Body, expected: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(WAIT, async {
        let mut buffer = Vec::new();
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx))
                .await
                .expect("SSE ended before the required message")
                .unwrap();
            if let Ok(bytes) = frame.into_data() {
                buffer.extend_from_slice(&bytes);
                assert!(
                    buffer.len() <= 64 * 1024,
                    "test SSE parser exceeded its bound"
                );
            }
            while let Some(end) = buffer.windows(2).position(|bytes| bytes == b"\n\n") {
                let frame = buffer.drain(..end + 2).collect::<Vec<_>>();
                let frame = std::str::from_utf8(&frame).unwrap();
                for line in frame.lines() {
                    if let Some(data) = line.strip_prefix("data:") {
                        if data.trim().is_empty() {
                            continue;
                        }
                        let message: Value = serde_json::from_str(data.trim()).unwrap();
                        if expected(&message) {
                            return message;
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("SSE did not deliver its required message before the outer deadline")
}

#[tokio::test]
async fn first_get_after_initialized_delivers_already_retained_roots_request() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, true).await;
    let mut observer = session.subscribe();
    initialized(&fixture, &session).await;
    let roots = tokio::time::timeout(WAIT, async {
        loop {
            let event = observer.recv().await.unwrap();
            if event.message["method"] == "roots/list" {
                break event;
            }
        }
    })
    .await
    .expect("actual worker did not request roots");
    assert!(session
        .retained_notification_events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.event_id == roots.event_id));
    assert!(!session.has_active_notification_stream());
    let response = handle_get(
        State(fixture.state.clone()),
        get_request(&session.session_id),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let delivered = next_message(&mut body, |message| message["method"] == "roots/list").await;
    assert_eq!(delivered["id"], roots.message["id"]);
    let response = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","id":delivered["id"],"result":{"roots":[]}}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
    let ping = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","id":9,"method":"ping","params":{}}),
    )
    .await;
    assert_eq!(ping.status(), StatusCode::OK);
    let ping = next_message(&mut ping.into_body(), |message| message["id"] == 9).await;
    assert_eq!(ping["result"], json!({}));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    drop(body);
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn pending_post_and_get_close_when_projection_kills_actual_worker() {
    let fixture = fixture(WORKER_KILLING_OUTPUT_BYTES, None);
    let session = initialize(&fixture, false).await;
    initialized(&fixture, &session).await;
    let get = handle_get(
        State(fixture.state.clone()),
        get_request(&session.session_id),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    let call = post(&fixture, Some(&session.session_id), &read_call(2)).await;
    assert_eq!(call.status(), StatusCode::OK);
    let (post_body, get_body) = tokio::join!(
        tokio::time::timeout(WAIT, axum::body::to_bytes(call.into_body(), 64 * 1024)),
        tokio::time::timeout(WAIT, axum::body::to_bytes(get.into_body(), 64 * 1024)),
    );
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        1,
        "the actual tool call did not reach execution; response={}",
        post_body
            .as_ref()
            .ok()
            .and_then(|result| result.as_ref().ok())
            .map(|bytes| String::from_utf8_lossy(bytes)
                .chars()
                .take(2048)
                .collect::<String>())
            .unwrap_or_else(|| "POST had no terminal body".into()),
    );
    let post_body = post_body
        .expect("POST stayed open after its worker died")
        .unwrap();
    get_body
        .expect("GET stayed open after its worker died")
        .unwrap();
    let wire = std::str::from_utf8(&post_body).unwrap();
    assert!(
        wire.contains("\"error\""),
        "lost tool outcome was not classified as uncertain"
    );
    assert!(
        !wire.contains("\"result\""),
        "worker loss manufactured a successful response"
    );
    assert!(!session.has_active_request_stream());
    assert!(!session.has_active_notification_stream());
    assert_eq!(
        session.lifecycle_snapshot().state,
        RemoteSessionState::Closed
    );
    let retry = post(&fixture, Some(&session.session_id), &read_call(3)).await;
    assert_ne!(retry.status(), StatusCode::OK);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn waiting_post_owner_observes_actual_worker_death_before_enqueue() {
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let fixture = fixture(WORKER_KILLING_OUTPUT_BYTES, Some(gate.clone()));
    let session = initialize(&fixture, false).await;
    initialized(&fixture, &session).await;
    let pending = post(&fixture, Some(&session.session_id), &read_call(2)).await;
    assert_eq!(pending.status(), StatusCode::OK);
    let entered = tokio::time::timeout(WAIT, async {
        while fixture.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    if entered.is_err() {
        let body =
            tokio::time::timeout(WAIT, axum::body::to_bytes(pending.into_body(), 64 * 1024)).await;
        let detail = body
            .as_ref()
            .ok()
            .and_then(|result| result.as_ref().ok())
            .map(|bytes| {
                String::from_utf8_lossy(bytes)
                    .chars()
                    .take(2048)
                    .collect::<String>()
            })
            .unwrap_or_else(|| "no terminal POST body".into());
        panic!("worker-death fixture did not enter actual dispatch: {detail}");
    }
    // The first SSE body still owns the mutex. A dead actor cannot require a
    // client to drop that body before refusing the next request.
    let request = post_request(Some(&session.session_id), &read_call(3));
    let mut waiting = Box::pin(handle_post(State(fixture.state.clone()), request));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // A POST waiting for the stream lock holds no session event subscription.
    assert_eq!(
        session.event_tx.receiver_count(),
        1,
        "second POST subscribed to session events before it owned the stream"
    );
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let waiting = tokio::time::timeout(WAIT, waiting)
        .await
        .expect("dead worker left the second POST waiting for the client-owned first stream");
    assert_ne!(waiting.status(), StatusCode::OK);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(pending);
}

/// A Ready session bound to the fixture bearer identity whose bounded inbox the
/// test drains in place of a worker.
async fn controlled_session(
    fixture: &Fixture,
    session_id: &str,
    event_capacity: usize,
) -> (Arc<RemoteSession>, McpInboxReceiver) {
    let clock = fixture.state.factory.config.clock.clone();
    let (input_tx, input_rx) = mcp_inbox();
    let (event_tx, _) = broadcast::channel(event_capacity);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
    );
    let session = Arc::new(
        RemoteSession::new(RemoteSessionInit {
            clock,
            session_id: session_id.into(),
            agent_id: "agent".into(),
            capabilities: vec![],
            issued_capabilities: vec![],
            auth_context: build_static_bearer_session_auth_context(&headers, TOKEN),
            auth_mode_fingerprint: "auth".into(),
            policy_fingerprint: "policy".into(),
            runtime_contract_fingerprint: "runtime".into(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle_policy: fixture.state.factory.config.lifecycle_policy(),
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: None,
            input_tx,
            event_tx,
            retained_notification_events: Arc::new(StdMutex::new(VecDeque::new())),
            next_event_id: Arc::new(AtomicU64::new(0)),
            session_db_path: None,
            approval_redemption: None,
            session_store_lease: None,
            resume_hmac_keyring: None,
            resume_generation: 0,
            upstream_transport: Arc::new(TestSessionTransport),
        })
        .unwrap(),
    );
    session
        .mark_ready(
            Some("2025-11-25".into()),
            json!({}),
            PeerCapabilities::default(),
        )
        .unwrap();
    fixture.state.sessions.insert_active(session.clone()).await;
    (session, input_rx)
}

#[tokio::test]
async fn lagged_post_response_fails_closed_without_reinvocation() {
    let fixture = fixture(0, None);
    let (session, input_rx) = controlled_session(&fixture, "lost-response-session", 8).await;
    let response = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","id":77,"method":"ping","params":{}}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(input_rx.try_recv().unwrap().unwrap().value()["id"], 77);
    session
        .event_tx
        .send(RemoteSessionEvent {
            seq: 1,
            event_id: "lost-response-session:1".into(),
            kind: RemoteSessionEventKind::RequestCorrelated,
            message: json!({"jsonrpc":"2.0","id":77,"result":{}}),
        })
        .unwrap();
    for sequence in 2..=18 {
        session.event_tx.send(RemoteSessionEvent {
            seq: sequence, event_id: format!("lost-response-session:{sequence}"),
            kind: RemoteSessionEventKind::Notification,
            message: json!({"jsonrpc":"2.0","method":"notifications/message","params":{"sequence":sequence}}),
        }).unwrap();
    }
    let bytes = tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 64 * 1024))
        .await
        .expect("lost terminal response left the POST waiting forever")
        .unwrap();
    let wire = std::str::from_utf8(&bytes).unwrap();
    assert!(wire.contains("\"error\""));
    assert!(!wire.contains("\"result\""));
    assert!(!session.has_active_request_stream());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn initialize_wait_closes_when_actual_worker_panics_before_reply() {
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let fixture = fixture_with_crash(0, None, Some(gate.clone()));
    let request = post_request(
        None,
        &json!({"jsonrpc":"2.0","id":1,
        "method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":{},"clientInfo":{"name":"actor-loss","version":"1"}}}),
    );
    let mut initialize = Box::pin(handle_post(State(fixture.state.clone()), request));
    std::future::poll_fn(|cx| {
        assert!(
            initialize.as_mut().poll(cx).is_pending(),
            "initialize did not reach its actual worker response wait"
        );
        Poll::Ready(())
    })
    .await;
    // The actor is blocked in its existing startup notification drain. It
    // cannot reply until this real initializer has subscribed and queued.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let response = tokio::time::timeout(WAIT, initialize)
        .await
        .expect("initialize stayed pending after its actual worker panicked");
    assert_ne!(response.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 64 * 1024))
        .await
        .expect("initializer refusal body stayed open")
        .unwrap();
    assert!(!std::str::from_utf8(&bytes).unwrap().contains("\"result\""));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert!(fixture.state.sessions.snapshot().await.0.is_empty());
}

/// Writes one worker output line through the production session writer, which
/// classifies it against the current request-stream owner.
fn publish(output: &mut BroadcastJsonRpcWriter, message: &Value) {
    let mut line = serde_json::to_vec(message).unwrap();
    line.push(b'\n');
    output.write_all(&line).unwrap();
}

fn sse_messages(wire: &[u8]) -> Vec<Value> {
    std::str::from_utf8(wire)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty())
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

struct OwnerHandOff {
    new_stream: Vec<Value>,
    new_terminal: Value,
}

/// Drives a request-owner hand-off through real `handle_post`. The actor has
/// completed the OLD request while the OLD HTTP body still owns the request
/// stream. A NEW POST waits for that owner while the OLD sample and terminal
/// are published, then owns the stream and is answered.
async fn owner_hand_off(old_id: u64, new_id: u64) -> OwnerHandOff {
    let fixture = fixture(0, None);
    let (session, inbox) = controlled_session(&fixture, "owner-hand-off-session", 16).await;
    let mut output = BroadcastJsonRpcWriter::new(
        session.event_tx.clone(),
        session.retained_notification_events.clone(),
        session.next_event_id.clone(),
        session.session_id.clone(),
        session.active_request_stream.clone(),
    );

    let old = post(&fixture, Some(&session.session_id), &read_call(old_id)).await;
    assert_eq!(old.status(), StatusCode::OK);
    assert!(
        session.has_active_request_stream(),
        "OLD POST body does not own the request stream"
    );
    // The actor takes the OLD request with its reservation and computes its
    // complete outcome before the NEW POST arrives.
    let old_request = inbox
        .try_recv()
        .unwrap()
        .expect("OLD request was not enqueued");
    assert_eq!(old_request.value()["id"], old_id);
    let old_sample = json!({"jsonrpc":"2.0","id":"old-owner-sampling",
        "method":"sampling/createMessage","params":{"maxTokens":1,
        "messages":[{"role":"user","content":{"type":"text","text":"old-owner-sample"}}]}});
    let old_terminal = json!({"jsonrpc":"2.0","id":old_id,"result":{
        "content":[{"type":"text","text":"old-owner-result"}],"isError":false}});

    let mut new_call = read_call(new_id);
    new_call["params"]["arguments"]["path"] = json!("/workspace/new.txt");
    let mut waiting = Box::pin(handle_post(
        State(fixture.state.clone()),
        post_request(Some(&session.session_id), &new_call),
    ));
    for _ in 0..8 {
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await;
        assert!(
            pending,
            "NEW POST completed while another body owned the request stream"
        );
        tokio::task::yield_now().await;
    }
    assert!(
        inbox.try_recv().unwrap().is_none(),
        "NEW request reached the actor before its POST owned the request stream"
    );

    // The OLD outcome is delivered while the NEW POST waits for the owner.
    publish(&mut output, &old_sample);
    publish(&mut output, &old_terminal);
    drop(old_request);
    let old_wire = tokio::time::timeout(WAIT, axum::body::to_bytes(old.into_body(), 64 * 1024))
        .await
        .expect("OLD POST body did not release the request stream")
        .unwrap();
    assert_eq!(
        sse_messages(&old_wire),
        [old_sample, old_terminal],
        "OLD owner did not receive its own outcome"
    );

    let new = tokio::time::timeout(WAIT, waiting)
        .await
        .expect("NEW POST did not take the released request stream");
    assert_eq!(new.status(), StatusCode::OK);
    let new_request = inbox
        .try_recv()
        .unwrap()
        .expect("NEW request was not enqueued once its POST owned the request stream");
    assert_eq!(new_request.value()["id"], new_id);
    assert_eq!(
        new_request.value()["params"]["arguments"]["path"],
        "/workspace/new.txt"
    );
    let new_terminal = json!({"jsonrpc":"2.0","id":new_id,"result":{
        "content":[{"type":"text","text":"new-owner-result"}],"isError":false}});
    publish(&mut output, &new_terminal);
    drop(new_request);
    let new_wire = tokio::time::timeout(WAIT, axum::body::to_bytes(new.into_body(), 64 * 1024))
        .await
        .expect("NEW POST stream did not end before its outer deadline")
        .unwrap();
    assert!(!session.has_active_request_stream());
    fixture.state.sessions.shutdown_all_active().await.unwrap();
    OwnerHandOff {
        new_stream: sse_messages(&new_wire),
        new_terminal,
    }
}

fn assert_only_own_outcome(hand_off: &OwnerHandOff) {
    let prior = hand_off
        .new_stream
        .iter()
        .filter(|message| message.to_string().contains("old-owner"))
        .collect::<Vec<_>>();
    assert!(
        prior.is_empty(),
        "NEW POST stream delivered prior-owner events: {prior:?}"
    );
    assert_eq!(
        hand_off.new_stream,
        std::slice::from_ref(&hand_off.new_terminal),
        "NEW POST stream did not deliver exactly its own outcome"
    );
}

#[tokio::test]
async fn new_post_after_completed_actor_id_reuse_excludes_old_owner_events() {
    assert_only_own_outcome(&owner_hand_off(17, 17).await);
}

#[tokio::test]
async fn new_post_with_distinct_id_excludes_prior_owner_nested_request() {
    assert_only_own_outcome(&owner_hand_off(17, 18).await);
}
