//! A required roots refresh withdraws the session's previous roots when it is
//! queued. Root-dependent operations are refused until a fresh roots reply
//! succeeds, and a failed, rejected, expired or cancelled refresh restores
//! nothing.
use super::*;
use std::sync::mpsc;

const IN_ROOT: &str = "file:///workspace/project/docs/roadmap.md";
const NO_ROOTS: &str =
    "resource read denied: no enforceable filesystem roots are available for this session";

struct StepClock(Mutex<u64>);
impl StepClock {
    fn new() -> Self {
        Self(Mutex::new(0))
    }
    fn set(&self, elapsed_ms: u64) {
        *self.0.lock().unwrap() = elapsed_ms;
    }
}
impl chio_security_types::clock::Clock for StepClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::*;
        let elapsed = *self.0.lock().unwrap();
        Ok(ClockReading::new(
            UnixMillis::new(1_700_000_000_000 + elapsed),
            MonotonicInstant::from_nanos(elapsed * 1_000_000),
        ))
    }
}

/// Complete JSON-RPC lines written by the edge.
struct LineSink {
    buffer: Vec<u8>,
    lines: mpsc::Sender<Value>,
}
impl std::io::Write for LineSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line = self.buffer.drain(..=end).collect::<Vec<_>>();
            if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                let _ = self.lines.send(value);
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An initialized session that declared `roots.listChanged`, holds a read grant
/// under `file:///workspace/`, and whose initial refresh returned
/// `file:///workspace/project`.
fn edge_with_existing_roots(
    clock: Option<Arc<dyn chio_security_types::clock::Clock>>,
) -> (ChioMcpEdge, SessionId) {
    let (kernel, _) = match clock {
        Some(clock) => protocol_boundaries::make_kernel_with_clock(clock),
        None => make_kernel(),
    };
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"capabilities":{"roots":{"listChanged":true}}}}));
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    refresh_with(
        &mut edge,
        vec![roots_reply("edge-client-1", "file:///workspace/project")],
    );
    assert_eq!(
        edge.kernel.session(&session_id).unwrap().roots().len(),
        1,
        "setup precondition: the initial refresh must install existing roots"
    );
    assert_ne!(
        read_denial(&mut edge, 2).as_deref(),
        Some(NO_ROOTS),
        "setup precondition: a read inside the existing roots must not be root-denied"
    );
    (edge, session_id)
}

fn roots_reply(id: &str, uri: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"roots":[{"uri":uri,"name":"root"}]}})
}

/// Service the queued refresh with these client messages already delivered.
fn refresh_with(edge: &mut ChioMcpEdge, messages: Vec<Value>) {
    let (tx, mut rx) = mpsc::channel();
    for message in messages {
        tx.send(ClientInbound::Message(message)).unwrap();
    }
    drop(tx);
    edge.process_pending_actions_with_channel(&mut rx, &mut Vec::new())
        .unwrap();
}

fn list_changed(edge: &mut ChioMcpEdge) {
    assert!(edge
        .handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"}))
        .is_none());
}

/// The error message of an in-root read, if it was refused.
fn read_denial(edge: &mut ChioMcpEdge, id: u64) -> Option<String> {
    let response = edge
        .handle_jsonrpc(json!({"jsonrpc":"2.0","id":id,"method":"resources/read",
            "params":{"uri":IN_ROOT}}))
        .unwrap();
    response["error"]["message"].as_str().map(str::to_owned)
}

#[test]
fn list_changed_withdraws_existing_roots_while_the_refresh_is_queued() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    list_changed(&mut edge);
    assert!(
        edge.kernel.session(&session_id).unwrap().roots().is_empty(),
        "previous roots stayed usable while the refresh was queued"
    );
    assert_eq!(read_denial(&mut edge, 3).as_deref(), Some(NO_ROOTS));
}

#[test]
fn refresh_error_reply_leaves_no_usable_roots() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    list_changed(&mut edge);
    refresh_with(
        &mut edge,
        vec![json!({"jsonrpc":"2.0","id":"edge-client-2",
            "error":{"code":-32603,"message":"roots unavailable"}})],
    );
    assert!(edge.kernel.session(&session_id).unwrap().roots().is_empty());
    assert_eq!(read_denial(&mut edge, 3).as_deref(), Some(NO_ROOTS));
}

#[test]
fn cancelled_roots_request_leaves_no_usable_roots() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    list_changed(&mut edge);
    refresh_with(
        &mut edge,
        vec![json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":"edge-client-2","reason":"client cancelled"}})],
    );
    assert!(edge.kernel.session(&session_id).unwrap().roots().is_empty());
    assert_eq!(read_denial(&mut edge, 3).as_deref(), Some(NO_ROOTS));
}

#[test]
fn refresh_deadline_is_thirty_seconds_and_leaves_no_usable_roots() {
    let clock = Arc::new(StepClock::new());
    let (mut edge, session_id) = edge_with_existing_roots(Some(clock.clone()));
    list_changed(&mut edge);
    let (client_tx, client_rx) = mpsc::channel::<ClientInbound>();
    let (line_tx, line_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut client_rx = client_rx;
        let mut sink = LineSink {
            buffer: Vec::new(),
            lines: line_tx,
        };
        edge.process_pending_actions_with_channel(&mut client_rx, &mut sink)
            .unwrap();
        sink.flush().unwrap();
        edge
    });
    let request = line_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the queued refresh did not request roots");
    assert_eq!(request["method"], "roots/list");

    clock.set(29_999);
    std::thread::sleep(Duration::from_millis(250));
    assert!(
        !worker.is_finished(),
        "the refresh ended before its 30 s deadline"
    );
    clock.set(30_001);
    let started = std::time::Instant::now();
    while !worker.is_finished() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the refresh outlived its 30 s deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut edge = worker.join().unwrap();
    drop(client_tx);
    assert!(edge.kernel.session(&session_id).unwrap().roots().is_empty());
    assert_eq!(read_denial(&mut edge, 3).as_deref(), Some(NO_ROOTS));
}

#[test]
fn healthy_refresh_after_list_changed_restores_reads_inside_the_new_roots() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    list_changed(&mut edge);
    refresh_with(
        &mut edge,
        vec![roots_reply("edge-client-2", "file:///workspace")],
    );
    let roots = edge.kernel.session(&session_id).unwrap().roots().to_vec();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].uri, "file:///workspace");
    assert_ne!(read_denial(&mut edge, 3).as_deref(), Some(NO_ROOTS));
}

// Test-only proposal. Append inside runtime_tests/roots_refresh_invalidation.rs.
// Not installed, compiled, or executed by the independent reviewer.
// The existing edge_with_existing_roots and LineSink fixtures are reused.

fn hold_all_ordinary_slots(sender: &crate::ingress::McpInboxSender) -> Vec<AccountedMessage> {
    let mut held = Vec::new();
    // 128 ordinary slots is the current fixed inbox ceiling. No open-ended fill.
    for _ in 0..128 {
        match sender.decode(
            br#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#,
            4096,
        ) {
            Ok(message) => held.push(message),
            Err(AdapterError::IngressCapacity) => break,
            Err(error) => panic!("ordinary admission failed: {error}"),
        }
    }
    assert_eq!(sender.usage().unwrap().messages, 128);
    held
}

#[test]
fn carried_roots_cancel_uses_reserved_capacity_under_ordinary_saturation() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    let (sender, mut inbox) = mcp_inbox();
    edge.inbox_admission = inbox.admission.clone();
    edge.pending_action_route = PendingActionRoute::NextClientRequest;
    list_changed(&mut edge);
    let carrier = sender
        .decode(
            br#"{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///workspace/project/docs/roadmap.md"}}"#,
            4096,
        )
        .unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (message, reservation) = carrier.into_parts();
        let mut sink = LineSink {
            buffer: Vec::new(),
            lines: line_tx,
        };
        let (_cancel_tx, mut cancel_rx) = mpsc::channel();
        let response = edge.handle_inbound_with_channel(
            message,
            reservation.request_digest().cloned(),
            &mut inbox.receiver,
            &mut cancel_rx,
            &mut sink,
        );
        // Keep the original carrier reservation until handling is complete.
        drop(reservation);
        (edge, response, inbox)
    });
    let roots = line_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(roots["method"], "roots/list");
    assert_eq!(roots["id"], "edge-client-2");
    let held = hold_all_ordinary_slots(&sender);
    for wire in [
        br#"{"jsonrpc":"2.0","id":"wrong","result":{"roots":[]}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":8}}"#,
    ] {
        assert!(matches!(
            sender.decode(wire, 4096),
            Err(AdapterError::IngressCapacity)
        ));
    }
    // A matching roots reply must still obtain the reserved share. Retaining
    // then dropping it demonstrates original reservation accounting.
    let full = sender.usage().unwrap();
    let reply = sender
        .decode(
            br#"{"jsonrpc":"2.0","id":"edge-client-2","result":{"roots":[]}}"#,
            4096,
        )
        .unwrap();
    assert_eq!(sender.usage().unwrap().messages, full.messages + 1);
    drop(reply);
    assert_eq!(sender.usage().unwrap(), full);

    let cancellation = sender.decode(
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"saturated carrier cancel"}}"#,
        4096,
    );
    let cancellation = match cancellation {
        Ok(message) => message,
        Err(error) => {
            // Wake and join the worker before the intended red assertion. Do
            // not leak a worker waiting for its production 30 second deadline.
            drop(held);
            drop(sender);
            let _ = worker.join().unwrap();
            panic!("matching carrier cancellation lost reserved admission: {error}");
        }
    };
    sender.send(cancellation).unwrap();
    let started = std::time::Instant::now();
    while !worker.is_finished() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !worker.is_finished() {
        drop(held);
        drop(sender);
        let _ = worker.join().unwrap();
        panic!("admitted carrier cancellation did not end the roots wait");
    }
    let (edge, response, inbox) = worker.join().unwrap();
    let response = response.unwrap().unwrap();
    assert_eq!(response["id"], 7);
    assert_eq!(response["error"]["code"], -32800);
    assert_eq!(edge.pending_actions.len(), 1);
    assert!(edge.kernel.session(&session_id).unwrap().roots().is_empty());
    assert!(edge
        .kernel
        .session(&session_id)
        .unwrap()
        .inflight()
        .is_empty());

    // The carrier reservation was released. Refill that slot before checking
    // that both active identities stopped claiming the reserved share.
    let extra = hold_all_ordinary_slots(&sender);
    for wire in [
        br#"{"jsonrpc":"2.0","id":"edge-client-2","result":{"roots":[]}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#,
    ] {
        assert!(matches!(
            sender.decode(wire, 4096),
            Err(AdapterError::IngressCapacity)
        ));
    }
    drop(extra);
    drop(held);
    drop(inbox);
    assert_eq!(
        sender.usage().unwrap(),
        crate::ingress::IngressUsage::default()
    );
}

#[test]
fn carried_roots_control_scope_ends_after_success_and_error_reply() {
    for reply in [
        br#"{"jsonrpc":"2.0","id":"edge-client-2","result":{"roots":[{"uri":"file:///workspace/project"}]}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":"edge-client-2","error":{"code":-32603,"message":"roots unavailable"}}"#,
    ] {
        let (mut edge, _) = edge_with_existing_roots(None);
        let (sender, mut inbox) = mcp_inbox();
        edge.inbox_admission = inbox.admission.clone();
        edge.pending_action_route = PendingActionRoute::NextClientRequest;
        list_changed(&mut edge);
        let (line_tx, line_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut sink = LineSink { buffer: Vec::new(), lines: line_tx };
            let terminal = edge.service_pending_actions_before_request(
                &json!({"jsonrpc":"2.0","id":7,"method":"ping","params":{}}),
                &mut inbox.receiver,
                &mut sink,
            ).unwrap();
            assert!(terminal.is_none());
            (edge, inbox)
        });
        assert_eq!(line_rx.recv_timeout(Duration::from_secs(10)).unwrap()["method"], "roots/list");
        let held = hold_all_ordinary_slots(&sender);
        sender.send(sender.decode(reply, 4096).unwrap()).unwrap();
        let (edge, inbox) = worker.join().unwrap();
        assert!(edge.pending_actions.is_empty());
        for wire in [
            br#"{"jsonrpc":"2.0","id":"edge-client-2","result":{"roots":[]}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#,
        ] {
            assert!(matches!(sender.decode(wire, 4096), Err(AdapterError::IngressCapacity)));
        }
        drop(held);
        drop(inbox);
        assert_eq!(sender.usage().unwrap(), crate::ingress::IngressUsage::default());
    }
}

// Test-only proposal. Append inside roots_refresh_invalidation.rs.
// Root owns installation and actual results. This test is uncompiled/unrun here.
#[test]
fn failed_carrier_control_registration_refuses_without_consuming_refresh() {
    let (mut edge, session_id) = edge_with_existing_roots(None);
    let (_sender, mut inbox) = mcp_inbox();
    edge.inbox_admission = inbox.admission.clone();
    edge.pending_action_route = PendingActionRoute::NextClientRequest;
    list_changed(&mut edge);
    let id = "x".repeat(513);
    let carrier = json!({"jsonrpc":"2.0","id":id,"method":"ping","params":{}});
    let digest = chio_kernel::ProtocolRequestDigest::from_decoded_json(&carrier).unwrap();
    let (_cancel_tx, mut cancel_rx) = mpsc::channel();
    let mut output = Vec::new();
    let response = edge
        .handle_inbound_with_channel(
            carrier,
            Some(digest),
            &mut inbox.receiver,
            &mut cancel_rx,
            &mut output,
        )
        .unwrap()
        .unwrap();
    assert!(
        response.get("error").is_some(),
        "carrier reached ping: {response}"
    );
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(
        edge.pending_actions.len(),
        1,
        "failed carrier consumed refresh"
    );
    assert!(
        output.is_empty(),
        "a rejected carrier emitted a roots request"
    );
    assert!(edge.kernel.session(&session_id).unwrap().roots().is_empty());
    let operation = inbox.admission.begin_operation(&json!(7), None).unwrap();
    drop(operation);
    let wait = inbox.admission.begin_wait(json!("next-reply")).unwrap();
    drop(wait);
}

#[test]
fn unavailable_carrier_control_remains_global_without_consuming_refresh() {
    let (mut edge, _) = edge_with_existing_roots(None);
    let (_sender, mut inbox) = mcp_inbox();
    edge.inbox_admission = inbox.admission.clone();
    edge.pending_action_route = PendingActionRoute::NextClientRequest;
    list_changed(&mut edge);
    let original = inbox.admission.begin_operation(&json!(900), None).unwrap();
    let (_cancel_tx, mut cancel_rx) = mpsc::channel();
    let mut output = Vec::new();
    let error = edge
        .handle_inbound_with_channel(
            json!({"jsonrpc":"2.0","id":7,"method":"ping","params":{}}),
            None,
            &mut inbox.receiver,
            &mut cancel_rx,
            &mut output,
        )
        .unwrap_err();
    assert!(
        matches!(error, AdapterError::ConnectionFailed(ref cause) if cause == "MCP operation control is unavailable")
    );
    assert_eq!(edge.pending_actions.len(), 1);
    assert!(output.is_empty());
    // The failed attempt must not release an unrelated active parent.
    assert!(matches!(
        inbox.admission.begin_operation(&json!(7), None),
        Err(AdapterError::ConnectionFailed(_))
    ));
    drop(original);
    drop(inbox.admission.begin_operation(&json!(7), None).unwrap());
}
