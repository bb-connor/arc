//! Subscription changes reach the observer before the client is answered.
use super::*;

const URI: &str = "repo://docs/roadmap";

#[derive(Default)]
struct RecordingObserver {
    calls: std::sync::Mutex<Vec<String>>,
    refuse: std::sync::atomic::AtomicBool,
}

impl RecordingObserver {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, call: String) -> Result<(), AdapterError> {
        self.calls.lock().unwrap().push(call);
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
            Err(AdapterError::ConnectionFailed(
                "injected persist outage".into(),
            ))
        } else {
            Ok(())
        }
    }
}

impl ResourceSubscriptionObserver for RecordingObserver {
    fn subscribed(&self, uri: &str, capability_id: &str) -> Result<(), AdapterError> {
        self.record(format!("subscribed {uri} {capability_id}"))
    }

    fn unsubscribed(&self, uri: &str) -> Result<(), AdapterError> {
        self.record(format!("unsubscribed {uri}"))
    }

    fn authority_lost(&self, uri: &str) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("authority_lost {uri}"));
    }
}

fn observed_edge() -> (ChioMcpEdge, Arc<RecordingObserver>, String) {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let capability_id = capabilities[0].id.clone();
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    let observer = Arc::new(RecordingObserver::default());
    edge.observe_resource_subscriptions(observer.clone());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
    }));
    (edge, observer, capability_id)
}

fn request(edge: &mut ChioMcpEdge, id: u64, method: &str) -> Value {
    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0", "id": id, "method": method, "params": { "uri": URI }
    }))
    .unwrap()
}

fn subscribed(edge: &ChioMcpEdge) -> bool {
    let EdgeState::Ready { session_id } = &edge.state else {
        panic!("expected ready state");
    };
    edge.kernel
        .session_has_resource_subscription(session_id, URI)
        .unwrap()
}

#[test]
fn a_new_subscription_is_observed_once() {
    let (mut edge, observer, capability_id) = observed_edge();
    assert_eq!(
        request(&mut edge, 2, "resources/subscribe")["result"],
        json!({})
    );
    assert_eq!(
        request(&mut edge, 3, "resources/subscribe")["result"],
        json!({})
    );
    assert_eq!(
        observer.calls(),
        vec![format!("subscribed {URI} {capability_id}")]
    );
    assert!(subscribed(&edge));
}

#[test]
fn a_refused_subscription_is_rolled_back_before_the_response() {
    let (mut edge, observer, _) = observed_edge();
    observer
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let response = request(&mut edge, 2, "resources/subscribe");
    assert_eq!(response["error"]["code"], JSONRPC_INTERNAL_ERROR);
    assert!(response.get("result").is_none());
    assert!(!subscribed(&edge));
}

#[test]
fn a_refused_unsubscription_keeps_the_subscription() {
    let (mut edge, observer, _) = observed_edge();
    assert_eq!(
        request(&mut edge, 2, "resources/subscribe")["result"],
        json!({})
    );
    observer
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let response = request(&mut edge, 3, "resources/unsubscribe");
    assert_eq!(response["error"]["code"], JSONRPC_INTERNAL_ERROR);
    assert!(subscribed(&edge));

    observer
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        request(&mut edge, 4, "resources/unsubscribe")["result"],
        json!({})
    );
    assert!(!subscribed(&edge));
    assert_eq!(
        request(&mut edge, 5, "resources/unsubscribe")["result"],
        json!({})
    );
    assert_eq!(
        observer
            .calls()
            .iter()
            .filter(|call| call.starts_with("unsubscribed"))
            .count(),
        2
    );
}

fn resource_updates(edge: &mut ChioMcpEdge) -> usize {
    edge.take_pending_notifications()
        .iter()
        .filter(|notification| notification["method"] == "notifications/resources/updated")
        .count()
}

#[test]
fn an_update_is_emitted_only_while_its_capability_still_authorizes_it() {
    let (mut edge, observer, capability_id) = observed_edge();
    assert_eq!(
        request(&mut edge, 2, "resources/subscribe")["result"],
        json!({})
    );
    edge.notify_resource_updated(URI);
    assert_eq!(resource_updates(&mut edge), 1);

    edge.kernel.revoke_capability(&capability_id).unwrap();
    edge.notify_resource_updated(URI);
    assert_eq!(resource_updates(&mut edge), 0);
    edge.notify_resource_updated(URI);
    assert_eq!(resource_updates(&mut edge), 0);
    assert_eq!(
        observer
            .calls()
            .iter()
            .filter(|call| call.starts_with("authority_lost"))
            .collect::<Vec<_>>(),
        vec![&format!("authority_lost {URI}")]
    );
}
