use super::*;

#[test]
fn standalone_server_request_is_retained_for_get_without_post_ownership() {
    let (sender, _) = broadcast::channel(8);
    let retained = Arc::new(StdMutex::new(VecDeque::new()));
    let writer = BroadcastJsonRpcWriter::new(
        sender,
        retained.clone(),
        Arc::new(AtomicU64::new(0)),
        "standalone-session".into(),
        Arc::new(Mutex::new(())),
    );
    let event = writer
        .next_event(json!({"jsonrpc":"2.0","id":"roots-1","method":"roots/list","params":{}}))
        .unwrap();
    assert!(
        !should_emit_post_stream_event(&event, Some(&json!(7)), true),
        "standalone server request was treated as request-correlated POST traffic"
    );
    let retained = retained.lock().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].message, event.message);
}

#[test]
fn sampling_and_terminal_reply_keep_the_actual_post_owner_and_skip_get_replay() {
    let (sender, _) = broadcast::channel(8);
    let retained = Arc::new(StdMutex::new(VecDeque::new()));
    let owner = Arc::new(Mutex::new(()));
    let writer = BroadcastJsonRpcWriter::new(
        sender,
        retained.clone(),
        Arc::new(AtomicU64::new(0)),
        "correlated-session".into(),
        owner.clone(),
    );
    let _post_owner = owner.try_lock().unwrap();
    for message in [
        json!({"jsonrpc":"2.0","id":"sampling-1","method":"sampling/createMessage","params":{}}),
        json!({"jsonrpc":"2.0","id":7,"result":{"content":[]}}),
    ] {
        let event = writer.next_event(message).unwrap();
        assert_eq!(event.kind, RemoteSessionEventKind::RequestCorrelated);
        assert!(should_emit_post_stream_event(&event, Some(&json!(7)), true));
        assert!(!event.kind.is_session_owned());
    }
    assert!(retained.lock().unwrap().is_empty());
}

#[test]
fn retained_event_schema_preserves_old_notifications_and_standalone_request_shape() {
    for (message, kind) in [
        (
            json!({"jsonrpc":"2.0","method":"notifications/message","params":{}}),
            RemoteSessionEventKind::Notification,
        ),
        (
            json!({"jsonrpc":"2.0","id":"roots-1","method":"roots/list","params":{}}),
            RemoteSessionEventKind::StandaloneRequest,
        ),
    ] {
        let original = json!({"seq":1,"event_id":"session-1","message":message});
        let retained: RetainedRemoteSessionEvent =
            serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(&retained).unwrap(), original);
        assert_eq!(
            classify_remote_session_event(&retained.message, false),
            kind
        );
    }
}
