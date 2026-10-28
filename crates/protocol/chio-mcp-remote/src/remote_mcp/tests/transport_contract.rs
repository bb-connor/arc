use super::*;

#[test]
fn standalone_server_request_is_retained_for_get_without_post_ownership() {
    let (sender, _) = broadcast::channel(8);
    let (inbox, _receiver) = mcp_inbox();
    let retained = Arc::new(StdMutex::new(VecDeque::new()));
    let writer = BroadcastJsonRpcWriter::new(
        sender,
        retained.clone(),
        Arc::new(AtomicU64::new(0)),
        "standalone-session".into(),
        inbox.response_context(),
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
    let (inbox, receiver) = mcp_inbox();
    let request = inbox
        .account(json!({"jsonrpc":"2.0","id":7,"method":"ping"}))
        .unwrap();
    let writer = BroadcastJsonRpcWriter::new(
        sender,
        retained.clone(),
        Arc::new(AtomicU64::new(0)),
        "correlated-session".into(),
        inbox.response_context(),
    );
    let _actor_scope = receiver.enter_response_scope(&request).unwrap();
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

#[test]
fn worker_output_line_with_a_duplicate_key_is_refused_before_an_event() {
    let (sender, mut events) = broadcast::channel(8);
    let (inbox, _receiver) = mcp_inbox();
    let mut writer = BroadcastJsonRpcWriter::new(
        sender,
        Arc::new(StdMutex::new(VecDeque::new())),
        Arc::new(AtomicU64::new(0)),
        "duplicate-session".into(),
        inbox.response_context(),
    );
    let line = concat!(
        r#"{"jsonrpc":"2.0","id":7,"result":{"_meta":{"chioEvidence":"#,
        r#"{"receipt":{"metadata":{"lane":"a","lane":"b"}}}}}}"#,
        "\n"
    );
    let error = std::io::Write::write(&mut writer, line.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let source = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<chio_core::canonical::UntrustedJsonError>());
    assert!(
        matches!(
            source,
            Some(chio_core::canonical::UntrustedJsonError::SignedInput(_))
        ),
        "{error:?}"
    );
    assert!(events.try_recv().is_err());
}
