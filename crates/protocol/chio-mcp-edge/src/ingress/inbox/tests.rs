#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;

#[test]
fn deferred_ownership_stays_charged_and_matching_control_uses_reserved_capacity() {
    let (sender, receiver) = mcp_inbox();
    let mut deferred = Vec::new();
    loop {
        let value = serde_json::json!({"jsonrpc":"2.0","method":"notifications/message",
            "params":{"data":"x".repeat(512 * 1024)}});
        let message = match sender.account(value) {
            Ok(message) => message,
            Err(AdapterError::IngressCapacity) => break,
            Err(error) => panic!("admission: {error}"),
        };
        sender.send(message).unwrap();
        match receiver.receiver.recv().unwrap() {
            ClientInbound::Accounted(message) => deferred.push(message),
            _ => panic!("expected accounted message"),
        }
    }
    while let Ok(message) = sender.decode(b"{}", 4096) {
        sender.send(message).unwrap();
        match receiver.receiver.recv().unwrap() {
            ClientInbound::Accounted(message) => deferred.push(message),
            _ => panic!("expected accounted message"),
        }
    }
    let full = sender.usage().unwrap();
    assert!(full.wire_bytes > 6 * 1024 * 1024);
    let _operation = receiver
        .admission
        .begin_operation(&serde_json::json!(5), Some("task"))
        .unwrap();
    let _wait = receiver
        .admission
        .begin_wait(serde_json::json!("reply"))
        .unwrap();
    for wire in [
        br#"{"jsonrpc":"2.0","id":"wrong","result":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":"reply","method":"tools/call","params":{}}"#,
        br#"{"jsonrpc":"2.0","id":"reply","method":null,"result":{}}"#,
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":6}}"#,
    ] {
        assert!(matches!(
            sender.decode(wire, 4096),
            Err(AdapterError::IngressCapacity)
        ));
    }
    for wire in [
        br#"{"jsonrpc":"2.0","id":"reply","result":{"roots":[]}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}"#,
        br#"{"jsonrpc":"2.0","id":7,"method":"tasks/cancel","params":{"taskId":"task"}}"#,
    ] {
        let message = sender.decode(wire, 4096).unwrap();
        sender.send(message).unwrap();
    }
    let retained = sender.usage().unwrap();
    assert_eq!(retained.messages, full.messages + 3);
    assert!(retained.wire_bytes <= 8 * 1024 * 1024);
    drop(receiver);
    assert_eq!(sender.usage().unwrap(), full);
    drop(deferred);
    assert_eq!(sender.usage().unwrap(), IngressUsage::default());
}

#[test]
fn rejected_original_bytes_release_capacity_without_relaxing_proofs_or_duplicates() {
    let (sender, _receiver) = mcp_inbox();
    let duplicate = br#"{"jsonrpc":"2.0","params":{"data":{"x":1,"x":2}}}"#;
    assert!(sender.decode(duplicate, 4096).is_err());
    assert_eq!(sender.usage().unwrap(), IngressUsage::default());
    let body = br#"{"jsonrpc":"2.0","params":{"ordinary":0.50,"small":1e-05,"wide":18446744073709551615}}"#;
    let message = sender.decode(body, body.len()).unwrap();
    assert_eq!(message["params"]["wide"].as_u64(), Some(u64::MAX));
    assert!(sender.decode(body, body.len() - 1).is_err());
    drop(message);
    assert_eq!(sender.usage().unwrap(), IngressUsage::default());
    let dense = format!("[{}0]", "0,".repeat(1024 * 1024));
    assert!(matches!(
        sender.decode(dense.as_bytes(), 8 * 1024 * 1024),
        Err(AdapterError::IngressCapacity)
    ));
    assert_eq!(sender.usage().unwrap(), IngressUsage::default());
}

#[test]
fn failed_send_releases_once_and_closed_receivers_refuse_future_decode() {
    let (sender, receiver) = mcp_inbox();
    let message = sender.decode(b"{}", 4096).unwrap();
    drop(receiver);
    assert!(sender.send(message).is_err());
    assert_eq!(sender.usage().unwrap(), IngressUsage::default());
    assert!(sender.decode(b"{}", 4096).is_err());
}

#[test]
fn missing_null_cancellation_identity_cannot_claim_control_capacity() {
    let (_sender, receiver) = mcp_inbox();
    let _operation = receiver
        .admission
        .begin_operation(&Value::Null, None)
        .unwrap();
    let identity =
        control_identity(br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#);
    assert!(!matches_control(
        &receiver.admission.state.lock().unwrap(),
        &identity
    ));
    let explicit = control_identity(
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}"#,
    );
    assert!(matches_control(
        &receiver.admission.state.lock().unwrap(),
        &explicit
    ));
}
