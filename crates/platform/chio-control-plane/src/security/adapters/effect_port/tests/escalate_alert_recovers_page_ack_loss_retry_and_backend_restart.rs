use super::*;

#[test]
fn escalate_alert_recovers_page_ack_loss_retry_and_backend_restart() {
    let store = Arc::new(RecordingAlertStore::default());
    store.lose_next_page_ack();
    let request = alert_request();
    let port = alert_port(store.clone());
    assert_eq!(
        port.load_result(&query(&request)),
        Ok(EffectExecutionStatus::NotExecuted)
    );

    let result = port
        .execute(&request)
        .unwrap_or_else(|error| panic!("execute alert after ack loss: {error}"));
    assert!(result.applied);
    assert_eq!(result.effect_id, request.effect_id);
    assert_ne!(result.resulting_version_hash, Digest32::new([0_u8; 32]));
    let (alert, status) = store.first_entry();
    assert!(matches!(status, AlertDeliveryStatus::Pending { .. }));
    assert!(alert
        .event_id
        .as_str()
        .starts_with("active_response_alert_event:"));
    assert!(alert
        .idempotency_key
        .as_str()
        .starts_with("active_response_alert_command:"));
    assert_ne!(alert.event_id, alert.idempotency_key);
    assert_ne!(alert.finding_id_hash, alert.evidence_hash);
    assert_ne!(
        result.resulting_version_hash,
        alert
            .action_id_hash
            .unwrap_or_else(|| panic!("alert action hash missing"))
    );
    assert_eq!(store.counts().0, 1);

    assert_eq!(port.execute(&request), Ok(result.clone()));
    assert_eq!(store.counts().0, 1);
    let restarted = alert_port(store.clone());
    assert_eq!(
        restarted.load_result(&query(&request)),
        Ok(EffectExecutionStatus::Completed {
            result: result.clone()
        })
    );
    assert_eq!(restarted.execute(&request), Ok(result));
    assert_eq!(store.counts().0, 1);
}
