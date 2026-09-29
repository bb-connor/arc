use super::*;


#[test]
fn escalate_alert_pending_and_delivered_replay_return_one_stable_result() {
    let store = Arc::new(RecordingAlertStore::default());
    let port = alert_port(store.clone());
    let request = alert_request();
    let result = port
        .execute(&request)
        .unwrap_or_else(|error| panic!("execute pending alert: {error}"));
    assert!(matches!(
        store.first_entry().1,
        AlertDeliveryStatus::Pending { .. }
    ));

    store.mark_delivered(now_unix_ms());
    assert_eq!(port.execute(&request), Ok(result.clone()));
    assert_eq!(
        port.load_result(&query(&request)),
        Ok(EffectExecutionStatus::Completed { result })
    );
    assert!(matches!(
        store.first_entry().1,
        AlertDeliveryStatus::Delivered { .. }
    ));
    assert_eq!(store.counts().0, 1);
}
