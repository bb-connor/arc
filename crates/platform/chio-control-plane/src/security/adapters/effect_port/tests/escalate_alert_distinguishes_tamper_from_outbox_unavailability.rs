use super::*;

#[test]
fn escalate_alert_distinguishes_tamper_from_outbox_unavailability() {
    let request = alert_request();
    let tampered_store = Arc::new(RecordingAlertStore::default());
    let tampered_port = alert_port(tampered_store.clone());
    tampered_port
        .execute(&request)
        .unwrap_or_else(|error| panic!("execute alert before tamper: {error}"));
    tampered_store.tamper_evidence();
    assert_eq!(
        require_error(tampered_port.load_result(&query(&request))).kind(),
        PortErrorKind::IntegrityFailure
    );

    let unavailable_store = Arc::new(RecordingAlertStore::default());
    let unavailable_port = alert_port(unavailable_store.clone());
    unavailable_port
        .execute(&request)
        .unwrap_or_else(|error| panic!("execute alert before outage: {error}"));
    unavailable_store.fail();
    assert_eq!(
        require_error(unavailable_port.load_result(&query(&request))).kind(),
        PortErrorKind::Unavailable
    );
}
