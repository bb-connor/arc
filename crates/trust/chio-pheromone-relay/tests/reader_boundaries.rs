use chio_pheromone_relay::*;
#[test]
fn relay_imports_reject_original_duplicate_keys() {
    let raw = r#"{"schema":"secret-sentinel","schema":"other"}"#;
    for result in [
        peer_directory_from_json(raw, 0).map(|_| ()),
        peer_directory_state_from_json(raw).map(|_| ()),
        relay_supervisor_profile_from_json(raw).map(|_| ()),
        relay_alert_routing_profile_from_json(raw, 0).map(|_| ()),
        relay_alert_handoff_profile_from_json(raw, 0).map(|_| ()),
        relay_alert_delivery_profile_from_json(raw, 0).map(|_| ()),
        relay_alert_delivery_evidence_from_json(raw).map(|_| ()),
        relay_alert_assurance_external_retention_profile_from_json(raw, 0).map(|_| ()),
    ] {
        let error = match result {
            Ok(_) => panic!("ambiguous document must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, PheromoneRelayError::Input(_)));
        assert!(!format!("{error} {error:?}").contains("secret-sentinel"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
