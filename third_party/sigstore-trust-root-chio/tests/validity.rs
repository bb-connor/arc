use chrono::{DateTime, Utc};
use sigstore_trust_root::{TrustedRoot, ValidityPeriod};

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn root_with_period(start: Option<&str>, end: Option<&str>) -> TrustedRoot {
    let mut root = TrustedRoot::production().unwrap();
    root.timestamp_authorities.truncate(1);
    assert_eq!(root.timestamp_authorities.len(), 1);
    root.timestamp_authorities[0].valid_for = Some(ValidityPeriod {
        start: start.map(str::to_owned),
        end: end.map(str::to_owned),
    });
    root
}

#[test]
fn malformed_tsa_bounds_do_not_authorize_a_timestamp() {
    for (start, end) in [(Some("invalid"), None), (None, Some("invalid"))] {
        assert!(!root_with_period(start, end).is_timestamp_within_tsa_validity(now()));
    }
}

#[test]
fn malformed_tsa_bounds_do_not_become_absent_certificate_constraints() {
    for (start, end) in [(Some("invalid"), None), (None, Some("invalid"))] {
        assert!(root_with_period(start, end)
            .tsa_certs_with_validity()
            .is_err());
    }
}

#[test]
fn malformed_tsa_bounds_produce_a_range_error() {
    for (start, end) in [(Some("invalid"), None), (None, Some("invalid"))] {
        assert!(root_with_period(start, end)
            .tsa_validity_for_time(now())
            .is_err());
    }
}

#[test]
fn parsing_rejects_invalid_authority_and_key_windows() {
    let original = serde_json::to_value(TrustedRoot::production().unwrap()).unwrap();
    for path in [
        "/timestampAuthorities/0",
        "/certificateAuthorities/0",
        "/tlogs/0/publicKey",
        "/ctlogs/0/publicKey",
    ] {
        for bounds in [
            serde_json::json!({"start": "invalid"}),
            serde_json::json!({"end": "invalid"}),
            serde_json::json!({"start": "2025-01-02T00:00:00Z", "end": "2025-01-01T00:00:00Z"}),
        ] {
            let mut root = original.clone();
            root.pointer_mut(path).unwrap()["validFor"] = bounds;
            assert!(TrustedRoot::from_json(&root.to_string()).is_err(), "{path}");
        }
    }
}

#[test]
fn valid_bounded_and_open_windows_keep_their_meaning() {
    let before = "2024-01-01T00:00:00Z";
    let after = "2026-01-01T00:00:00Z";
    for (start, end, allowed) in [
        (None, None, true),
        (Some(before), None, true),
        (None, Some(after), true),
        (Some(after), None, false),
        (None, Some(before), false),
        (Some(before), Some(after), true),
    ] {
        let root = root_with_period(start, end);
        assert_eq!(root.is_timestamp_within_tsa_validity(now()), allowed);
        assert!(root.tsa_certs_with_validity().is_ok());
        assert!(TrustedRoot::from_json(&serde_json::to_string(&root).unwrap()).is_ok());
    }
    let root = root_with_period(Some(before), Some(after));
    let bounds = root.tsa_validity_for_time(now()).unwrap().unwrap();
    assert!(bounds.0 < now() && now() < bounds.1);
    assert!(root.is_timestamp_within_tsa_validity(bounds.0));
    assert!(root.is_timestamp_within_tsa_validity(bounds.1));
    assert!(TrustedRoot::staging().is_ok());
}
