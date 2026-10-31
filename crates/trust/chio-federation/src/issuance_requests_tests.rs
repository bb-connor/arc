use super::*;

#[test]
fn decisions_name_their_status_and_capability() {
    let approved = IssuanceDecision::Approved {
        capability_id: "cap-1".into(),
    };
    assert_eq!(approved.status(), IssuanceRequestStatus::Approved);
    assert_eq!(approved.capability_id(), Some("cap-1"));
    assert_eq!(
        IssuanceDecision::Denied.status(),
        IssuanceRequestStatus::Denied
    );
    assert_eq!(IssuanceDecision::Denied.capability_id(), None);
}

#[test]
fn status_names_round_trip_and_unknown_names_fail_closed() {
    for status in [
        IssuanceRequestStatus::Pending,
        IssuanceRequestStatus::Deciding,
        IssuanceRequestStatus::Approved,
        IssuanceRequestStatus::Denied,
    ] {
        assert_eq!(IssuanceRequestStatus::parse(status.as_str()), Some(status));
    }
    assert_eq!(IssuanceRequestStatus::parse("expired"), None);
}

#[test]
fn page_limits_outside_one_to_max_are_refused() {
    assert_eq!(
        IssuancePageLimit::new(0),
        Err(IssuanceStoreError::InvalidPageLimit(0))
    );
    assert_eq!(
        IssuancePageLimit::new(MAX_ISSUANCE_LIST_PAGE + 1),
        Err(IssuanceStoreError::InvalidPageLimit(
            MAX_ISSUANCE_LIST_PAGE + 1
        ))
    );
    assert_eq!(IssuancePageLimit::new(1).map(IssuancePageLimit::get), Ok(1));
    assert_eq!(
        IssuancePageLimit::new(MAX_ISSUANCE_LIST_PAGE),
        Ok(IssuancePageLimit::MAX)
    );
}

#[test]
fn in_memory_repository_conforms() {
    conformance::all(&|pending_cap| {
        std::sync::Arc::new(memory::InMemoryIssuanceRequestRepository::with_pending_cap(
            pending_cap,
        )) as std::sync::Arc<dyn IssuanceRequestRepository>
    });
}

#[test]
fn summaries_never_carry_presentation_or_challenge_payloads() {
    let page = IssuanceRequestPage {
        requests: vec![IssuanceRequestSummary {
            challenge_id: "c7".into(),
            subject: "did:chio:abc".into(),
            verifier: "https://b.example".into(),
            submitted_at: 100,
            expires_at: 1_000,
            status: IssuanceRequestStatus::Pending,
            decided_at: None,
            capability_id: None,
            decision_reason: None,
        }],
        next_after: None,
    };
    let json = serde_json::to_string(&page).unwrap_or_default();
    assert!(json.contains("\"challengeId\":\"c7\""), "{json}");
    assert!(!json.contains("presentation"), "{json}");
    assert!(!json.contains("challengeJson"), "{json}");
}
