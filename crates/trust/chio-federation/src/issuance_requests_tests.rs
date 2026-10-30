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
fn list_page_size_is_clamped() {
    let query = |limit| IssuanceListQuery {
        status: None,
        after: None,
        limit,
    };
    assert_eq!(query(0).page_size(), 1);
    assert_eq!(query(10).page_size(), 10);
    assert_eq!(query(10_000).page_size(), MAX_ISSUANCE_LIST_PAGE);
}
