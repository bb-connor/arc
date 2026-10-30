//! Behaviour every [`IssuanceRequestRepository`] implementation must show.
//! The in-memory double and each durable store run [`all`].

use std::sync::{Arc, Barrier};

use super::{
    IssuanceDecision, IssuanceListQuery, IssuancePageLimit, IssuanceRequestPage,
    IssuanceRequestRecord, IssuanceRequestRepository, IssuanceRequestStatus, IssuanceStoreError,
    EXPIRED_REASON, MAX_ISSUANCE_LIST_PAGE,
};

/// Opens a fresh, empty repository holding at most `pending_cap` open
/// requests.
pub type Factory<'a> = &'a dyn Fn(usize) -> Arc<dyn IssuanceRequestRepository>;

fn record_expiring(id: &str, expires_at: u64) -> IssuanceRequestRecord {
    IssuanceRequestRecord {
        challenge_id: id.into(),
        subject: "did:chio:abc".into(),
        verifier: "https://b.example".into(),
        presentation_json: "{\"presentation\":true}".into(),
        challenge_json: "{\"challenge\":true}".into(),
        submitted_at: 100,
        expires_at,
        status: IssuanceRequestStatus::Pending,
        decided_at: None,
        capability_id: None,
        decision_reason: None,
    }
}

fn record(id: &str) -> IssuanceRequestRecord {
    record_expiring(id, 1_000)
}

fn query(
    status: Option<IssuanceRequestStatus>,
    after: Option<&str>,
    limit: usize,
) -> IssuanceListQuery<'_> {
    let Ok(limit) = IssuancePageLimit::new(limit) else {
        panic!("conformance page limit {limit} is outside 1..={MAX_ISSUANCE_LIST_PAGE}");
    };
    IssuanceListQuery {
        status,
        after,
        limit,
    }
}

fn ids(page: &Result<IssuanceRequestPage, IssuanceStoreError>) -> Vec<String> {
    match page {
        Ok(page) => page
            .requests
            .iter()
            .map(|request| request.challenge_id.clone())
            .collect(),
        Err(error) => vec![format!("error: {error}")],
    }
}

fn next_after(page: &Result<IssuanceRequestPage, IssuanceStoreError>) -> Option<String> {
    page.as_ref().ok().and_then(|page| page.next_after.clone())
}

fn status_of(
    repository: &dyn IssuanceRequestRepository,
    id: &str,
) -> Option<IssuanceRequestStatus> {
    repository
        .get(id)
        .ok()
        .flatten()
        .map(|stored| stored.status)
}

pub fn already_expired_record_is_refused(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(
        repository.submit(&record_expiring("late", 150), 150),
        Err(IssuanceStoreError::Expired("late".into()))
    );
    assert_eq!(repository.get("late"), Ok(None));
}

pub fn second_submission_for_a_challenge_is_already_submitted(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record("c1"), 100), Ok(()));
    assert_eq!(
        repository.submit(&record("c1"), 100),
        Err(IssuanceStoreError::AlreadySubmitted("c1".into()))
    );
}

pub fn only_the_claimant_finishes_a_request(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record("c2"), 100), Ok(()));
    assert!(matches!(
        repository.claim("c2", 120),
        Ok(claimed) if claimed.status == IssuanceRequestStatus::Deciding
    ));
    assert_eq!(
        repository.claim("c2", 120).map(|_| ()),
        Err(IssuanceStoreError::NotPending("c2".into()))
    );
    let approved = IssuanceDecision::Approved {
        capability_id: "cap-1".into(),
    };
    assert_eq!(repository.finish("c2", &approved, 150, None), Ok(()));
    let stored = repository.get("c2").ok().flatten();
    assert_eq!(
        stored.as_ref().map(|stored| stored.status),
        Some(IssuanceRequestStatus::Approved)
    );
    assert_eq!(
        stored.as_ref().and_then(|stored| stored.decided_at),
        Some(150)
    );
    assert_eq!(
        stored
            .as_ref()
            .and_then(|stored| stored.capability_id.as_deref()),
        Some("cap-1")
    );
    assert_eq!(
        repository.finish("c2", &IssuanceDecision::Denied, 160, Some("late")),
        Err(IssuanceStoreError::NotClaimed("c2".into()))
    );
    assert_eq!(
        repository.claim("absent", 120).map(|_| ()),
        Err(IssuanceStoreError::NotFound("absent".into()))
    );
}

pub fn released_request_is_pending_again(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record("c3"), 100), Ok(()));
    assert!(repository.claim("c3", 120).is_ok());
    assert_eq!(repository.release("c3"), Ok(()));
    assert_eq!(
        status_of(&*repository, "c3"),
        Some(IssuanceRequestStatus::Pending)
    );
    assert!(repository.claim("c3", 120).is_ok());
    assert_eq!(
        repository.release("absent"),
        Err(IssuanceStoreError::NotClaimed("absent".into()))
    );
}

pub fn expired_pending_request_is_not_claimed(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(
        repository.submit(&record_expiring("c-old", 200), 100),
        Ok(())
    );
    assert_eq!(
        repository.claim("c-old", 200).map(|_| ()),
        Err(IssuanceStoreError::NotPending("c-old".into()))
    );
    let old = repository.get("c-old").ok().flatten();
    assert_eq!(
        old.as_ref().map(|old| old.status),
        Some(IssuanceRequestStatus::Denied)
    );
    assert_eq!(
        old.as_ref().and_then(|old| old.decision_reason.as_deref()),
        Some(EXPIRED_REASON)
    );
}

pub fn denied_request_names_no_capability(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record("c5"), 100), Ok(()));
    assert!(repository.claim("c5", 120).is_ok());
    assert_eq!(
        repository.finish("c5", &IssuanceDecision::Denied, 150, Some("no")),
        Ok(())
    );
    let denied = repository.get("c5").ok().flatten();
    assert_eq!(
        denied.as_ref().map(|denied| denied.capability_id.clone()),
        Some(None)
    );
    assert_eq!(
        denied
            .as_ref()
            .and_then(|denied| denied.decision_reason.as_deref()),
        Some("no")
    );
}

pub fn list_pages_summaries_by_status(make: Factory<'_>) {
    let repository = make(4);
    for id in ["c4", "c5", "c6"] {
        assert_eq!(repository.submit(&record(id), 100), Ok(()));
    }
    assert!(repository.claim("c5", 120).is_ok());
    assert_eq!(
        repository.finish("c5", &IssuanceDecision::Denied, 150, Some("no")),
        Ok(())
    );
    let pending = Some(IssuanceRequestStatus::Pending);
    let first = repository.list(query(pending, None, 1), 150);
    assert_eq!(ids(&first), ["c4"]);
    assert_eq!(next_after(&first).as_deref(), Some("c4"));
    let cursor = next_after(&first);
    let second = repository.list(query(pending, cursor.as_deref(), 1), 150);
    assert_eq!(ids(&second), ["c6"]);
    assert_eq!(next_after(&second), None);
    assert_eq!(
        ids(&repository.list(query(None, None, 10), 150)),
        ["c4", "c5", "c6"]
    );
    assert_eq!(
        repository.list(query(None, Some("absent"), 10), 150),
        Err(IssuanceStoreError::NotFound("absent".into()))
    );
}

pub fn status_listing_pages_across_terminal_history(make: Factory<'_>) {
    let repository = make(8);
    for id in ["d1", "p1", "d2", "p2", "d3", "p3"] {
        assert_eq!(repository.submit(&record(id), 100), Ok(()));
    }
    for id in ["d1", "d2", "d3"] {
        assert!(repository.claim(id, 120).is_ok());
        assert_eq!(
            repository.finish(id, &IssuanceDecision::Denied, 130, Some("no")),
            Ok(())
        );
    }
    let pending = Some(IssuanceRequestStatus::Pending);
    let first = repository.list(query(pending, None, 2), 150);
    assert_eq!(ids(&first), ["p1", "p2"]);
    let cursor = next_after(&first);
    let second = repository.list(query(pending, cursor.as_deref(), 2), 150);
    assert_eq!(ids(&second), ["p3"]);
    assert_eq!(next_after(&second), None);
    let denied = Some(IssuanceRequestStatus::Denied);
    assert_eq!(
        ids(&repository.list(query(denied, Some("d1"), 10), 150)),
        ["d2", "d3"]
    );
}

pub fn listing_pages_hold_at_most_the_page_limit(make: Factory<'_>) {
    let repository = make(MAX_ISSUANCE_LIST_PAGE + 10);
    for n in 0..MAX_ISSUANCE_LIST_PAGE + 5 {
        assert_eq!(repository.submit(&record(&format!("p{n:02}")), 100), Ok(()));
    }
    let page = repository.list(query(None, None, MAX_ISSUANCE_LIST_PAGE), 150);
    assert_eq!(ids(&page).len(), MAX_ISSUANCE_LIST_PAGE);
    let last = format!("p{:02}", MAX_ISSUANCE_LIST_PAGE - 1);
    assert_eq!(next_after(&page), Some(last));
    let single = repository.list(query(None, None, 1), 150);
    assert_eq!(ids(&single), ["p00"]);
    assert_eq!(next_after(&single).as_deref(), Some("p00"));
}

pub fn expired_pending_request_is_denied_and_frees_capacity(make: Factory<'_>) {
    let repository = make(2);
    assert_eq!(
        repository.submit(&record_expiring("old-1", 200), 100),
        Ok(())
    );
    assert_eq!(
        repository.submit(&record_expiring("old-2", 200), 100),
        Ok(())
    );
    assert_eq!(
        repository.submit(&record("new-0"), 150),
        Err(IssuanceStoreError::Full)
    );
    assert_eq!(repository.submit(&record("new-1"), 250), Ok(()));
    let old = repository.get("old-1").ok().flatten();
    assert_eq!(
        old.as_ref().map(|old| old.status),
        Some(IssuanceRequestStatus::Denied)
    );
    assert_eq!(old.as_ref().and_then(|old| old.decided_at), Some(250));
    assert_eq!(
        old.as_ref().and_then(|old| old.decision_reason.as_deref()),
        Some(EXPIRED_REASON)
    );
    let denied = Some(IssuanceRequestStatus::Denied);
    assert_eq!(
        ids(&repository.list(query(denied, None, 10), 250)),
        ["old-1", "old-2"]
    );
}

pub fn listing_retires_expired_pending_requests(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record_expiring("old", 200), 100), Ok(()));
    let pending = Some(IssuanceRequestStatus::Pending);
    assert!(ids(&repository.list(query(pending, None, 10), 200)).is_empty());
    assert_eq!(
        repository
            .get("old")
            .ok()
            .flatten()
            .and_then(|old| old.decision_reason),
        Some(EXPIRED_REASON.to_string())
    );
}

pub fn deciding_request_is_never_expired(make: Factory<'_>) {
    let repository = make(4);
    assert_eq!(repository.submit(&record_expiring("c8", 200), 100), Ok(()));
    assert!(repository.claim("c8", 150).is_ok());
    assert!(repository.list(query(None, None, 10), 500).is_ok());
    assert_eq!(
        status_of(&*repository, "c8"),
        Some(IssuanceRequestStatus::Deciding)
    );
}

pub fn concurrent_submissions_cannot_exceed_the_cap(make: Factory<'_>) {
    let repository = make(4);
    for id in ["a", "b", "c"] {
        assert_eq!(repository.submit(&record(id), 100), Ok(()));
    }
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let (repository, barrier) = (Arc::clone(&repository), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                repository.submit(&record(&format!("race-{n}")), 100)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect();
    let submitted = results
        .iter()
        .filter(|result| matches!(result, Ok(Ok(()))))
        .count();
    let refused = results
        .iter()
        .filter(|result| matches!(result, Ok(Err(IssuanceStoreError::Full))))
        .count();
    assert_eq!((submitted, refused), (1, 7));
}

/// Every check above, each against a fresh repository.
pub fn all(make: Factory<'_>) {
    already_expired_record_is_refused(make);
    second_submission_for_a_challenge_is_already_submitted(make);
    only_the_claimant_finishes_a_request(make);
    released_request_is_pending_again(make);
    expired_pending_request_is_not_claimed(make);
    denied_request_names_no_capability(make);
    list_pages_summaries_by_status(make);
    status_listing_pages_across_terminal_history(make);
    listing_pages_hold_at_most_the_page_limit(make);
    expired_pending_request_is_denied_and_frees_capacity(make);
    listing_retires_expired_pending_requests(make);
    deciding_request_is_never_expired(make);
    concurrent_submissions_cannot_exceed_the_cap(make);
}
