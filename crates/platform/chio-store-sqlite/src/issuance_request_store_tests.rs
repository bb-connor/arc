use std::sync::{Arc, Barrier};

use chio_test_support::clock::ClockScope;
use chio_test_support::prelude::*;

use super::*;

struct Fixture {
    store: SqliteIssuanceRequestStore,
    dir: tempfile::TempDir,
    _clock: ClockScope,
}

impl Fixture {
    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("issuance.sqlite3")
    }
}

fn fixture_with_cap(pending_cap: usize) -> Fixture {
    let clock = chio_test_support::clock::scope_unix_secs(1_000);
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteIssuanceRequestStore::open(dir.path().join("issuance.sqlite3"))
        .test_unwrap()
        .with_pending_cap(pending_cap);
    Fixture {
        store,
        dir,
        _clock: clock,
    }
}

fn fixture() -> Fixture {
    fixture_with_cap(MAX_PENDING_ISSUANCE_REQUESTS)
}

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
    IssuanceListQuery {
        status,
        after,
        limit,
    }
}

fn ids(page: &IssuanceRequestPage) -> Vec<&str> {
    page.requests
        .iter()
        .map(|request| request.challenge_id.as_str())
        .collect()
}

fn approved(capability_id: &str) -> IssuanceDecision {
    IssuanceDecision::Approved {
        capability_id: capability_id.into(),
    }
}

#[test]
fn already_expired_record_is_refused() {
    let fixture = fixture();
    assert_eq!(
        fixture.store.submit(&record_expiring("late", 150), 150),
        Err(IssuanceStoreError::Expired("late".into()))
    );
    assert_eq!(fixture.store.get("late"), Ok(None));
}

#[test]
fn second_submission_for_a_challenge_is_already_submitted() {
    let fixture = fixture();
    fixture.store.submit(&record("c1"), 100).test_unwrap();
    assert_eq!(
        fixture.store.submit(&record("c1"), 100),
        Err(IssuanceStoreError::AlreadySubmitted("c1".into()))
    );
}

#[test]
fn only_the_claimant_finishes_a_request() {
    let fixture = fixture();
    let store = &fixture.store;
    store.submit(&record("c2"), 100).test_unwrap();
    assert_eq!(
        store.claim("c2", 120).test_unwrap().status,
        IssuanceRequestStatus::Deciding
    );
    assert_eq!(
        store.claim("c2", 120),
        Err(IssuanceStoreError::NotPending("c2".into()))
    );
    store
        .finish("c2", &approved("cap-1"), 150, None)
        .test_unwrap();
    let got = store.get("c2").test_unwrap().test_unwrap();
    assert_eq!(got.status, IssuanceRequestStatus::Approved);
    assert_eq!(got.decided_at, Some(150));
    assert_eq!(got.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(
        store.finish("c2", &IssuanceDecision::Denied, 160, Some("late")),
        Err(IssuanceStoreError::NotClaimed("c2".into()))
    );
    assert_eq!(
        store.claim("absent", 120),
        Err(IssuanceStoreError::NotFound("absent".into()))
    );
}

#[test]
fn denied_request_names_no_capability() {
    let fixture = fixture();
    let store = &fixture.store;
    store.submit(&record("c5"), 100).test_unwrap();
    store.claim("c5", 120).test_unwrap();
    store
        .finish("c5", &IssuanceDecision::Denied, 150, Some("no"))
        .test_unwrap();
    let denied = store.get("c5").test_unwrap().test_unwrap();
    assert_eq!(denied.capability_id, None);
    assert_eq!(denied.decision_reason.as_deref(), Some("no"));
}

#[test]
fn released_request_is_pending_again() {
    let fixture = fixture();
    let store = &fixture.store;
    store.submit(&record("c3"), 100).test_unwrap();
    store.claim("c3", 120).test_unwrap();
    store.release("c3").test_unwrap();
    assert_eq!(
        store.get("c3").test_unwrap().test_unwrap().status,
        IssuanceRequestStatus::Pending
    );
    store.claim("c3", 120).test_unwrap();
    assert_eq!(
        store.release("absent"),
        Err(IssuanceStoreError::NotClaimed("absent".into()))
    );
}

#[test]
fn expired_pending_request_is_not_claimed() {
    let fixture = fixture();
    let store = &fixture.store;
    store
        .submit(&record_expiring("c-old", 200), 100)
        .test_unwrap();
    assert_eq!(
        store.claim("c-old", 200),
        Err(IssuanceStoreError::NotPending("c-old".into()))
    );
    let old = store.get("c-old").test_unwrap().test_unwrap();
    assert_eq!(old.status, IssuanceRequestStatus::Denied);
    assert_eq!(old.decision_reason.as_deref(), Some(EXPIRED_REASON));
}

#[test]
fn list_pages_summaries_by_status() {
    let fixture = fixture();
    let store = &fixture.store;
    for id in ["c4", "c5", "c6"] {
        store.submit(&record(id), 100).test_unwrap();
    }
    store.claim("c5", 120).test_unwrap();
    store
        .finish("c5", &IssuanceDecision::Denied, 150, Some("no"))
        .test_unwrap();
    let pending = Some(IssuanceRequestStatus::Pending);
    let first = store.list(query(pending, None, 1), 150).test_unwrap();
    assert_eq!(ids(&first), vec!["c4"]);
    assert_eq!(first.next_after.as_deref(), Some("c4"));
    let second = store
        .list(query(pending, first.next_after.as_deref(), 1), 150)
        .test_unwrap();
    assert_eq!(ids(&second), vec!["c6"]);
    assert_eq!(second.next_after, None);
    let all = store.list(query(None, None, 10), 150).test_unwrap();
    assert_eq!(ids(&all), vec!["c4", "c5", "c6"]);
    assert_eq!(
        store.list(query(None, Some("absent"), 10), 150),
        Err(IssuanceStoreError::NotFound("absent".into()))
    );
}

#[test]
fn status_listing_pages_across_terminal_history() {
    let fixture = fixture_with_cap(8);
    let store = &fixture.store;
    for id in ["d1", "p1", "d2", "p2", "d3", "p3"] {
        store.submit(&record(id), 100).test_unwrap();
    }
    for id in ["d1", "d2", "d3"] {
        store.claim(id, 120).test_unwrap();
        store
            .finish(id, &IssuanceDecision::Denied, 130, Some("no"))
            .test_unwrap();
    }
    let pending = Some(IssuanceRequestStatus::Pending);
    let first = store.list(query(pending, None, 2), 150).test_unwrap();
    assert_eq!(ids(&first), vec!["p1", "p2"]);
    let second = store
        .list(query(pending, first.next_after.as_deref(), 2), 150)
        .test_unwrap();
    assert_eq!(ids(&second), vec!["p3"]);
    assert_eq!(second.next_after, None);
    let denied = store
        .list(
            query(Some(IssuanceRequestStatus::Denied), Some("d1"), 10),
            150,
        )
        .test_unwrap();
    assert_eq!(ids(&denied), vec!["d2", "d3"]);
}

#[test]
fn listing_never_carries_presentation_or_challenge_payloads() {
    let fixture = fixture();
    fixture.store.submit(&record("c7"), 100).test_unwrap();
    let page = fixture.store.list(query(None, None, 10), 150).test_unwrap();
    let json = serde_json::to_string(&page).test_unwrap();
    assert!(!json.contains("presentation"), "{json}");
    assert!(!json.contains("challengeJson"), "{json}");
}

#[test]
fn listing_pages_hold_at_most_fifty_summaries() {
    let fixture = fixture_with_cap(60);
    for n in 0..55 {
        fixture
            .store
            .submit(&record(&format!("p{n:02}")), 100)
            .test_unwrap();
    }
    let page = fixture
        .store
        .list(query(None, None, 500), 150)
        .test_unwrap();
    assert_eq!(page.requests.len(), 50);
    assert_eq!(page.next_after.as_deref(), Some("p49"));
}

#[test]
fn expired_pending_request_is_denied_and_frees_capacity() {
    let fixture = fixture_with_cap(2);
    let store = &fixture.store;
    store
        .submit(&record_expiring("old-1", 200), 100)
        .test_unwrap();
    store
        .submit(&record_expiring("old-2", 200), 100)
        .test_unwrap();
    assert_eq!(
        store.submit(&record("new-0"), 150),
        Err(IssuanceStoreError::Full)
    );
    store.submit(&record("new-1"), 250).test_unwrap();
    let old = store.get("old-1").test_unwrap().test_unwrap();
    assert_eq!(old.status, IssuanceRequestStatus::Denied);
    assert_eq!(old.decided_at, Some(250));
    assert_eq!(old.decision_reason.as_deref(), Some(EXPIRED_REASON));
    let denied = store
        .list(query(Some(IssuanceRequestStatus::Denied), None, 10), 250)
        .test_unwrap();
    assert_eq!(ids(&denied), vec!["old-1", "old-2"]);
}

#[test]
fn listing_retires_expired_pending_requests() {
    let fixture = fixture();
    let store = &fixture.store;
    store
        .submit(&record_expiring("old", 200), 100)
        .test_unwrap();
    let pending = store
        .list(query(Some(IssuanceRequestStatus::Pending), None, 10), 200)
        .test_unwrap();
    assert!(pending.requests.is_empty());
    assert_eq!(
        store
            .get("old")
            .test_unwrap()
            .test_unwrap()
            .decision_reason
            .as_deref(),
        Some(EXPIRED_REASON)
    );
}

#[test]
fn deciding_request_is_never_expired() {
    let fixture = fixture();
    let store = &fixture.store;
    store.submit(&record_expiring("c8", 200), 100).test_unwrap();
    store.claim("c8", 150).test_unwrap();
    store.list(query(None, None, 10), 500).test_unwrap();
    assert_eq!(
        store.get("c8").test_unwrap().test_unwrap().status,
        IssuanceRequestStatus::Deciding
    );
}

#[test]
fn concurrent_submissions_cannot_exceed_the_cap() {
    let fixture = fixture_with_cap(4);
    let store = Arc::new(
        SqliteIssuanceRequestStore::open(fixture.path())
            .test_unwrap()
            .with_pending_cap(4),
    );
    for id in ["a", "b", "c"] {
        store.submit(&record(id), 100).test_unwrap();
    }
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let (store, barrier) = (Arc::clone(&store), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                store.submit(&record(&format!("race-{n}")), 100)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().test_unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(IssuanceStoreError::Full)))
            .count(),
        7
    );
}

#[test]
fn requests_survive_reopen() {
    let fixture = fixture();
    fixture.store.submit(&record("kept"), 100).test_unwrap();
    let reopened = SqliteIssuanceRequestStore::open(fixture.path()).test_unwrap();
    assert_eq!(
        reopened.get("kept").test_unwrap().test_unwrap().status,
        IssuanceRequestStatus::Pending
    );
}

#[test]
fn a_tampered_status_is_an_integrity_failure() {
    let fixture = fixture();
    fixture.store.submit(&record("c9"), 100).test_unwrap();
    let raw = Connection::open(fixture.path()).test_unwrap();
    raw.pragma_update(None, "ignore_check_constraints", true)
        .test_unwrap();
    raw.execute(
        "UPDATE federation_issuance_requests SET status = 'expired' WHERE challenge_id = 'c9'",
        [],
    )
    .test_unwrap();
    drop(raw);
    assert_eq!(fixture.store.get("c9"), Err(IssuanceStoreError::Integrity));
    assert_eq!(
        fixture.store.list(query(None, None, 10), 150),
        Err(IssuanceStoreError::Integrity)
    );
}

#[test]
fn an_in_memory_path_is_refused() {
    assert!(matches!(
        SqliteIssuanceRequestStore::open(":memory:"),
        Err(IssuanceRequestStoreOpenError::InvalidPath)
    ));
}
