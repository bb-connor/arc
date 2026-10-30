use std::cell::Cell;
use std::sync::Arc;

use chio_federation::issuance_requests::{conformance, IssuancePageLimit};
use chio_test_support::clock::ClockScope;
use chio_test_support::prelude::*;

use super::*;

struct Fixture {
    dir: tempfile::TempDir,
    opened: Cell<usize>,
    _clock: ClockScope,
}

impl Fixture {
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(format!("{name}.sqlite3"))
    }

    fn fresh(&self, pending_cap: usize) -> SqliteIssuanceRequestStore {
        let n = self.opened.get();
        self.opened.set(n + 1);
        SqliteIssuanceRequestStore::open(self.path(&format!("issuance-{n}")))
            .test_unwrap()
            .with_pending_cap(pending_cap)
    }
}

fn fixture() -> Fixture {
    let clock = chio_test_support::clock::scope_unix_secs(1_000);
    Fixture {
        dir: tempfile::tempdir().test_unwrap(),
        opened: Cell::new(0),
        _clock: clock,
    }
}

fn record(id: &str, expires_at: u64) -> IssuanceRequestRecord {
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

fn all(store: &SqliteIssuanceRequestStore) -> Result<IssuanceRequestPage, IssuanceStoreError> {
    store.list(
        IssuanceListQuery {
            status: None,
            after: None,
            limit: IssuancePageLimit::MAX,
        },
        150,
    )
}

#[test]
fn sqlite_store_conforms() {
    let fixture = fixture();
    conformance::all(&|pending_cap| {
        Arc::new(fixture.fresh(pending_cap)) as Arc<dyn IssuanceRequestRepository>
    });
}

#[test]
fn requests_survive_reopen() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    store.submit(&record("kept", 1_000), 100).test_unwrap();
    drop(store);
    let reopened = SqliteIssuanceRequestStore::open(fixture.path("issuance-0")).test_unwrap();
    assert_eq!(
        reopened.get("kept").test_unwrap().map(|kept| kept.status),
        Some(IssuanceRequestStatus::Pending)
    );
}

#[test]
fn a_tampered_status_is_an_integrity_failure() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    store.submit(&record("c9", 1_000), 100).test_unwrap();
    let raw = Connection::open(fixture.path("issuance-0")).test_unwrap();
    raw.pragma_update(None, "ignore_check_constraints", true)
        .test_unwrap();
    raw.execute(
        "UPDATE federation_issuance_requests SET status = 'expired' WHERE challenge_id = 'c9'",
        [],
    )
    .test_unwrap();
    drop(raw);
    assert_eq!(store.get("c9"), Err(IssuanceStoreError::Integrity));
    assert_eq!(all(&store), Err(IssuanceStoreError::Integrity));
}

#[test]
fn a_held_write_lock_is_busy_and_writes_nothing() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    let mut raw = Connection::open(fixture.path("issuance-0")).test_unwrap();
    let holder = raw
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .test_unwrap();
    assert_eq!(
        store.submit(&record("blocked", 1_000), 100),
        Err(IssuanceStoreError::Busy)
    );
    drop(holder);
    assert_eq!(store.get("blocked"), Ok(None));
}

#[test]
fn an_out_of_range_timestamp_is_refused_without_a_row() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    assert_eq!(
        store.submit(&record("far", u64::MAX), 100),
        Err(IssuanceStoreError::InvalidTimestamp)
    );
    assert_eq!(store.get("far"), Ok(None));
    assert_eq!(
        store.claim("far", u64::MAX),
        Err(IssuanceStoreError::InvalidTimestamp)
    );
}

#[test]
fn an_in_memory_path_is_refused() {
    assert!(matches!(
        SqliteIssuanceRequestStore::open(":memory:"),
        Err(IssuanceRequestStoreOpenError::InvalidPath)
    ));
}

fn query_plan(path: &std::path::Path, statement: &str) -> Vec<String> {
    let raw = Connection::open(path).test_unwrap();
    let mut plan = raw
        .prepare(&format!("EXPLAIN QUERY PLAN {statement}"))
        .test_unwrap();
    let unbound = vec![rusqlite::types::Null; plan.parameter_count()];
    plan.query_map(rusqlite::params_from_iter(unbound), |row| {
        row.get::<_, String>(3)
    })
    .test_unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .test_unwrap()
}

#[test]
fn hot_lookups_seek_an_index_and_never_sort() {
    let fixture = fixture();
    let _store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    let path = fixture.path("issuance-0");
    for (name, statement) in [
        ("get", sql::GET),
        ("exists", sql::EXISTS),
        ("submitted_at", sql::SUBMITTED_AT),
        ("claim", sql::CLAIM),
        ("finish", sql::FINISH),
        ("release", sql::RELEASE),
        ("count_open", sql::COUNT_OPEN),
        ("expire_stale", sql::EXPIRE_STALE),
        ("list_status", sql::LIST_STATUS),
        ("list_status_after", sql::LIST_STATUS_AFTER),
        ("list_all_after", sql::LIST_ALL_AFTER),
    ] {
        let plan = query_plan(&path, statement);
        assert!(
            !plan.is_empty() && plan.iter().all(|step| step.starts_with("SEARCH ")),
            "{name}: {plan:?}"
        );
    }
    let walk = query_plan(&path, sql::LIST_ALL);
    assert!(
        matches!(
            walk.as_slice(),
            [step] if step.contains("USING INDEX idx_federation_issuance_requests_order")
        ),
        "list_all: {walk:?}"
    );
}
