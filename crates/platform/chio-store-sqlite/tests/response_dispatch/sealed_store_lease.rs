use super::*;
use chio_security_types::ports::PortError;
use chio_store_sqlite::security_state::{
    SecurityParticipantSourceBinding, SqliteSecurityParticipantSource,
};

#[test]
fn superseded_lease_on_a_writable_store_is_a_conflict() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("writable-lease.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (_, work) = claim_due_planned_response(
        &store,
        "action-writable-stale-lease",
        "writable-stale-claim",
        "writable-stale-owner",
        now_unix_ms(),
    );
    store
        .validate_lease(&work)
        .unwrap_or_else(|error| panic!("live lease refused: {error}"));
    let superseded = ScheduledWork {
        fencing_token: work.fencing_token.saturating_add(1),
        ..work
    };
    let error = rejected(
        store.validate_lease(&superseded),
        "superseded lease validated",
    );
    assert_eq!(error, PortError::conflict());
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert!(!error.is_retired());
}

#[test]
fn live_lease_on_a_sealed_store_is_refused_as_retired() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("sealed-lease.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let (_, work) = claim_due_planned_response(
        &store,
        "action-sealed-live-lease",
        "sealed-live-claim",
        "sealed-live-owner",
        now_unix_ms(),
    );
    store
        .validate_lease(&work)
        .unwrap_or_else(|error| panic!("live lease refused before sealing: {error}"));
    let source = SqliteSecurityParticipantSource::open(&path)
        .unwrap_or_else(|error| panic!("participant source open failed: {error}"));
    let binding = SecurityParticipantSourceBinding::new("source", "authority", "destination")
        .unwrap_or_else(|error| panic!("participant source binding failed: {error}"));
    let expected = source
        .preview(&binding)
        .unwrap_or_else(|error| panic!("participant source preview failed: {error}"));
    source
        .seal_exact(&expected)
        .unwrap_or_else(|error| panic!("participant source seal failed: {error}"));

    let error = rejected(
        store.validate_lease(&work),
        "sealed store validated a lease",
    );
    assert_eq!(error, PortError::retired());
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert!(error.is_retired());
}
