//! Joint budget capture uses its injected authority epoch and expiry boundary.

use super::*;
use crate::clock_consumer_tests::TestClock;
use chio_kernel::RevocationStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<(tempfile::TempDir, SqliteAuthorityStore, Arc<TestClock>)> {
    let directory = tempfile::tempdir()?;
    crate::test_authority::secure_directory(directory.path());
    let database = directory.path().join("authority.db");
    let locks = directory.path().join("locks");
    std::fs::create_dir(&locks)?;
    crate::test_authority::secure_directory(&locks);
    SqliteAuthorityStore::provision(&database, &locks)?;
    let clock = TestClock::new();
    let authority =
        SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.clone())?;
    Ok((directory, authority, clock))
}

#[test]
fn sqlite_injected_budget_capture_retains_owner_epoch() -> TestResult {
    let (_directory, authority, _clock) = fixture()?;
    let store = authority.budget_store();
    let authorized =
        store.authorize_budget_hold(owned(&store, authorize_request("clock", 0, 2)))?;
    assert!(matches!(
        authorized,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let captured =
        store.capture_invocation_reservations(owned(&store, capture_request("clock")))?;
    assert!(matches!(
        captured,
        BudgetInvocationCaptureDecision::Captured(_)
    ));
    let times: (Option<i64>, Option<i64>) = store.connection()?.query_row(
        "SELECT hold.trusted_capture_time, event.trusted_time
         FROM budget_authorization_holds AS hold
         JOIN budget_mutation_events AS event ON event.hold_id = hold.hold_id
         WHERE hold.hold_id = 'hold-clock' AND event.kind = 'capture_invocation'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(times, (Some(42), Some(42)));
    Ok(())
}

#[test]
fn sqlite_injected_budget_capture_enforces_supplemental_expiry() -> TestResult {
    let (_directory, authority, clock) = fixture()?;
    let store = authority.budget_store();
    let revocations = authority.revocation_store();
    revocations.revoke("unrelated-clock")?;
    for id in ["live-clock", "expired-clock"] {
        let mut request = supplemental_request(id, 43);
        request
            .admission_binding
            .as_mut()
            .ok_or("missing supplemental admission")?
            .last_observed_revocation = revocations.observe_revocation("cap-composite")?.commit;
        let authorized = store.authorize_budget_hold(owned(&store, request))?;
        assert!(matches!(
            authorized,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }
    let live =
        store.capture_invocation_reservations(owned(&store, capture_request("live-clock")))?;
    assert!(matches!(live, BudgetInvocationCaptureDecision::Captured(_)));
    let before = crate::tests::authority_snapshot(&*store.connection()?)?;
    clock.set(Ok(TestClock::reading(43_000, 200)))?;
    let error = store
        .capture_invocation_reservations(owned(&store, capture_request("expired-clock")))
        .err()
        .ok_or("expiry boundary accepted supplemental capture")?;
    assert!(
        error
            .to_string()
            .contains("expired before invocation capture"),
        "{error}"
    );
    assert_eq!(
        crate::tests::authority_snapshot(&*store.connection()?)?,
        before
    );
    Ok(())
}
