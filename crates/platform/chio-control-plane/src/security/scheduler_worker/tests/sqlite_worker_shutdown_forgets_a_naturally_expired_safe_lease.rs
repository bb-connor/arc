use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn sqlite_worker_shutdown_forgets_a_naturally_expired_safe_lease() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("expired-safe-shutdown.sqlite");
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    install_due_sqlite_plan(
        &store,
        "action-expired-safe-shutdown",
        now_unix_ms.saturating_sub(1),
    );
    let port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-expired-safe-shutdown",
        "incarnation-expired-safe-shutdown",
        100,
    );
    let work = port
        .claim(0)
        .unwrap_or_else(|error| panic!("safe lease claim: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("safe lease claim missing"));
    clock.set(work.lease_expires_at_unix_ms.saturating_add(1));

    port.shutdown()
        .unwrap_or_else(|error| panic!("expired safe lease shutdown: {error}"));
    assert!(port
        .owned_leases
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty());
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("expired safe lease readback: {error}"));
    let durable_leases = connection
        .query_row(
            "SELECT COUNT(*) FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("expired safe lease count: {error}"));
    assert_eq!(durable_leases, 1);
}
