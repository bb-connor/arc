use super::*;

#[test]
fn a_stopped_sqlite_port_claims_nothing_and_shutdown_rearms_it() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("response-stop.sqlite"),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    let due_at_unix_ms = now_unix_ms.saturating_sub(1);
    for action_id in ["action-stop-a", "action-stop-b"] {
        install_due_sqlite_plan(&store, action_id, due_at_unix_ms);
    }
    let port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-stop",
        "incarnation-sqlite-stop",
        100,
    );

    port.request_stop();
    assert!(matches!(
        port.tick(0, false),
        Err(ResponseWorkerTickError::WorkerStopped)
    ));
    port.shutdown()
        .unwrap_or_else(|error| panic!("shutdown: {error}"));

    let report = port
        .tick(1, false)
        .unwrap_or_else(|error| panic!("tick after shutdown: {error}"));
    assert_eq!(
        report.claimed, 2,
        "the stopped tick claimed nothing and shutdown re-armed the port"
    );
}
