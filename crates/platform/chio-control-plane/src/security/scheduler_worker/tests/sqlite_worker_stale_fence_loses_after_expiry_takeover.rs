use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn sqlite_worker_stale_fence_loses_after_expiry_takeover() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("response-fence.sqlite"))
            .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    let now_unix_ms = current_unix_ms();
    install_due_sqlite_plan(&store, "action-sqlite-fence", now_unix_ms.saturating_sub(1));
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let stale_port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-stale",
        "incarnation-sqlite-stale",
        150,
    );
    let _stale_worker = ProductionResponseWorker::new_for_test(Arc::clone(&stale_port))
        .unwrap_or_else(|error| panic!("stale worker: {error}"));
    clock.set(current_unix_ms());
    let stale_work = stale_port
        .claim(0)
        .unwrap_or_else(|error| panic!("stale claim: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("stale work missing"));

    std::thread::sleep(Duration::from_millis(200));
    let takeover_now = current_unix_ms();
    clock.set(takeover_now);
    let takeover_port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-takeover",
        "incarnation-sqlite-takeover",
        5_000,
    );
    let takeover_work = takeover_port
        .claim(0)
        .unwrap_or_else(|error| panic!("takeover claim: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover work missing"));
    assert!(takeover_work.fencing_token > stale_work.fencing_token);
    assert!(matches!(
        stale_port.scheduler.process(&stale_work, takeover_now),
        Ok(SchedulerWorkOutcome::LeaseLost { .. })
    ));
    let takeover = ProductionResponseWorker::new_for_test(takeover_port)
        .unwrap_or_else(|error| panic!("takeover worker: {error}"));
    takeover
        .complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("takeover shutdown: {error}"));
}
