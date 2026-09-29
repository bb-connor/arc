use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn sqlite_worker_operation_gate_recovers_after_panic_for_cleanup() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("operation-gate-poison.sqlite"),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    let port = sqlite_worker_port(
        store,
        clock,
        "worker-operation-gate-poison",
        "incarnation-operation-gate-poison",
        100,
    );
    let panicking_port = Arc::clone(&port);
    let panicked = std::thread::spawn(move || {
        let _operation_guard = panicking_port
            .operation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        panic!("forced worker operation panic");
    })
    .join();
    assert!(panicked.is_err());
    let report = port
        .tick(0, false)
        .unwrap_or_else(|error| panic!("post-panic worker tick: {error}"));
    assert_eq!(report.claimed, 0);
    port.shutdown()
        .unwrap_or_else(|error| panic!("post-panic worker shutdown: {error}"));
}
