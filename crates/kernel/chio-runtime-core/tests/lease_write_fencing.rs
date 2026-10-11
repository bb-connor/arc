use chio_runtime_core::{
    ChioRuntimeError, RuntimeOrchestrationStepState, RuntimeRunLease,
    SqliteRuntimeOrchestrationStore,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use rusqlite::{types::Value, Connection};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "lease_write_fencing/transactions.rs"]
mod transactions;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        match self.0.load(Ordering::SeqCst) {
            u64::MAX => Err(ClockError::Unavailable),
            now => FixedClock::from_millis(now).read(),
        }
    }
}

fn image(path: &Path) -> Result<Vec<Vec<Value>>, rusqlite::Error> {
    let connection = Connection::open(path)?;
    let mut result = Vec::new();
    for table in [
        "runtime_runs",
        "runtime_step_states",
        "runtime_run_leases",
        "runtime_evidence_artifacts",
    ] {
        let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2"))?;
        let width = statement.column_count();
        for row in statement.query_map([], |row| (0..width).map(|i| row.get(i)).collect())? {
            result.push(row?);
        }
    }
    Ok(result)
}

fn write_run(
    store: &SqliteRuntimeOrchestrationStore,
    lease: &RuntimeRunLease,
    status: &str,
) -> Result<(), ChioRuntimeError> {
    store.record_run_state(lease, status, None)
}

fn write_step(
    store: &SqliteRuntimeOrchestrationStore,
    lease: &RuntimeRunLease,
    status: &str,
) -> Result<(), ChioRuntimeError> {
    store.record_run_step_state(
        lease,
        RuntimeOrchestrationStepState {
            step_index: 0,
            admission_id: "admission-a".into(),
            state: status.into(),
            destructive: true,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: Some("2".repeat(64)),
            lease_id: Some("distinct-destructive-operation-lease".into()),
        },
    )
}

fn refused(result: Result<(), ChioRuntimeError>, code: &str) {
    match result {
        Err(error) => assert_eq!(error.code(), code, "{error}"),
        Ok(()) => panic!("expected {code}; protected write succeeded"),
    }
}

#[test]
fn stale_run_owner_cannot_overwrite_successor_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let first = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    assert!(first.register_run("run")?);
    let a = first.acquire_run_lease("run", "a", 100, 20)?;
    write_run(&first, &a, "running")?;
    clock.0.store(120, Ordering::SeqCst);
    let reopened = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock)?;
    let b = reopened.acquire_run_lease("run", "b", 120, 20)?;
    write_run(&reopened, &b, "completed")?;
    let before = image(&path)?;
    refused(
        write_run(&first, &a, "terminal_failure"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn stale_step_owner_cannot_replace_successor_receipt_or_destructive_flag() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("steps.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    assert!(store.register_run("run")?);
    let a = store.acquire_run_lease("run", "a", 100, 20)?;
    write_run(&store, &a, "running")?;
    write_step(&store, &a, "planned")?;
    clock.0.store(120, Ordering::SeqCst);
    let b = store.acquire_run_lease("run", "b", 120, 20)?;
    write_step(&store, &b, "completed")?;
    let before = image(&path)?;
    refused(
        write_step(&store, &a, "planned"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn exact_expiry_uses_owned_time_instead_of_retained_caller_timestamp() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("expired.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    assert!(store.register_run("run")?);
    let lease = store.acquire_run_lease("run", "a", 100, 20)?;
    write_run(&store, &lease, "running")?;
    clock.0.store(120, Ordering::SeqCst);
    let before = image(&path)?;
    refused(
        write_run(&store, &lease, "completed"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn owned_clock_failure_prevents_step_mutation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("clock.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    assert!(store.register_run("run")?);
    let lease = store.acquire_run_lease("run", "a", 100, 20)?;
    write_run(&store, &lease, "running")?;
    clock.0.store(u64::MAX, Ordering::SeqCst);
    let before = image(&path)?;
    assert!(matches!(
        write_step(&store, &lease, "completed"),
        Err(ChioRuntimeError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn stale_owner_cannot_add_evidence_that_changes_successor_recovery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("evidence.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    assert!(store.register_run("run")?);
    let a = store.acquire_run_lease("run", "a", 100, 20)?;
    clock.0.store(120, Ordering::SeqCst);
    let b = store.acquire_run_lease("run", "b", 120, 20)?;
    write_run(&store, &b, "completed")?;
    write_step(&store, &b, "completed")?;
    assert!(store.recovery_drill_report("run", 120)?.blocked);
    let before = image(&path)?;
    let entry = chio_runtime_core::RuntimeEvidenceManifestEntry {
        role: "workflow_run_report".into(),
        path: "report.json".into(),
        sha256: "3".repeat(64),
        byte_count: 100,
    };
    refused(
        store.record_evidence_artifact(&a, &entry),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    assert!(store.recovery_drill_report("run", 120)?.blocked);
    Ok(())
}
