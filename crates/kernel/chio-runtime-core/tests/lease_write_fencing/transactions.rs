use super::*;
use chio_runtime_core::RuntimeEvidenceManifestEntry;
use std::sync::{atomic::AtomicBool, Barrier};

fn step() -> RuntimeOrchestrationStepState {
    RuntimeOrchestrationStepState {
        step_index: 0,
        admission_id: "admission-a".into(),
        state: "completed".into(),
        destructive: true,
        admission_report_sha256: Some("1".repeat(64)),
        tool_receipt_sha256: Some("2".repeat(64)),
        lease_id: Some("destructive-lease-not-the-run-lease".into()),
    }
}

#[test]
fn registration_cannot_reset_completed_work_or_mint_step_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("register.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock)?;
    assert!(store.register_run("run")?);
    let lease = store.acquire_current_run_lease("run", "owner", 20)?;
    store.complete_run_write(&lease, "completed", None, &[step()], &[])?;
    let before = image(&path)?;
    assert!(!store.register_run("run")?);
    refused(
        write_run(&store, &lease, "planned"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    let mut default = lease;
    default.run_id = "default".into();
    refused(
        store.record_step_state(&default, step()),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn run_identity_owner_lease_and_fence_are_independently_bound() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("identity.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    store.register_run("run")?;
    store.register_run("other")?;
    let lease = store.acquire_current_run_lease("run", "owner", 20)?;
    store.acquire_current_run_lease("other", "other-owner", 20)?;
    let before = image(&path)?;
    for field in ["run", "owner", "lease", "fence", "incarnation"] {
        let mut wrong = lease.clone();
        match field {
            "run" => wrong.run_id = "other".into(),
            "owner" => wrong.owner_id = "other-owner".into(),
            "lease" => wrong.lease_id = "another-lease".into(),
            "fence" => wrong.fencing_token = 2,
            "incarnation" => wrong.acquired_at_unix_ms = 99,
            _ => unreachable!(),
        }
        refused(
            write_step(&store, &wrong, "completed"),
            "runtime_run_write_lease_rejected",
        );
        assert_eq!(image(&path)?, before, "changed {field}");
    }
    // Extending the copied observation cannot extend the durable grant.
    let mut forged = lease;
    forged.expires_at_unix_ms = u64::MAX;
    clock.0.store(120, Ordering::SeqCst);
    refused(
        write_run(&store, &forged, "completed"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn write_clock_floor_survives_reopen_and_cannot_be_backdated() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("floor.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    store.register_run("run")?;
    let lease = store.acquire_current_run_lease("run", "owner", 20)?;
    clock.0.store(110, Ordering::SeqCst);
    write_step(&store, &lease, "completed")?;
    let before = image(&path)?;
    drop(store);
    clock.0.store(109, Ordering::SeqCst);
    let reopened = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock)?;
    refused(
        write_run(&reopened, &lease, "planned"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn late_artifact_failure_rolls_back_run_steps_heartbeat_and_release() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("atomic.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    store.register_run("run")?;
    let lease = store.acquire_current_run_lease("run", "owner", 20)?;
    let entry = RuntimeEvidenceManifestEntry {
        role: "proof_package".into(),
        path: "proof.json".into(),
        sha256: "3".repeat(64),
        byte_count: 100,
    };
    let connection = Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER fail_artifact BEFORE INSERT ON runtime_evidence_artifacts BEGIN SELECT RAISE(ABORT, 'injected artifact failure'); END;")?;
    let before = image(&path)?;
    clock.0.store(110, Ordering::SeqCst);
    let result = store.complete_run_write(
        &lease,
        "completed",
        None,
        &[step()],
        std::slice::from_ref(&entry),
    );
    assert!(
        matches!(&result, Err(ChioRuntimeError::Sqlite(error)) if error.to_string().contains("injected artifact failure")),
        "{result:?}"
    );
    assert_eq!(image(&path)?, before);
    connection.execute_batch("DROP TRIGGER fail_artifact")?;
    store.complete_run_write(&lease, "completed", None, &[step()], &[entry])?;
    let released: String = connection.query_row(
        "SELECT state FROM runtime_run_leases WHERE run_id = 'run'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(released, "released");
    let operation_lease: String = connection.query_row(
        "SELECT lease_id FROM runtime_step_states WHERE run_id = 'run'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(operation_lease, "destructive-lease-not-the-run-lease");
    let after = image(&path)?;
    refused(
        write_run(&store, &lease, "planned"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, after);
    let next = store.acquire_current_run_lease("run", "next", 20)?;
    assert_eq!(next.fencing_token, 2);
    Ok(())
}

#[test]
fn corrupt_durable_lease_fields_cannot_authorize_or_change_data() -> TestResult {
    for (field, value) in [
        ("fencing_token", "0"),
        ("fencing_token", "-1"),
        ("acquired_at_unix_ms", "-1"),
        ("heartbeat_at_unix_ms", "99"),
        ("heartbeat_at_unix_ms", "121"),
        ("expires_at_unix_ms", "-1"),
        ("state", "'released'"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("corrupt.db");
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock)?;
        store.register_run("run")?;
        let lease = store.acquire_current_run_lease("run", "owner", 20)?;
        Connection::open(&path)?.execute(
            &format!("UPDATE runtime_run_leases SET {field} = {value}"),
            [],
        )?;
        let before = image(&path)?;
        refused(
            write_step(&store, &lease, "completed"),
            "runtime_run_write_lease_rejected",
        );
        assert_eq!(image(&path)?, before, "{field} = {value}");
    }
    Ok(())
}

#[test]
fn competing_takeovers_and_stale_progress_share_one_fence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("takeover.db");
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    store.register_run("run")?;
    let stale = store.acquire_current_run_lease("run", "stale", 20)?;
    let handles = (0..8)
        .map(|_| SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    clock.0.store(120, Ordering::SeqCst);
    let barrier = Arc::new(Barrier::new(9));
    let workers = handles
        .into_iter()
        .enumerate()
        .map(|(index, handle)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let lease =
                    handle.acquire_current_run_lease("run", &format!("owner-{index}"), 20)?;
                write_run(&handle, &lease, "completed")?;
                Ok::<_, ChioRuntimeError>(lease)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    refused(
        write_step(&store, &stale, "planned"),
        "runtime_run_write_lease_rejected",
    );
    let mut winners = Vec::new();
    let mut conflicts = 0;
    for worker in workers {
        match worker.join().map_err(|_| "takeover worker panicked")? {
            Ok(lease) => winners.push(lease),
            Err(error) => {
                assert_eq!(error.code(), "runtime_run_lease_conflict");
                conflicts += 1;
            }
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(conflicts, 7);
    assert_eq!(winners[0].fencing_token, 2);
    let before = image(&path)?;
    refused(
        write_run(&store, &stale, "planned"),
        "runtime_run_write_lease_rejected",
    );
    assert_eq!(image(&path)?, before);
    Ok(())
}

#[test]
fn noninteger_durable_times_cannot_extend_or_authorize_a_lease() -> TestResult {
    for (table, field, value) in [
        ("runtime_run_leases", "expires_at_unix_ms", "'corrupt'"),
        ("runtime_run_leases", "expires_at_unix_ms", "X'ff'"),
        ("runtime_run_leases", "expires_at_unix_ms", "120.5"),
        ("runtime_run_leases", "heartbeat_at_unix_ms", "100.5"),
        ("runtime_runs", "started_at_unix_ms", "99.5"),
        ("runtime_runs", "updated_at_unix_ms", "100.5"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("storage-class.db");
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
        store.register_run("run")?;
        let lease = store.acquire_current_run_lease("run", "owner", 20)?;
        Connection::open(&path)?.execute(&format!("UPDATE {table} SET {field} = {value}"), [])?;
        clock.0.store(
            if field == "expires_at_unix_ms" {
                120
            } else {
                110
            },
            Ordering::SeqCst,
        );
        let before = image(&path)?;
        refused(
            write_run(&store, &lease, "completed"),
            "runtime_run_write_lease_rejected",
        );
        assert_eq!(image(&path)?, before, "{table}.{field} = {value}");
    }
    Ok(())
}

#[test]
fn owned_time_is_observed_inside_the_sqlite_write_transaction() -> TestResult {
    struct LockObservingClock {
        path: std::path::PathBuf,
        armed: AtomicBool,
        observed: AtomicBool,
    }
    impl Clock for LockObservingClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            if self.armed.load(Ordering::SeqCst) {
                let connection =
                    Connection::open(&self.path).map_err(|_| ClockError::Unavailable)?;
                connection
                    .busy_timeout(std::time::Duration::ZERO)
                    .map_err(|_| ClockError::Unavailable)?;
                let result = connection.execute_batch("BEGIN IMMEDIATE");
                if !matches!(result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy)
                {
                    return Err(ClockError::Unavailable);
                }
                self.observed.store(true, Ordering::SeqCst);
            }
            FixedClock::from_millis(100).read()
        }
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owned-time.db");
    let clock = Arc::new(LockObservingClock {
        path: path.clone(),
        armed: AtomicBool::new(false),
        observed: AtomicBool::new(false),
    });
    let store = SqliteRuntimeOrchestrationStore::open_with_clock(&path, clock.clone())?;
    store.register_run("run")?;
    let lease = store.acquire_current_run_lease("run", "owner", 20)?;
    clock.armed.store(true, Ordering::SeqCst);
    write_run(&store, &lease, "running")?;
    assert!(clock.observed.load(Ordering::SeqCst));
    Ok(())
}
