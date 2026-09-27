use chio_runtime_core::*;
use rusqlite::{params, types::Value, Connection};
use std::{
    path::Path,
    sync::{Arc, Barrier},
};

#[path = "runtime_ops/support.rs"]
mod support;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, PartialEq)]
struct DurableState {
    leases: Vec<Vec<Value>>,
    ticks: Vec<Vec<Value>>,
}

fn snapshot(path: &Path) -> Result<DurableState, rusqlite::Error> {
    let connection = Connection::open(path)?;
    let rows = |sql| -> Result<Vec<Vec<Value>>, rusqlite::Error> {
        let mut statement = connection.prepare(sql)?;
        let columns = statement.column_count();
        let result = statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())?
            .collect();
        result
    };
    Ok(DurableState {
        leases: rows("SELECT * FROM runtime_run_leases ORDER BY run_id")?,
        ticks: rows("SELECT * FROM runtime_scheduler_ticks ORDER BY tick_id")?,
    })
}

fn refused<T: std::fmt::Debug>(result: Result<T, ChioRuntimeError>, code: &str) {
    match result {
        Err(error) => assert_eq!(error.code(), code, "{error}"),
        Ok(value) => panic!("expected {code}, got {value:?}"),
    }
}

fn early_profile() -> RuntimeSupervisorProfile {
    RuntimeSupervisorProfile {
        issued_at_unix_ms: 0,
        expires_at_unix_ms: 10_000,
        run_lease_ttl_ms: 100,
        stale_run_after_ms: 300,
        ..support::supervisor_profile()
    }
}

#[test]
fn lease_expiry_checks_both_integer_ranges_before_publishing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let empty = snapshot(&path)?;
    for (now, ttl, code) in [
        (100, 0, "runtime_run_lease_invalid_ttl"),
        (100, u64::MAX, "runtime_run_lease_expiry_overflow"),
        (i64::MAX as u64, 1, "runtime_run_lease_expiry_overflow"),
        (u64::MAX, 1, "runtime_sqlite_integer_out_of_range"),
    ] {
        refused(store.acquire_run_lease("run", "owner", now, ttl), code);
        assert_eq!(snapshot(&path)?, empty);
    }
    let invalid_expiry = RuntimeSupervisorProfile {
        run_lease_ttl_ms: u64::MAX,
        ..early_profile()
    };
    refused(
        store.scheduler_tick_report(&invalid_expiry, "scheduler", 100, 2),
        "runtime_run_lease_expiry_overflow",
    );
    assert_eq!(snapshot(&path)?, empty);
    let lease = store.acquire_run_lease("run", "owner", i64::MAX as u64 - 1, 1)?;
    assert_eq!(lease.expires_at_unix_ms, i64::MAX as u64);
    assert_eq!(lease.fencing_token, 1);
    let before = snapshot(&path)?;
    drop(store);
    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    refused(
        reopened.acquire_run_lease("run", "other", i64::MAX as u64 - 1, 1),
        "runtime_run_lease_conflict",
    );
    assert_eq!(snapshot(&path)?, before);
    Ok(())
}

#[test]
fn fencing_exhaustion_and_invalid_tokens_survive_reopen_without_replacement() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    store.acquire_run_lease("run", "first", 10, 10)?;
    Connection::open(&path)?.execute(
        "UPDATE runtime_run_leases SET fencing_token = ?1",
        params![i64::MAX - 1],
    )?;
    let last = store.acquire_run_lease("run", "last", 20, 10)?;
    assert_eq!(last.fencing_token, i64::MAX as u64);
    drop(store);
    for token in [i64::MAX, 0, -1] {
        Connection::open(&path)?.execute(
            "UPDATE runtime_run_leases SET fencing_token = ?1",
            params![token],
        )?;
        let before = snapshot(&path)?;
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let code = if token == i64::MAX {
            "runtime_run_lease_fencing_exhausted"
        } else {
            "runtime_run_lease_invalid_fencing_token"
        };
        refused(store.acquire_run_lease("run", "next", 30, 10), code);
        drop(store);
        let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
        refused(reopened.acquire_run_lease("run", "retry", 31, 10), code);
        assert_eq!(snapshot(&path)?, before);
    }
    Ok(())
}

#[test]
fn refused_heartbeats_preserve_every_persisted_field() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let first = store.acquire_run_lease("run", "owner", 100, 20)?;
    let before = snapshot(&path)?;
    for (owner, token, now, ttl, code) in [
        ("owner", 1, 110, 0, "runtime_run_lease_invalid_ttl"),
        ("owner", 1, 99, 20, "runtime_run_lease_clock_regressed"),
        ("owner", 1, 120, 20, "runtime_run_lease_expired"),
        (
            "owner",
            1,
            110,
            u64::MAX,
            "runtime_run_lease_expiry_overflow",
        ),
        ("other", 1, 110, 20, "runtime_run_stale_fencing_token"),
        ("owner", 2, 110, 20, "runtime_run_stale_fencing_token"),
    ] {
        refused(
            store.heartbeat_run_lease("run", owner, token, now, ttl),
            code,
        );
        assert_eq!(snapshot(&path)?, before);
    }
    // The former implementation updated first, then discovered this invalid order.
    Connection::open(&path)?.execute(
        "UPDATE runtime_run_leases SET acquired_at_unix_ms = 115",
        [],
    )?;
    let invalid = snapshot(&path)?;
    refused(
        store.heartbeat_run_lease("run", "owner", first.fencing_token, 110, 30),
        "runtime_run_lease_invalid_time_order",
    );
    assert_eq!(snapshot(&path)?, invalid);
    Connection::open(&path)?.execute("UPDATE runtime_run_leases SET fencing_token = 0", [])?;
    let invalid_token = snapshot(&path)?;
    refused(
        store.heartbeat_run_lease("run", "owner", 0, 116, 30),
        "runtime_run_lease_invalid_fencing_token",
    );
    assert_eq!(snapshot(&path)?, invalid_token);
    Connection::open(&path)?.execute(
        "UPDATE runtime_run_leases SET acquired_at_unix_ms = 100, fencing_token = 1",
        [],
    )?;
    let renewed = store.heartbeat_run_lease("run", "owner", first.fencing_token, 110, 30)?;
    assert_eq!(renewed.expires_at_unix_ms, 140);
    assert_eq!(renewed.acquired_at_unix_ms, 100);
    assert_eq!(renewed.fencing_token, first.fencing_token);
    let after = snapshot(&path)?;
    drop(store);
    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    refused(
        reopened.heartbeat_run_lease("run", "owner", 1, 109, 30),
        "runtime_run_lease_clock_regressed",
    );
    assert_eq!(snapshot(&path)?, after);
    Ok(())
}

#[test]
fn a_late_scheduler_write_failure_rolls_back_expirations_claims_and_tick() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    for run in ["a-good", "z-bad"] {
        store.record_run_state(run, "pending", None, 0)?;
    }
    store.acquire_run_lease("old", "previous", 0, 1)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER fail_late_claim BEFORE INSERT ON runtime_run_leases WHEN NEW.run_id = 'z-bad' BEGIN SELECT RAISE(ABORT, 'injected late lease failure'); END;")?;
    let before = snapshot(&path)?;
    let result = store.scheduler_tick_report(&early_profile(), "owner", 10, 2);
    assert!(
        matches!(result, Err(ChioRuntimeError::Store(ref detail)) if detail.contains("injected late lease failure")),
        "{result:?}"
    );
    assert_eq!(snapshot(&path)?, before);
    drop(store);
    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_eq!(snapshot(&path)?, before);
    connection.execute_batch("DROP TRIGGER fail_late_claim;")?;
    let report = reopened.scheduler_tick_report(&early_profile(), "owner", 10, 2)?;
    assert_eq!(report.claimed_run_ids, ["a-good", "z-bad"]);
    assert_eq!(report.expired_run_ids, ["old"]);
    assert_eq!(report.skipped_run_count, 0);
    assert_eq!(snapshot(&path)?.ticks.len(), 1);
    Ok(())
}

#[test]
fn scheduler_fencing_exhaustion_rolls_back_an_earlier_claim() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    for run in ["a-good", "z-exhausted"] {
        store.record_run_state(run, "pending", None, 0)?;
    }
    store.acquire_run_lease("z-exhausted", "previous", 0, 1)?;
    Connection::open(&path)?.execute(
        "UPDATE runtime_run_leases SET fencing_token = ?1",
        params![i64::MAX],
    )?;
    let before = snapshot(&path)?;
    refused(
        store.scheduler_tick_report(&early_profile(), "owner", 10, 2),
        "runtime_run_lease_fencing_exhausted",
    );
    assert_eq!(snapshot(&path)?, before);
    Ok(())
}

#[test]
fn competing_schedulers_share_one_capacity_snapshot() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    for index in 0..8 {
        store.record_run_state(&format!("run-{index}"), "pending", None, 0)?;
    }
    // Open every connection before starting workers so a failed open cannot strand a barrier.
    let handles = (0..4)
        .map(|_| SqliteRuntimeOrchestrationStore::open(&path))
        .collect::<Result<Vec<_>, _>>()?;
    let barrier = Arc::new(Barrier::new(handles.len()));
    let workers = handles
        .into_iter()
        .enumerate()
        .map(|(index, handle)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                handle.scheduler_tick_report(&early_profile(), &format!("owner-{index}"), 10, 2)
            })
        })
        .collect::<Vec<_>>();
    let mut claimed = Vec::new();
    for worker in workers {
        let report = worker.join().map_err(|_| "scheduler worker panicked")??;
        assert!(report.accepted);
        claimed.extend(report.claimed_run_ids);
    }
    assert_eq!(claimed.len(), 2);
    claimed.sort();
    claimed.dedup();
    assert_eq!(claimed.len(), 2);
    let after = snapshot(&path)?;
    assert_eq!(after.leases.len(), 2);
    assert_eq!(after.ticks.len(), 4);
    Ok(())
}

#[test]
fn competing_owners_fence_once_and_old_heartbeats_cannot_revive_after_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let handles = (0..4)
        .map(|_| SqliteRuntimeOrchestrationStore::open(&path))
        .collect::<Result<Vec<_>, _>>()?;
    let barrier = Arc::new(Barrier::new(handles.len()));
    let workers = handles
        .into_iter()
        .enumerate()
        .map(|(index, handle)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                handle.acquire_run_lease("run", &format!("owner-{index}"), 10, 10)
            })
        })
        .collect::<Vec<_>>();
    let mut winners = Vec::new();
    let mut conflicts = 0;
    for worker in workers {
        match worker.join().map_err(|_| "lease worker panicked")? {
            Ok(lease) => winners.push(lease),
            Err(error) => {
                assert_eq!(error.code(), "runtime_run_lease_conflict");
                conflicts += 1;
            }
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(conflicts, 3);
    assert_eq!(winners[0].fencing_token, 1);
    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let next = reopened.acquire_run_lease("run", "next", 20, 10)?;
    assert_eq!(next.fencing_token, 2);
    let before = snapshot(&path)?;
    refused(
        reopened.heartbeat_run_lease("run", &winners[0].owner_id, 1, 21, 10),
        "runtime_run_stale_fencing_token",
    );
    assert_eq!(snapshot(&path)?, before);
    Ok(())
}

#[test]
fn heartbeat_zero_is_not_stale_until_the_timeout_has_elapsed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("leases.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let profile = RuntimeSupervisorProfile {
        stale_run_after_ms: 100,
        ..early_profile()
    };
    store.acquire_run_lease("run", "owner", 0, 200)?;
    let status = store.ops_status_report(&profile, 50, true, true)?;
    assert!(status.ready);
    assert_eq!(status.stale_lease_count, 0);
    let early = store.scheduler_tick_report(&profile, "scheduler", 50, 2)?;
    assert!(early.expired_run_ids.is_empty());
    let stale = store.ops_status_report(&profile, 100, true, true)?;
    assert_eq!(
        stale.failure_code.as_deref(),
        Some("runtime_ops_status_degraded")
    );
    assert_eq!(stale.stale_lease_count, 1);
    let boundary = store.scheduler_tick_report(&profile, "scheduler", 100, 2)?;
    assert_eq!(boundary.expired_run_ids, ["run"]);
    Ok(())
}
