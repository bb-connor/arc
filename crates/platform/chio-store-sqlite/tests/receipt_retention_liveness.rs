//! The retention rotation and the receipt writer under induced slow sync and
//! lock contention, observed through a SQLite VFS shim in its own process.
//!
//! The shim holds a chosen `xSync` at a gate and records which thread owns
//! which SQLite lock while it is held, so every stall these tests create is
//! placed at an exact durability boundary and attributed to its owner
//! without a timing assumption. A fixed per-sync latency
//! (`CHIO_RETENTION_SYNC_DELAY_MS`) reproduces a slow disk for the whole
//! workload.
#![cfg(unix)]

#[path = "receipt_retention_liveness/sync_shim.rs"]
mod sync_shim;
#[path = "receipt_retention_liveness/workload.rs"]
mod workload;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use chio_kernel::ReceiptWriterLiveness;
use chio_store_sqlite::SqliteReceiptStore;
use chio_test_support::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use sync_shim::{FileKind, GateSpec, SyncShim};
use workload::{
    describe_threads, keypair, op_strategy, receipt_ids, signer, thread_name, tool_receipt,
    CaseFiles, CaseReport, Op, Watchdog, ROTATION_CUTOFF_UNIX_SECS,
};

/// The receipt writer's supervised thread name.
const WRITER_THREAD: &str = "chio-receipt-writer";
/// No progress for this long at zero induced latency is a stall.
const STEP_BUDGET: Duration = Duration::from_secs(60);
/// How long a gated sync may take to be reached.
const GATE_WAIT: Duration = Duration::from_secs(30);
/// Fixed seed so every run drives the same operation sequences.
const WORKLOAD_SEED: [u8; 32] = [7; 32];
const WORKLOAD_CASES: usize = 24;

/// The shim's gate and delay are process-wide, so the tests run one at a time.
static EXCLUSIVE: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    EXCLUSIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn induced_sync_delay() -> Duration {
    std::env::var("CHIO_RETENTION_SYNC_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::ZERO)
}

/// Releases a held gate when the test unwinds, so a failing assertion never
/// leaves the writer thread parked forever.
struct GateRelease<'a>(&'a SyncShim);

impl Drop for GateRelease<'_> {
    fn drop(&mut self) {
        self.0.release();
        self.0.disarm();
    }
}

fn operation_sequences(cases: usize) -> Vec<Vec<Op>> {
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &WORKLOAD_SEED),
    );
    let strategy = proptest::collection::vec(op_strategy(), 1..40);
    (0..cases)
        .map(|_| {
            strategy
                .new_tree(&mut runner)
                .test_expect("operation sequence")
                .current()
        })
        .collect()
}

fn wait_until(what: &str, deadline: Duration, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < deadline,
            "{what} was not observed within {deadline:?}"
        );
        thread::yield_now();
    }
}

fn scope_of(directory: &tempfile::TempDir) -> String {
    directory.path().to_string_lossy().into_owned()
}

/// The property's workload, case by case, under the stall watchdog. Receipt
/// commits are attributed by the WAL write lock, separately from bootstrap,
/// teardown and caller-side WAL checkpoints. Public flushes deliberately run
/// passive checkpoint maintenance on their caller. All syncs still count
/// toward the observed I/O cost and the per-step watchdog.
#[test]
fn retention_workload_commits_are_serialized_on_writer() {
    let _exclusive = exclusive();
    let shim = sync_shim::install();
    let directory = tempfile::tempdir().test_expect("temp dir");
    let scope = scope_of(&directory);
    let delay = induced_sync_delay();
    shim.set_delay(delay);
    shim.clear_history();
    let watchdog = Watchdog {
        shim,
        scope: scope.clone(),
        budget: STEP_BUDGET + delay * 64,
    };
    let sequences = operation_sequences(WORKLOAD_CASES);
    let mut reports: Vec<CaseReport> = Vec::new();
    let started = Instant::now();
    for (case, ops) in sequences.iter().enumerate() {
        let files = CaseFiles::in_directory(directory.path(), case);
        reports.push(workload::run_case(ops, &files, &watchdog));
    }
    let elapsed = started.elapsed();
    shim.set_delay(Duration::ZERO);

    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for report in &reports {
        for (label, count) in &report.syncs {
            *totals.entry(label.clone()).or_default() += count;
        }
    }
    let total_syncs: u64 = reports.iter().map(CaseReport::total_syncs).sum();
    let total_ops: usize = reports.iter().map(|report| report.ops).sum();
    let total_rotations: usize = reports.iter().map(|report| report.rotations).sum();
    println!(
        "{} cases, {} ops, {} rotations, {} syncs in {:?} (induced sync delay {:?})",
        reports.len(),
        total_ops,
        total_rotations,
        total_syncs,
        elapsed,
        delay
    );
    println!("syncs by file: {totals:?}");
    for (case, report) in reports.iter().enumerate() {
        println!(
            "  case {case:>2}: ops={:>2} rotations={:>2} archived={:>3} syncs={:>4} {:?}",
            report.ops,
            report.rotations,
            report.archived_rows,
            report.total_syncs(),
            report.syncs
        );
    }

    let wal_sync_threads: std::collections::BTreeSet<Option<String>> = reports
        .iter()
        .flat_map(|report| report.live_wal_commit_threads.iter().cloned())
        .collect();
    assert_eq!(
        wal_sync_threads,
        std::collections::BTreeSet::from([Some(WRITER_THREAD.to_owned())]),
        "every live WAL write-lock sync during the workload must be issued by the supervised writer thread"
    );
    assert!(
        reports.iter().any(|report| report.archived_rows > 0),
        "the workload must exercise the co-archive-and-delete path"
    );

    // The budget is a property of the operation sequence: replaying the
    // first case yields the same syncs on every file.
    let replay_files = CaseFiles::in_directory(directory.path(), WORKLOAD_CASES);
    let replay = workload::run_case(&sequences[0], &replay_files, &watchdog);
    assert_eq!(
        replay.syncs, reports[0].syncs,
        "replaying an operation sequence must reproduce its sync budget exactly"
    );
}

/// A rotation dispatched while the writer thread is inside an append's WAL
/// sync waits in the writer's command queue. The writer thread owns the WAL
/// write lock and the held sync; the rotating thread owns nothing and has
/// not touched the archive. Releasing the sync completes the append first
/// and the rotation second, with the invariants intact.
#[test]
fn rotation_waits_behind_the_writer_commit_it_cannot_preempt() {
    let _exclusive = exclusive();
    let shim = sync_shim::install();
    let directory = tempfile::tempdir().test_expect("temp dir");
    let scope = scope_of(&directory);
    let watchdog = Watchdog {
        shim,
        scope: scope.clone(),
        budget: STEP_BUDGET,
    };
    let files = CaseFiles::in_directory(directory.path(), 0);
    let live_prefix = files.live.to_string_lossy().into_owned();
    let archive_path = files
        .archive
        .to_str()
        .test_expect("archive path is UTF-8")
        .to_owned();
    let keypair = keypair();
    let store = Arc::new(SqliteReceiptStore::open(&files.live).test_expect("open live store"));
    store
        .enable_background_checkpoints(signer(&keypair))
        .test_expect("install signer");
    for seq in 1..=2u64 {
        store
            .append_chio_receipt_returning_seq(&tool_receipt(&format!("aged-{seq}"), 100, &keypair))
            .test_expect("aged append");
    }
    store
        .flush_receipt_writes()
        .test_expect("flush aged prefix");
    shim.clear_history();

    shim.arm(GateSpec {
        path_prefix: live_prefix.clone(),
        kind: FileKind::Wal,
        skip: 0,
    });
    let release = GateRelease(shim);
    let appending = Arc::clone(&store);
    let append_keypair = keypair.clone();
    let append = thread::Builder::new()
        .name("caller-append".to_owned())
        .spawn(move || {
            appending.append_chio_receipt_returning_seq(&tool_receipt(
                "fresh-3",
                2_000,
                &append_keypair,
            ))
        })
        .test_expect("spawn appending caller");
    let held = shim
        .wait_for_block(GATE_WAIT)
        .test_expect("the append's WAL sync reaches the gate");
    assert_eq!(thread_name(&held.thread), WRITER_THREAD);
    assert_eq!(held.kind, FileKind::Wal);
    assert!(held.path.starts_with(&live_prefix));

    let rotating = Arc::clone(&store);
    let rotation = thread::Builder::new()
        .name("caller-rotate".to_owned())
        .spawn(move || rotating.archive_receipts_before(ROTATION_CUTOFF_UNIX_SECS, &archive_path))
        .test_expect("spawn rotating caller");
    wait_until(
        "the rotation command queued behind the held append",
        GATE_WAIT,
        || {
            store
                .receipt_store_health()
                .map(|health| health.writer.queue_depth >= 1)
                .unwrap_or(false)
        },
    );

    let snapshot = shim.snapshot(&scope);
    println!("{snapshot}");
    let health = store
        .receipt_store_health()
        .test_expect("health while held");
    assert_eq!(
        health.writer.inflight, 2,
        "append and rotation are both in flight"
    );
    assert_eq!(
        health.writer.queue_depth, 1,
        "the rotation is queued, not running"
    );
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Wedged
    );
    let ledger = shim.locks_under(&live_prefix);
    assert!(
        ledger.contains(&format!("wal-index WRITE EXCLUSIVE by {WRITER_THREAD}")),
        "the writer thread must hold the WAL write lock while its sync is held:\n{ledger}"
    );
    assert!(
        !ledger.contains("caller-rotate"),
        "the rotating caller must hold no SQLite lock while queued:\n{ledger}"
    );
    assert!(
        shim.syncs_under(&files.archive.to_string_lossy())
            .is_empty(),
        "no archive file may be touched while the rotation is queued"
    );
    let backtrace = held.backtrace.clone().unwrap_or_default();
    assert!(
        backtrace.contains("receipt_store") || backtrace.contains("sqlite3"),
        "the held sync must be attributed to the writer's commit path:\n{backtrace}"
    );

    drop(release);
    let appended = watchdog
        .join("append-after-release", append)
        .test_expect("append completes after release");
    assert_eq!(appended, 3);
    let archived = watchdog
        .join("rotation-after-release", rotation)
        .test_expect("rotation completes after release");
    assert_eq!(
        archived, 2,
        "the aged checkpointed prefix archives after the append"
    );
    let flushing = Arc::clone(&store);
    watchdog
        .step("flush-after-release", move || {
            flushing.flush_receipt_writes()
        })
        .test_expect("flush after release");
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Healthy
    );
    let checking = Arc::clone(&store);
    let health = watchdog
        .step("health-after-release", move || {
            checking.receipt_store_health()
        })
        .test_expect("health after release");
    assert!(health.healthy, "{health:?}");
    let records = shim.syncs_under(&scope);
    println!(
        "{}",
        describe_threads(&records, &files.live, &files.archive)
    );
    for record in records
        .iter()
        .filter(|record| record.kind == FileKind::Wal && record.path.starts_with(&live_prefix))
    {
        assert!(
            record.wal_write_lock || record.wal_checkpoint_lock,
            "{record}"
        );
        if record.wal_write_lock {
            assert_eq!(thread_name(&record.thread), WRITER_THREAD, "{record}");
        }
    }
    drop(store);
    assert_eq!(
        receipt_ids(&files.live),
        std::collections::BTreeSet::from([tool_receipt("fresh-3", 2_000, &keypair).id])
    );
    assert_eq!(
        receipt_ids(&files.archive),
        std::collections::BTreeSet::from([
            tool_receipt("aged-1", 100, &keypair).id,
            tool_receipt("aged-2", 100, &keypair).id,
        ])
    );
}

/// An append dispatched while the writer thread is inside the rotation's
/// archive write waits in the writer's command queue. The writer thread owns
/// the rotation, its connection and the held sync; the appending caller
/// owns nothing. Releasing the sync completes the rotation first and the
/// append second, and the fresh receipt lands live while the aged prefix is
/// archived.
#[test]
fn appends_wait_behind_the_rotation_holding_the_archive_sync() {
    let _exclusive = exclusive();
    let shim = sync_shim::install();
    let directory = tempfile::tempdir().test_expect("temp dir");
    let scope = scope_of(&directory);
    let watchdog = Watchdog {
        shim,
        scope: scope.clone(),
        budget: STEP_BUDGET,
    };
    let files = CaseFiles::in_directory(directory.path(), 0);
    let archive_prefix = files.archive.to_string_lossy().into_owned();
    let archive_path = archive_prefix.clone();
    let keypair = keypair();
    let store = Arc::new(SqliteReceiptStore::open(&files.live).test_expect("open live store"));
    store
        .enable_background_checkpoints(signer(&keypair))
        .test_expect("install signer");
    for seq in 1..=2u64 {
        store
            .append_chio_receipt_returning_seq(&tool_receipt(&format!("aged-{seq}"), 100, &keypair))
            .test_expect("aged append");
    }
    store
        .flush_receipt_writes()
        .test_expect("flush aged prefix");
    shim.clear_history();

    shim.arm(GateSpec {
        path_prefix: archive_prefix.clone(),
        kind: FileKind::MainDb,
        skip: 0,
    });
    let release = GateRelease(shim);
    let rotating = Arc::clone(&store);
    let rotation = thread::Builder::new()
        .name("caller-rotate".to_owned())
        .spawn(move || rotating.archive_receipts_before(ROTATION_CUTOFF_UNIX_SECS, &archive_path))
        .test_expect("spawn rotating caller");
    let held = shim
        .wait_for_block(GATE_WAIT)
        .test_expect("the rotation's archive sync reaches the gate");
    assert_eq!(thread_name(&held.thread), WRITER_THREAD);
    assert_eq!(held.kind, FileKind::MainDb);
    assert!(held.path.starts_with(&archive_prefix));

    let appending = Arc::clone(&store);
    let append_keypair = keypair.clone();
    let append = thread::Builder::new()
        .name("caller-append".to_owned())
        .spawn(move || {
            appending.append_chio_receipt_returning_seq(&tool_receipt(
                "fresh-3",
                2_000,
                &append_keypair,
            ))
        })
        .test_expect("spawn appending caller");
    wait_until(
        "the append command queued behind the held rotation",
        GATE_WAIT,
        || {
            store
                .receipt_store_health()
                .map(|health| health.writer.queue_depth >= 1)
                .unwrap_or(false)
        },
    );

    let snapshot = shim.snapshot(&scope);
    println!("{snapshot}");
    let health = store
        .receipt_store_health()
        .test_expect("health while held");
    assert_eq!(
        health.writer.inflight, 2,
        "rotation and append are both in flight"
    );
    assert_eq!(
        health.writer.queue_depth, 1,
        "the append is queued, not running"
    );
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Wedged
    );
    let ledger = shim.locks_under(&scope);
    assert!(
        !ledger.contains("caller-append"),
        "the appending caller must hold no SQLite lock while queued:\n{ledger}"
    );
    assert!(
        ledger.contains(&format!("changed by {WRITER_THREAD}")),
        "the writer thread must own the archive's locks while its sync is held:\n{ledger}"
    );
    let backtrace = held.backtrace.clone().unwrap_or_default();
    assert!(
        backtrace.contains("receipt_store") || backtrace.contains("sqlite3"),
        "the held sync must be attributed to the rotation path:\n{backtrace}"
    );

    drop(release);
    let archived = watchdog
        .join("rotation-after-release", rotation)
        .test_expect("rotation completes after release");
    assert_eq!(archived, 2);
    let appended = watchdog
        .join("append-after-release", append)
        .test_expect("append completes after release");
    assert_eq!(appended, 3, "the fresh receipt commits after the rotation");
    let flushing = Arc::clone(&store);
    watchdog
        .step("flush-after-release", move || {
            flushing.flush_receipt_writes()
        })
        .test_expect("flush after release");
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Healthy
    );
    let checking = Arc::clone(&store);
    let health = watchdog
        .step("health-after-release", move || {
            checking.receipt_store_health()
        })
        .test_expect("health after release");
    assert!(health.healthy, "{health:?}");
    let records = shim.syncs_under(&scope);
    println!(
        "{}",
        describe_threads(&records, &files.live, &files.archive)
    );
    drop(store);
    assert_eq!(
        receipt_ids(&files.live),
        std::collections::BTreeSet::from([tool_receipt("fresh-3", 2_000, &keypair).id])
    );
    assert_eq!(
        receipt_ids(&files.archive),
        std::collections::BTreeSet::from([
            tool_receipt("aged-1", 100, &keypair).id,
            tool_receipt("aged-2", 100, &keypair).id,
        ])
    );
}
