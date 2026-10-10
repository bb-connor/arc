//! The retention state-machine workload: interleaved tool and child receipt
//! appends with non-monotonic aged timestamps, probe appends after every
//! operation, and checkpoint-aligned rotations at a cutoff above every
//! timestamp, over a store whose background signer checkpoints every two
//! entries. This is the operation model of the retention property in the
//! library test suite, driven here through the public API so a separate
//! process can observe it through the VFS shim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_store_sqlite::{BackgroundCheckpointSigner, SqliteReceiptStore};
use chio_test_support::prelude::*;
use proptest::prelude::*;

use super::sync_shim::{FileKind, SyncRecord, SyncShim, ThreadTag};

/// Every receipt timestamp in the workload sits below this cutoff, so every
/// fully checkpointed prefix is eligible for archival.
pub const ROTATION_CUTOFF_UNIX_SECS: u64 = 3_000;
/// The background signer checkpoints every two claim-log entries.
pub const CHECKPOINT_BATCH: u64 = 2;
/// Probe appends carry this timestamp, above the aged band and below the cutoff.
const PROBE_TIMESTAMP: u64 = 2_000;

#[derive(Clone, Debug)]
pub enum Op {
    AppendTool(u8),
    AppendChild(u8),
    Rotate,
}

pub fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..8).prop_map(Op::AppendTool),
        (0u8..8).prop_map(Op::AppendChild),
        Just(Op::Rotate),
    ]
}

pub fn keypair() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

pub fn signer(keypair: &Keypair) -> BackgroundCheckpointSigner {
    BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch: CHECKPOINT_BATCH,
    }
}

pub fn tool_receipt(id: &str, timestamp: u64, keypair: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_owned(),
            timestamp,
            capability_id: "cap-1".to_owned(),
            tool_server: "shell".to_owned(),
            tool_name: "bash".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({"receipt": id}))
                .test_expect("tool action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-1".to_owned(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_expect("signed tool receipt")
}

pub fn child_receipt(id: &str, timestamp: u64, keypair: &Keypair) -> ChildRequestReceipt {
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_owned(),
            timestamp,
            session_id: SessionId::new("sess-1"),
            parent_request_id: RequestId::new("parent-1"),
            request_id: RequestId::new(format!("child-{id}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{id}"),
            policy_hash: "policy-1".to_owned(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        keypair,
    )
    .test_expect("signed child receipt")
}

/// Every receipt id in a database file's tool and child receipt tables.
pub fn receipt_ids(path: &Path) -> BTreeSet<String> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .test_expect("open receipt database read-only");
    let mut ids = BTreeSet::new();
    for table in ["chio_tool_receipts", "chio_child_receipts"] {
        let mut statement = connection
            .prepare(&format!("SELECT receipt_id FROM {table}"))
            .test_expect("prepare receipt id query");
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .test_expect("query receipt ids");
        for id in rows {
            ids.insert(id.test_expect("receipt id row"));
        }
    }
    ids
}

/// Where a step's work runs and how long it may take before the harness
/// declares a stall and dumps the shim's snapshot.
pub struct Watchdog<'a> {
    pub shim: &'a SyncShim,
    pub scope: String,
    pub budget: Duration,
}

impl Watchdog<'_> {
    /// Finish a caller that was started before a held sync was released.
    pub fn join<T: Send + 'static>(&self, name: &str, worker: thread::JoinHandle<T>) -> T {
        self.step(name, move || worker.join())
            .unwrap_or_else(|_| panic!("caller {name} panicked"))
    }

    /// Run one blocking store call on its own thread and wait for it with the
    /// step budget. Exceeding the budget is a stall: the failure carries the
    /// held sync, the lock ledger and every thread's kernel state.
    pub fn step<T: Send + 'static>(
        &self,
        name: &str,
        call: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, outcome) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("workload-{name}"))
            .spawn(move || {
                let _ = done.send(call());
            })
            .test_expect("spawn workload step");
        match outcome.recv_timeout(self.budget) {
            Ok(value) => {
                let _ = worker.join();
                value
            }
            Err(_) => panic!(
                "step {name} made no progress within {:?}\n{}",
                self.budget,
                self.shim.snapshot(&self.scope)
            ),
        }
    }
}

#[test]
fn released_caller_timeout_reports_the_stalled_step() {
    let _exclusive = super::exclusive();
    let shim = super::sync_shim::install();
    let (release, held) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || held.recv().test_expect("release injected caller"));
    let (completed, outcome) = mpsc::sync_channel(1);
    let observer = thread::spawn(move || {
        let watchdog = Watchdog {
            shim,
            scope: "injected-noncompletion".to_owned(),
            budget: Duration::from_millis(20),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            watchdog.join("released-caller", worker)
        }));
        let _ = completed.send(result);
    });
    let observed = outcome.recv_timeout(Duration::from_secs(2));
    release
        .send(())
        .test_expect("release injected caller for cleanup");
    observer.join().test_expect("join timeout observer");
    let failure = observed
        .test_expect("completion must fail within its deadline")
        .test_expect_err("held caller must time out");
    let message = failure
        .downcast_ref::<String>()
        .test_expect("timeout diagnostic string");
    assert!(
        message.contains("step released-caller made no progress"),
        "{message}"
    );
    assert!(message.contains("lock ledger:"), "{message}");
    assert!(message.contains("threads:"), "{message}");
}

/// What one case of the workload cost and who paid it.
#[derive(Clone, Debug, Default)]
pub struct CaseReport {
    pub ops: usize,
    pub rotations: usize,
    pub archived_rows: u64,
    /// Sync count per `<live|archive>.<file kind>`.
    pub syncs: BTreeMap<String, u64>,
    /// Threads syncing while holding the WAL write lock during the workload.
    pub live_wal_commit_threads: BTreeSet<Option<String>>,
}

impl CaseReport {
    pub fn total_syncs(&self) -> u64 {
        self.syncs.values().sum()
    }
}

/// Classify a sync as live or archive work by its path.
pub fn sync_label(record: &SyncRecord, live: &Path, archive: &Path) -> String {
    let side = if record
        .path
        .starts_with(&live.to_string_lossy().into_owned())
    {
        "live"
    } else if record
        .path
        .starts_with(&archive.to_string_lossy().into_owned())
    {
        "archive"
    } else {
        "other"
    };
    format!("{side}.{}", record.kind.label())
}

pub struct CaseFiles {
    pub live: PathBuf,
    pub archive: PathBuf,
}

impl CaseFiles {
    pub fn in_directory(directory: &Path, case: usize) -> Self {
        Self {
            live: directory.join(format!("live-{case}.sqlite3")),
            archive: directory.join(format!("archive-{case}.sqlite3")),
        }
    }
}

/// Run one operation sequence with the property's four invariants: every
/// append after any operation succeeds, the store reopens, health holds at
/// every rotation and at the end, and the archived and live receipt ids
/// partition the appended history.
pub fn run_case(ops: &[Op], files: &CaseFiles, watchdog: &Watchdog<'_>) -> CaseReport {
    let keypair = keypair();
    let archive_path = files
        .archive
        .to_str()
        .test_expect("archive path is UTF-8")
        .to_owned();
    let shim = watchdog.shim;
    let history_start = shim.syncs_under(&watchdog.scope).len();
    let mut seq = 0u64;
    let mut appended: BTreeSet<String> = BTreeSet::new();
    let mut report = CaseReport {
        ops: ops.len(),
        ..CaseReport::default()
    };
    let workload_start;
    let workload_end;
    {
        let live = files.live.clone();
        let store = Arc::new(
            watchdog
                .step("open-live", move || SqliteReceiptStore::open(&live))
                .test_expect("open live store"),
        );
        store
            .enable_background_checkpoints(signer(&keypair))
            .test_expect("install signer");
        // Bootstrap and last-connection cleanup are separate from receipt
        // commits. Public flushes can also checkpoint the WAL on their caller.
        workload_start = shim.syncs_under(&watchdog.scope).len();
        for (index, op) in ops.iter().enumerate() {
            let timestamp = 100 + ((index as u64 * 7) % 13);
            match op {
                Op::AppendTool(n) => {
                    seq += 1;
                    let receipt = tool_receipt(&format!("pt-{seq}-{n}-{seq}"), timestamp, &keypair);
                    appended.insert(receipt.id.clone());
                    let store = Arc::clone(&store);
                    watchdog
                        .step("append-tool", move || {
                            store.append_chio_receipt_returning_seq(&receipt)
                        })
                        .test_expect("tool receipt append");
                }
                Op::AppendChild(n) => {
                    seq += 1;
                    let receipt =
                        child_receipt(&format!("pc-{seq}-{n}-{seq}"), timestamp, &keypair);
                    appended.insert(receipt.id.clone());
                    let store = Arc::clone(&store);
                    watchdog
                        .step("append-child", move || {
                            store.append_child_receipt_record(&receipt)
                        })
                        .test_expect("child receipt append");
                }
                Op::Rotate => {
                    report.rotations += 1;
                    let flushing = Arc::clone(&store);
                    watchdog
                        .step("flush-before-rotate", move || {
                            flushing.flush_receipt_writes()
                        })
                        .test_expect("flush before rotation");
                    let rotating = Arc::clone(&store);
                    let archive = archive_path.clone();
                    report.archived_rows += watchdog
                        .step("rotate", move || {
                            rotating.archive_receipts_before(ROTATION_CUTOFF_UNIX_SECS, &archive)
                        })
                        .test_expect("rotation");
                    let flushing = Arc::clone(&store);
                    watchdog
                        .step("flush-after-rotate", move || {
                            flushing.flush_receipt_writes()
                        })
                        .test_expect("flush after rotation");
                    let checking = Arc::clone(&store);
                    let health = watchdog
                        .step("health-after-rotate", move || {
                            checking.receipt_store_health()
                        })
                        .test_expect("health after rotation");
                    assert!(health.healthy, "unhealthy after rotation: {health:?}");
                }
            }
            seq += 1;
            let probe = tool_receipt(&format!("probe-{seq}-{seq}"), PROBE_TIMESTAMP, &keypair);
            appended.insert(probe.id.clone());
            let store = Arc::clone(&store);
            watchdog
                .step("append-probe", move || {
                    store.append_chio_receipt_returning_seq(&probe)
                })
                .test_expect("probe append");
        }
        let flushing = Arc::clone(&store);
        watchdog
            .step("final-flush", move || flushing.flush_receipt_writes())
            .test_expect("final flush");
        let checking = Arc::clone(&store);
        let health = watchdog
            .step("final-health", move || checking.receipt_store_health())
            .test_expect("final health");
        assert!(
            health.healthy,
            "unhealthy at the end of the run: {health:?}"
        );
        workload_end = shim.syncs_under(&watchdog.scope).len();
        watchdog.step("teardown-original", move || drop(store));
    }
    let live = files.live.clone();
    let reopened = watchdog.step("reopen", move || SqliteReceiptStore::open(&live));
    let reopened = Arc::new(reopened.test_expect("reopen live store"));
    let flushing = Arc::clone(&reopened);
    watchdog
        .step("reopen-flush", move || flushing.flush_receipt_writes())
        .test_expect("flush after reopen");
    let checking = Arc::clone(&reopened);
    let health = watchdog
        .step("reopen-health", move || checking.receipt_store_health())
        .test_expect("health after reopen");
    assert!(health.healthy, "unhealthy after reopen: {health:?}");
    watchdog.step("teardown-reopened", move || drop(reopened));

    let live = files.live.clone();
    let live_ids = watchdog.step("read-live-ids", move || receipt_ids(&live));
    let archived_ids = if files.archive.exists() {
        let archive = files.archive.clone();
        let archive_store =
            watchdog.step("open-archive", move || SqliteReceiptStore::open(&archive));
        let archive_store = archive_store.test_expect("open archive as a store");
        watchdog.step("teardown-archive", move || drop(archive_store));
        let archive = files.archive.clone();
        watchdog.step("read-archive-ids", move || receipt_ids(&archive))
    } else {
        BTreeSet::new()
    };
    let overlap: Vec<&String> = live_ids.intersection(&archived_ids).collect();
    assert!(
        overlap.is_empty(),
        "receipt ids present in both live and archive: {overlap:?}"
    );
    let union: BTreeSet<String> = live_ids.union(&archived_ids).cloned().collect();
    assert_eq!(
        union, appended,
        "archived and live receipt ids must partition the appended history"
    );

    for (position, record) in shim
        .syncs_under(&watchdog.scope)
        .iter()
        .enumerate()
        .skip(history_start)
    {
        *report
            .syncs
            .entry(sync_label(record, &files.live, &files.archive))
            .or_default() += 1;
        if record.kind == FileKind::Wal
            && record
                .path
                .starts_with(&files.live.to_string_lossy().into_owned())
            && (workload_start..workload_end).contains(&position)
        {
            assert!(
                record.wal_write_lock || record.wal_checkpoint_lock,
                "unclassified live WAL sync during workload: {record}"
            );
            if record.wal_write_lock {
                report
                    .live_wal_commit_threads
                    .insert(record.thread.name.clone());
            }
        }
    }
    report
}

/// Render the per-thread view of who synced what, for a report.
pub fn describe_threads(records: &[SyncRecord], live: &Path, archive: &Path) -> String {
    let mut by_thread: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for record in records {
        *by_thread
            .entry(record.thread.to_string())
            .or_default()
            .entry(sync_label(record, live, archive))
            .or_default() += 1;
    }
    let mut rendered = String::new();
    for (thread, counts) in by_thread {
        rendered.push_str(&format!("  {thread}: {counts:?}\n"));
    }
    rendered
}

pub fn thread_name(tag: &ThreadTag) -> &str {
    tag.name.as_deref().unwrap_or("")
}
