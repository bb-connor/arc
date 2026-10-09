//! `linux-file` capacity: snapshots built through the production constructor,
//! which binds each one to a private file, from signed history held in a live
//! store and its archive.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::crypto::Keypair;
use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQuerySnapshotError};
use chio_kernel::ReceiptStoreError;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use super::super::support::{context, keypair, other_keypair, Fixture, Spec};
use super::{
    attrs, divisor, emit, full_count_check, per_second, projected, reset_peak_rss, rounded, scaled,
    ProcMemory, StepCounter, SIGNER,
};
use crate::receipt_query_snapshot::db::{
    OwnedCheckpoint, PendingLeaf, SnapshotBatch, SnapshotDb, KIND_TOOL,
};
use crate::receipt_query_snapshot::pass::{build_snapshot, retry_busy, Target};
use crate::receipt_query_snapshot::query::select;
use crate::receipt_query_snapshot::service::{
    GateAction, GatePoint, ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState,
    ReceiptQuerySnapshots,
};
use crate::receipt_query_snapshot::walk::{observe, WalkContext, WalkError, WalkLimits};
use crate::receipt_store::support::receipt_signature_verifications;
use crate::receipt_store::BackgroundCheckpointSigner;

const LINUX_FILE: &str = "linux-file";
const SIGNED_RECEIPTS: u64 = 1_000_000;
const SMALL_BATCH: u64 = 1_000;
const ROLLOVER_BATCH: u64 = 1_024;
const APPEND_CHUNK: u64 = 1_024;
const HOLD_TAIL: u64 = 100_000;
const MIB: u64 = 1024 * 1024;

/// Timestamp below which `Spec::varied(index)` receipts are older.
fn cutoff(index: u64) -> u64 {
    1_700_000_000 + index * 600
}

/// The walker limits the service derives from `config`.
fn production_limits(config: &ReceiptQuerySnapshotConfig) -> WalkLimits {
    WalkLimits {
        step_rows: config.step_rows,
        step_bytes: config.step_bytes,
        max_receipt_bytes: config.max_receipt_bytes,
        sql_steps: config.walker_sql_steps,
        insert_rows: config.insert_rows,
        checkpoint_page: config.checkpoint_page,
        busy_timeout: config.walker_busy_timeout,
    }
}

fn file_bytes(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |metadata| metadata.len())
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Sign and append `Spec::varied(index)` for every index. Parallel workers
/// take the indexes of each chunk round robin, so the writer group-commits
/// them while commit order stays within one chunk of index order, and with it
/// timestamp order, which checkpoint-aligned rotation relies on.
fn append_signed(fixture: &Fixture, indexes: std::ops::Range<u64>, key: &Keypair) {
    let workers = u64::try_from(
        std::thread::available_parallelism()
            .map_or(4, std::num::NonZeroUsize::get)
            .min(16),
    )
    .unwrap();
    let mut start = indexes.start;
    while start < indexes.end {
        let end = (start + APPEND_CHUNK).min(indexes.end);
        std::thread::scope(|scope| {
            for worker in 0..workers {
                let store = &fixture.store;
                scope.spawn(move || {
                    let step = usize::try_from(workers).unwrap();
                    for index in (start + worker..end).step_by(step) {
                        store
                            .append_chio_receipt_returning_seq(&Spec::varied(index).sign(key))
                            .unwrap();
                    }
                });
            }
        });
        start = end;
    }
    fixture.flush();
}

fn set_signer(fixture: &Fixture, key: Keypair, max_batch: u64) {
    fixture
        .store
        .enable_background_checkpoints(BackgroundCheckpointSigner {
            keypair: Arc::new(key),
            max_batch,
        })
        .unwrap();
    fixture.flush();
}

/// Signed history of `receipts` tool receipts: a prefix in small batches, one
/// large batch, then a signer rollover; the older half is archived.
struct History {
    fixture: Fixture,
    large_batch: u64,
    checkpoints: i64,
    signers: i64,
    archived: u64,
    append_seconds: f64,
    rotate_seconds: f64,
}

fn signed_history(receipts: u64) -> History {
    let small = (SMALL_BATCH / divisor()).max(1);
    let prefix = receipts * 3 / 10;
    let large = (receipts / 10).max(1);
    assert_eq!(prefix % small, 0, "the prefix must end on a checkpoint");
    let fixture = Fixture::new(small);
    let started = Instant::now();
    append_signed(&fixture, 0..prefix, &keypair());
    set_signer(&fixture, keypair(), large);
    append_signed(&fixture, prefix..prefix + large, &keypair());
    set_signer(
        &fixture,
        other_keypair(),
        (ROLLOVER_BATCH / divisor()).max(1),
    );
    append_signed(&fixture, prefix + large..receipts, &other_keypair());
    let append_seconds = started.elapsed().as_secs_f64();

    let live =
        Connection::open_with_flags(&fixture.live, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let (checkpoints, signers, large_batches): (i64, i64, i64) = live
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT kernel_key), SUM(tree_size = ?1) FROM kernel_checkpoints",
            [i64::try_from(large).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(live);
    assert_eq!(large_batches, 1, "one checkpoint covers the large batch");
    assert_eq!(signers, 2, "the history rolls its signer over");

    // Archive the older half in steps of a tenth of the history.
    let started = Instant::now();
    let archive = fixture.archive.to_str().unwrap().to_owned();
    let mut archived = 0;
    for tenth in 1..=5 {
        archived += fixture
            .store
            .archive_receipts_before(cutoff(receipts * tenth / 10), &archive)
            .unwrap();
    }
    let rotate_seconds = started.elapsed().as_secs_f64();
    assert!(archived > 0);
    History {
        fixture,
        large_batch: large,
        checkpoints,
        signers,
        archived,
        append_seconds,
        rotate_seconds,
    }
}

fn observed_target(ctx: &WalkContext<'_>) -> Target {
    let observation = retry_busy(ctx, || observe(ctx)).unwrap();
    Target {
        head: observation.head,
        checkpoint: observation.checkpoint,
        lineage_rowid: observation.lineage_rowid,
        max_source_seqs: observation.max_source_seqs,
        observed_at_ms: 1,
        observed_at: Instant::now(),
    }
}

struct Built {
    db: SnapshotDb,
    head: i64,
    seconds: f64,
    steps: Vec<Duration>,
    entry_steps: u64,
    verified: u64,
}

/// Build through the production entry point, timing every step. The receipt
/// signature counter is per thread, so `verified` counts this build only.
fn build(
    ctx: &WalkContext<'_>,
    target: Target,
    quota: u64,
    mut between_steps: impl FnMut(u64),
) -> Result<Built, WalkError> {
    let verified_before = receipt_signature_verifications();
    let started = Instant::now();
    let mut last = started;
    let mut steps = Vec::new();
    let mut authenticated = 0;
    let mut entry_steps = 0;
    let result = build_snapshot(ctx, target, quota, &mut |done, _| {
        let now = Instant::now();
        steps.push(now - last);
        last = now;
        if done > authenticated {
            entry_steps += 1;
            authenticated = done;
        }
        between_steps(done);
    });
    let seconds = started.elapsed().as_secs_f64();
    let (db, result) = result?;
    Ok(Built {
        db,
        head: result.target.head,
        seconds,
        steps,
        entry_steps,
        verified: receipt_signature_verifications() - verified_before,
    })
}

fn step_millis(mut steps: Vec<Duration>) -> Value {
    steps.sort();
    let at = |quantile: f64| {
        let index = (steps.len().saturating_sub(1) as f64 * quantile).round() as usize;
        steps
            .get(index)
            .map_or(0.0, |step| rounded(step.as_secs_f64() * 1_000.0))
    };
    let total: Duration = steps.iter().sum();
    json!({
        "count": steps.len(),
        "p50": at(0.5),
        "p90": at(0.9),
        "p99": at(0.99),
        "max": at(1.0),
        "mean": rounded(total.as_secs_f64() * 1_000.0 / steps.len().max(1) as f64),
    })
}

/// Samples resident and virtual size until finished and keeps the maxima.
struct PeakSampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<ProcMemory>,
}

impl PeakSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut peak = ProcMemory::default();
            loop {
                let now = ProcMemory::read();
                peak.rss = peak.rss.max(now.rss);
                peak.size = peak.size.max(now.size);
                peak.hwm = now.hwm;
                peak.peak = now.peak;
                if stopped.load(Ordering::SeqCst) {
                    return peak;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        Self { stop, handle }
    }

    fn finish(self) -> ProcMemory {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

fn admin(limit: usize) -> ReceiptQuery {
    ReceiptQuery {
        limit,
        ..ReceiptQuery::default().local_operator_admin()
    }
}

/// Totals of a built snapshot against counts derived from `Spec::varied`,
/// plus the full maintained-count check.
fn check_answers(db: &SnapshotDb, receipts: u64, sql_steps: u64) -> Value {
    let count = |matches: &dyn Fn(u64) -> bool| -> u64 {
        let matched = (0..receipts).filter(|index| matches(*index)).count();
        u64::try_from(matched).unwrap()
    };
    let shapes: [(&str, ReceiptQuery, u64); 4] = [
        ("admin", admin(10), receipts),
        (
            "tenant_a",
            ReceiptQuery {
                limit: 10,
                ..ReceiptQuery::default().authenticated_tenant("tenant-a")
            },
            count(&|index| matches!(index % 4, 1 | 2)),
        ),
        (
            "tool_pair",
            ReceiptQuery {
                tool_server: Some("web".into()),
                tool_name: Some("fetch".into()),
                ..admin(10)
            },
            count(&|index| index % 6 == 0),
        ),
        (
            "capability_deny",
            ReceiptQuery {
                capability_id: Some("cap-1".into()),
                outcome: Some("deny".into()),
                ..admin(10)
            },
            count(&|index| index % 5 == 1 && index % 7 == 0),
        ),
    ];
    for (name, query, expected) in &shapes {
        let selection = select(db, query, sql_steps).unwrap();
        assert_eq!(selection.total_count, *expected, "{name}");
    }
    let (compared, mismatches) = full_count_check(db);
    assert_eq!(mismatches, 0);
    json!({ "shapes_checked": shapes.len(), "count_rows_compared": compared, "mismatches": mismatches })
}

#[test]
#[ignore = "capacity evidence: 1,000,000 signed receipts built through the production constructor"]
fn linux_file_signed_build() {
    let receipts = scaled(SIGNED_RECEIPTS);
    let config = ReceiptQuerySnapshotConfig::default();
    let history = signed_history(receipts);
    let fixture = &history.fixture;
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, production_limits(&config));
    let head = i64::try_from(receipts).unwrap();

    // Quiet build: the walker's single worker with nothing else running.
    let quiet_reset = reset_peak_rss();
    let quiet_before = ProcMemory::read();
    let sampler = PeakSampler::start();
    let Built {
        db,
        head: quiet_head,
        seconds,
        steps,
        entry_steps,
        verified,
    } = build(&ctx, observed_target(&ctx), config.quota_bytes, |_| {}).unwrap();
    let quiet_peak = sampler.finish();
    let quiet_built = ProcMemory::read();
    assert_eq!(quiet_head, head);
    assert_eq!(db.tool_row_count().unwrap(), receipts);
    assert_eq!(verified, receipts, "one signature check per receipt");
    let quiet_answers = check_answers(&db, receipts, config.query_sql_steps);
    let used = db.used_bytes().unwrap();
    let backing = PathBuf::from(db.connection().unwrap().path().unwrap());
    let backing_bytes = file_bytes(&backing);
    assert_eq!(
        backing_bytes, used,
        "the private file holds exactly the counted pages"
    );
    let directory = backing.parent().unwrap().to_path_buf();
    drop(db);
    assert!(
        !backing.exists() && !directory.exists(),
        "custody removes its directory"
    );
    let quiet_dropped = ProcMemory::read();
    let quiet = json!({
        "entries": receipts,
        "seconds": rounded(seconds),
        "entries_per_second": per_second(receipts, seconds),
        "steps": step_millis(steps),
        "entry_steps": entry_steps,
        "signature_checks": verified,
        "used_bytes": used,
        "backing_file_bytes": backing_bytes,
        "bytes_per_receipt": rounded(used as f64 / receipts as f64),
        "process": {
            "peak_reset": quiet_reset,
            "before": quiet_before.json(),
            "sampled_peak": quiet_peak.json(),
            "built": quiet_built.json(),
            "dropped": quiet_dropped.json(),
            "peak_rss_growth_kib": quiet_built.hwm.saturating_sub(quiet_before.rss),
        },
        "answers": quiet_answers,
    });

    // Contended build: appends continue and an archive rotation runs while
    // the walker is inside the range it moves.
    let live_wal = sidecar(&fixture.live, "-wal");
    let wal_before = file_bytes(&live_wal);
    let live_before = file_bytes(&fixture.live);
    let archive_before = file_bytes(&fixture.archive);
    let target = observed_target(&ctx);
    assert_eq!(target.head, head);
    let running = Arc::new(AtomicBool::new(true));
    let progress = Arc::new(AtomicU64::new(0));
    let appender = {
        let store = Arc::clone(&fixture.store);
        let running = Arc::clone(&running);
        let cap = (receipts / 10).max(1);
        std::thread::spawn(move || {
            let key = other_keypair();
            let started = Instant::now();
            let mut appended = 0;
            while running.load(Ordering::SeqCst) && appended < cap {
                store
                    .append_chio_receipt_returning_seq(
                        &Spec::varied(receipts + appended).sign(&key),
                    )
                    .unwrap();
                appended += 1;
            }
            (appended, started.elapsed().as_secs_f64())
        })
    };
    let rotation_cutoff = cutoff(receipts * 3 / 4);
    let archive = fixture.archive.to_str().unwrap().to_owned();
    let rotation = {
        let store = Arc::clone(&fixture.store);
        let running = Arc::clone(&running);
        let progress = Arc::clone(&progress);
        let archive = archive.clone();
        let trigger = receipts * 55 / 100;
        std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) && progress.load(Ordering::SeqCst) < trigger {
                std::thread::sleep(Duration::from_millis(5));
            }
            let started_at = progress.load(Ordering::SeqCst);
            let started_during = running.load(Ordering::SeqCst);
            let started = Instant::now();
            let outcome = store.archive_receipts_before(rotation_cutoff, &archive);
            let finished_during = running.load(Ordering::SeqCst);
            (
                outcome.map_err(|error| error.to_string()),
                started.elapsed().as_secs_f64(),
                started_at,
                progress.load(Ordering::SeqCst),
                started_during,
                finished_during,
            )
        })
    };
    let contended_reset = reset_peak_rss();
    let contended_before = ProcMemory::read();
    let sampler = PeakSampler::start();
    let mut wal_max = wal_before;
    let built = build(&ctx, target, config.quota_bytes, |done| {
        progress.store(done, Ordering::SeqCst);
        wal_max = wal_max.max(file_bytes(&live_wal));
    });
    running.store(false, Ordering::SeqCst);
    let contended_peak = sampler.finish();
    let (appended, append_seconds) = appender.join().unwrap();
    let (outcome, rotation_seconds, started_at, finished_at, started_during, finished_during) =
        rotation.join().unwrap();
    let Built {
        db,
        head: contended_head,
        seconds,
        steps,
        entry_steps,
        verified,
    } = built.unwrap();
    // A rotation refused under contention is retried, as maintenance does.
    let mut attempts = 1;
    let mut archived = outcome.clone().unwrap_or(0);
    while archived == 0 && attempts < 4 {
        attempts += 1;
        archived = fixture
            .store
            .archive_receipts_before(rotation_cutoff, &archive)
            .unwrap_or(0);
    }
    assert!(archived > 0, "the rotation archived rows: {outcome:?}");
    assert_eq!(
        contended_head, head,
        "appends after the target belong to extension"
    );
    assert_eq!(db.tool_row_count().unwrap(), receipts);
    assert_eq!(verified, receipts, "one signature check per receipt");
    let contended_answers = check_answers(&db, receipts, config.query_sql_steps);
    let contended_used = db.used_bytes().unwrap();
    drop(db);
    fixture.flush();
    let contended = json!({
        "entries": receipts,
        "seconds": rounded(seconds),
        "entries_per_second": per_second(receipts, seconds),
        "steps": step_millis(steps),
        "entry_steps": entry_steps,
        "signature_checks": verified,
        "used_bytes": contended_used,
        "appended_during_build": appended,
        "append_rate_per_second": per_second(appended, append_seconds),
        "rotation": {
            "cutoff_index": receipts * 3 / 4,
            "first_outcome": outcome.map_err(|error| error.chars().take(200).collect::<String>()),
            "archived": archived,
            "attempts": attempts,
            "seconds": rounded(rotation_seconds),
            "started_at_entry": started_at,
            "finished_at_entry": finished_at,
            "started_during_build": started_during,
            "finished_during_build": finished_during,
        },
        "wal_bytes": {
            "before": wal_before,
            "max_between_steps": wal_max,
            "after_flush": file_bytes(&live_wal),
        },
        "live_db_bytes": { "before": live_before, "after": file_bytes(&fixture.live) },
        "archive_bytes": { "before": archive_before, "after": file_bytes(&fixture.archive) },
        "process": {
            "peak_reset": contended_reset,
            "before": contended_before.json(),
            "sampled_peak": contended_peak.json(),
        },
        "answers": contended_answers,
    });

    // On the production backing, a quota the history cannot fit is the
    // typed capacity outcome, and no snapshot is returned.
    let quota = (used / 4).min(16 * MIB);
    let reached = AtomicU64::new(0);
    let started = Instant::now();
    let refused = build(&ctx, observed_target(&ctx), quota, |done| {
        reached.store(done, Ordering::SeqCst);
    });
    let refusal_seconds = started.elapsed().as_secs_f64();
    let (quota_bytes, used_bytes) = match refused {
        Err(WalkError::Capacity {
            quota_bytes,
            used_bytes,
        }) => (quota_bytes, used_bytes),
        Err(other) => panic!("expected a capacity outcome, got {other}"),
        Ok(_) => panic!("expected a capacity outcome, the build completed"),
    };
    assert!(used_bytes <= quota_bytes);

    emit(
        "linux_file_signed_build",
        LINUX_FILE,
        receipts,
        json!({
            "history": {
                "receipts": receipts,
                "large_batch": history.large_batch,
                "checkpoints": history.checkpoints,
                "signers": history.signers,
                "archived_before_build": history.archived,
                "live_before_build": receipts - history.archived,
                "append_seconds": rounded(history.append_seconds),
                "append_rate_per_second": per_second(receipts, history.append_seconds),
                "rotate_seconds": rounded(history.rotate_seconds),
            },
            "config": {
                "step_rows": config.step_rows,
                "step_bytes": config.step_bytes,
                "insert_rows": config.insert_rows,
                "checkpoint_page": config.checkpoint_page,
                "walker_sql_steps": config.walker_sql_steps,
                "quota_bytes": config.quota_bytes,
            },
            "quiet_build": quiet,
            "contended_build": contended,
            "c17": {
                "quota_bytes": quota_bytes,
                "used_bytes_at_refusal": used_bytes,
                "entries_authenticated_at_refusal": reached.load(Ordering::SeqCst),
                "seconds": rounded(refusal_seconds),
                "refusal": "capacity",
            },
        }),
    );
}

fn wait_for(
    service: &ReceiptQuerySnapshots,
    what: &str,
    done: impl Fn(&ReceiptQuerySnapshotState) -> bool,
) -> ReceiptQuerySnapshotState {
    let deadline = Instant::now() + Duration::from_secs(1_800);
    loop {
        let state = service.status().state;
        if done(&state) {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {state:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Reads issued while the service accepts checkpoint `seq`, which became due
/// at `due`, and a rotation archives the checkpointed receipts below
/// `rotation_cutoff`.
fn settle(
    service: &ReceiptQuerySnapshots,
    fixture: &Fixture,
    seq: u64,
    due: Instant,
    rotation_cutoff: u64,
) -> Value {
    let rotation = {
        let store = Arc::clone(&fixture.store);
        let archive = fixture.archive.to_str().unwrap().to_owned();
        std::thread::spawn(move || {
            // The rotation archives nothing until the checkpoint is persisted.
            let deadline = Instant::now() + Duration::from_secs(600);
            let started = Instant::now();
            let mut attempts = 0;
            let mut refusals = Vec::new();
            loop {
                attempts += 1;
                match store.archive_receipts_before(rotation_cutoff, &archive) {
                    Ok(archived) if archived > 0 => {
                        return (
                            archived,
                            attempts,
                            refusals,
                            started.elapsed().as_secs_f64(),
                        )
                    }
                    Ok(_) => {}
                    Err(error) => refusals.push(error.to_string()),
                }
                assert!(
                    Instant::now() < deadline,
                    "rotation never archived: {refusals:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let deadline = Instant::now() + Duration::from_secs(1_800);
    let mut served = 0_u64;
    let mut refused: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut slowest = Duration::ZERO;
    let mut accepted = None;
    while accepted.is_none() || !rotation.is_finished() {
        let read = Instant::now();
        let outcome = service.query_receipts(&admin(5));
        slowest = slowest.max(read.elapsed());
        match outcome {
            Ok(page) => {
                served += 1;
                if accepted.is_none() && page.snapshot.unwrap().checkpoint_seq == Some(seq) {
                    accepted = Some(due.elapsed());
                }
            }
            Err(ReceiptStoreError::QuerySnapshot(error)) => {
                *refused.entry(error.wire_code().to_string()).or_default() += 1;
            }
            Err(error) => panic!("an untyped read outcome: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "checkpoint {seq} was not accepted"
        );
        // Reads arrive at a steady rate rather than back to back.
        std::thread::sleep(Duration::from_millis(2));
    }
    let (archived, attempts, refusals, rotation_seconds) = rotation.join().unwrap();
    assert!(
        !refused.contains_key("receipt_query_snapshot_invalid"),
        "a large checkpoint or rotation is never tamper: {refused:?}"
    );
    assert!(served > 0);
    json!({
        "checkpoint_seq": seq,
        "accepted_after_ms": accepted.map(|elapsed| rounded(elapsed.as_secs_f64() * 1_000.0)),
        "reads_served": served,
        "reads_refused": refused,
        "slowest_read_ms": rounded(slowest.as_secs_f64() * 1_000.0),
        "rotation": {
            "archived": archived,
            "attempts": attempts,
            "refusals": refusals.len(),
            "seconds": rounded(rotation_seconds),
        },
    })
}

#[derive(Default)]
struct HoldSteps {
    holds: u64,
    max: u64,
    total: u64,
}

impl HoldSteps {
    fn record(&mut self, steps: u64) {
        self.holds += 1;
        self.max = self.max.max(steps);
        self.total += steps;
    }

    fn json(&self) -> Value {
        json!({ "holds": self.holds, "max_vm_steps": self.max, "mean": self.total / self.holds.max(1) })
    }
}

/// VM steps of each walker hold kind for a large checkpoint over `entries`
/// uncheckpointed receipts, measured on the production backing.
fn hold_steps(entries: u64, config: &ReceiptQuerySnapshotConfig) -> Value {
    let mut db = SnapshotDb::open_private(config.quota_bytes).unwrap();
    let chunk = i64::try_from(config.insert_rows).unwrap();
    let last = i64::try_from(entries).unwrap();
    let signer = SIGNER.to_string();
    let mut insert = HoldSteps::default();
    let mut accept = HoldSteps::default();
    let mut read = HoldSteps::default();
    let mut delete = HoldSteps::default();
    // Extension inserts each tail row with its pending leaf.
    for start in (1..=last).step_by(config.insert_rows) {
        let end = (start + chunk - 1).min(last);
        let tools: Vec<_> = (start..=end)
            .map(|seq| projected(&attrs(seq, false)))
            .collect();
        let pending = tools
            .iter()
            .map(|row| PendingLeaf {
                entry_seq: row.entry_seq,
                kind: KIND_TOOL,
                leaf_hash: row.leaf_hash,
                signer: signer.clone(),
            })
            .collect();
        let counter = StepCounter::install(&db);
        db.commit(&SnapshotBatch {
            tools,
            pending,
            ..SnapshotBatch::default()
        })
        .unwrap();
        insert.record(counter.finish(&db));
    }
    // Streaming root verification reads the pending leaves chunk by chunk.
    for start in (1..=last).step_by(config.insert_rows) {
        let (leaves, steps) = db
            .count_steps_for_test(|db| {
                db.pending_leaves(start, (start + chunk - 1).min(last))
                    .unwrap()
            })
            .unwrap();
        read.record(steps);
        assert!(!leaves.is_empty());
    }
    let counter = StepCounter::install(&db);
    db.commit(&SnapshotBatch {
        checkpoints: vec![OwnedCheckpoint {
            seq: 1,
            batch_start: 1,
            batch_end: last,
            tree_size: last,
            merkle_root: [7; 32],
            kernel_key: signer,
            canonical_sha256: [0; 32],
        }],
        ..SnapshotBatch::default()
    })
    .unwrap();
    accept.record(counter.finish(&db));
    // Settled leaves are removed at most one chunk per hold.
    loop {
        let counter = StepCounter::install(&db);
        let removed = db.delete_pending_chunk(1, last, chunk).unwrap();
        delete.record(counter.finish(&db));
        if removed == 0 {
            break;
        }
    }
    let settled = db.max_settled_per_hold.get();
    assert!(settled <= u64::try_from(chunk).unwrap());
    for kind in [&insert, &accept, &read, &delete] {
        assert!(
            kind.max < config.hold_sql_steps,
            "a hold exceeded its budget"
        );
    }
    json!({
        "entries": entries,
        "insert_rows": config.insert_rows,
        "hold_sql_steps": config.hold_sql_steps,
        "max_settled_per_hold": settled,
        "insert_tail_rows": insert.json(),
        "settle_read": read.json(),
        "accept_checkpoint": accept.json(),
        "settle_delete": delete.json(),
    })
}

#[test]
#[ignore = "capacity evidence: large-checkpoint and rotation holds through the production service"]
fn linux_file_large_checkpoint_and_rotation_holds() {
    let tail = scaled(HOLD_TAIL);
    let rollover = (tail / 2).max(1);
    let config = ReceiptQuerySnapshotConfig {
        extension_tick: Duration::from_millis(20),
        invalid_retry_backoff: Duration::from_millis(20),
        ..ReceiptQuerySnapshotConfig::default()
    };
    let fixture = Fixture::new(0);
    let started = Instant::now();
    append_signed(&fixture, 0..tail, &keypair());
    let append_seconds = started.elapsed().as_secs_f64();

    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), config.clone()).unwrap();
    let started = Instant::now();
    wait_for(&service, "ready", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    let build_seconds = started.elapsed().as_secs_f64();
    let built_bytes = service.status().used_bytes;

    // One checkpoint covers the whole uncheckpointed history, and a rotation
    // archives it while the snapshot settles it.
    let due = Instant::now();
    set_signer(&fixture, keypair(), tail);
    let large = settle(&service, &fixture, 1, due, cutoff(tail));
    // A signer rollover, then a second large checkpoint and rotation.
    set_signer(&fixture, other_keypair(), rollover);
    append_signed(&fixture, tail..tail + rollover, &other_keypair());
    let rolled = settle(
        &service,
        &fixture,
        2,
        Instant::now(),
        cutoff(tail + rollover),
    );

    let settled = service.max_settled_per_hold_for_test();
    assert!(settled > 0);
    assert!(settled <= u64::try_from(config.insert_rows).unwrap());
    let page = service.query_receipts(&admin(5)).unwrap();
    assert_eq!(page.total_count, tail + rollover);
    let status = service.status();
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(status.tool_receipts, tail + rollover);
    service.shutdown();
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Stopped);

    // Through the service, when the history exceeds the smallest valid
    // quota, the build ends in the typed capacity outcome.
    let minimum = MIB;
    let capacity = if built_bytes > minimum {
        let small = ReceiptQuerySnapshots::start(
            fixture.store.clone(),
            ReceiptQuerySnapshotConfig {
                quota_bytes: minimum,
                ..config.clone()
            },
        )
        .unwrap();
        let state = wait_for(&small, "a resource outcome", |state| {
            !matches!(
                state,
                ReceiptQuerySnapshotState::WaitingForWriterSeed
                    | ReceiptQuerySnapshotState::Building { .. }
            )
        });
        let reason = match state {
            ReceiptQuerySnapshotState::Unavailable { reason } => reason,
            other => panic!("expected the capacity outcome, got {other:?}"),
        };
        assert!(reason.contains("quota"), "{reason}");
        let read = small.query_receipts(&admin(5)).unwrap_err();
        assert!(
            matches!(
                read,
                ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Unavailable(_))
            ),
            "{read}"
        );
        small.shutdown();
        json!({ "quota_bytes": minimum, "state": "unavailable", "reason": reason })
    } else {
        assert!(
            divisor() > 1,
            "the claimed history must exceed the minimum quota"
        );
        json!({ "skipped": "the development history fits the minimum quota" })
    };

    let holds = hold_steps(tail, &config);
    emit(
        "linux_file_large_checkpoint_and_rotation_holds",
        LINUX_FILE,
        tail + rollover,
        json!({
            "large_checkpoint_entries": tail,
            "rollover_checkpoint_entries": rollover,
            "append_seconds": rounded(append_seconds),
            "build_seconds": rounded(build_seconds),
            "built_used_bytes": built_bytes,
            "large_checkpoint": large,
            "rollover_checkpoint": rolled,
            "max_settled_per_hold": settled,
            "insert_rows": config.insert_rows,
            "service_c17": capacity,
            "hold_steps": holds,
        }),
    );
}

const COVERED_RANGE: u64 = 100_000;
const CANCEL_RANGE: u64 = 10_000;

/// Wait until the store's observation covers `head` entries with checkpoint
/// `seq` persisted.
fn await_checkpoint(fixture: &Fixture, limits: WalkLimits, seq: i64, head: u64) {
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits);
    let head = i64::try_from(head).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1_800);
    loop {
        let observation = observe(&ctx).unwrap();
        if observation.checkpoint >= seq && observation.head >= head {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "checkpoint {seq} over {head} entries was never persisted"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The admin total the snapshot serves, or `None` for a typed refusal such as
/// staleness. An integrity refusal fails the run.
fn served_total(service: &ReceiptQuerySnapshots) -> Option<u64> {
    match service.query_receipts(&admin(5)) {
        Ok(page) => Some(page.total_count),
        Err(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(reason))) => {
            panic!("a covered range was refused as tamper: {reason}")
        }
        Err(ReceiptStoreError::QuerySnapshot(_)) => None,
        Err(error) => panic!("an untyped read outcome: {error}"),
    }
}

/// Whether a positive point read returns `Spec::varied(index)`.
fn served(service: &ReceiptQuerySnapshots, index: u64) -> bool {
    let id = Spec::varied(index).sign(&keypair()).id;
    matches!(
        service.load_receipt(
            &id,
            &chio_kernel::receipt_query::ReceiptReadContext::admin_service()
        ),
        Ok((Some(_), _))
    )
}

/// Snapshot answers against the authenticated per-call path for an admin and
/// a tenant page: page seqs, total and cursor.
fn per_call_parity(service: &ReceiptQuerySnapshots, fixture: &Fixture) -> Value {
    let queries = [
        ("admin", admin(200)),
        (
            "tenant_a",
            ReceiptQuery {
                limit: 200,
                ..ReceiptQuery::default().authenticated_tenant("tenant-a")
            },
        ),
    ];
    let mut checked = serde_json::Map::new();
    for (name, query) in queries {
        let expected = super::super::support::per_call(&fixture.store, &query);
        let page = service.query_receipts(&query).unwrap();
        let seqs: Vec<u64> = page.receipts.iter().map(|row| row.seq).collect();
        assert_eq!(
            (seqs, page.total_count, page.next_cursor),
            expected,
            "{name} page differs from the authenticated per-call path"
        );
        checked.insert(name.to_string(), json!({ "total_count": expected.1 }));
    }
    Value::Object(checked)
}

/// A large checkpoint-covered range appended behind a paused extension is
/// staged as pending leaves without publishing a row, verified against its
/// signed root, then re-read and published, while reads continue and a
/// rotation archives it. A second covered range is cancelled midway
/// through publication.
#[test]
#[ignore = "capacity evidence: a large unpublished checkpoint-covered range staged, verified and published through the production service"]
fn linux_file_large_covered_range_staging() {
    let covered = scaled(COVERED_RANGE);
    let prefix = scaled(SMALL_BATCH);
    let config = ReceiptQuerySnapshotConfig {
        extension_tick: Duration::from_millis(20),
        invalid_retry_backoff: Duration::from_millis(20),
        ..ReceiptQuerySnapshotConfig::default()
    };
    let insert_rows = u64::try_from(config.insert_rows).unwrap();
    let limits = production_limits(&config);

    // A published, checkpointed prefix.
    let fixture = Fixture::new(prefix);
    append_signed(&fixture, 0..prefix, &keypair());
    await_checkpoint(&fixture, limits, 1, prefix);
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), config.clone()).unwrap();
    wait_for(&service, "ready", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    let published = service.query_receipts(&admin(5)).unwrap();
    assert_eq!(published.total_count, prefix);

    // The covered range: signed and checkpointed while extension is paused,
    // so none of it has been published.
    service.pause_extension_for_test(true);
    set_signer(&fixture, keypair(), covered);
    let started = Instant::now();
    append_signed(&fixture, prefix..prefix + covered, &keypair());
    await_checkpoint(&fixture, limits, 2, prefix + covered);
    let append_seconds = started.elapsed().as_secs_f64();
    let used_before = service.status().used_bytes;

    // Resume and stop at the root check: the whole range is staged.
    let peak_reset = reset_peak_rss();
    let memory_before = ProcMemory::read();
    let sampler = PeakSampler::start();
    let resumed = Instant::now();
    service.arm_gate_for_test(GatePoint::Settlement, GateAction::Hold, 0);
    service.pause_extension_for_test(false);
    assert!(
        service.await_gate_for_test(Duration::from_secs(1_800)),
        "extension never staged the covered range"
    );
    let staged_seconds = resumed.elapsed().as_secs_f64();
    let staged_per_hold = service.max_staged_per_hold_for_test();
    assert!(staged_per_hold > 0 && staged_per_hold <= insert_rows);
    let used_staged = service.status().used_bytes;
    // While the range is staged, readers see the previous version or a
    // typed stale refusal, never a covered row.
    let during = served_total(&service);
    assert!(during.is_none_or(|total| total == prefix), "{during:?}");
    assert!(!served(&service, prefix));
    assert!(!served(&service, prefix + covered - 1));

    // Verify the root, then re-read and publish the range while reads run
    // and a rotation archives the prefix and the whole covered range.
    let released = Instant::now();
    service.release_gate_for_test();
    let publication = settle(&service, &fixture, 2, released, cutoff(prefix + covered));
    let publish_seconds = released.elapsed().as_secs_f64();
    let memory_peak = sampler.finish();
    let memory_after = ProcMemory::read();
    let used_after = service.status().used_bytes;
    let settled_per_hold = service.max_settled_per_hold_for_test();
    assert!(settled_per_hold > 0 && settled_per_hold <= insert_rows);
    let page = service.query_receipts(&admin(5)).unwrap();
    assert_eq!(page.total_count, prefix + covered);
    let parity = per_call_parity(&service, &fixture);
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Ready);

    // A second covered range, cancelled after part of it is published.
    let cancel_range = scaled(CANCEL_RANGE);
    service.pause_extension_for_test(true);
    set_signer(&fixture, keypair(), cancel_range);
    let start = prefix + covered;
    append_signed(&fixture, start..start + cancel_range, &keypair());
    await_checkpoint(&fixture, limits, 3, start + cancel_range);
    // Stop midway through publication when the range spans several
    // publication steps; a development-sized range is cancelled while staged.
    let step_rows = config.step_rows;
    let (gate, skip) = if cancel_range > step_rows {
        (
            GatePoint::Publication,
            u32::try_from((cancel_range / 2) / step_rows)
                .unwrap()
                .max(1),
        )
    } else {
        (GatePoint::Settlement, 0)
    };
    service.arm_gate_for_test(gate, GateAction::Hold, skip);
    service.pause_extension_for_test(false);
    assert!(
        service.await_gate_for_test(Duration::from_secs(1_800)),
        "extension never reached {gate:?} for the second range"
    );
    // Verified steps before the gate are published; the rest are not.
    if gate == GatePoint::Publication {
        assert!(served(&service, start));
    }
    assert!(!served(&service, start + cancel_range - 1));
    let cancelled = Instant::now();
    service.shutdown();
    let shutdown_ms = cancelled.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(service.status().state, ReceiptQuerySnapshotState::Stopped);

    emit(
        "linux_file_large_covered_range_staging",
        LINUX_FILE,
        prefix + covered + cancel_range,
        json!({
            "prefix_entries": prefix,
            "covered_entries": covered,
            "append_seconds": rounded(append_seconds),
            "config": {
                "step_rows": config.step_rows,
                "step_bytes": config.step_bytes,
                "insert_rows": config.insert_rows,
                "hold_sql_steps": config.hold_sql_steps,
                "quota_bytes": config.quota_bytes,
            },
            "staging": {
                "seconds": rounded(staged_seconds),
                "max_leaves_per_hold": staged_per_hold,
                "served_total_while_staged": during,
                "used_bytes_before": used_before,
                "used_bytes_staged": used_staged,
            },
            "publication": {
                "seconds_after_release": rounded(publish_seconds),
                "settle": publication,
                "max_settled_per_hold": settled_per_hold,
                "used_bytes_after": used_after,
                "served_total": page.total_count,
                "per_call_parity": parity,
            },
            "memory": {
                "peak_reset": peak_reset,
                "before": memory_before.json(),
                "peak": memory_peak.json(),
                "after": memory_after.json(),
            },
            "cancellation": {
                "range_entries": cancel_range,
                "gate": format!("{gate:?}"),
                "gate_skipped_publication_steps": skip,
                "shutdown_ms": rounded(shutdown_ms),
                "state": "stopped",
            },
        }),
    );
}
