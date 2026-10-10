//! Bounds on the work of one capability lineage refresh.
//!
//! A lineage row newer than the published snapshot makes the extension refresh
//! that capability's receipts in chunks of `REFRESH_CHUNK` unsigned rows, one
//! budgeted walker hold each. A hold must not depend on how many signed
//! receipts the capability has.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_kernel::receipt_query::ReceiptQuery;
use rusqlite::params;

use super::super::db::{ProjectedToolRow, SnapshotBatch, SnapshotDb};
use super::super::service::ReceiptQuerySnapshotConfig;
use super::service::{config, ready};
use super::support::{keypair, Fixture, Spec};

const HOT: &str = "cap-hot";
/// `extend.rs` `REFRESH_CHUNK`.
const REFRESH_CHUNK: i64 = 256;

fn row(seq: i64, signed: bool) -> ProjectedToolRow {
    ProjectedToolRow {
        seq,
        entry_seq: seq,
        leaf_hash: [7; 32],
        signer: "signer-a".into(),
        receipt_id: format!("rcpt-{seq}"),
        ts: 1_700_000_000 + seq,
        tenant: Some("tenant-a".into()),
        capability: HOT.into(),
        tool_server: "shell".into(),
        tool_name: "bash".into(),
        decision: "allow".into(),
        subject: signed.then(|| "signed-subject".to_string()),
        subject_signed: signed,
        cost_currency: None,
        cost_charged: None,
    }
}

/// A snapshot holding runs of `(signed, count)` receipts of `HOT`, in order.
fn hot_db(runs: &[(bool, i64)]) -> SnapshotDb {
    let mut db = SnapshotDb::open_memory(1024 * 1024 * 1024).unwrap();
    let mut seq = 1;
    for &(signed, count) in runs {
        let end = seq + count;
        while seq < end {
            let stop = (seq + 5_000).min(end);
            db.commit(&SnapshotBatch {
                tools: (seq..stop).map(|seq| row(seq, signed)).collect(),
                ..SnapshotBatch::default()
            })
            .unwrap();
            seq = stop;
        }
    }
    db
}

/// Exact SQLite VM steps of mutating work on the snapshot connection.
fn counted<T>(db: &mut SnapshotDb, work: impl FnOnce(&mut SnapshotDb) -> T) -> (T, u64) {
    let steps = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&steps);
    db.connection()
        .unwrap()
        .progress_handler(
            1,
            Some(move || {
                counter.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
    let value = work(db);
    db.connection()
        .unwrap()
        .progress_handler(0, None::<fn() -> bool>)
        .unwrap();
    (value, steps.load(Ordering::Relaxed))
}

/// The VM steps of every walker hold `refresh_capability` runs for one
/// lineage row of `HOT`, mirroring its loop exactly.
fn refresh_holds(db: &mut SnapshotDb, subject: &str) -> Vec<u64> {
    let mut after = 0_i64;
    let mut holds = Vec::new();
    loop {
        let (outcome, steps) = counted(db, |db| {
            db.refresh_subject(HOT, subject, after, REFRESH_CHUNK)
                .unwrap()
        });
        holds.push(steps);
        let rows = outcome.unwrap();
        match rows.last() {
            Some(last) if i64::try_from(rows.len()).unwrap() >= REFRESH_CHUNK => after = *last,
            _ => return holds,
        }
    }
}

fn lineage_of(snapshot_id: &str) -> String {
    snapshot_id.split(':').next().unwrap().to_string()
}

/// Insert a legacy lineage row for `HOT`, as `lineage.rs` does; the
/// canonical reader accepts it.
fn insert_legacy_lineage(fixture: &Fixture, subject: &str) {
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth, provenance, signed_capability_json)
             VALUES (?1, ?2, 'issuer-1', 1700000000, 4000000000, '[]', 0, 'legacy_projection', NULL)",
            params![HOT, subject],
        )
        .unwrap();
}

struct Outcome {
    before: String,
    after: String,
    integrity_waits: Vec<Duration>,
}

/// `signed` signed receipts of `HOT` then one unsigned one; publish; append a
/// lineage row for `HOT`; return the snapshot lineage before the row and the
/// lineage that first serves the unsigned receipt under the lineage subject.
fn apply_lineage(signed: u64, hold_sql_steps: u64) -> Outcome {
    let fixture = Fixture::new(0);
    for index in 0..signed {
        let mut spec = Spec::new(format!("hot-signed-{index:06}"), 1_700_000_000 + index);
        spec.capability = HOT.into();
        spec.subject = Some("signed-subject".into());
        fixture.append(&spec);
    }
    let mut unsigned = Spec::new("hot-unsigned", 1_700_000_000 + signed);
    unsigned.capability = HOT.into();
    fixture.append(&unsigned);
    fixture.flush();
    // Receipt ids derive from signed content, so take the stored id.
    let unsigned_id = unsigned.sign(&keypair()).id;
    let service = ready(
        &fixture,
        ReceiptQuerySnapshotConfig {
            step_rows: 512,
            hold_sql_steps,
            ..config()
        },
    );
    let before = lineage_of(&service.status().watermark.unwrap().snapshot_id);
    insert_legacy_lineage(&fixture, "lineage-subject");
    let query = ReceiptQuery {
        limit: 10,
        agent_subject: Some("lineage-subject".into()),
        ..ReceiptQuery::default().local_operator_admin()
    };
    // Wait for the effect only; the verdict is the lineage identity, not time.
    let deadline = Instant::now() + Duration::from_secs(300);
    let after = loop {
        if let Ok(page) = service.query_receipts(&query) {
            if page
                .receipts
                .iter()
                .any(|row| row.receipt.id == unsigned_id)
            {
                break lineage_of(&page.snapshot.unwrap().snapshot_id);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the lineage row was never applied"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let integrity_waits = service.integrity_waits_for_test();
    service.shutdown();
    Outcome {
        before,
        after,
        integrity_waits,
    }
}

#[test]
fn refresh_hold_steps_do_not_grow_with_capability_size() {
    let mut steps = Vec::new();
    for size in [2_000_i64, 50_000] {
        let mut db = hot_db(&[(true, size), (false, 1)]);
        let holds = refresh_holds(&mut db, "lineage-subject");
        assert_eq!(holds.len(), 1, "size {size}: {holds:?}");
        steps.push(holds[0]);
    }
    assert!(
        steps[0].abs_diff(steps[1]) <= 100,
        "refresh hold steps grew with signed receipts: {steps:?}"
    );
}

#[test]
fn lineage_row_over_large_signed_capability_refreshes_in_place() {
    const LARGE: u64 = 4_000;
    const HOLD_SQL_STEPS: u64 = 5_000;
    let outcome = apply_lineage(LARGE, HOLD_SQL_STEPS);
    assert_eq!(
        outcome.before, outcome.after,
        "the snapshot was rebuilt instead of refreshed in place"
    );
    assert!(outcome.integrity_waits.is_empty());
}
