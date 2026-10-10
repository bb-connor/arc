//! Owned snapshot storage, fixed query plans, work budgets and quotas.
use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQuerySnapshotError};
use chio_kernel::ReceiptStoreError;

use super::super::db::{ProjectedToolRow, SnapshotBatch, SnapshotDb, SnapshotDbError};
use super::super::pass::build_snapshot;
use super::super::query::select;
use super::support::{context, limits, per_call, target, Fixture, Spec};

const STEPS: u64 = 10_000_000;

fn built_fixture() -> (Fixture, SnapshotDb) {
    let fixture = Fixture::new(4);
    fixture.append_varied(0..40);
    fixture.append_child("child-1", 1_700_000_100);
    // Archive the checkpointed prefix older than receipt 20.
    assert!(fixture.rotate(1_700_000_000 + 20 * 600) > 0);
    fixture.append_varied(40..46);
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let (db, _) = build_snapshot(&ctx, target(&ctx), 64 * 1024 * 1024, &mut |_, _| {}).unwrap();
    (fixture, db)
}

type Filter = Box<dyn Fn(&mut ReceiptQuery)>;

fn queries() -> Vec<ReceiptQuery> {
    let scopes = [
        ReceiptQuery::default().local_operator_admin(),
        ReceiptQuery::default().authenticated_tenant("tenant-a"),
        ReceiptQuery::default().authenticated_tenant("tenant-b"),
        ReceiptQuery::default().authenticated_tenant("tenant-z"),
        ReceiptQuery {
            tenant_filter: Some("tenant-a".into()),
            ..ReceiptQuery::default().local_operator_admin()
        },
    ];
    let mut filters: Vec<Filter> = vec![
        Box::new(|_| {}),
        Box::new(|q| q.capability_id = Some("cap-1".into())),
        Box::new(|q| q.capability_id = Some("cap-unknown".into())),
        Box::new(|q| q.tool_server = Some("web".into())),
        Box::new(|q| q.tool_name = Some("bash".into())),
        Box::new(|q| {
            q.tool_server = Some("shell".into());
            q.tool_name = Some("fetch".into());
        }),
        Box::new(|q| q.outcome = Some("deny".into())),
        Box::new(|q| {
            q.outcome = Some("allow".into());
            q.tool_server = Some("shell".into());
        }),
        Box::new(|q| q.since = Some(1_700_000_000 + 10 * 600)),
        Box::new(|q| q.until = Some(1_700_000_000 + 30 * 600 + 59)),
        Box::new(|q| {
            q.since = Some(1_700_000_000 + 5 * 600 + 1);
            q.until = Some(1_700_000_000 + 41 * 600);
        }),
        Box::new(|q| {
            q.since = Some(1_700_000_000 + 30 * 600);
            q.until = Some(1_700_000_000 + 10 * 600);
        }),
        Box::new(|q| q.cost_currency = Some("USD".into())),
        Box::new(|q| {
            q.cost_currency = Some("USD".into());
            q.min_cost = Some(100);
            q.max_cost = Some(300);
        }),
        Box::new(|q| q.agent_subject = Some("subject-0".into())),
        Box::new(|q| {
            q.agent_subject = Some("subject-1".into());
            q.since = Some(1_700_000_000);
        }),
    ];
    filters.push(Box::new(|q| q.cursor = Some(u64::MAX)));
    let mut queries = Vec::new();
    for scope in &scopes {
        for filter in &filters {
            for (limit, cursor) in [(200, None), (3, None), (3, Some(9)), (1, Some(30))] {
                let mut query = scope.clone();
                query.limit = limit;
                query.cursor = cursor;
                filter(&mut query);
                queries.push(query);
            }
        }
    }
    queries
}

#[test]
fn snapshot_selection_matches_the_per_call_path() {
    let (fixture, db) = built_fixture();
    for query in queries() {
        let expected = per_call(&fixture.store, &query);
        let selection = select(&db, &query, STEPS).unwrap();
        let seqs: Vec<u64> = selection.rows.iter().map(|row| row.seq).collect();
        let next = (seqs.len() == selection.limit)
            .then(|| seqs.last().copied())
            .flatten();
        assert_eq!(
            (seqs, selection.total_count, next),
            expected,
            "query {query:?}"
        );
    }
}

#[test]
fn time_bounds_at_the_top_of_the_timestamp_range_match_the_per_call_path() {
    let max = u64::try_from(i64::MAX).unwrap();
    let final_hour = max - max % 3_600;
    let edges = [final_hour - 1, final_hour, max - 1, max];
    let fixture = Fixture::new(4);
    fixture.append_varied(0..4);
    for (index, timestamp) in edges.into_iter().enumerate() {
        for tenant in ["tenant-a", "tenant-b"] {
            let mut spec = Spec::new(format!("rcpt-edge-{index}-{tenant}"), timestamp);
            spec.tenant = Some(tenant.into());
            fixture.append(&spec);
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, limits());
    let (db, _) = build_snapshot(&ctx, target(&ctx), 64 * 1024 * 1024, &mut |_, _| {}).unwrap();

    let bounds = [
        None,
        Some(final_hour - 1),
        Some(final_hour),
        Some(max - 1),
        Some(max),
    ];
    let scopes = [
        ReceiptQuery::default().local_operator_admin(),
        ReceiptQuery::default().authenticated_tenant("tenant-a"),
    ];
    for scope in &scopes {
        for since in bounds {
            for until in bounds {
                let query = ReceiptQuery {
                    limit: 200,
                    since,
                    until,
                    ..scope.clone()
                };
                let expected = per_call(&fixture.store, &query);
                let selection = select(&db, &query, STEPS).unwrap();
                let seqs: Vec<u64> = selection.rows.iter().map(|row| row.seq).collect();
                let next = (seqs.len() == selection.limit)
                    .then(|| seqs.last().copied())
                    .flatten();
                assert_eq!(
                    (seqs, selection.total_count, next),
                    expected,
                    "since {since:?} until {until:?} as {:?}",
                    scope.read_context
                );
            }
        }
    }
    // A receipt stamped at the last representable second is selected and
    // counted from that second on, for the admin and for its tenant.
    for (scope, expected) in scopes.iter().zip([2, 1]) {
        let query = ReceiptQuery {
            limit: 200,
            since: Some(max),
            ..scope.clone()
        };
        let selection = select(&db, &query, STEPS).unwrap();
        assert_eq!(
            (selection.rows.len(), selection.total_count),
            (expected, u64::try_from(expected).unwrap()),
            "since the last second as {:?}",
            scope.read_context
        );
    }
}

#[test]
fn invalid_queries_fail_exactly_as_on_the_per_call_path() {
    let (fixture, db) = built_fixture();
    let cases = [
        ReceiptQuery {
            outcome: Some("maybe".into()),
            ..ReceiptQuery::default().local_operator_admin()
        },
        ReceiptQuery {
            min_cost: Some(1),
            ..ReceiptQuery::default().local_operator_admin()
        },
        ReceiptQuery {
            cost_currency: Some("usd".into()),
            ..ReceiptQuery::default().local_operator_admin()
        },
        ReceiptQuery::default(),
    ];
    for query in cases {
        let expected = fixture
            .store
            .query_receipts(&query)
            .unwrap_err()
            .to_string();
        let actual = select(&db, &query, STEPS).unwrap_err().to_string();
        assert_eq!(actual, expected, "query {query:?}");
    }
}

fn synthetic(seq: i64, long: usize) -> ProjectedToolRow {
    ProjectedToolRow {
        seq,
        entry_seq: seq,
        leaf_hash: [u8::try_from(seq % 251).unwrap(); 32],
        signer: "signer-a".into(),
        receipt_id: format!("rcpt-{seq}-{}", "x".repeat(long)),
        ts: 1_700_000_000 + seq * 97,
        tenant: (seq % 3 != 0).then(|| format!("tenant-{}", seq % 4)),
        capability: format!("cap-{}", seq % 11),
        tool_server: format!("server-{}", seq % 3),
        tool_name: format!("tool-{}-{}", seq % 5, "y".repeat(long)),
        decision: if seq % 4 == 0 { "deny" } else { "allow" }.into(),
        subject: (seq % 2 == 0).then(|| format!("subject-{}", seq % 7)),
        subject_signed: seq % 2 == 0,
        cost_currency: (seq % 5 == 0).then(|| "USD".to_string()),
        cost_charged: (seq % 5 == 0).then(|| u64::try_from(seq).unwrap().to_be_bytes().to_vec()),
    }
}

#[test]
fn over_budget_selection_withholds_rows_and_count() {
    let mut db = SnapshotDb::open_memory(64 * 1024 * 1024).unwrap();
    db.commit(&SnapshotBatch {
        tools: (1..=3_000).map(|seq| synthetic(seq, 0)).collect(),
        ..SnapshotBatch::default()
    })
    .unwrap();
    // Two unselective equality filters force an indexed scan with per-row checks.
    let query = ReceiptQuery {
        outcome: Some("allow".into()),
        tool_server: Some("server-1".into()),
        ..ReceiptQuery::default().local_operator_admin()
    };
    let within = select(&db, &query, STEPS).unwrap();
    assert!(within.total_count > 0);
    let error = select(&db, &query, 1_000).unwrap_err();
    assert!(
        matches!(
            error,
            ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::WorkBudgetExhausted(ref surface))
                if surface == "receipt query"
        ),
        "{error}"
    );
}

#[test]
fn quota_exhaustion_is_typed_and_leaves_the_snapshot_unchanged() {
    let mut db = SnapshotDb::open_memory(512 * 1024).unwrap();
    let mut committed = 0_u64;
    let mut seq = 1_i64;
    let error = loop {
        // Long values are stored verbatim and count against the quota.
        let rows: Vec<_> = (seq..seq + 8).map(|seq| synthetic(seq, 2_000)).collect();
        let batch = SnapshotBatch {
            tools: rows,
            ..SnapshotBatch::default()
        };
        match db.commit(&batch) {
            Ok(()) => {
                committed += 8;
                seq += 8;
            }
            Err(error) => break error,
        }
        assert!(seq < 100_000, "quota never reached");
    };
    match error {
        SnapshotDbError::Capacity {
            quota_bytes,
            used_bytes,
        } => {
            assert_eq!(quota_bytes, db.quota_bytes());
            assert!(used_bytes <= quota_bytes);
        }
        other => panic!("expected a capacity outcome, got {other}"),
    }
    assert_eq!(db.tool_row_count().unwrap(), committed);
    let stored: String = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT receipt_id FROM snapshot_tool_receipt WHERE seq = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.len(), synthetic(1, 2_000).receipt_id.len());
}

thread_local! {
    static TRACED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn trace(event: rusqlite::trace::TraceEvent<'_>) {
    if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event {
        TRACED.with(|traced| traced.borrow_mut().push(sql.to_string()));
    }
}

#[test]
fn fixed_plans_never_use_a_temporary_btree() {
    let (_fixture, mut db) = built_fixture();
    db.trace_for_test(Some(trace)).unwrap();
    for query in queries() {
        let _ = select(&db, &query, STEPS);
    }
    db.trace_for_test(None).unwrap();
    let traced = TRACED.with(|traced| traced.take());
    let mut explained = 0;
    for sql in traced
        .iter()
        .filter(|sql| sql.contains("FROM snapshot_tool_receipt"))
    {
        let mut statement = db
            .connection()
            .unwrap()
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let unbound = vec![rusqlite::types::Value::Null; statement.parameter_count()];
        let details: Vec<String> = statement
            .query_map(rusqlite::params_from_iter(unbound), |row| row.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            details.iter().all(|detail| !detail.contains("TEMP B-TREE")),
            "{sql}: {details:?}"
        );
        explained += 1;
    }
    assert!(explained > 50, "only {explained} plans were traced");
}

/// Every maintained count row, in key order.
pub(super) const MAINTAINED_COUNTS_SQL: &str =
    "SELECT scope, dim, value, n, min_seq, max_seq FROM snapshot_count ORDER BY 1, 2, 3";

pub(super) fn count_rows(db: &SnapshotDb) -> Vec<(i64, i64, i64, i64, i64, i64)> {
    let mut statement = db
        .connection()
        .unwrap()
        .prepare(MAINTAINED_COUNTS_SQL)
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The rows of [`MAINTAINED_COUNTS_SQL`] recomputed with `GROUP BY` over the
/// owned receipts, in the same key order.
pub(super) fn grouped_counts_sql() -> String {
    let mut parts = vec![
        "SELECT -1, 0, 0, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt HAVING COUNT(*) > 0".to_string(),
        "SELECT tenant, 0, 0, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt WHERE tenant != 0 GROUP BY tenant".to_string(),
        "SELECT -1, 100, ts / 3600, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt GROUP BY ts / 3600".to_string(),
        "SELECT tenant, 100, ts / 3600, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt WHERE tenant != 0 GROUP BY tenant, ts / 3600".to_string(),
    ];
    for (dim, column, skip_absent) in [
        (2, "capability", false),
        (3, "tool_server", false),
        (4, "tool_name", false),
        (5, "tool", false),
        (6, "decision", false),
        (7, "subject", true),
        (8, "cost_currency", true),
    ] {
        let absent = if skip_absent {
            format!("AND {column} != 0")
        } else {
            String::new()
        };
        parts.push(format!(
            "SELECT -1, {dim}, {column}, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt WHERE 1 {absent} GROUP BY {column}"
        ));
        parts.push(format!(
            "SELECT tenant, {dim}, {column}, COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt WHERE tenant != 0 {absent} GROUP BY tenant, {column}"
        ));
    }
    format!("{} ORDER BY 1, 2, 3", parts.join(" UNION ALL "))
}

pub(super) fn grouped_rows(db: &SnapshotDb) -> Vec<(i64, i64, i64, i64, i64, i64)> {
    let mut statement = db
        .connection()
        .unwrap()
        .prepare(&grouped_counts_sql())
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn maintained_counts_equal_group_by_after_every_generation() {
    let mut db = SnapshotDb::open_memory(64 * 1024 * 1024).unwrap();
    let mut seq = 1_i64;
    for generation in 0..12 {
        let size = 1 + (generation * 7) % 13;
        let rows: Vec<_> = (seq..seq + size).map(|seq| synthetic(seq, 0)).collect();
        seq += size;
        db.commit(&SnapshotBatch {
            tools: rows,
            ..SnapshotBatch::default()
        })
        .unwrap();
        if generation % 3 == 2 {
            // A lineage refresh fills absent unsigned subjects of one capability.
            let capability = format!("cap-{}", generation % 11);
            db.refresh_subject(&capability, "lineage-subject", 0, 1_000)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            count_rows(&db),
            grouped_rows(&db),
            "generation {generation}"
        );
    }
}

#[test]
fn a_changed_unsigned_subject_is_reported_as_drift() {
    let mut db = SnapshotDb::open_memory(64 * 1024 * 1024).unwrap();
    db.commit(&SnapshotBatch {
        tools: (1..=4).map(|seq| synthetic(seq, 0)).collect(),
        ..SnapshotBatch::default()
    })
    .unwrap();
    let first = db.refresh_subject("cap-1", "lineage-a", 0, 100).unwrap();
    assert_eq!(first, Ok(vec![1]));
    let before = count_rows(&db);
    let second = db.refresh_subject("cap-1", "lineage-b", 0, 100).unwrap();
    assert_eq!(second, Err(1));
    assert_eq!(count_rows(&db), before);
}

#[test]
fn hold_status_metrics_are_constant_work_for_high_cardinality_dimensions() {
    let mut db = SnapshotDb::open_memory(512 * 1024 * 1024).unwrap();
    for chunk in 0..10_i64 {
        let rows: Vec<_> = (chunk * 2_000 + 1..=(chunk + 1) * 2_000)
            .map(|seq| {
                let mut row = synthetic(seq, 0);
                // Every receipt carries its own capability and tool.
                row.capability = format!("cap-unique-{seq}");
                row.tool_name = format!("tool-unique-{seq}");
                row
            })
            .collect();
        db.commit(&SnapshotBatch {
            tools: rows,
            ..SnapshotBatch::default()
        })
        .unwrap();
    }
    let (stats, steps) = db
        .count_steps_for_test(|db| db.dim_stats().unwrap())
        .unwrap();
    assert!(steps < 100, "status metrics spent {steps} VM steps");
    let (count, bytes): (i64, i64) = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*), SUM(length(CAST(value AS BLOB))) FROM snapshot_dim",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        stats,
        (u64::try_from(count).unwrap(), u64::try_from(bytes).unwrap())
    );
}

#[test]
fn a_typed_unavailable_store_error_is_never_an_integrity_outcome() {
    use super::super::walk::WalkError;
    let classify_store_error = |error| WalkError::from(SnapshotDbError::Store(error));
    let unavailable = ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Unavailable(
        "snapshot storage is unavailable".into(),
    ));
    let outcome = classify_store_error(unavailable);
    assert!(
        !matches!(outcome, WalkError::Integrity(_)),
        "a typed unavailable outcome became {outcome:?}"
    );
    assert!(outcome
        .to_string()
        .contains("snapshot storage is unavailable"));
    let invalid = ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(
        "custody mismatch".into(),
    ));
    assert!(matches!(
        classify_store_error(invalid),
        WalkError::Integrity(_)
    ));
}

#[test]
fn a_snapshot_storage_io_error_on_a_read_refuses_as_unavailable() {
    use super::super::query::snapshot_error;
    let io = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_READ),
        Some("disk I/O error".into()),
    );
    let outcome = snapshot_error(SnapshotDbError::Sqlite(io));
    assert!(
        matches!(
            &outcome,
            ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Unavailable(_))
        ),
        "a read storage I/O error surfaced as {outcome:?}"
    );
    let custody = snapshot_error(SnapshotDbError::Store(
        ReceiptQuerySnapshotError::Invalid("custody mismatch".into()).into(),
    ));
    assert!(matches!(
        custody,
        ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(_))
    ));
}

fn sqlite_failure(code: std::os::raw::c_int) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
}

#[test]
fn nested_sqlite_resource_failures_are_unavailable_and_other_classes_keep_theirs() {
    use super::super::query::snapshot_error;
    use super::super::walk::WalkError;
    let walker = |error| WalkError::from(SnapshotDbError::Store(error));
    for code in [
        rusqlite::ffi::SQLITE_IOERR_READ,
        rusqlite::ffi::SQLITE_CANTOPEN,
        rusqlite::ffi::SQLITE_NOMEM,
        rusqlite::ffi::SQLITE_READONLY,
        rusqlite::ffi::SQLITE_PERM,
    ] {
        let outcome = walker(ReceiptStoreError::Sqlite(sqlite_failure(code)));
        assert!(
            matches!(outcome, WalkError::Unavailable(_)),
            "nested SQLite code {code} in the walker became {outcome:?}"
        );
        let read = snapshot_error(SnapshotDbError::Store(ReceiptStoreError::Sqlite(
            sqlite_failure(code),
        )));
        assert!(
            matches!(
                read,
                ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Unavailable(_))
            ),
            "nested SQLite code {code} on a read became {read:?}"
        );
    }
    assert!(matches!(
        walker(ReceiptQuerySnapshotError::ExportRefused("legacy lineage".into()).into()),
        WalkError::Unavailable(reason) if reason == "legacy lineage"
    ));
    // Interruption, contention, work budgets and integrity keep their class.
    assert!(matches!(
        walker(ReceiptStoreError::Sqlite(sqlite_failure(
            rusqlite::ffi::SQLITE_INTERRUPT
        ))),
        WalkError::Busy(_)
    ));
    assert!(matches!(
        walker(ReceiptStoreError::Sqlite(sqlite_failure(
            rusqlite::ffi::SQLITE_BUSY
        ))),
        WalkError::Busy(_)
    ));
    assert!(matches!(
        walker(ReceiptQuerySnapshotError::WorkBudgetExhausted("walker".into()).into()),
        WalkError::WalkerBudget
    ));
    assert!(matches!(
        walker(ReceiptStoreError::Sqlite(sqlite_failure(
            rusqlite::ffi::SQLITE_CORRUPT
        ))),
        WalkError::Integrity(_)
    ));
    assert!(matches!(
        snapshot_error(SnapshotDbError::Store(ReceiptStoreError::Sqlite(
            sqlite_failure(rusqlite::ffi::SQLITE_INTERRUPT)
        ))),
        ReceiptStoreError::Sqlite(_)
    ));
    // Ordinary capacity is a capacity outcome, never an integrity one.
    assert!(matches!(
        WalkError::from(SnapshotDbError::Capacity {
            quota_bytes: 1,
            used_bytes: 1
        }),
        WalkError::Capacity { .. }
    ));
}
