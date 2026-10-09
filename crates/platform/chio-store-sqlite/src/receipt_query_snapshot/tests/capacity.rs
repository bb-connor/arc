//! Capacity evidence. Every test is ignored by default, asserts its
//! invariants, and prints one `CAPACITY {json}` line.
//!
//! Labels: `memory` values come from the private in-memory backend filled
//! through the bulk commit path; `linux-file` values come from the production
//! constructor, which on Linux binds each snapshot to a private file.
//!
//! `vm_steps` is the exact SQLite VM step count of the work, as
//! `count_steps_for_test` counts it. A selection installs its own work budget,
//! which replaces any counting handler, so selections report
//! `vm_steps_budget`: the smallest production budget that completes them,
//! found by bisection at the budget's 1,000-step granularity.
//! `CHIO_CAPACITY_DIVISOR` divides every size for development runs; each line
//! reports it, and only divisor 1 is a claimed measurement.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQuerySnapshotError, MAX_QUERY_LIMIT};
use chio_kernel::ReceiptStoreError;
use serde_json::{json, Value};

use crate::receipt_query_snapshot::db::{
    ProjectedToolRow, SnapshotBatch, SnapshotDb, SnapshotDbError, ABSENT, COUNT_HOUR, COUNT_TOTAL,
    DIM_CAPABILITY, DIM_CURRENCY, DIM_DECISION, DIM_SUBJECT, DIM_TOOL, DIM_TOOL_NAME,
    DIM_TOOL_SERVER, SCOPE_ALL,
};
use crate::receipt_query_snapshot::query::{locate, select, Selection};
use crate::receipt_query_snapshot::service::ReceiptQuerySnapshotConfig;

#[cfg(target_os = "linux")]
#[path = "capacity/linux_file.rs"]
mod linux_file;

const MEMORY: &str = "memory";
const PROJECTED_ROWS: u64 = 10_000_000;
/// Page quota for the projection measurement: large enough that only the
/// rows, never the quota, bound it.
const UNBOUNDED_QUOTA: u64 = 64 * 1024 * 1024 * 1024;
const LOAD_BATCH: usize = 10_000;
const LONG_ID_BYTES: usize = 1_024;
const LONG_TOOL_BYTES: usize = 4_096;
const LONG_SUBJECT_BYTES: usize = 512;
const STEP_UNIT: u64 = 1_000;
/// Largest budget the step search tries before reporting the shape as
/// unmeasured.
const SEARCH_CAP: u64 = 4_000_000_000;
const BASE_TS: i64 = 1_700_000_000;
const TENANTS: [&str; 4] = ["tenant-big", "tenant-mid", "tenant-small", "tenant-sparse"];
const CURRENCIES: [&str; 2] = ["USD", "EUR"];
const SIGNER: &str = "5f0d6c2e9a1b4c7d8e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";

fn divisor() -> u64 {
    std::env::var("CHIO_CAPACITY_DIVISOR")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(1)
}

fn scaled(size: u64) -> u64 {
    (size / divisor()).max(1)
}

fn kib_field(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// Resident and virtual memory of this process in KiB, from
/// `/proc/self/status`; zero where the platform has no procfs.
#[derive(Debug, Clone, Copy, Default)]
struct ProcMemory {
    rss: u64,
    hwm: u64,
    size: u64,
    peak: u64,
}

impl ProcMemory {
    fn read() -> Self {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        Self {
            rss: kib_field(&status, "VmRSS:"),
            hwm: kib_field(&status, "VmHWM:"),
            size: kib_field(&status, "VmSize:"),
            peak: kib_field(&status, "VmPeak:"),
        }
    }

    fn json(self) -> Value {
        json!({
            "vm_rss_kib": self.rss,
            "vm_hwm_kib": self.hwm,
            "vm_size_kib": self.size,
            "vm_peak_kib": self.peak,
        })
    }
}

/// Restart VmHWM at the current resident size, so a later reading is the
/// peak since this call. Returns whether the kernel accepted the reset.
fn reset_peak_rss() -> bool {
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

fn host() -> Value {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    json!({
        "hostname": hostname.trim(),
        "cpus": std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        "mem_total_kib": kib_field(&meminfo, "MemTotal:"),
    })
}

fn emit(test: &str, label: &str, n: u64, fields: Value) {
    let mut line = json!({
        "test": test,
        "label": label,
        "n": n,
        "divisor": divisor(),
        "claimed": divisor() == 1,
        "host": host(),
    });
    if let (Value::Object(line), Value::Object(fields)) = (&mut line, fields) {
        line.extend(fields);
    }
    println!("CAPACITY {line}");
}

fn rounded(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn per_second(count: u64, seconds: f64) -> f64 {
    rounded(count as f64 / seconds.max(f64::EPSILON))
}

/// Exact VM step count of mutating work on the snapshot connection, the
/// counterpart of `count_steps_for_test` for work that needs `&mut`.
struct StepCounter(Arc<AtomicU64>);

impl StepCounter {
    fn install(db: &SnapshotDb) -> Self {
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
        Self(steps)
    }

    fn finish(self, db: &SnapshotDb) -> u64 {
        db.connection()
            .unwrap()
            .progress_handler(0, None::<fn() -> bool>)
            .unwrap();
        self.0.load(Ordering::Relaxed)
    }
}

fn budget_refusal(error: &ReceiptStoreError) -> bool {
    matches!(
        error,
        ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::WorkBudgetExhausted(surface))
            if surface == "receipt query"
    )
}

/// Smallest selection budget that completes `query`, with its selection, or
/// `None` when even `SEARCH_CAP` is exhausted. Every refusal on the way must
/// be the typed budget refusal.
fn budget_needed(db: &SnapshotDb, query: &ReceiptQuery) -> Option<(u64, Selection)> {
    let attempt = |units: u64| match select(db, query, units * STEP_UNIT) {
        Ok(selection) => Some(selection),
        Err(error) if budget_refusal(&error) => None,
        Err(error) => panic!("selection failed with {error}"),
    };
    let mut low = 0;
    let mut high = 1;
    let mut found = loop {
        if let Some(selection) = attempt(high) {
            break selection;
        }
        if high * STEP_UNIT >= SEARCH_CAP {
            return None;
        }
        low = high;
        high = (high * 2).min(SEARCH_CAP / STEP_UNIT);
    };
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        match attempt(middle) {
            Some(selection) => {
                high = middle;
                found = selection;
            }
            None => low = middle,
        }
    }
    Some((high * STEP_UNIT, found))
}

/// Recompute every maintained count from the stored rows and compare it with
/// `snapshot_count`. Returns `(count rows compared, mismatches)`; a count row
/// with no recomputed partner, or the reverse, is a mismatch.
fn full_count_check(db: &SnapshotDb) -> (u64, u64) {
    let connection = db.connection().unwrap();
    let mut expected: HashMap<(i64, i64, i64), (i64, i64, i64)> = HashMap::new();
    let mut statement = connection
        .prepare(
            "SELECT seq, ts, tenant, capability, tool_server, tool_name, tool, decision, subject,
                    cost_currency FROM snapshot_tool_receipt",
        )
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let values: [i64; 10] = std::array::from_fn(|index| row.get(index).unwrap());
        let [seq, ts, tenant, capability, server, name, tool, decision, subject, currency] = values;
        let mut keys = vec![
            (COUNT_TOTAL, 0),
            (DIM_CAPABILITY, capability),
            (DIM_TOOL_SERVER, server),
            (DIM_TOOL_NAME, name),
            (DIM_TOOL, tool),
            (DIM_DECISION, decision),
            (COUNT_HOUR, ts.div_euclid(3_600)),
        ];
        if subject != ABSENT {
            keys.push((DIM_SUBJECT, subject));
        }
        if currency != ABSENT {
            keys.push((DIM_CURRENCY, currency));
        }
        let scopes = [Some(SCOPE_ALL), (tenant != ABSENT).then_some(tenant)];
        for (dim, value) in keys {
            for scope in scopes.into_iter().flatten() {
                let entry = expected
                    .entry((scope, dim, value))
                    .or_insert((0, i64::MAX, i64::MIN));
                entry.0 += 1;
                entry.1 = entry.1.min(seq);
                entry.2 = entry.2.max(seq);
            }
        }
    }
    let mut compared = 0;
    let mut mismatches = 0;
    let mut statement = connection
        .prepare("SELECT scope, dim, value, n, min_seq, max_seq FROM snapshot_count")
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let values: [i64; 6] = std::array::from_fn(|index| row.get(index).unwrap());
        let [scope, dim, value, n, min_seq, max_seq] = values;
        compared += 1;
        if expected.remove(&(scope, dim, value)) != Some((n, min_seq, max_seq)) {
            mismatches += 1;
        }
    }
    (
        compared,
        mismatches + u64::try_from(expected.len()).unwrap(),
    )
}

/// Integer attributes of synthetic row `seq`. Rows, filters and the count
/// oracle all derive from them.
#[derive(Clone, Copy)]
struct Attrs {
    seq: i64,
    long: bool,
    tenant: Option<usize>,
    capability: i64,
    server: i64,
    tool: i64,
    deny: bool,
    subject: Option<i64>,
    signed_subject: bool,
    cost: Option<(usize, u64)>,
    ts: i64,
}

fn attrs(seq: i64, long: bool) -> Attrs {
    let tenant = if seq % 10_000 == 3 {
        Some(3)
    } else {
        match seq % 10 {
            0 => None,
            1..=4 => Some(0),
            5..=7 => Some(1),
            _ => Some(2),
        }
    };
    let cost = match seq % 5 {
        0 => Some((0, u64::try_from(seq % 10_000).unwrap())),
        1 => Some((1, u64::try_from(seq % 777).unwrap())),
        _ => None,
    };
    Attrs {
        seq,
        long,
        tenant,
        capability: seq % 101,
        server: seq % 3,
        tool: seq % 13,
        deny: seq % 9 == 0,
        subject: (seq % 2 == 0).then_some(seq % 1_000),
        signed_subject: seq % 3 != 0,
        cost,
        // Four receipts per second.
        ts: BASE_TS + seq / 4,
    }
}

fn capability_name(index: i64) -> String {
    format!("capability-{index:032x}")
}

/// The projected row of `attrs`. Long rows carry long receipt ids, tool names
/// and subjects, which the snapshot must store verbatim.
fn projected(attrs: &Attrs) -> ProjectedToolRow {
    let mut leaf_hash = [0x5a_u8; 32];
    leaf_hash[..8].copy_from_slice(&attrs.seq.to_be_bytes());
    let (receipt_id, tool_name, subject) = if attrs.long {
        (
            format!("rcpt-{:010}-{}", attrs.seq, "x".repeat(LONG_ID_BYTES)),
            format!("tool-{}-{}", attrs.tool, "y".repeat(LONG_TOOL_BYTES)),
            attrs.subject.map(|_| {
                format!(
                    "subject-{}-{}",
                    attrs.seq / 10,
                    "s".repeat(LONG_SUBJECT_BYTES)
                )
            }),
        )
    } else {
        (
            format!("{:08x}-0000-4000-8000-{:012x}", attrs.seq >> 16, attrs.seq),
            format!("tool-{}", attrs.tool),
            attrs.subject.map(|subject| format!("subject-{subject}")),
        )
    };
    ProjectedToolRow {
        seq: attrs.seq,
        entry_seq: attrs.seq,
        leaf_hash,
        signer: SIGNER.into(),
        receipt_id,
        ts: attrs.ts,
        tenant: attrs.tenant.map(|tenant| TENANTS[tenant].to_string()),
        capability: capability_name(attrs.capability),
        tool_server: format!("server-{}", attrs.server),
        tool_name,
        decision: if attrs.deny { "deny" } else { "allow" }.into(),
        subject,
        subject_signed: attrs.signed_subject && attrs.subject.is_some(),
        cost_currency: attrs
            .cost
            .map(|(currency, _)| CURRENCIES[currency].to_string()),
        cost_charged: attrs.cost.map(|(_, cost)| cost.to_be_bytes().to_vec()),
    }
}

fn load(db: &mut SnapshotDb, seqs: std::ops::RangeInclusive<i64>, long: bool) {
    let mut batch = SnapshotBatch::default();
    for seq in seqs {
        batch.tools.push(projected(&attrs(seq, long)));
        if batch.tools.len() == LOAD_BATCH {
            db.commit(&batch).unwrap();
            batch.tools.clear();
        }
    }
    if !batch.tools.is_empty() {
        db.commit(&batch).unwrap();
    }
}

type Matches = Box<dyn Fn(&Attrs) -> bool>;

/// One query shape and the predicate that defines its exact answer.
struct Case {
    name: &'static str,
    query: ReceiptQuery,
    matches: Matches,
}

fn case(
    name: &'static str,
    query: ReceiptQuery,
    matches: impl Fn(&Attrs) -> bool + 'static,
) -> Case {
    Case {
        name,
        query,
        matches: Box::new(matches),
    }
}

fn admin() -> ReceiptQuery {
    ReceiptQuery {
        limit: MAX_QUERY_LIMIT,
        ..ReceiptQuery::default().local_operator_admin()
    }
}

fn tenant(index: usize) -> ReceiptQuery {
    ReceiptQuery {
        limit: MAX_QUERY_LIMIT,
        ..ReceiptQuery::default().authenticated_tenant(TENANTS[index])
    }
}

fn window(query: ReceiptQuery, (since, until): (i64, i64)) -> ReceiptQuery {
    ReceiptQuery {
        since: Some(u64::try_from(since).unwrap()),
        until: Some(u64::try_from(until).unwrap()),
        ..query
    }
}

/// The measured shapes over `n` rows: scope only, one equality, a time
/// window, and combinations. The unselective pair is the over-budget shape.
fn cases(n: i64) -> Vec<Case> {
    let middle = u64::try_from(n / 2).unwrap();
    let hour = {
        let since = BASE_TS + n / 8;
        (since, since + 3_599)
    };
    let tenth = (BASE_TS + n * 45 / 400, BASE_TS + n * 55 / 400);
    let in_hour = move |a: &Attrs| (hour.0..=hour.1).contains(&a.ts);
    let in_tenth = move |a: &Attrs| (tenth.0..=tenth.1).contains(&a.ts);
    let cap = capability_name(42);
    vec![
        case("s1_admin_first_page", admin(), |_| true),
        case(
            "s1_admin_mid_cursor",
            ReceiptQuery {
                cursor: Some(middle),
                ..admin()
            },
            |_| true,
        ),
        case(
            "s1_big_tenant_mid_cursor",
            ReceiptQuery {
                cursor: Some(middle),
                ..tenant(0)
            },
            |a| a.tenant == Some(0),
        ),
        case("s1_sparse_tenant", tenant(3), |a| a.tenant == Some(3)),
        case(
            "s2_capability",
            ReceiptQuery {
                capability_id: Some(cap.clone()),
                ..admin()
            },
            |a| a.capability == 42,
        ),
        case(
            "s2_big_tenant_tool_name",
            ReceiptQuery {
                tool_name: Some("tool-3".into()),
                ..tenant(0)
            },
            |a| a.tenant == Some(0) && !a.long && a.tool == 3,
        ),
        case(
            "s2_tool_pair",
            ReceiptQuery {
                tool_server: Some("server-1".into()),
                tool_name: Some("tool-4".into()),
                ..admin()
            },
            |a| a.server == 1 && !a.long && a.tool == 4,
        ),
        case(
            "s2_mid_tenant_deny",
            ReceiptQuery {
                outcome: Some("deny".into()),
                ..tenant(1)
            },
            |a| a.tenant == Some(1) && a.deny,
        ),
        case(
            "s2_subject",
            ReceiptQuery {
                agent_subject: Some("subject-42".into()),
                ..admin()
            },
            |a| !a.long && a.subject == Some(42),
        ),
        case(
            "s2_currency",
            ReceiptQuery {
                cost_currency: Some("USD".into()),
                ..admin()
            },
            |a| matches!(a.cost, Some((0, _))),
        ),
        case("s3_one_hour", window(admin(), hour), in_hour),
        case("s3_tenth", window(admin(), tenth), in_tenth),
        case("s3_big_tenant_tenth", window(tenant(0), tenth), move |a| {
            a.tenant == Some(0) && in_tenth(a)
        }),
        case(
            "s5_capability_deny",
            ReceiptQuery {
                capability_id: Some(cap),
                outcome: Some("deny".into()),
                ..admin()
            },
            |a| a.capability == 42 && a.deny,
        ),
        case(
            "s5_big_tenant_tool_hour",
            window(
                ReceiptQuery {
                    tool_name: Some("tool-3".into()),
                    ..tenant(0)
                },
                hour,
            ),
            move |a| a.tenant == Some(0) && !a.long && a.tool == 3 && in_hour(a),
        ),
        case(
            "s5_sparse_tenant_cost_range",
            ReceiptQuery {
                cost_currency: Some("USD".into()),
                min_cost: Some(0),
                max_cost: Some(5_000),
                ..tenant(3)
            },
            |a| a.tenant == Some(3) && matches!(a.cost, Some((0, cost)) if cost <= 5_000),
        ),
        case(
            "s5_cost_range",
            ReceiptQuery {
                cost_currency: Some("USD".into()),
                min_cost: Some(100),
                max_cost: Some(200),
                ..admin()
            },
            |a| matches!(a.cost, Some((0, cost)) if (100..=200).contains(&cost)),
        ),
        case(
            "s5_unselective_pair",
            ReceiptQuery {
                outcome: Some("allow".into()),
                tool_server: Some("server-1".into()),
                ..admin()
            },
            |a| !a.deny && a.server == 1,
        ),
    ]
}

/// Exact `(total, rows after the cursor)` of every case over rows `1..=n`,
/// computed from the generator rather than from SQLite.
fn oracle(cases: &[Case], n: i64, short: i64) -> Vec<(u64, u64)> {
    let mut expected = vec![(0_u64, 0_u64); cases.len()];
    for seq in 1..=n {
        let row = attrs(seq, seq > short);
        for (case, counts) in cases.iter().zip(expected.iter_mut()) {
            if (case.matches)(&row) {
                counts.0 += 1;
                if case
                    .query
                    .cursor
                    .is_none_or(|cursor| u64::try_from(seq).unwrap() > cursor)
                {
                    counts.1 += 1;
                }
            }
        }
    }
    expected
}

/// Measure one shape and check its answer against the oracle at the default
/// budget and at the measured one. The default outcome is either the exact
/// answer or the typed refusal, never a partial one.
fn measure_shape(db: &SnapshotDb, case: &Case, expected: (u64, u64), default_steps: u64) -> Value {
    let limit = u64::try_from(case.query.limit.clamp(1, MAX_QUERY_LIMIT)).unwrap();
    let page = expected.1.min(limit);
    let check = |selection: &Selection| {
        assert_eq!(selection.total_count, expected.0, "{} total", case.name);
        assert_eq!(
            u64::try_from(selection.rows.len()).unwrap(),
            page,
            "{} page",
            case.name
        );
        assert!(
            selection
                .rows
                .windows(2)
                .all(|pair| pair[0].seq < pair[1].seq),
            "{} page order",
            case.name
        );
    };
    let at_default = match select(db, &case.query, default_steps) {
        Ok(selection) => {
            check(&selection);
            "served"
        }
        Err(error) if budget_refusal(&error) => "refused",
        Err(error) => panic!("{} failed with {error}", case.name),
    };
    let needed = budget_needed(db, &case.query).map(|(steps, selection)| {
        check(&selection);
        steps
    });
    assert_eq!(
        at_default == "refused",
        needed.is_none_or(|steps| steps > default_steps),
        "{}: the default outcome must follow the measured need",
        case.name
    );
    json!({
        "shape": case.name,
        "vm_steps_budget": needed,
        "default_budget": at_default,
        "total_count": expected.0,
        "page_rows": page,
    })
}

fn point_read(
    db: &SnapshotDb,
    name: &str,
    id: &str,
    tenant: Option<&str>,
    expected: Option<i64>,
) -> Value {
    let (located, steps) = db
        .count_steps_for_test(|db| locate(db, id, tenant).unwrap())
        .unwrap();
    assert_eq!(
        located.map(|located| i64::try_from(located.row.seq).unwrap()),
        expected,
        "{name}"
    );
    json!({ "shape": name, "vm_steps": steps })
}

#[test]
#[ignore = "capacity evidence: 10,000,000 projected rows in the memory backend"]
fn memory_projection_capacity() {
    let n = i64::try_from(scaled(PROJECTED_ROWS)).unwrap();
    let large = (n / 100).max(1);
    let short = n - large;
    let config = ReceiptQuerySnapshotConfig::default();
    let peak_reset = reset_peak_rss();
    let baseline = ProcMemory::read();

    let mut db = SnapshotDb::open_memory(UNBOUNDED_QUOTA).unwrap();
    let started = Instant::now();
    load(&mut db, 1..=short, false);
    let short_used = db.used_bytes().unwrap();
    load(&mut db, short + 1..=n, true);
    let load_seconds = started.elapsed().as_secs_f64();
    let used = db.used_bytes().unwrap();
    let loaded = ProcMemory::read();
    assert_eq!(db.tool_row_count().unwrap(), u64::try_from(n).unwrap());
    assert!(used <= db.quota_bytes());

    // Long values are stored verbatim and counted in `used_bytes`.
    let probe = projected(&attrs(short + 1, true));
    let (id_bytes, tool_bytes): (i64, i64) = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT length(CAST(r.receipt_id AS BLOB)), length(CAST(d.value AS BLOB))
             FROM snapshot_tool_receipt r JOIN snapshot_dim d ON d.id = r.tool_name
             WHERE r.seq = ?1",
            [short + 1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(usize::try_from(id_bytes).unwrap(), probe.receipt_id.len());
    assert_eq!(usize::try_from(tool_bytes).unwrap(), probe.tool_name.len());
    let (dimensions, dimension_bytes) = db.dim_stats().unwrap();

    let cases = cases(n);
    let expected = oracle(&cases, n, short);
    let shapes: Vec<Value> = cases
        .iter()
        .zip(&expected)
        .map(|(case, expected)| measure_shape(&db, case, *expected, config.query_sql_steps))
        .collect();

    // An over-budget combined shape is refused with the typed budget outcome,
    // carrying neither rows nor a count. Development sizes shrink the budget
    // with the rows.
    let c16_budget = if divisor() == 1 {
        config.query_sql_steps
    } else {
        (config.query_sql_steps / divisor()).max(STEP_UNIT)
    };
    let c16 = cases
        .iter()
        .find(|case| case.name == "s5_unselective_pair")
        .unwrap();
    let refusal = select(&db, &c16.query, c16_budget).unwrap_err();
    assert!(budget_refusal(&refusal), "{refusal}");
    let c16_needed = budget_needed(&db, &c16.query).map(|(steps, _)| steps);

    let middle = n / 2;
    let sparse = (1..=n)
        .find(|seq| attrs(*seq, false).tenant == Some(3))
        .unwrap();
    let points = [
        point_read(
            &db,
            "s4_hit",
            &projected(&attrs(middle, false)).receipt_id,
            None,
            Some(middle),
        ),
        point_read(&db, "s4_hit_long", &probe.receipt_id, None, Some(short + 1)),
        point_read(
            &db,
            "s4_hit_sparse_tenant",
            &projected(&attrs(sparse, false)).receipt_id,
            Some(TENANTS[3]),
            Some(sparse),
        ),
        point_read(
            &db,
            "s4_other_tenant",
            &projected(&attrs(sparse, false)).receipt_id,
            Some(TENANTS[0]),
            None,
        ),
        point_read(&db, "s4_miss", "absent-receipt-id", None, None),
    ];

    // One walker insert hold at full depth stays inside its hold budget.
    let hold_rows = i64::try_from(config.insert_rows).unwrap();
    let batch = SnapshotBatch {
        tools: (n + 1..=n + hold_rows)
            .map(|seq| projected(&attrs(seq, false)))
            .collect(),
        ..SnapshotBatch::default()
    };
    let counter = StepCounter::install(&db);
    db.commit(&batch).unwrap();
    let insert_hold_steps = counter.finish(&db);
    assert!(insert_hold_steps < config.hold_sql_steps);

    // Every maintained count equals its recomputation from the rows.
    let started = Instant::now();
    let (compared, mismatches) = full_count_check(&db);
    let count_check_seconds = started.elapsed().as_secs_f64();
    assert!(compared > 0);
    assert_eq!(mismatches, 0);
    assert_eq!(
        db.count(SCOPE_ALL, COUNT_TOTAL, 0).unwrap().unwrap().0,
        u64::try_from(n + hold_rows).unwrap()
    );
    let peak = ProcMemory::read();
    drop(db);
    let dropped = ProcMemory::read();

    let short_rows = u64::try_from(short).unwrap();
    let large_rows = u64::try_from(large).unwrap();
    let rows = u64::try_from(n).unwrap();
    emit(
        "memory_projection_capacity",
        MEMORY,
        rows,
        json!({
            "short_rows": short_rows,
            "large_rows": large_rows,
            "large_field_bytes": {
                "receipt_id": LONG_ID_BYTES,
                "tool_name": LONG_TOOL_BYTES,
                "subject": LONG_SUBJECT_BYTES,
            },
            "load_seconds": rounded(load_seconds),
            "load_rows_per_second": per_second(rows, load_seconds),
            "used_bytes": used,
            "bytes_per_row": rounded(used as f64 / rows as f64),
            "short_bytes_per_row": rounded(short_used as f64 / short_rows as f64),
            "large_bytes_per_row": rounded((used - short_used) as f64 / large_rows as f64),
            "rows_per_default_quota_at_short_size":
                config.quota_bytes / (short_used / short_rows).max(1),
            "dimensions": dimensions,
            "dimension_bytes": dimension_bytes,
            "process": {
                "peak_reset": peak_reset,
                "baseline": baseline.json(),
                "loaded": loaded.json(),
                "peak": peak.json(),
                "dropped": dropped.json(),
            },
            "query_sql_steps_default": config.query_sql_steps,
            "shapes": shapes,
            "point_reads": points,
            "c16": {
                "shape": c16.name,
                "budget": c16_budget,
                "outcome": ReceiptQuerySnapshotError::WorkBudgetExhausted("receipt query".into())
                    .wire_code(),
                "vm_steps_budget": c16_needed,
            },
            "insert_hold": {
                "rows": hold_rows,
                "vm_steps": insert_hold_steps,
                "hold_sql_steps": config.hold_sql_steps,
            },
            "c20": {
                "count_rows_compared": compared,
                "mismatches": mismatches,
                "seconds": rounded(count_check_seconds),
            },
        }),
    );
}

#[test]
#[ignore = "capacity evidence: quota exhaustion at the default memory quota"]
fn memory_quota_exhaustion_is_typed() {
    let config = ReceiptQuerySnapshotConfig::default();
    let requested = (config.quota_bytes / divisor()).max(1024 * 1024);
    let mut db = SnapshotDb::open_memory(requested).unwrap();
    let hold = i64::try_from(config.insert_rows).unwrap();
    let mut committed = 0_u64;
    let mut batches = 0_u64;
    let mut seq = 1_i64;
    let started = Instant::now();
    let (error, probe) = loop {
        let mut rows: Vec<_> = (seq..seq + hold)
            .map(|seq| projected(&attrs(seq, false)))
            .collect();
        // Each batch interns a capability of its own, so any surviving part of
        // a refused batch would be visible.
        let probe = format!("capability-batch-{batches}");
        rows.last_mut().unwrap().capability = probe.clone();
        match db.commit(&SnapshotBatch {
            tools: rows,
            ..SnapshotBatch::default()
        }) {
            Ok(()) => {
                committed += u64::try_from(hold).unwrap();
                batches += 1;
                seq += hold;
            }
            Err(error) => break (error, probe),
        }
        assert!(seq < 1_000_000_000, "the quota was never reached");
    };
    let seconds = started.elapsed().as_secs_f64();
    let (quota_bytes, used_bytes) = match error {
        SnapshotDbError::Capacity {
            quota_bytes,
            used_bytes,
        } => (quota_bytes, used_bytes),
        other => panic!("expected a capacity outcome, got {other}"),
    };
    assert_eq!(quota_bytes, db.quota_bytes());
    assert!(used_bytes <= quota_bytes);
    // The refused batch left nothing behind: no row, no dimension, no count.
    assert_eq!(db.tool_row_count().unwrap(), committed);
    assert_eq!(db.dim_id(DIM_CAPABILITY, &probe), None);
    let stored: i64 = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM snapshot_dim WHERE value = ?1",
            [&probe],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, 0);
    let (compared, mismatches) = full_count_check(&db);
    assert_eq!(mismatches, 0);
    emit(
        "memory_quota_exhaustion_is_typed",
        MEMORY,
        committed,
        json!({
            "quota_bytes": quota_bytes,
            "used_bytes_at_refusal": used_bytes,
            "rows_committed": committed,
            "batch_rows": hold,
            "bytes_per_row_at_quota": rounded(used_bytes as f64 / committed.max(1) as f64),
            "refusal": "capacity",
            "refused_batch_left_no_rows_or_dimensions": true,
            "count_rows_compared": compared,
            "seconds": rounded(seconds),
        }),
    );
}
