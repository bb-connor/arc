// Aggregation contract for the receipt analytics financial totals.

use super::*;

use std::collections::BTreeMap;

use chio_core::receipt::body::ChioReceiptBody;
use chio_core::receipt::decision::ToolCallAction;
use chio_test_support::prelude::*;

/// Charged-cost aggregate the analytics queries carried before the typed
/// projection replaced it. Kept here as the oracle the replacement is measured
/// against: it is exact for every charged cost below `2^63`.
const JSON_COST_CHARGED_SUM: &str = "COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, \
     '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0)";

/// Attempted-cost aggregate. No typed projection exists for this field, so the
/// analytics queries still carry this expression.
const JSON_ATTEMPTED_COST_SUM: &str = "COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, \
     '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0)";

const FIXTURE_FROM: &str = "FROM chio_tool_receipts r \
     LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id";

const DAY_SECS: u64 = 86_400;

/// One receipt the fixture writes, described by the values the financial
/// aggregates have to reproduce.
struct FixtureReceipt {
    capability_id: String,
    subject_key: &'static str,
    tool_server: &'static str,
    tool_name: &'static str,
    decision: Decision,
    timestamp: u64,
    /// `None` writes a receipt with no financial block at all, which leaves the
    /// charged-cost projection NULL.
    financial: Option<(u64, Option<u64>)>,
}

struct Fixture {
    store: SqliteReceiptStore,
    path: std::path::PathBuf,
    receipts: Vec<FixtureReceipt>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn decision_for(index: usize) -> Decision {
    match index % 4 {
        0 => Decision::Allow,
        1 => Decision::Deny {
            reason: "budget".to_string(),
            guard: "kernel".to_string(),
        },
        2 => Decision::Cancelled {
            reason: "operator".to_string(),
        },
        _ => Decision::Incomplete {
            reason: "stream ended".to_string(),
        },
    }
}

/// The receipts whose charged costs stay inside the range the JSON aggregate
/// reproduces exactly, so the two aggregations can be compared value for value.
///
/// Every shape the aggregate has to handle appears: a financial block with a
/// zero cost, a receipt with no financial block, a cost whose eight encoded
/// bytes are all distinct (so a byte-order or width mistake cannot cancel out),
/// and repeated values across every grouping dimension.
fn json_domain_receipts() -> Vec<FixtureReceipt> {
    let subjects = ["agent-alpha", "agent-beta", "agent-gamma"];
    let tools = [
        ("shell", "bash"),
        ("shell", "zsh"),
        ("files", "read"),
        ("files", "write"),
    ];

    let mut receipts = Vec::new();
    for index in 0..320_usize {
        let (tool_server, tool_name) = tools[index % tools.len()];
        let financial = match index % 8 {
            0 => None,
            1 => Some((0, None)),
            2 => Some((0x0102_0304_0506_0708, None)),
            3 => Some((17, Some(4_001))),
            4 => Some((u64::from(u32::MAX) + 1, None)),
            5 => Some((97, Some(0))),
            6 => Some((1_000_003, None)),
            _ => Some((97, None)),
        };
        receipts.push(FixtureReceipt {
            capability_id: format!("cap-{}", index % 5),
            subject_key: subjects[index % subjects.len()],
            tool_server,
            tool_name,
            decision: decision_for(index),
            timestamp: DAY_SECS * (1 + (index % 3) as u64) + index as u64,
            financial,
        });
    }
    receipts
}

/// Charged cost at each boundary of the unsigned range, one capability per
/// value so a report can be scoped to a single one and assert its exact total.
const RANGE_EDGE_COSTS: [(&str, u64); 5] = [
    ("cap-edge-two-to-53", 1 << 53),
    ("cap-edge-under-i64-max", (1 << 53) + 1),
    ("cap-edge-i64-max", i64::MAX as u64),
    ("cap-edge-i64-max-plus-one", 1 << 63),
    ("cap-edge-u64-max", u64::MAX),
];

/// Three charges whose individual values fit a signed total but whose sum does
/// not, which is where the JSON aggregate stops returning a number at all.
const SIGNED_TOTAL_OVERFLOW_CAPABILITY: &str = "cap-edge-signed-total-overflow";
const SIGNED_TOTAL_OVERFLOW_CHARGE: u64 = 1 << 62;
const SIGNED_TOTAL_OVERFLOW_ROWS: usize = 3;

fn range_edge_receipts() -> Vec<FixtureReceipt> {
    let edge = |index: usize, capability_id: &str, cost_charged: u64| FixtureReceipt {
        capability_id: capability_id.to_string(),
        subject_key: "agent-edge",
        tool_server: "shell",
        tool_name: "bash",
        decision: Decision::Allow,
        timestamp: DAY_SECS + index as u64,
        financial: Some((cost_charged, None)),
    };

    let mut receipts: Vec<FixtureReceipt> = RANGE_EDGE_COSTS
        .into_iter()
        .enumerate()
        .map(|(index, (capability_id, cost_charged))| edge(index, capability_id, cost_charged))
        .collect();
    for row in 0..SIGNED_TOTAL_OVERFLOW_ROWS {
        receipts.push(edge(
            RANGE_EDGE_COSTS.len() + row,
            SIGNED_TOTAL_OVERFLOW_CAPABILITY,
            SIGNED_TOTAL_OVERFLOW_CHARGE,
        ));
    }
    receipts
}

fn sign_fixture_receipt(index: usize, receipt: &FixtureReceipt) -> ChioReceipt {
    let keypair = Keypair::generate();
    let financial =
        receipt
            .financial
            .map(|(cost_charged, attempted_cost)| FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 1_000,
                budget_total: 2_000,
                delegation_depth: 0,
                root_budget_holder: "root-agent".to_string(),
                payment_reference: None,
                settlement_status: SettlementStatus::Settled,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            });
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: receipt.subject_key.to_string(),
            issuer_key: "issuer-key".to_string(),
            delegation_depth: 0,
            grant_index: Some(0),
        },
        "financial": financial,
    });

    let action = ToolCallAction::from_parameters(serde_json::json!({ "index": index }))
        .test_expect("tool call action");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("analytics-fixture-{index}"),
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.to_string(),
            tool_name: receipt.tool_name.to_string(),
            action,
            decision: Some(receipt.decision.clone()),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{index}"),
            policy_hash: "policy-analytics-fixture".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_expect("sign fixture receipt")
}

fn populate(prefix: &str, receipts: Vec<FixtureReceipt>) -> Fixture {
    let path = unique_db_path(prefix);
    let store = SqliteReceiptStore::open(&path).test_expect("open receipt store");
    for (index, receipt) in receipts.iter().enumerate() {
        store
            .append_chio_receipt_returning_seq(&sign_fixture_receipt(index, receipt))
            .test_expect("append fixture receipt");
    }
    store.flush_receipt_writes().test_expect("flush fixture");
    Fixture {
        store,
        path,
        receipts,
    }
}

/// Charged cost as the signed receipt body carries it, parsed outside SQLite so
/// the full unsigned range survives the read.
fn signed_cost_charged(raw_json: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(raw_json)
        .test_expect("fixture receipt is valid json")
        .get("metadata")?
        .get("financial")?
        .get("cost_charged")?
        .as_u64()
}

/// Reference aggregation: decode the eight-byte projection and accumulate in a
/// width no total of `u64` charges can exceed.
fn reference_totals(fixture: &Fixture, group_key: &str) -> BTreeMap<Option<String>, u128> {
    let connection = fixture.store.connection().test_expect("reader connection");
    let sql = format!("SELECT {group_key} AS grouped, r.cost_charged_be {FIXTURE_FROM}");
    let mut totals: BTreeMap<Option<String>, u128> = BTreeMap::new();
    let mut statement = connection
        .prepare(&sql)
        .test_expect("prepare reference sql");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<[u8; 8]>>(1)?,
            ))
        })
        .test_expect("run reference sql");
    for row in rows {
        let (grouped, projection) = row.test_expect("reference row");
        let charged = projection.map_or(0, |bytes| u128::from(u64::from_be_bytes(bytes)));
        *totals.entry(grouped).or_insert(0) += charged;
    }
    totals
}

fn json_totals(fixture: &Fixture, group_key: &str) -> BTreeMap<Option<String>, i64> {
    let connection = fixture.store.connection().test_expect("reader connection");
    let sql = format!(
        "SELECT {group_key} AS grouped, {JSON_COST_CHARGED_SUM} {FIXTURE_FROM} GROUP BY grouped"
    );
    let mut statement = connection.prepare(&sql).test_expect("prepare json sql");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?))
        })
        .test_expect("run json sql");
    rows.map(|row| row.test_expect("json row")).collect()
}

/// Every grouping the analytics report returns, as a SQL expression.
fn report_dimensions() -> [(&'static str, String); 4] {
    [
        ("summary", "'all'".to_string()),
        (
            "by_agent",
            "COALESCE(r.subject_key, cl.subject_key)".to_string(),
        ),
        ("by_tool", "r.tool_server || '/' || r.tool_name".to_string()),
        (
            "by_time",
            format!("CAST((r.timestamp / {DAY_SECS}) * {DAY_SECS} AS TEXT)"),
        ),
    ]
}

#[test]
fn receipt_write_path_agrees_with_itself_about_charged_cost() {
    let fixture = populate("chio-analytics-agreement", {
        let mut receipts = json_domain_receipts();
        receipts.extend(range_edge_receipts());
        receipts
    });
    let connection = fixture.store.connection().test_expect("reader connection");
    let mut statement = connection
        .prepare(
            "SELECT receipt_id, cost_charged_be, cost_currency, raw_json FROM chio_tool_receipts",
        )
        .test_expect("prepare projection read");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<[u8; 8]>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .test_expect("read projections");

    let mut compared = 0_usize;
    let mut absent = 0_usize;
    for row in rows {
        let (receipt_id, projection, currency, raw_json) = row.test_expect("projection row");
        match (projection, signed_cost_charged(&raw_json)) {
            (Some(bytes), Some(signed)) => {
                assert_eq!(
                    u64::from_be_bytes(bytes),
                    signed,
                    "projection disagrees with the signed body for {receipt_id}"
                );
                assert_eq!(
                    currency.as_deref(),
                    Some("USD"),
                    "charged cost without its currency for {receipt_id}"
                );
                compared += 1;
            }
            (None, None) => {
                assert_eq!(
                    currency, None,
                    "currency without a charged cost for {receipt_id}"
                );
                absent += 1;
            }
            (projection, signed) => panic!(
                "projection and signed body disagree about presence for {receipt_id}: \
                 projection {projection:?}, signed {signed:?}"
            ),
        }
    }

    assert_eq!(compared + absent, fixture.receipts.len());
    assert_eq!(
        absent,
        fixture
            .receipts
            .iter()
            .filter(|receipt| receipt.financial.is_none())
            .count()
    );
}

#[test]
fn typed_projection_totals_match_the_json_aggregate_on_its_exact_range() {
    let fixture = populate("chio-analytics-identity", json_domain_receipts());
    for (dimension, group_key) in report_dimensions() {
        let json = json_totals(&fixture, &group_key);
        let reference = reference_totals(&fixture, &group_key);
        assert_eq!(
            json.len(),
            reference.len(),
            "{dimension} groups differ between the two aggregations"
        );
        for (group, total) in json {
            let expected = reference
                .get(&group)
                .copied()
                .test_expect("reference total for group");
            assert_eq!(
                u128::try_from(total).test_expect("json total is not negative"),
                expected,
                "{dimension} total differs for group {group:?}"
            );
        }
    }
}

#[test]
fn json_aggregate_loses_charged_costs_at_and_above_two_to_the_sixty_third() {
    let fixture = populate("chio-analytics-range-edge", range_edge_receipts());
    let connection = fixture.store.connection().test_expect("reader connection");
    let mut statement = connection
        .prepare(&format!(
            "SELECT r.cost_charged_be, \
             CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER), \
             r.raw_json {FIXTURE_FROM} ORDER BY r.seq"
        ))
        .test_expect("prepare range read");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, [u8; 8]>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .test_expect("read range rows");

    let mut exact = 0_usize;
    let mut clamped = 0_usize;
    for row in rows {
        let (projection, json_value, raw_json) = row.test_expect("range row");
        let signed = signed_cost_charged(&raw_json).test_expect("signed charged cost");
        assert_eq!(u64::from_be_bytes(projection), signed);
        if signed < 1 << 63 {
            assert_eq!(json_value as u64, signed);
            exact += 1;
        } else {
            assert_eq!(
                json_value,
                i64::MAX,
                "the json aggregate clamps rather than reporting {signed}"
            );
            clamped += 1;
        }
    }
    assert_eq!(exact, 3 + SIGNED_TOTAL_OVERFLOW_ROWS);
    assert_eq!(clamped, 2);
}

#[test]
fn json_aggregate_returns_no_total_once_the_charges_exceed_the_signed_range() {
    let fixture = populate("chio-analytics-total-overflow", range_edge_receipts());
    let connection = fixture.store.connection().test_expect("reader connection");

    for scope in [
        format!("WHERE r.capability_id = '{SIGNED_TOTAL_OVERFLOW_CAPABILITY}'"),
        String::new(),
    ] {
        let refusal = connection
            .query_row(
                &format!("SELECT {JSON_COST_CHARGED_SUM} {FIXTURE_FROM} {scope}"),
                [],
                |row| row.get::<_, i64>(0),
            )
            .test_unwrap_err();
        match refusal {
            rusqlite::Error::SqliteFailure(_, Some(message)) => {
                assert_eq!(message, "integer overflow", "scope {scope:?}");
            }
            other => panic!("expected an integer overflow for scope {scope:?}, got {other:?}"),
        }
    }

    let signed_overflow = reference_totals(
        &fixture,
        &format!(
            "CASE WHEN r.capability_id = '{SIGNED_TOTAL_OVERFLOW_CAPABILITY}' THEN 'scoped' END"
        ),
    );
    assert_eq!(
        signed_overflow.get(&Some("scoped".to_string())).copied(),
        Some(u128::from(SIGNED_TOTAL_OVERFLOW_CHARGE) * SIGNED_TOTAL_OVERFLOW_ROWS as u128),
        "the typed projection totals a charge set the signed aggregate refuses"
    );

    let whole_fixture = reference_totals(&fixture, "'all'")
        .get(&Some("all".to_string()))
        .copied()
        .test_expect("reference total");
    let expected: u128 = range_edge_receipts()
        .iter()
        .filter_map(|receipt| receipt.financial)
        .map(|(cost_charged, _)| u128::from(cost_charged))
        .sum();
    assert_eq!(whole_fixture, expected);
    assert!(
        whole_fixture > u128::from(u64::MAX),
        "the range-edge fixture must exceed the width the report returns a total in"
    );
}

#[test]
fn attempted_cost_still_comes_from_the_signed_body() {
    let fixture = populate("chio-analytics-attempted", json_domain_receipts());
    let connection = fixture.store.connection().test_expect("reader connection");
    let total = connection
        .query_row(
            &format!("SELECT {JSON_ATTEMPTED_COST_SUM} {FIXTURE_FROM}"),
            [],
            |row| row.get::<_, i64>(0),
        )
        .test_expect("attempted cost total");
    let expected: i64 = fixture
        .receipts
        .iter()
        .filter_map(|receipt| receipt.financial)
        .filter_map(|(_, attempted_cost)| attempted_cost)
        .map(|attempted_cost| attempted_cost as i64)
        .sum();
    assert_eq!(total, expected);
    assert!(expected > 0, "the fixture must carry attempted costs");
}

fn admin_query() -> ReceiptAnalyticsQuery {
    ReceiptAnalyticsQuery {
        group_limit: Some(MAX_ANALYTICS_GROUP_LIMIT),
        time_bucket: Some(AnalyticsTimeBucket::Day),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        ..ReceiptAnalyticsQuery::default()
    }
}

/// One stored receipt as the analytics predicates see it, read back so the
/// oracle re-derives the aggregation and nothing else.
struct StoredRow {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    subject_key: Option<String>,
    timestamp: i64,
    decision_kind: String,
    cost_charged: Option<u64>,
    attempted_cost: u64,
}

fn stored_rows(fixture: &Fixture) -> Vec<StoredRow> {
    let connection = fixture.store.connection().test_expect("reader connection");
    let mut statement = connection
        .prepare(
            "SELECT capability_id, tool_server, tool_name, subject_key, timestamp, \
             decision_kind, cost_charged_be, raw_json FROM chio_tool_receipts",
        )
        .test_expect("prepare stored row read");
    let rows = statement
        .query_map([], |row| {
            Ok(StoredRow {
                capability_id: row.get(0)?,
                tool_server: row.get(1)?,
                tool_name: row.get(2)?,
                subject_key: row.get(3)?,
                timestamp: row.get(4)?,
                decision_kind: row.get(5)?,
                cost_charged: row.get::<_, Option<[u8; 8]>>(6)?.map(u64::from_be_bytes),
                attempted_cost: signed_attempted_cost(&row.get::<_, String>(7)?),
            })
        })
        .test_expect("read stored rows");
    rows.map(|row| row.test_expect("stored row")).collect()
}

fn signed_attempted_cost(raw_json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(raw_json)
        .test_expect("fixture receipt is valid json")
        .get("metadata")
        .and_then(|metadata| metadata.get("financial"))
        .and_then(|financial| financial.get("attempted_cost"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn expected_metrics<'row>(rows: impl Iterator<Item = &'row StoredRow>) -> ReceiptAnalyticsMetrics {
    let mut total_receipts = 0_u64;
    let mut allow = 0_u64;
    let mut deny = 0_u64;
    let mut cancelled = 0_u64;
    let mut incomplete = 0_u64;
    let mut charged = 0_u128;
    let mut attempted = 0_u64;
    for row in rows {
        total_receipts += 1;
        match row.decision_kind.as_str() {
            "allow" => allow += 1,
            "deny" => deny += 1,
            "cancelled" => cancelled += 1,
            "incomplete" => incomplete += 1,
            other => panic!("unexpected decision kind {other}"),
        }
        charged += u128::from(row.cost_charged.unwrap_or(0));
        attempted += row.attempted_cost;
    }
    ReceiptAnalyticsMetrics::from_raw(
        total_receipts,
        allow,
        deny,
        cancelled,
        incomplete,
        u64::try_from(charged).test_expect("charged total fits the report"),
        attempted,
    )
}

type RowPredicate = Box<dyn Fn(&StoredRow) -> bool>;

/// A window narrow enough to select a handful of the fixture's receipts, used
/// both for the filter-shape comparison and for the scan ceiling.
const NARROW_WINDOW: (u64, u64) = (DAY_SECS, DAY_SECS + 20);

fn filter_shapes() -> Vec<(&'static str, ReceiptAnalyticsQuery, RowPredicate)> {
    let (since, until) = NARROW_WINDOW;
    vec![
        (
            "unfiltered",
            admin_query(),
            Box::new(|_: &StoredRow| true) as RowPredicate,
        ),
        (
            "capability",
            ReceiptAnalyticsQuery {
                capability_id: Some("cap-2".to_string()),
                ..admin_query()
            },
            Box::new(|row: &StoredRow| row.capability_id == "cap-2"),
        ),
        (
            "tool",
            ReceiptAnalyticsQuery {
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                ..admin_query()
            },
            Box::new(|row: &StoredRow| row.tool_server == "shell" && row.tool_name == "bash"),
        ),
        (
            "time window",
            ReceiptAnalyticsQuery {
                since: Some(since),
                until: Some(until),
                ..admin_query()
            },
            Box::new(move |row: &StoredRow| {
                row.timestamp >= since as i64 && row.timestamp <= until as i64
            }),
        ),
        (
            "agent subject",
            ReceiptAnalyticsQuery {
                agent_subject: Some("agent-beta".to_string()),
                ..admin_query()
            },
            Box::new(|row: &StoredRow| row.subject_key.as_deref() == Some("agent-beta")),
        ),
    ]
}

#[test]
fn analytics_report_totals_the_typed_projection_for_every_filter_shape() {
    let fixture = populate("chio-analytics-report-shapes", json_domain_receipts());
    let rows = stored_rows(&fixture);
    assert_eq!(rows.len(), fixture.receipts.len());
    assert!(
        rows.iter().any(|row| row.cost_charged.is_none()),
        "the fixture must carry receipts with no financial block"
    );

    for (shape, query, matches) in filter_shapes() {
        let report = fixture
            .store
            .query_receipt_analytics(&query)
            .test_expect(shape);
        let expected = expected_metrics(rows.iter().filter(|row| matches(row)));
        assert_eq!(report.summary, expected, "summary differs for {shape}");
        assert!(
            expected.total_receipts > 0,
            "{shape} selects no receipts, so it proves nothing"
        );
    }
}

#[test]
fn analytics_report_groups_match_the_typed_projection() {
    let fixture = populate("chio-analytics-report-groups", json_domain_receipts());
    let rows = stored_rows(&fixture);
    let report = fixture
        .store
        .query_receipt_analytics(&admin_query())
        .test_expect("analytics report");

    for agent in &report.by_agent {
        let expected = expected_metrics(
            rows.iter()
                .filter(|row| row.subject_key.as_deref() == Some(agent.subject_key.as_str())),
        );
        assert_eq!(agent.metrics, expected, "agent {}", agent.subject_key);
    }
    assert_eq!(
        report.by_agent.len(),
        rows.iter()
            .filter_map(|row| row.subject_key.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );

    for tool in &report.by_tool {
        let expected =
            expected_metrics(rows.iter().filter(|row| {
                row.tool_server == tool.tool_server && row.tool_name == tool.tool_name
            }));
        assert_eq!(
            tool.metrics, expected,
            "tool {}/{}",
            tool.tool_server, tool.tool_name
        );
    }

    let bucket = DAY_SECS as i64;
    for time in &report.by_time {
        let start = time.bucket_start as i64;
        let expected = expected_metrics(
            rows.iter()
                .filter(|row| (row.timestamp / bucket) * bucket == start),
        );
        assert_eq!(time.metrics, expected, "bucket {}", time.bucket_start);
    }
}

#[test]
fn analytics_report_returns_the_exact_charge_at_each_unsigned_boundary() {
    let fixture = populate("chio-analytics-boundaries", range_edge_receipts());
    for (capability_id, cost_charged) in RANGE_EDGE_COSTS {
        let report = fixture
            .store
            .query_receipt_analytics(&ReceiptAnalyticsQuery {
                capability_id: Some(capability_id.to_string()),
                ..admin_query()
            })
            .test_expect(capability_id);
        assert_eq!(report.summary.total_receipts, 1, "{capability_id}");
        assert_eq!(
            report.summary.total_cost_charged, cost_charged,
            "{capability_id}"
        );
    }

    let signed_overflow = fixture
        .store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            capability_id: Some(SIGNED_TOTAL_OVERFLOW_CAPABILITY.to_string()),
            ..admin_query()
        })
        .test_expect("charges beyond the signed total");
    assert_eq!(
        signed_overflow.summary.total_cost_charged,
        SIGNED_TOTAL_OVERFLOW_CHARGE * SIGNED_TOTAL_OVERFLOW_ROWS as u64
    );
}

#[test]
fn analytics_report_refuses_a_charge_total_beyond_the_reportable_range() {
    let fixture = populate("chio-analytics-unreportable", range_edge_receipts());
    let refusal = fixture
        .store
        .query_receipt_analytics(&admin_query())
        .test_unwrap_err();
    match refusal {
        ReceiptStoreError::Sqlite(rusqlite::Error::UserFunctionError(error)) => {
            let message = error.to_string();
            assert!(
                message.starts_with(COST_TOTAL_UNREPORTABLE),
                "unexpected refusal: {message}"
            );
        }
        other => panic!("expected an unreportable-total refusal, got {other:?}"),
    }
}

/// The report's own metric columns over the whole table, grouped as the summary
/// groups them and again as the time dimension does, so the two can be compared
/// across an append that lands between the two reads.
fn summary_and_bucketed_totals(source: &Connection) -> ((u64, u64), (u64, u64)) {
    let summary = source
        .query_row(
            &format!("SELECT {} FROM chio_tool_receipts r", metric_columns()),
            [],
            |row| metrics_from_row(row, 0),
        )
        .test_expect("summary metrics");

    let bucket_sql = format!(
        "SELECT CAST((r.timestamp / {DAY_SECS}) * {DAY_SECS} AS INTEGER) AS bucket_start, {} \
         FROM chio_tool_receipts r GROUP BY bucket_start",
        metric_columns()
    );
    let mut statement = source.prepare(&bucket_sql).test_expect("prepare buckets");
    let buckets = statement
        .query_map([], |row| metrics_from_row(row, 1))
        .test_expect("bucket metrics");
    let mut bucketed = (0_u64, 0_u64);
    for bucket in buckets {
        let metrics = bucket.test_expect("bucket row");
        bucketed.0 += metrics.total_receipts;
        bucketed.1 += metrics.total_cost_charged;
    }

    (
        (summary.total_receipts, summary.total_cost_charged),
        bucketed,
    )
}

fn append_one_more(fixture: &Fixture, id: usize) {
    let receipt = FixtureReceipt {
        capability_id: "cap-interleaved".to_string(),
        subject_key: "agent-interleaved",
        tool_server: "shell",
        tool_name: "bash",
        decision: Decision::Allow,
        timestamp: DAY_SECS,
        financial: Some((11, None)),
    };
    fixture
        .store
        .append_chio_receipt_returning_seq(&sign_fixture_receipt(100_000 + id, &receipt))
        .test_expect("append an interleaved receipt");
    fixture
        .store
        .flush_receipt_writes()
        .test_expect("flush the interleaved receipt");
}

#[test]
fn a_report_reads_one_snapshot_across_its_dimensions() {
    let fixture = populate("chio-analytics-snapshot", json_domain_receipts());
    let connection = fixture.store.connection().test_expect("reader connection");
    register_total_cost_charged(&connection).test_expect("register charged-cost aggregate");

    let snapshot = report_snapshot(&connection).test_expect("report snapshot");
    let (summary, _) = summary_and_bucketed_totals(&snapshot);
    append_one_more(&fixture, 1);
    let (_, bucketed) = summary_and_bucketed_totals(&snapshot);
    assert_eq!(
        summary, bucketed,
        "an append between two dimensions reached the second one"
    );
    drop(snapshot);

    // Outside a snapshot the same interleaving is visible, which is what makes
    // the snapshot load-bearing rather than decorative.
    let (unpinned_summary, _) = summary_and_bucketed_totals(&connection);
    append_one_more(&fixture, 2);
    let (_, unpinned_buckets) = summary_and_bucketed_totals(&connection);
    assert_eq!(
        unpinned_buckets,
        (unpinned_summary.0 + 1, unpinned_summary.1 + 11),
        "statements outside a snapshot are expected to see the append"
    );

    let report = fixture
        .store
        .query_receipt_analytics(&admin_query())
        .test_expect("analytics report");
    assert_eq!(report.summary.total_receipts, summary.0 + 2);
    assert_eq!(report.summary.total_cost_charged, summary.1 + 22);
}
