//! Receipt analytics report, measured against a populated receipt table in the
//! filter shapes callers actually send.
//!
//! The report aggregates financial totals over every matching receipt, so its
//! cost grows with history. Measuring it on an empty table would report the cost
//! of preparing four statements.

use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::economics::{FinancialReceiptMetadata, SettlementStatus};
use chio_core::receipt::metadata::ReceiptAttributionMetadata;
use chio_kernel::{AnalyticsTimeBucket, ReceiptAnalyticsQuery, ReceiptReadContext};
use chio_store_sqlite::SqliteReceiptStore;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Receipts in the table before the first measured report.
const POPULATED_RECEIPTS: u64 = 20_000;

const SUBJECTS: usize = 97;
const CAPABILITIES: u64 = 500;
const TOOL_SERVERS: usize = 7;
const TOOL_NAMES: usize = 13;
const FIRST_TIMESTAMP: u64 = 1_700_000_000;

/// Timestamps advance one second per receipt, so this window covers a tenth of
/// the populated corpus.
const WINDOW_SECS: u64 = POPULATED_RECEIPTS / 10;

fn fail_bench(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

fn unique_db_path() -> std::path::PathBuf {
    let nonce = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos(),
        Err(error) => fail_bench(&format!("time before epoch: {error}")),
    };
    std::env::temp_dir().join(format!("chio-bench-receipt-analytics-{nonce}.sqlite3"))
}

fn subject_key(index: u64) -> String {
    format!("bench-agent-{}", index % SUBJECTS as u64)
}

fn tool_server(index: u64) -> String {
    format!("bench-server-{}", index % TOOL_SERVERS as u64)
}

fn tool_name(index: u64) -> String {
    format!("bench-tool-{}", index % TOOL_NAMES as u64)
}

fn receipt_for_index(index: u64, keypair: &Keypair) -> ChioReceipt {
    let decision = match index % 4 {
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
    };
    // Every eighth receipt carries no financial block, which is the NULL case the
    // charged-cost aggregate has to skip.
    let financial = (!index.is_multiple_of(8)).then(|| FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: (index % 977) + 1,
        currency: "USD".to_string(),
        budget_remaining: 10_000,
        budget_total: 20_000,
        delegation_depth: 1,
        root_budget_holder: "bench-root".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Settled,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: index.is_multiple_of(5).then_some((index % 977) * 2),
    });
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key(index),
            issuer_key: "bench-issuer".to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": financial,
    });
    let action = match ToolCallAction::from_parameters(serde_json::json!({ "index": index })) {
        Ok(action) => action,
        Err(error) => fail_bench(&format!("valid tool call action: {error}")),
    };

    match ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("bench-analytics-receipt-{index}"),
            timestamp: FIRST_TIMESTAMP + index,
            capability_id: format!("bench-capability-{}", index % CAPABILITIES),
            tool_server: tool_server(index),
            tool_name: tool_name(index),
            action,
            decision: Some(decision),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("bench-content-{index}"),
            policy_hash: "bench-policy".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    ) {
        Ok(receipt) => receipt,
        Err(error) => fail_bench(&format!("sign receipt: {error}")),
    }
}

fn populated_store(path: &std::path::Path) -> SqliteReceiptStore {
    let store = match SqliteReceiptStore::open(path) {
        Ok(store) => store,
        Err(error) => fail_bench(&format!("open sqlite receipt store: {error}")),
    };
    let keypair = Keypair::generate();
    for index in 0..POPULATED_RECEIPTS {
        if let Err(error) =
            store.append_chio_receipt_returning_seq(&receipt_for_index(index, &keypair))
        {
            fail_bench(&format!("populate receipt: {error}"));
        }
    }
    if let Err(error) = store.flush_receipt_writes() {
        fail_bench(&format!("flush populated receipts: {error}"));
    }
    store
}

fn analytics_query() -> ReceiptAnalyticsQuery {
    ReceiptAnalyticsQuery {
        group_limit: Some(50),
        time_bucket: Some(AnalyticsTimeBucket::Day),
        read_context: Some(ReceiptReadContext::local_operator_admin_all()),
        ..ReceiptAnalyticsQuery::default()
    }
}

fn bench_receipt_analytics_report(c: &mut Criterion) {
    let path = unique_db_path();
    let store = populated_store(&path);

    let window_start = FIRST_TIMESTAMP + POPULATED_RECEIPTS / 2;
    let shapes: [(&str, ReceiptAnalyticsQuery); 5] = [
        ("unfiltered", analytics_query()),
        (
            "capability",
            ReceiptAnalyticsQuery {
                capability_id: Some("bench-capability-3".to_string()),
                ..analytics_query()
            },
        ),
        (
            "time_window",
            ReceiptAnalyticsQuery {
                since: Some(window_start),
                until: Some(window_start + WINDOW_SECS),
                ..analytics_query()
            },
        ),
        (
            "tool",
            ReceiptAnalyticsQuery {
                tool_server: Some(tool_server(3)),
                tool_name: Some(tool_name(3)),
                ..analytics_query()
            },
        ),
        (
            "agent_subject",
            ReceiptAnalyticsQuery {
                agent_subject: Some(subject_key(5)),
                ..analytics_query()
            },
        ),
    ];

    let mut group = c.benchmark_group("receipt_analytics_report_populated");
    for (shape, query) in &shapes {
        group.bench_function(*shape, |b| {
            b.iter(|| match store.query_receipt_analytics(query) {
                Ok(response) => {
                    black_box(response);
                }
                Err(error) => fail_bench(&format!("receipt analytics report ({shape}): {error}")),
            });
        });
    }
    group.finish();

    drop(store);
    let _ = std::fs::remove_file(path);
}

criterion_group!(benches, bench_receipt_analytics_report);
criterion_main!(benches);
