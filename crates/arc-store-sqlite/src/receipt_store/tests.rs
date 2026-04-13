#[allow(clippy::expect_used, clippy::unwrap_used)]
use std::time::{SystemTime, UNIX_EPOCH};

use arc_core::capability::{
    ArcScope, CapabilityToken, CapabilityTokenBody, MonetaryAmount, Operation, ToolGrant,
};
use arc_core::crypto::Keypair;
use arc_core::receipt::{
    ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
    FinancialReceiptMetadata, ReceiptAttributionMetadata, SettlementStatus, ToolCallAction,
};
use arc_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use arc_kernel::{build_checkpoint, AnalyticsTimeBucket, ReceiptAnalyticsQuery};

use super::*;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn sample_receipt() -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: "rcpt-test-001".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({}),
                parameter_hash: "abc123".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn sample_child_receipt() -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: "child-rcpt-test-001".to_string(),
            timestamp: 2,
            session_id: SessionId::new("sess-1"),
            parent_request_id: RequestId::new("parent-1"),
            request_id: RequestId::new("child-1"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-1".to_string(),
            policy_hash: "policy-1".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

#[test]
fn sqlite_receipt_store_persists_across_reopen() {
    let path = unique_db_path("arc-receipts");
    {
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        store.append_arc_receipt(&sample_receipt()).unwrap();
        store.append_child_receipt(&sample_child_receipt()).unwrap();
        assert_eq!(store.tool_receipt_count().unwrap(), 1);
        assert_eq!(store.child_receipt_count().unwrap(), 1);
    }

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    assert_eq!(reopened.tool_receipt_count().unwrap(), 1);
    assert_eq!(reopened.child_receipt_count().unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_lists_filtered_receipts() {
    let path = unique_db_path("arc-receipts-filtered");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    store.append_arc_receipt(&sample_receipt()).unwrap();
    store.append_child_receipt(&sample_child_receipt()).unwrap();

    let tool_receipts = store
        .list_tool_receipts(
            10,
            Some("cap-1"),
            Some("shell"),
            Some("bash"),
            Some("allow"),
        )
        .unwrap();
    assert_eq!(tool_receipts.len(), 1);
    assert_eq!(tool_receipts[0].capability_id, "cap-1");
    assert_eq!(tool_receipts[0].tool_name, "bash");

    let child_receipts = store
        .list_child_receipts(
            10,
            Some("sess-1"),
            Some("parent-1"),
            Some("child-1"),
            Some("create_message"),
            Some("completed"),
        )
        .unwrap();
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
    assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

    let _ = fs::remove_file(path);
}

fn sample_receipt_with_id(id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({}),
                parameter_hash: "abc123".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

#[test]
fn open_creates_kernel_checkpoints_table() {
    let path = unique_db_path("arc-receipts-cp-table");
    let store = SqliteReceiptStore::open(&path).unwrap();
    // Query the table to confirm it exists.
    let count: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn append_arc_receipt_returning_seq_returns_seq() {
    let path = unique_db_path("arc-receipts-seq");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let receipt = sample_receipt_with_id("rcpt-seq-001");
    let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
    assert!(seq > 0, "seq should be non-zero for a new insert");
    let _ = fs::remove_file(path);
}

#[test]
fn append_100_receipts_seqs_span_1_to_100() {
    let path = unique_db_path("arc-receipts-100");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let mut seqs = Vec::new();
    for i in 0..100usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
        let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
        seqs.push(seq);
    }
    assert_eq!(seqs[0], 1);
    assert_eq!(seqs[99], 100);
    let _ = fs::remove_file(path);
}

#[test]
fn store_and_load_checkpoint_by_seq() {
    let path = unique_db_path("arc-receipts-cp-store");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    // Append 5 receipts.
    let mut seqs = Vec::new();
    for i in 0..5usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
        let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
        seqs.push(seq);
    }

    // Build checkpoint.
    let kp = Keypair::generate();
    let bytes: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("receipt-bytes-{i}").into_bytes())
        .collect();
    let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).unwrap();

    // Store and retrieve.
    store.store_checkpoint(&cp).unwrap();
    let loaded = store.load_checkpoint_by_seq(1).unwrap();
    assert!(loaded.is_some(), "checkpoint should be loadable");
    let loaded = loaded.unwrap();
    assert_eq!(loaded.body.checkpoint_seq, 1);
    assert_eq!(loaded.body.tree_size, 5);
    assert_eq!(loaded.body.batch_start_seq, seqs[0]);
    assert_eq!(loaded.body.batch_end_seq, seqs[4]);
    assert_eq!(
        loaded.signature.to_hex(),
        cp.signature.to_hex(),
        "signature should round-trip"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn load_checkpoint_by_seq_returns_none_for_missing() {
    let path = unique_db_path("arc-receipts-cp-missing");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let result = store.load_checkpoint_by_seq(999).unwrap();
    assert!(result.is_none());
    let _ = fs::remove_file(path);
}

#[test]
fn receipts_canonical_bytes_range_returns_correct_count() {
    let path = unique_db_path("arc-receipts-canon-range");
    let mut store = SqliteReceiptStore::open(&path).unwrap();

    for i in 0..10usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
        store.append_arc_receipt_returning_seq(&receipt).unwrap();
    }

    // Fetch seqs 3..=7 (5 receipts).
    let range = store.receipts_canonical_bytes_range(3, 7).unwrap();
    assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
    assert_eq!(range[0].0, 3);
    assert_eq!(range[4].0, 7);

    // Verify all bytes are non-empty canonical JSON.
    for (_, bytes) in &range {
        assert!(!bytes.is_empty());
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    }

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_analytics_groups_by_agent_tool_and_time() {
    let path = unique_db_path("arc-receipts-analytics");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let keypair = Keypair::generate();

    let make_receipt = |id: &str,
                        subject_key: &str,
                        tool_server: &str,
                        tool_name: &str,
                        decision: Decision,
                        timestamp: u64,
                        cost_charged: u64,
                        attempted_cost: Option<u64>| {
        let financial = if cost_charged > 0 || attempted_cost.is_some() {
            Some(FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 1_000,
                budget_total: 2_000,
                delegation_depth: 0,
                root_budget_holder: "root-agent".to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            })
        } else {
            None
        };
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_key.to_string(),
                issuer_key: "issuer-key".to_string(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": financial,
        });

        ArcReceipt::sign(
            ArcReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: format!("cap-{subject_key}"),
                tool_server: tool_server.to_string(),
                tool_name: tool_name.to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-analytics".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    };

    store
        .append_arc_receipt(&make_receipt(
            "analytics-1",
            "agent-a",
            "shell",
            "bash",
            Decision::Allow,
            86_400,
            100,
            None,
        ))
        .unwrap();
    store
        .append_arc_receipt(&make_receipt(
            "analytics-2",
            "agent-a",
            "shell",
            "bash",
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            86_450,
            0,
            Some(50),
        ))
        .unwrap();
    store
        .append_arc_receipt(&make_receipt(
            "analytics-3",
            "agent-b",
            "files",
            "read",
            Decision::Incomplete {
                reason: "stream ended".to_string(),
            },
            172_800,
            0,
            None,
        ))
        .unwrap();

    let analytics = store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            group_limit: Some(10),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            ..ReceiptAnalyticsQuery::default()
        })
        .unwrap();

    assert_eq!(analytics.summary.total_receipts, 3);
    assert_eq!(analytics.summary.allow_count, 1);
    assert_eq!(analytics.summary.deny_count, 1);
    assert_eq!(analytics.summary.incomplete_count, 1);
    assert_eq!(analytics.summary.total_cost_charged, 100);
    assert_eq!(analytics.summary.total_attempted_cost, 50);
    assert_eq!(
        analytics.summary.reliability_score,
        Some(0.5),
        "allow / (allow + incomplete)"
    );
    assert_eq!(
        analytics.summary.compliance_rate,
        Some(2.0 / 3.0),
        "1 - deny / total"
    );
    assert_eq!(
        analytics.summary.budget_utilization_rate,
        Some(100.0 / 150.0)
    );

    assert_eq!(analytics.by_agent.len(), 2);
    assert_eq!(analytics.by_agent[0].subject_key, "agent-a");
    assert_eq!(analytics.by_agent[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_tool.len(), 2);
    assert_eq!(analytics.by_tool[0].tool_server, "shell");
    assert_eq!(analytics.by_tool[0].tool_name, "bash");
    assert_eq!(analytics.by_tool[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_time.len(), 2);
    assert_eq!(analytics.by_time[0].bucket_start, 86_400);
    assert_eq!(analytics.by_time[1].bucket_start, 172_800);

    let _ = fs::remove_file(path);
}

#[test]
fn cost_attribution_report_aggregates_matching_corpus_and_limits_detail_rows() {
    let path = unique_db_path("arc-receipts-cost-attribution");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: ArcScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope: ArcScope::default(),
            issued_at: 1_100,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();

    store.record_capability_snapshot(&root, None).unwrap();
    store
        .record_capability_snapshot(&child, Some("cap-root"))
        .unwrap();

    let make_financial_receipt = |id: &str,
                                  capability_id: &str,
                                  subject_key: Option<String>,
                                  root_budget_holder: &str,
                                  delegation_depth: u32,
                                  timestamp: u64,
                                  decision: Decision,
                                  cost_charged: u64,
                                  attempted_cost: Option<u64>| {
        let attribution = subject_key.map(|subject_key| ReceiptAttributionMetadata {
            subject_key,
            issuer_key: issuer_hex.clone(),
            delegation_depth,
            grant_index: Some(0),
        });
        let metadata = serde_json::json!({
            "attribution": attribution,
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 900,
                budget_total: 1_000,
                delegation_depth,
                root_budget_holder: root_budget_holder.to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ArcReceipt::sign(
            ArcReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: format!("param-{id}"),
                },
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-cost".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                kernel_key: receipt_kp.public_key(),
            },
            &receipt_kp,
        )
        .unwrap()
    };

    store
        .append_arc_receipt(&make_financial_receipt(
            "cost-1",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_200,
            Decision::Allow,
            125,
            None,
        ))
        .unwrap();
    store
        .append_arc_receipt(&make_financial_receipt(
            "cost-2",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_201,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            0,
            Some(75),
        ))
        .unwrap();
    store
        .append_arc_receipt(&make_financial_receipt(
            "cost-3",
            "cap-orphan",
            None,
            "orphan-root",
            2,
            1_202,
            Decision::Allow,
            50,
            None,
        ))
        .unwrap();

    let report = store
        .query_cost_attribution_report(&CostAttributionQuery {
            limit: Some(1),
            ..CostAttributionQuery::default()
        })
        .unwrap();

    assert_eq!(report.summary.matching_receipts, 3);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.total_cost_charged, 175);
    assert_eq!(report.summary.total_attempted_cost, 75);
    assert_eq!(report.summary.max_delegation_depth, 2);
    assert_eq!(report.summary.distinct_root_subjects, 2);
    assert_eq!(report.summary.distinct_leaf_subjects, 1);
    assert_eq!(report.summary.lineage_gap_count, 1);
    assert!(report.summary.truncated);

    assert_eq!(report.by_root.len(), 2);
    assert_eq!(
        report.by_root[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(report.by_root[0].receipt_count, 2);
    assert_eq!(report.by_root[0].total_cost_charged, 125);
    assert_eq!(report.by_root[0].total_attempted_cost, 75);
    assert_eq!(report.by_root[0].distinct_leaf_subjects, 1);

    assert_eq!(report.by_leaf.len(), 1);
    assert_eq!(
        report.by_leaf[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(
        report.by_leaf[0].leaf_subject_key.as_str(),
        leaf_hex.as_str()
    );
    assert_eq!(report.by_leaf[0].receipt_count, 2);
    assert_eq!(report.by_leaf[0].total_cost_charged, 125);
    assert_eq!(report.by_leaf[0].total_attempted_cost, 75);

    assert_eq!(report.receipts.len(), 1);
    assert_eq!(report.receipts[0].capability_id, "cap-child");
    assert_eq!(
        report.receipts[0].root_subject_key.as_deref(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        report.receipts[0].leaf_subject_key.as_deref(),
        Some(leaf_hex.as_str())
    );
    assert!(report.receipts[0].lineage_complete);
    assert_eq!(report.receipts[0].chain.len(), 2);

    let _ = fs::remove_file(path);
}

#[test]
fn compliance_report_counts_proof_and_lineage_coverage_truthfully() {
    let path = unique_db_path("arc-receipts-compliance");
    let mut store = SqliteReceiptStore::open(&path).unwrap();
    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-compliance".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ArcScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(4),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1000,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .unwrap();
    store.record_capability_snapshot(&token, None).unwrap();

    let make_receipt = |id: &str,
                        timestamp: u64,
                        decision: Decision,
                        settlement_status: SettlementStatus,
                        attempted_cost: Option<u64>| {
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_hex.clone(),
                issuer_key: issuer_hex.clone(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged: if attempted_cost.is_some() { 0 } else { 250 },
                currency: "USD".to_string(),
                budget_remaining: 750,
                budget_total: 1000,
                delegation_depth: 0,
                root_budget_holder: subject_hex.clone(),
                payment_reference: None,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ArcReceipt::sign(
            ArcReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: "cap-compliance".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: format!("param-{id}"),
                },
                decision,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-compliance".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                kernel_key: checkpoint_kp.public_key(),
            },
            &checkpoint_kp,
        )
        .unwrap()
    };

    let seq = store
        .append_arc_receipt_returning_seq(&make_receipt(
            "compliance-1",
            2_000,
            Decision::Allow,
            SettlementStatus::Settled,
            None,
        ))
        .unwrap();
    store
        .append_arc_receipt(&make_receipt(
            "compliance-2",
            2_001,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            SettlementStatus::Pending,
            Some(100),
        ))
        .unwrap();

    let bytes = store
        .receipts_canonical_bytes_range(seq, seq)
        .unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();
    let checkpoint = build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).unwrap();
    store.store_checkpoint(&checkpoint).unwrap();

    let report = store
        .query_compliance_report(&OperatorReportQuery {
            agent_subject: Some(subject_hex.clone()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            ..OperatorReportQuery::default()
        })
        .unwrap();

    assert_eq!(report.matching_receipts, 2);
    assert_eq!(report.evidence_ready_receipts, 1);
    assert_eq!(report.uncheckpointed_receipts, 1);
    assert_eq!(report.lineage_covered_receipts, 2);
    assert_eq!(report.lineage_gap_receipts, 0);
    assert_eq!(report.pending_settlement_receipts, 1);
    assert_eq!(report.failed_settlement_receipts, 0);
    assert!(!report.direct_evidence_export_supported);
    assert_eq!(
        report.child_receipt_scope,
        crate::EvidenceChildReceiptScope::OmittedNoJoinPath
    );
    assert!(report
        .export_scope_note
        .as_deref()
        .is_some_and(|note| note.contains("tool filters narrow the operator report only")));

    let _ = fs::remove_file(path);
}
