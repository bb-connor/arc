//! Original-byte MCP ingress refuses without dispatch and retains observations.

use super::*;
use chio_core::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::kinds::{BoundaryClass, ReceiptKind};
use chio_kernel::{ChioKernel, KernelConfig, KernelError, ReceiptStore, ToolServerConnection};
use chio_manifest::ToolManifest;
use chio_mcp_adapter::edge::ingress::mcp_inbox;
use chio_mcp_adapter::edge::{ChioMcpEdge, McpEdgeConfig};
use chio_store_sqlite::SqliteReceiptStore;
use std::sync::atomic::AtomicUsize;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CountedTool(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountedTool {
    fn server_id(&self) -> &str {
        "refusal-srv"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"unexpected_dispatch":true}))
    }
}

fn edge_fixture(
    path: &std::path::Path,
    constraint: Constraint,
    invalid_matcher: bool,
) -> TestResult<(ChioMcpEdge, Arc<AtomicUsize>)> {
    let signer = Keypair::generate();
    let config = KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "protocol-refusal-policy".into(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };
    let mut kernel = ChioKernel::new_with_clock(config, chio_test_support::clock::clock());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(path)?))?;
    let calls = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountedTool(calls.clone())));
    let agent = Keypair::generate();
    let mut capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "refusal-srv".into(),
                tool_name: "read_file".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![constraint],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        300,
    )?;
    if invalid_matcher {
        capability.scope.grants[0].constraints = vec![Constraint::RegexMatch("(".into())];
    }
    let manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.into(),
        server_id: "refusal-srv".into(),
        name: "Refusal Test".into(),
        description: None,
        version: "0.1.0".into(),
        tools: vec![chio_manifest::ToolDefinition {
            name: "read_file".into(),
            description: "Read".into(),
            input_schema: json!({"type":"object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: vec![],
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    Ok((
        ChioMcpEdge::new(
            McpEdgeConfig::default(),
            kernel,
            agent.public_key().to_hex(),
            vec![capability],
            vec![manifest],
        )?,
        calls,
    ))
}

fn serve_request(edge: &mut ChioMcpEdge, request: &Value) -> TestResult<(Value, Vec<u8>)> {
    let (sender, receiver) = mcp_inbox();
    for value in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    ] {
        let bytes = serde_json::to_vec(&value)?;
        sender.send(sender.decode(&bytes, 4 * 1024 * 1024)?)?;
    }
    let mut bytes = b"  ".to_vec();
    bytes.extend(serde_json::to_vec(request)?);
    bytes.extend(b" \n");
    sender.send(sender.decode(&bytes, 4 * 1024 * 1024)?)?;
    drop(sender);
    let mut output = Vec::new();
    edge.serve_inbox(receiver, &mut output)?;
    let response = std::str::from_utf8(&output)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|value| value.get("id") == Some(&json!(2)))
        .ok_or("refusal response")?;
    Ok((response, bytes))
}

fn refusal_evidence(response: &Value) -> &Value {
    response
        .pointer("/result/_meta/chioProtocolRefusal")
        .or_else(|| response.pointer("/error/data/chioProtocolRefusal"))
        .unwrap_or(&Value::Null)
}

#[test]
fn protocol_refusal_original_ingress_is_durable_without_logging_or_dispatch() -> TestResult {
    for (method, constraint, params, invalid_matcher, reason) in [
        (
            "tools/call",
            Constraint::PathPrefix("/allowed/".into()),
            json!({"name":"read_file","arguments":{"path":"/denied/raw-argument-sentinel"}}),
            false,
            "capability_not_matched",
        ),
        (
            "tools/call",
            Constraint::ModelConstraint {
                allowed_model_ids: vec!["allowed-model".into()],
                min_safety_tier: None,
            },
            json!({"name":"read_file","arguments":{},"_meta":{"modelMetadata":{"model_id":"denied-model"}}}),
            false,
            "capability_not_matched",
        ),
        (
            "tools/call",
            Constraint::PathPrefix("/allowed/".into()),
            json!({"name":"read_file","arguments":{"path":"/allowed/file"}}),
            true,
            "capability_matcher_invalid",
        ),
        (
            "resources/read",
            Constraint::PathPrefix("/allowed/".into()),
            json!({"uri":"repo://denied/raw-target-sentinel"}),
            false,
            "capability_not_matched",
        ),
        (
            "prompts/get",
            Constraint::PathPrefix("/allowed/".into()),
            json!({"name":"denied-prompt","arguments":{"secret":"raw-argument-sentinel"}}),
            false,
            "capability_not_matched",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("receipts.db");
        let (mut edge, calls) = edge_fixture(&path, constraint, invalid_matcher)?;
        let mut params = params;
        params
            .as_object_mut()
            .ok_or("params")?
            .entry("_meta")
            .or_insert_with(|| json!({}))["protocol_refusal"] = json!({"reason":"forged","tenant_id":"forged-tenant","auth_epoch":9000,"token":"raw-token-sentinel"});
        let request = json!({"jsonrpc":"2.0","id":2,"method":method,"params":params});
        let (response, original_bytes) = serve_request(&mut edge, &request)?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let evidence = refusal_evidence(&response);
        assert_eq!(
            evidence["status"], "retained",
            "refusal lacked retained evidence: {response}"
        );
        let receipt: ChioReceipt = serde_json::from_value(evidence["receipt"].clone())?;
        assert!(receipt.verify_signature()?);
        assert!(receipt.action.verify_hash()?);
        assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
        assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
        assert!(receipt.decision.is_none());
        assert!(!receipt.is_allowed());
        assert!(receipt.capability_id.is_empty());
        assert!(response
            .pointer("/result/_meta/chioExecutionNonce")
            .is_none());
        let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
        assert_eq!(event["reason"], reason);
        assert_eq!(event["request_digest"]["source"], "original_wire");
        assert_eq!(
            event["request_digest"]["sha256"],
            sha256_hex(&original_bytes)
        );
        let encoded = serde_json::to_string(&receipt)?;
        for raw in [
            "raw-argument-sentinel",
            "raw-target-sentinel",
            "raw-token-sentinel",
            "forged-tenant",
        ] {
            assert!(!encoded.contains(raw));
        }
        drop(edge);
        let reopened = SqliteReceiptStore::open(&path)?;
        let retained = reopened
            .load_chio_receipt(&receipt.id)?
            .ok_or("retained refusal")?;
        assert_eq!(
            canonical_json_bytes(&retained)?,
            canonical_json_bytes(&receipt)?
        );
        assert!(retained.verify_signature()?);
        let conn = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })?;
        assert_eq!(count, 1);
    }
    Ok(())
}

#[test]
fn protocol_refusal_failed_persistence_keeps_denial_and_reports_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.db");
    let (mut edge, calls) = edge_fixture(&path, Constraint::PathPrefix("/allowed/".into()), false)?;
    let conn = rusqlite::Connection::open(&path)?;
    conn.execute_batch("CREATE TRIGGER fail_refusal BEFORE INSERT ON chio_tool_receipts BEGIN SELECT RAISE(ABORT, 'test refusal writer failure'); END;")?;
    drop(conn);
    let (response, _) = serve_request(
        &mut edge,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"read_file","arguments":{"path":"/denied/file"}}}),
    )?;
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(refusal_evidence(&response)["status"], "unavailable");
    assert!(refusal_evidence(&response).get("receipt").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(edge);
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 0);
    Ok(())
}
