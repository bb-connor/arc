//! Error and evidence text of the `SAFE` data-layer guards.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_data_guards::{
    QueryResultGuard, QueryResultGuardConfig, SqlGuardConfig, SqlQueryGuard, VectorDbGuard,
    VectorGuardConfig, WarehouseCostGuard, WarehouseCostGuardConfig,
};
use chio_kernel::{
    Guard, GuardContext, GuardEvidenceDeclaration, ToolCallRequest, ToolServerOutput,
};
use serde_json::{json, Value};

const MARKER: &str = "chio-data-guard-err-marker-9a41";

/// Guards with no `Err` path on the `Guard` trait: `query-result` acts on
/// output through its post-invocation hook and allows every guard call.
const ERR_UNREACHABLE_FROM_INPUT: &[&str] = &["query-result"];

fn safe_guards() -> Vec<Box<dyn Guard>> {
    vec![
        Box::new(SqlQueryGuard::new(SqlGuardConfig::default())),
        Box::new(VectorDbGuard::new(VectorGuardConfig::default())),
        Box::new(WarehouseCostGuard::new(WarehouseCostGuardConfig::default())),
        Box::new(QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap()),
    ]
}

/// Database, vector and warehouse calls with the marker in every argument
/// value, plus a mistyped shape of each.
fn marker_calls() -> Vec<(String, Value)> {
    let m = MARKER;
    let mut calls = vec![
        (
            "execute_sql".to_string(),
            json!({ "database": m, "query": format!("SELECT {m} FROM {m}; DROP TABLE {m}") }),
        ),
        (
            "run_sql".to_string(),
            json!({ "sql": format!("DELETE FROM {m} WHERE x = '{m}'") }),
        ),
        (
            "vector_search".to_string(),
            json!({ "collection": m, "namespace": m, "query": m, "top_k": 100_000 }),
        ),
        (
            "vector_upsert".to_string(),
            json!({ "collection": m, "vectors": [{ "id": m, "metadata": { m: m } }] }),
        ),
        (
            "bigquery".to_string(),
            json!({ "query": format!("SELECT * FROM `{m}`"), "dry_run_bytes": m }),
        ),
        (
            "snowflake".to_string(),
            json!({ "statement": format!("SELECT {m}"), "warehouse": m }),
        ),
    ];
    let mistyped: Vec<(String, Value)> = calls
        .iter()
        .map(|(tool, args)| {
            let object = args.as_object().cloned().unwrap_or_default();
            let mistyped = object
                .keys()
                .map(|key| (key.clone(), json!({ m: [m, 7] })))
                .collect::<serde_json::Map<_, _>>();
            (tool.clone(), Value::Object(mistyped))
        })
        .collect();
    calls.extend(mistyped);
    calls.push(("execute_sql".to_string(), json!(m)));
    calls
}

fn marker_request(tool: &str, arguments: Value) -> (ToolCallRequest, ChioScope) {
    let keypair = Keypair::generate();
    let scope = ChioScope::default();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{MARKER}"),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .unwrap();
    let request = ToolCallRequest {
        request_id: format!("req-{MARKER}"),
        capability,
        tool_name: tool.to_string(),
        server_id: format!("srv-{MARKER}"),
        agent_id: format!("agent-{MARKER}"),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    (request, scope)
}

fn assert_no_marker(guard: &dyn Guard, tool: &str, text: &str) {
    assert!(
        !text.contains(MARKER),
        "{} carries request or result text for {tool}: {text}",
        guard.name()
    );
}

/// A `SAFE` guard's `Err` text becomes the signed deny reason, so neither it
/// nor any evidence detail carries request or result text. Each guard either
/// reaches an `Err` path here or is listed as having none reachable from input.
#[test]
fn safe_data_guard_err_text_is_static() {
    let guards = safe_guards();
    let output = ToolServerOutput::Value(json!({
        "rows": [{ "email": format!("{MARKER}@example.com"), "ssn": "123-45-6789", MARKER: MARKER }],
    }));
    let mut reached = BTreeSet::new();
    for (tool, arguments) in marker_calls() {
        let (request, scope) = marker_request(&tool, arguments);
        let agent_id = request.agent_id.clone();
        let server_id = request.server_id.clone();
        for guard in &guards {
            let guard = guard.as_ref();
            assert_eq!(
                guard.evidence_declaration(),
                GuardEvidenceDeclaration::SAFE,
                "{}",
                guard.name()
            );
            let mut ctx = GuardContext::new(&request, &scope);
            ctx.agent_id = &agent_id;
            ctx.server_id = &server_id;
            ctx.matched_grant_index = Some(0);
            match guard.evaluate(&ctx) {
                Ok(decision) => {
                    for evidence in &decision.evidence {
                        assert_no_marker(guard, &tool, evidence.details.as_deref().unwrap_or(""));
                    }
                }
                Err(error) => {
                    reached.insert(guard.name().to_string());
                    assert_no_marker(guard, &tool, &error.to_string());
                }
            }
            for result in [
                guard.revalidate_before_dispatch(&ctx),
                guard.validate_output_before_release(&ctx, &output),
            ] {
                if let Err(error) = result {
                    reached.insert(guard.name().to_string());
                    assert_no_marker(guard, &tool, &error.to_string());
                }
            }
        }
    }
    let mismatched: Vec<(String, bool)> = guards
        .iter()
        .map(|guard| guard.name())
        .filter(|name| reached.contains(*name) == ERR_UNREACHABLE_FROM_INPUT.contains(name))
        .map(|name| (name.to_string(), reached.contains(name)))
        .collect();
    assert!(
        mismatched.is_empty(),
        "each guard must reach an Err path or be listed as unreachable; (guard, reached): {mismatched:?}"
    );
}
