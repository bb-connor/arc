//! Integration tests for `VectorDbGuard`.
//!
//! Drives the guard through the `arc_kernel::Guard` trait with realistic
//! capability scopes, verifying the acceptance criteria called out in
//! roadmap phase 7.2:
//!
//! - Query to a collection not in `CollectionAllowlist` is denied.
//! - Cross-namespace access is denied.
//! - Upsert is denied when the operation class is `ReadOnly`.
//! - `top_k=500` is denied when `MaxRowsReturned=50`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use arc_core::capability::{
    ArcScope, CapabilityToken, CapabilityTokenBody, Constraint, Operation, SqlOperationClass,
    ToolGrant,
};
use arc_core::crypto::Keypair;
use arc_data_guards::{VectorDbGuard, VectorGuardConfig};
use arc_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn grant(constraints: Vec<Constraint>) -> ToolGrant {
    ToolGrant {
        server_id: "srv-vec".into(),
        tool_name: "*".into(),
        operations: vec![Operation::Invoke],
        constraints,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_request(
    tool: &str,
    args: serde_json::Value,
    scope: ArcScope,
) -> (ArcScope, String, String, ToolCallRequest) {
    let kp = Keypair::generate();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-vec".to_string();

    let cap_body = CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
    };
    let cap = CapabilityToken::sign(cap_body, &kp).expect("sign cap");

    let req = ToolCallRequest {
        request_id: "req-vec".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
    };

    (scope, agent_id, server_id, req)
}

fn evaluate(
    guard: &VectorDbGuard,
    tool: &str,
    args: serde_json::Value,
    scope: ArcScope,
) -> Verdict {
    let (scope, agent_id, server_id, req) = make_request(tool, args, scope);
    let ctx = GuardContext {
        request: &req,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    guard.evaluate(&ctx).expect("evaluate should not error")
}

fn cfg_docs_only() -> VectorGuardConfig {
    VectorGuardConfig {
        collection_allowlist: vec!["docs".into()],
        ..Default::default()
    }
}

#[test]
fn denies_query_to_collection_not_in_allowlist() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone",
        serde_json::json!({
            "collection": "secrets",
            "operation": "query",
            "top_k": 10
        }),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allows_query_to_collection_in_allowlist() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 10
        }),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_cross_namespace_access() {
    let cfg = VectorGuardConfig {
        collection_allowlist: vec!["docs".into()],
        namespace_allowlist: Some(vec!["tenant-a".into()]),
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "qdrant",
        serde_json::json!({
            "collection": "docs",
            "namespace": "tenant-b",
            "operation": "query",
            "top_k": 10
        }),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_upsert_under_readonly_grant() {
    let scope = ArcScope {
        grants: vec![grant(vec![Constraint::OperationClass(
            SqlOperationClass::ReadOnly,
        )])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "weaviate",
        serde_json::json!({
            "collection": "docs",
            "operation": "upsert",
            "top_k": 1
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allows_query_under_readonly_grant() {
    let scope = ArcScope {
        grants: vec![grant(vec![
            Constraint::OperationClass(SqlOperationClass::ReadOnly),
            Constraint::MaxRowsReturned(50),
        ])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "qdrant",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 10
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_top_k_500_when_max_rows_returned_50() {
    let scope = ArcScope {
        grants: vec![grant(vec![Constraint::MaxRowsReturned(50)])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "chroma",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 500
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn passes_through_non_vector_database_actions() {
    // A request against a SQL-shaped database with no vendor marker in
    // the tool name or database id should pass the vector guard.
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "postgres",
        serde_json::json!({"query": "SELECT 1", "database": "postgres"}),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_parse_error_missing_collection() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone_query",
        // A memory-shaped call with no collection/index/class/store: the
        // guard should deny on parse error.
        serde_json::json!({"namespace": "anywhere"}),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allow_all_permits_any_vector_call() {
    let guard = VectorDbGuard::new(VectorGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "weaviate",
        serde_json::json!({
            "collection": "whatever",
            "operation": "upsert",
            "top_k": 50_000
        }),
        ArcScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn memory_read_action_routed_through_vector_guard() {
    // arc-guards maps `recall` into ToolAction::MemoryRead; the vector
    // guard must still be able to inspect it.
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "recall",
        // Must pick up "collection" and the tool name contains no vendor
        // marker, but the store field is "pinecone".
        serde_json::json!({
            "collection": "pinecone",
            "operation": "query",
            "top_k": 1
        }),
        ArcScope::default(),
    );
    // collection "pinecone" is not on the allowlist, so this is deny.
    assert_eq!(verdict, Verdict::Deny);
}
