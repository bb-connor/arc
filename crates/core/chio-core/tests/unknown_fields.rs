// Unknown-member handling for chio-core signed artifacts.
//
// Receipts and child receipts sign their body and ignore members outside it.
// The capability tree and signed manifests are closed: an unknown member at
// any layer fails to decode with serde's `unknown field` error.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::sha256_hex;
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::{
    capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    receipt::body::ChioReceipt,
    receipt::body::ChioReceiptBody,
    receipt::decision::Decision,
    receipt::decision::ToolCallAction,
    receipt::lineage::ChildRequestReceipt,
    receipt::lineage::ChildRequestReceiptBody,
    receipt::metadata::GuardEvidence,
    Keypair, ToolAnnotations, ToolDefinition,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_token_body(issuer_kp: &Keypair) -> CapabilityTokenBody {
    let subject_kp = Keypair::generate();
    CapabilityTokenBody {
        id: "cap-fwd-001".to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_000_000,
        expires_at: 2_000_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

fn make_receipt_body(kp: &Keypair) -> ChioReceiptBody {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "path": "/app/src/main.rs"
    }))
    .unwrap();
    ChioReceiptBody {
        id: "rcpt-fwd-001".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-fwd-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "deadbeefdeadbeef".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    }
}

fn make_tool_definition() -> ToolDefinition {
    ToolDefinition {
            name: "file_read".to_string(),
            description: "Read a file".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: Some(chio_core::manifest::LatencyHint::Fast),
            flow: None,
    }
}

fn make_delegation_link(delegator_kp: &Keypair, delegatee_kp: &Keypair) -> DelegationLink {
    let body = DelegationLinkBody {
        capability_id: "cap-fwd-001".to_string(),
        delegator: delegator_kp.public_key(),
        delegatee: delegatee_kp.public_key(),
        attenuations: vec![],
        timestamp: 1_000_100,
        scope_hash: None,
        aggregate_budget: None,
        cumulative_approval: None,
    };
    DelegationLink::sign(body, delegator_kp).unwrap()
}

fn make_child_receipt_body(kp: &Keypair) -> ChildRequestReceiptBody {
    ChildRequestReceiptBody {
        id: "child-fwd-001".to_string(),
        timestamp: 1_710_000_001,
        session_id: SessionId::new("sess-fwd-001"),
        parent_request_id: RequestId::new("parent-fwd-001"),
        request_id: RequestId::new("child-req-001"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
        policy_hash: "aabbccddaabbccdd".to_string(),
        metadata: None,
        kernel_key: kp.public_key(),
    }
}

#[test]
fn token_round_trips() {
    let kp = Keypair::generate();
    let body = make_token_body(&kp);
    let token = CapabilityToken::sign(body, &kp).unwrap();

    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

    assert_eq!(token.id, restored.id);
    assert_eq!(token.issuer, restored.issuer);
    assert_eq!(token.issued_at, restored.issued_at);
    assert_eq!(token.expires_at, restored.expires_at);
    assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn token_refuses_unknown_members() {
    let kp = Keypair::generate();
    let token = CapabilityToken::sign(make_token_body(&kp), &kp).unwrap();
    let value = serde_json::to_value(&token).unwrap();

    let mut envelope = value.clone();
    envelope["future_data"] = serde_json::json!({"nested_key": true});
    assert_unknown_field_refused::<CapabilityToken>(envelope, "future_data");

    let mut scope = value.clone();
    scope["scope"]["future_scope"] = serde_json::json!([]);
    assert_unknown_field_refused::<CapabilityToken>(scope, "future_scope");

    let mut grant = value;
    grant["scope"]["grants"][0]["future_priority"] = serde_json::json!(5);
    assert_unknown_field_refused::<CapabilityToken>(grant, "future_priority");
}

#[test]
fn receipt_with_unknown_fields_accepted() {
    let kp = Keypair::generate();
    let body = make_receipt_body(&kp);
    let receipt = ChioReceipt::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&receipt).unwrap();

    // Inject at top level
    value["billing_ref"] = serde_json::Value::String("inv-2026-0001".to_string());
    value["future_trace_id"] = serde_json::json!("trace-abc123");

    // Inject inside evidence[0]
    if let Some(ev) = value["evidence"].get_mut(0) {
        ev["confidence_score"] = serde_json::json!(0.98);
        ev["future_rule_version"] = serde_json::json!("1.2.0");
    }

    // Inject inside action
    value["action"]["execution_time_ms"] = serde_json::json!(12);

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: ChioReceipt =
        serde_json::from_str(&json_with_unknowns).expect("ChioReceipt must accept unknown fields");

    assert_eq!(receipt.id, restored.id);
    assert_eq!(receipt.capability_id, restored.capability_id);
    assert_eq!(receipt.tool_name, restored.tool_name);
    assert_eq!(receipt.content_hash, restored.content_hash);
    assert_eq!(receipt.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn tool_definition_refuses_unknown_members_at_every_policy_layer() {
    let value = serde_json::to_value(make_tool_definition()).unwrap();

    let mut definition = value.clone();
    definition["rate_limit"] = serde_json::json!({"per_minute": 60});
    assert_unknown_field_refused::<ToolDefinition>(definition, "rate_limit");

    let mut annotations = value.clone();
    annotations["annotations"]["sandboxed"] = serde_json::json!(true);
    assert_unknown_field_refused::<ToolDefinition>(annotations, "sandboxed");

    let mut pricing = value;
    pricing["pricing"] = serde_json::json!({
        "pricing_model": "flat",
        "future_cost_basis": "compute"
    });
    assert_unknown_field_refused::<ToolDefinition>(pricing, "future_cost_basis");
}

#[test]
fn delegation_link_refuses_unknown_members() {
    let delegator_kp = Keypair::generate();
    let delegatee_kp = Keypair::generate();
    let link = make_delegation_link(&delegator_kp, &delegatee_kp);

    let mut value = serde_json::to_value(&link).unwrap();
    value["expiry_override"] = serde_json::json!(1_999_999);
    assert_unknown_field_refused::<DelegationLink>(value.clone(), "expiry_override");

    let mut token_value = serde_json::to_value(
        CapabilityToken::sign(
            CapabilityTokenBody {
                delegation_chain: vec![link],
                ..make_token_body(&delegator_kp)
            },
            &delegator_kp,
        )
        .unwrap(),
    )
    .unwrap();
    token_value["delegation_chain"][0] = value;
    assert_unknown_field_refused::<CapabilityToken>(token_value, "expiry_override");
}

fn assert_unknown_field_refused<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    member: &str,
) {
    let error = serde_json::from_value::<T>(value)
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    let expected = format!("unknown field `{member}`, expected");
    assert!(error.starts_with(&expected), "`{member}`: {error}");
}

#[test]
fn child_receipt_with_unknown_fields() {
    let kp = Keypair::generate();
    let body = make_child_receipt_body(&kp);
    let original_id = body.id.clone();
    let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&receipt).unwrap();

    // Inject unknown fields simulating child receipt extensions.
    value["sampling_cost"] = serde_json::json!({"tokens": 512, "model": "claude-3"});
    value["future_trace_parent"] = serde_json::json!("00-abc123-xyz456-01");

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: ChildRequestReceipt = serde_json::from_str(&json_with_unknowns)
        .expect("ChildRequestReceipt must accept unknown fields");

    assert_eq!(original_id, restored.id);
    assert_eq!(receipt.session_id, restored.session_id);
    assert_eq!(receipt.parent_request_id, restored.parent_request_id);
    assert_eq!(receipt.request_id, restored.request_id);
    assert_eq!(receipt.outcome_hash, restored.outcome_hash);
    assert_eq!(receipt.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}
