//! The agreement context a request carries may name identifiers and hashes only.
//! Receiver-owned trust material is refused wherever it appears in that context,
//! at any nesting depth, in objects and inside arrays.

use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use chio_runtime_core::{
    ChioRuntimeAdmissionHook, InMemoryRuntimeAdmissionStore, RuntimeAdmissionProfile,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-agreement-scan".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn capability() -> Result<CapabilityToken, Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-agreement-scan".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "vendor-ledger".to_string(),
                    tool_name: "close_account".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_800_000_000,
            expires_at: 1_800_003_600,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?)
}

fn request_with_context(
    context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let cap = capability()?;
    Ok(ToolCallRequest {
        request_id: "req-agreement-scan".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({ "record": "vendor-ledger-7" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-agreement-scan".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            purpose: "exercise the agreement context scan".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(context),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
    })
}

/// The failure code a request's agreement context produces. The store is empty,
/// so evaluation stops at the context scan or at the first missing field after
/// it, which is exactly the range these cases assert over.
fn failure_code(context: serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let request = request_with_context(context)?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), InMemoryRuntimeAdmissionStore::new());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;
    assert!(!decision.allowed, "agreement context scan must fail closed");
    let metadata = decision
        .metadata
        .ok_or_else(|| std::io::Error::other("runtime denial metadata missing"))?;
    let code = metadata["chio_runtime"]["failure_code"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("runtime denial code missing"))?;
    Ok(code.to_string())
}

fn admission() -> serde_json::Value {
    serde_json::json!({ "admissionId": "adm-agreement-scan" })
}

fn treaty() -> serde_json::Value {
    serde_json::json!({
        "treatyScopeId": "treaty-1",
        "treatyScopeSha256": "a".repeat(64),
        "ladderIntersectionId": "intersection-1",
        "ladderIntersectionSha256": "b".repeat(64),
        "actionClassId": "workflow.destructive.vendor_call"
    })
}

fn swarm() -> serde_json::Value {
    serde_json::json!({
        "taskGraph": { "id": "swarm-task-graph", "sha256": "a".repeat(64) },
        "continuationToken": { "id": "swarm-continuation", "sha256": "b".repeat(64) },
        "routePlanReceipt": { "id": "swarm-route-plan", "sha256": "c".repeat(64) },
        "delegationWitness": { "id": "swarm-witness", "sha256": "d".repeat(64) },
        "joinReceipt": { "id": "swarm-join", "sha256": "e".repeat(64) },
        "revocationEpoch": { "id": "swarm-epoch", "sha256": "f".repeat(64) },
        "budgetPool": { "id": "swarm-budget", "sha256": "0".repeat(64) }
    })
}

#[test]
fn treaty_context_refuses_a_trust_root_nested_below_the_agreement_object() -> TestResult {
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::json!({
        "attachments": { "trustRoot": { "issuer": "caller-smuggled" } }
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn treaty_context_refuses_a_trust_root_inside_an_array() -> TestResult {
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::json!([
        { "note": "harmless" },
        [{ "ladderManifest": { "classes": ["workflow.destructive.vendor_call"] } }]
    ]);
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn treaty_context_refuses_a_trust_root_outside_the_agreement_object() -> TestResult {
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty(),
        "sidecar": { "peerDirectory": { "kernel.buyer": "https://example.invalid" } }
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn treaty_context_refuses_dynamic_trust_nested_below_the_agreement_object() -> TestResult {
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::json!({
        "attachments": [{ "runtimeTrustInput": { "score": 1.0 } }]
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "request_smuggled_dynamic_trust");
    Ok(())
}

#[test]
fn treaty_context_reports_a_smuggled_trust_root_ahead_of_dynamic_trust() -> TestResult {
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::json!({
        "nested": { "peerDiscovery": "https://example.invalid" },
        "signingKey": "caller-smuggled"
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn treaty_context_deeper_than_the_scan_bound_is_refused() -> TestResult {
    let mut nested = serde_json::json!({ "trustRoot": "buried" });
    for _ in 0..64 {
        nested = serde_json::json!({ "next": nested });
    }
    let mut treaty = treaty();
    treaty["evidence"] = nested;
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "invalid_chio_treaty_context");
    Ok(())
}

#[test]
fn treaty_context_wider_than_the_scan_bound_is_refused() -> TestResult {
    let mut wide = serde_json::Map::new();
    for index in 0..8_192 {
        wide.insert(format!("field-{index}"), serde_json::Value::from(index));
    }
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::Value::Object(wide);
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_eq!(code, "invalid_chio_treaty_context");
    Ok(())
}

#[test]
fn a_nested_agreement_context_without_trust_material_is_not_refused_as_smuggled() -> TestResult {
    let mut treaty = treaty();
    treaty["evidence"] = serde_json::json!({
        "attachments": [
            { "class": "receipt-lineage", "labels": ["a", "b"] },
            { "class": "bilateral-invocation", "nested": { "depth": 3 } }
        ]
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioTreaty": treaty
    }))?;
    assert_ne!(code, "request_smuggled_trust_root");
    assert_ne!(code, "request_smuggled_dynamic_trust");
    assert_ne!(code, "invalid_chio_treaty_context");
    // The scan passes the context through; evaluation then stops where an empty
    // store makes it stop.
    assert_eq!(code, "missing_admission_bundle");
    Ok(())
}

#[test]
fn swarm_context_refuses_a_trust_root_nested_below_the_agreement_object() -> TestResult {
    let mut swarm = swarm();
    swarm["plan"] = serde_json::json!({
        "hops": [{ "witnessKeys": ["caller-smuggled"] }]
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioSwarm": swarm
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn swarm_context_refuses_a_trust_root_outside_the_agreement_object() -> TestResult {
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioSwarm": swarm(),
        "sidecar": { "authorityBundle": { "issuer": "caller-smuggled" } }
    }))?;
    assert_eq!(code, "request_smuggled_trust_root");
    Ok(())
}

#[test]
fn swarm_context_refuses_dynamic_trust_nested_below_the_agreement_object() -> TestResult {
    let mut swarm = swarm();
    swarm["plan"] = serde_json::json!({
        "hops": [{ "dynamicTrustBundle": { "source": "caller-smuggled" } }]
    });
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioSwarm": swarm
    }))?;
    assert_eq!(code, "request_smuggled_dynamic_trust");
    Ok(())
}

#[test]
fn swarm_context_deeper_than_the_scan_bound_is_refused() -> TestResult {
    let mut nested = serde_json::json!({ "trustRoot": "buried" });
    for _ in 0..64 {
        nested = serde_json::json!({ "next": nested });
    }
    let mut swarm = swarm();
    swarm["plan"] = nested;
    let code = failure_code(serde_json::json!({
        "chioAdmission": admission(),
        "chioSwarm": swarm
    }))?;
    assert_eq!(code, "invalid_chio_swarm_context");
    Ok(())
}
