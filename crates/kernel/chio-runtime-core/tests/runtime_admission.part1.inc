use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core_types::capability::{
    governance::{GovernedToolInvocationIntentBody, GovernedTransactionIntent},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::{
    bilateral_dsse::sign_chio_bilateral_dsse_envelope,
    bilateral_dsse::BilateralDsseInvocationInput, bilateral_dsse::BilateralDsseLocalSigningInput,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_dsse::TreatyBindingRef, bilateral_dsse::PAYLOAD_TYPE_IN_TOTO,
};
use chio_kernel::{
    RuntimeAdmissionContext, RuntimeAdmissionHook, RuntimeAdmissionRevalidationContext,
    ToolCallRequest,
};
use chio_runtime_core::{
    compute_ladder_intersection, evaluate_runtime_admission, runtime_admission_bundle_sha256,
    runtime_peer_weights_sha256, sign_runtime_admission_report, tool_args_sha256,
    verify_signed_runtime_admission_report, BilateralInvocation, ChioRuntimeAdmissionHook,
    CrossKernelContinuation, InMemoryRuntimeAdmissionStore, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionInput,
    RuntimeAdmissionProfile, RuntimeAdmissionStore, RuntimePeerWeight, RuntimePeerWeights,
    RuntimePheromoneAdvisory, RuntimePheromonePolicy, RuntimePheromonePolicyRule,
    RuntimeRequestBinding, RuntimeTrustFloorEntry, RuntimeTrustedVerifierKey,
    RuntimeVerifierTrustBundleV4, SignedRuntimePheromoneQueryReport,
    SqliteRuntimeOrchestrationStore, TreatyRuntimeArtifactRecord, TreatyScope,
    CHIO_BILATERAL_INVOCATION_SCHEMA,
    CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIO_RUNTIME_FAILURE_CODES,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
use chio_swarm_authority::{
    sign_swarm_continuation_token, sign_swarm_delegation_witness_hop, sign_swarm_join_receipt,
    sign_swarm_revocation_epoch, sign_swarm_route_plan_receipt, sign_swarm_task_graph,
    sign_swarm_terminal_graph_receipt, verify_swarm_authority_bundle, SwarmAuthorityBundle,
    SwarmBudgetAllocation, SwarmBudgetAllocationState, SwarmBudgetPool, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphEdge,
    SwarmGraphJoin, SwarmGraphNode, SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_BUDGET_POOL_SCHEMA, CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
};
use std::io;

use chio_runtime_core::ChioRuntimeError;

use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

fn emit_threat_matrix_code(code: &str) {
    if std::env::var_os("CHIO_THREAT_MATRIX_EMIT_CODE").is_some() {
        println!("CHIO_THREAT_MATRIX_CODE={code}");
    }
}

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-live-spine".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn capability(capability_id: &str) -> Result<CapabilityToken, Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
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

fn binding() -> RuntimeRequestBinding {
    RuntimeRequestBinding {
        request_id: "req-live-destructive".to_string(),
        capability_id: "cap-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: Some("kernel.buyer".to_string()),
        host_kernel_id: "kernel.vendor-b".to_string(),
    }
}

fn bundle() -> RuntimeAdmissionBundle {
    RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "adm-live-1".to_string(),
        binding: binding(),
        workflow_id: "wf-live-1".to_string(),
        workflow_grant_id: "grant-live-1".to_string(),
        step_index: 1,
        destructive: true,
        lease_id: Some("lease-live-1".to_string()),
        governance_receipt_id: Some("gov-live-1".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    }
}

include!("runtime_admission/fault_cases.rs");

#[test]
fn chio_native_runtime_admission_schema_emits_chio_report() -> Result<(), Box<dyn std::error::Error>>
{
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let mut bundle = bundle();
    bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    bundle.destructive = false;
    bundle.lease_id = None;
    bundle.governance_receipt_id = None;

    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone())?;
    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile,
        store: &store,
        admission_id: &bundle.admission_id,
        request: &bundle.binding,
        action_class_id: None,
        runtime_trust_input: None,
        trusted_verifier_keys: &[],
        pheromone_query_report: None,
        runtime_pheromone_policy: None,
        runtime_peer_weights: None,
        now_unix_ms: 1_800_000_000_001,
    })?;

    assert!(report.accepted);
    assert_eq!(report.schema, "chio.runtime.admission-report.v1");
    let metadata = report
        .receipt_metadata
        .get("chio_runtime")
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["admission_id"], bundle.admission_id);
    assert_eq!(metadata["accepted"], true);
    Ok(())
}

fn trusted_keys(verifier: &Keypair) -> Vec<RuntimeTrustedVerifierKey> {
    vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }]
}

fn trust_body(version: u64, previous_hash_sha256: Option<String>) -> RuntimeVerifierTrustBundleV4 {
    RuntimeVerifierTrustBundleV4 {
        schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        version,
        previous_hash_sha256,
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
        revocation_checkpoint_sha256: "d".repeat(64),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn advisory(strength: f64) -> RuntimePheromoneAdvisory {
    RuntimePheromoneAdvisory {
        source_report_sha256: "1".repeat(64),
        accepted: true,
        subject_class: "workflow.destructive_step".to_string(),
        subject_class_namespace: "chio.runtime".to_string(),
        total_strength: strength,
        distinct_origin_pairs: 1,
        reputation_epoch: 7,
        evaluated_at_unix_ms: 1_800_000_001_000,
        observe_only: true,
    }
}

fn policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
    RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: "policy-runtime-risk".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        allowed_reputation_epochs: vec![7],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: "b".repeat(64),
        peer_weights_sha256,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-runtime-risk".to_string(),
            subject_class: "workflow.destructive_step".to_string(),
            subject_class_namespace: "chio.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.75,
            effect: "deny".to_string(),
        }],
    }
}

fn peer_weights() -> RuntimePeerWeights {
    RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        reputation_epoch: 7,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: "kernel.vendor-b".to_string(),
            weight: 1.0,
        }],
    }
}

type SignedPolicyInputs = (
    SignedExportEnvelope<RuntimeVerifierTrustBundleV4>,
    Vec<RuntimeTrustedVerifierKey>,
    SignedRuntimePheromoneQueryReport,
    SignedExportEnvelope<RuntimePheromonePolicy>,
    SignedExportEnvelope<RuntimePeerWeights>,
);

fn query_report_body(advisory: RuntimePheromoneAdvisory) -> serde_json::Value {
    serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": advisory.accepted,
        "concentration": {
            "subjectClass": advisory.subject_class,
            "subjectClassNamespace": advisory.subject_class_namespace,
            "totalStrength": advisory.total_strength,
            "distinctOriginPairs": advisory.distinct_origin_pairs,
            "reputationEpoch": advisory.reputation_epoch,
            "evaluatedAtUnixMs": advisory.evaluated_at_unix_ms
        }
    })
}

fn signed_query_report(
    advisory: RuntimePheromoneAdvisory,
    verifier: &Keypair,
) -> Result<SignedRuntimePheromoneQueryReport, Box<dyn std::error::Error>> {
    Ok(SignedExportEnvelope::sign(
        query_report_body(advisory),
        verifier,
    )?)
}

fn signed_policy_inputs(strength: f64) -> Result<SignedPolicyInputs, Box<dyn std::error::Error>> {
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let signed_query_report = signed_query_report(advisory(strength), &verifier)?;
    Ok((
        signed_trust,
        trusted_keys(&verifier),
        signed_query_report,
        signed_policy,
        signed_weights,
    ))
}

fn allowing_policy_hook<S>(
    store: S,
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(ChioRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

fn allowing_chio_policy_hook<S>(
    store: S,
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(ChioRuntimeAdmissionHook::new(profile, store)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

#[test]
fn runtime_failure_code_registry_covers_hook_surface_codes() {
    let registry: std::collections::BTreeSet<_> =
        CHIO_RUNTIME_FAILURE_CODES.iter().copied().collect();
    assert_eq!(registry.len(), CHIO_RUNTIME_FAILURE_CODES.len());

    for code in [
        "missing_governed_intent",
        "missing_chio_admission_context",
        "invalid_chio_admission_context",
        "missing_admission_id",
        "invalid_chio_swarm_context",
        "invalid_chio_swarm_evidence_ref",
        "missing_chio_swarm_evidence_ref",
        "missing_chio_swarm_authority_bundle",
        "chio_swarm_authority_ref_mismatch",
        "chio_swarm_authority_rejected",
        "chio_swarm_continuation_replay",
        "chio_swarm_continuation_store_unsupported",
        "missing_chio_treaty_context",
        "invalid_chio_treaty_context",
        "request_smuggled_trust_root",
        "request_smuggled_dynamic_trust",
        "missing_treaty_scope_id",
        "missing_treaty_scope_hash",
        "missing_ladder_intersection_id",
        "missing_ladder_intersection_hash",
        "missing_action_class_id",
        "invalid_chio_treaty_hash",
        "invalid_chio_treaty_evidence_ref",
        "missing_chio_treaty_evidence_ref",
        "chio_treaty_missing_scope",
        "chio_treaty_scope_hash_mismatch",
        "chio_treaty_missing_intersection",
        "unsupported_cross_kernel_continuation_schema",
        "continuation_invalid_window",
        "unsupported_receipt_lineage_statement_schema",
        "receipt_lineage_invalid_evidence_class",
        "chio_ladder_invalid_consistency_model",
        "chio_ladder_invalid_cosign_mode",
        "unsupported_runtime_step_evidence_schema",
        "runtime_step_evidence_missing_admission_id",
        "runtime_step_evidence_missing_consistency_anchor",
        "runtime_step_evidence_missing_governance",
        "runtime_swarm_authority_empty_graph_id",
        "duplicate_swarm_authority_bundle_mismatch",
        "duplicate_consumed_swarm_continuation",
    ] {
        assert!(
            registry.contains(code),
            "runtime failure code registry missing {code}"
        );
    }
}

#[test]
fn matching_destructive_admission_accepts_once_then_rejects_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let bundle = bundle();
    store.insert_bundle(bundle.clone())?;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;

    let first = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(first.accepted);
    assert_eq!(first.failure_code, None);
    assert_eq!(
        first.receipt_metadata["chio_runtime"]["admission_id"],
        "adm-live-1"
    );
    assert_eq!(first.receipt_metadata["chio_runtime"]["destructive"], true);

    let replay = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!replay.accepted);
    assert_eq!(
        replay.failure_code.as_deref(),
        Some("destructive_lease_replay")
    );
    Ok(())
}

#[test]
fn signed_runtime_admission_report_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;
    let signer = Keypair::generate();
    let mut signed = sign_runtime_admission_report(report, &signer)?;
    assert!(verify_signed_runtime_admission_report(&signed)?);
    signed.body.accepted = false;
    assert!(!verify_signed_runtime_admission_report(&signed)?);
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_missing_lineage_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("receiptLineageBundle");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_trust_root() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["trustRoot"] = serde_json::json!({"issuer": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "request_smuggled_trust_root"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_dynamic_trust(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["dynamicTrust"] = serde_json::json!({"discovery": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "request_smuggled_dynamic_trust"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_missing_bilateral_invocation_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralInvocation");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_requires_signed_bilateral_evidence_before_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralDsse");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_mismatched_continuation_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let mut context = treaty_runtime_context(&fixture);
    context["crossKernelContinuation"]["sha256"] = serde_json::Value::String("f".repeat(64));
    let request = treaty_runtime_request(args, bundle_hash, context)?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_hash_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_continuation_from_non_origin_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.source_kernel_id = "kernel.vendor-b".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_bare_tool_continuation_audience(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.audience_tool = "close_account".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.lineage_bundle.statements[0].evidence_class = "asserted".to_string();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_lineage_bundle_unverified_edge"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_stale_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_000_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_preserves_millisecond_time_for_continuation_staleness(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_001_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_600,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_replayed_continuation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    assert!(first.has_verified_treaty_material(), "{first:#?}");
    assert!(first
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_runtime"))
        .and_then(|runtime| runtime.get("federation_treaty_dsse"))
        .is_none());
    let replay = hook.evaluate(&context)?;

    assert!(!replay.allowed);
    let metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_replay"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_releases_continuation_after_runtime_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let good_args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&good_args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let hook = allowing_policy_hook(store)?;
    let treaty_context = treaty_runtime_context(&fixture);

    let mut denied_request = treaty_runtime_request(
        good_args.clone(),
        bundle_hash.clone(),
        treaty_context.clone(),
    )?;
    denied_request.request_id = "req-runtime-binding-mismatch".to_string();
    let denied = hook.evaluate(&RuntimeAdmissionContext {
        request: &denied_request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;
    assert!(!denied.allowed);
    let metadata = denied
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "request_binding_mismatch"
    );

    let allowed_request = treaty_runtime_request(good_args, bundle_hash, treaty_context)?;
    let allowed = hook.evaluate(&RuntimeAdmissionContext {
        request: &allowed_request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;
    assert!(allowed.allowed, "{allowed:#?}");
    Ok(())
}

#[test]
fn treaty_runtime_hook_releases_reserved_state_after_kernel_abort(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let metadata = first
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    hook.release_reserved(&metadata)?;
    let second = hook.evaluate(&context)?;

    assert!(second.allowed, "{second:#?}");
    Ok(())
}

#[test]
fn chio_runtime_hook_releases_chio_native_reserved_state_after_kernel_abort(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            GovernedToolInvocationIntentBody {
                id: "intent-live-1".to_string(),
                server_id: "vendor-ledger".to_string(),
                tool_name: "close_account".to_string(),
                purpose: "close governed vendor account".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    "chioAdmission": {
                        "admissionId": "adm-live-1",
                        "bundleSha256": bundle_hash
                    }
                })),
            },
        )),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };

    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let metadata = first
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    let runtime_metadata = metadata
        .get("chio_runtime")
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(runtime_metadata["admission_id"], "adm-live-1");
    assert_eq!(runtime_metadata["accepted"], true);
    hook.release_reserved(&metadata)?;
    let second = hook.evaluate(&context)?;

    assert!(second.allowed, "{second:#?}");
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_context_without_required_evidence_refs(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            GovernedToolInvocationIntentBody {
                id: "intent-live-1".to_string(),
                server_id: "vendor-ledger".to_string(),
                tool_name: "close_account".to_string(),
                purpose: "close governed vendor account".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    "chioAdmission": {
                        "admissionId": "adm-live-1",
                        "bundleSha256": bundle_hash
                    },
                    "chioSwarm": {
                        "taskGraph": {
                            "id": "swarm-task-graph-runtime",
                            "sha256": "a".repeat(64)
                        },
                        "continuationToken": {
                            "id": "swarm-continuation-runtime",
                            "sha256": "b".repeat(64)
                        }
                    }
                })),
            },
        )),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_swarm_evidence_ref"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_stale_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(true)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            GovernedToolInvocationIntentBody {
                id: "intent-live-1".to_string(),
                server_id: "vendor-ledger".to_string(),
                tool_name: "close_account".to_string(),
                purpose: "close governed vendor account".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    "chioAdmission": {
                        "admissionId": "adm-live-1",
                        "bundleSha256": bundle_hash
                    },
                    "chioSwarm": swarm_runtime_context(&swarm_bundle)?
                })),
            },
        )),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}
#[test]
fn chio_runtime_hook_denies_swarm_continuation_expired_since_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let mut swarm_bundle = runtime_swarm_bundle(false)?;
    swarm_bundle.continuation_tokens[0].expires_at_unix_ms = 1_800_000_001_500;
    swarm_bundle.continuation_tokens[0].signature = sign_swarm_continuation_token(
        &swarm_bundle.continuation_tokens[0],
        &swarm_witness_keypair(),
    )?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_600,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_metadata_mismatch_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "a2a",
            "protocolTarget": "a2a://provider-b"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_selection_id_mismatch_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route_selection": {
            "selectedRouteId": "a2a:task-child-b",
            "selectedTargetProtocol": "mcp"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_incomplete_swarm_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "mcp"
        }
    });
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}
