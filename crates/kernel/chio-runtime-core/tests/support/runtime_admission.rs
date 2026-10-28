use super::runtime_api;
pub(super) use chio_core_types::capability::attenuation::{
    compute_attenuation_witness, scope_hash,
};
pub(super) use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
pub(super) use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
pub(super) use chio_core_types::receipt::lineage::SignedExportEnvelope;
pub(super) use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
pub(super) use chio_federation::{
    bilateral_dsse::sign_chio_bilateral_dsse_envelope,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_dsse::TreatyBindingRef, bilateral_dsse::PAYLOAD_TYPE_IN_TOTO,
};
pub(super) use chio_kernel::{RuntimeAdmissionContext, ToolCallRequest};
pub(super) use chio_swarm_authority::{
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
pub(super) use runtime_api::{
    compute_ladder_intersection, runtime_admission_bundle_sha256, runtime_peer_weights_sha256,
    tool_args_sha256, verify_signed_runtime_admission_report, BilateralInvocation,
    ChioRuntimeAdmissionHook, CrossKernelContinuation, InMemoryRuntimeAdmissionStore,
    ReceiptLineageBundle, ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionProfile,
    RuntimeAdmissionStore, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromoneAdvisory,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeRequestBinding,
    RuntimeTrustFloorEntry, RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundle,
    SignedRuntimePheromoneQueryReport, SqliteRuntimeOrchestrationStore, TreatyScope,
    CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
pub(super) use std::io;

pub(super) use runtime_api::ChioRuntimeError;

#[path = "treaty.rs"]
pub(super) mod treaty_support;
pub(super) use treaty_support::{treaty_action_class, treaty_manifest, treaty_scope};

#[path = "../runtime_admission/swarm_request_support.rs"]
pub(super) mod swarm_request_support;
pub(super) use swarm_request_support::{chio_swarm_runtime_request, swarm_runtime_context};

#[path = "../runtime_admission/swarm_fixtures.rs"]
pub(super) mod swarm_fixtures;
pub(super) use swarm_fixtures::{
    canonical_test_hash, issue_root, runtime_swarm_continuation,
    runtime_swarm_join_parent_set_hash, runtime_swarm_revocation_root,
    runtime_swarm_route_plan_receipt, runtime_swarm_scope, runtime_swarm_terminal_graph_receipt,
    runtime_swarm_witness_chain, swarm_witness_issuer, swarm_witness_keypair,
    trusted_swarm_witness_keys, IssuedGraphs,
};

pub(super) fn emit_threat_matrix_code(code: &str) {
    if std::env::var_os("CHIO_THREAT_MATRIX_EMIT_CODE").is_some() {
        println!("CHIO_THREAT_MATRIX_CODE={code}");
    }
}

pub(super) fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-live-spine".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

pub(super) fn capability(
    capability_id: &str,
) -> Result<CapabilityToken, Box<dyn std::error::Error>> {
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

pub(super) fn binding() -> RuntimeRequestBinding {
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

pub(super) fn bundle() -> RuntimeAdmissionBundle {
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

pub(super) fn trusted_keys(verifier: &Keypair) -> Vec<RuntimeTrustedVerifierKey> {
    vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }]
}

pub(super) fn trust_body(
    version: u64,
    previous_hash_sha256: Option<String>,
) -> RuntimeVerifierTrustBundle {
    RuntimeVerifierTrustBundle {
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

pub(super) fn advisory(strength: f64) -> RuntimePheromoneAdvisory {
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

pub(super) fn policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
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

pub(super) fn peer_weights() -> RuntimePeerWeights {
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

pub(super) type SignedPolicyInputs = (
    SignedExportEnvelope<RuntimeVerifierTrustBundle>,
    Vec<RuntimeTrustedVerifierKey>,
    SignedRuntimePheromoneQueryReport,
    SignedExportEnvelope<RuntimePheromonePolicy>,
    SignedExportEnvelope<RuntimePeerWeights>,
);

pub(super) fn query_report_body(advisory: RuntimePheromoneAdvisory) -> serde_json::Value {
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

pub(super) fn signed_query_report(
    advisory: RuntimePheromoneAdvisory,
    verifier: &Keypair,
) -> Result<SignedRuntimePheromoneQueryReport, Box<dyn std::error::Error>> {
    Ok(SignedExportEnvelope::sign(
        query_report_body(advisory),
        verifier,
    )?)
}

pub(super) fn signed_policy_inputs(
    strength: f64,
) -> Result<SignedPolicyInputs, Box<dyn std::error::Error>> {
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

#[derive(Clone)]
pub(super) struct TreatyRuntimeFixture {
    pub(super) treaty_scope: TreatyScope,
    pub(super) treaty_scope_sha256: String,
    pub(super) ladder_intersection: runtime_api::LadderIntersection,
    pub(super) ladder_intersection_sha256: String,
    pub(super) continuation: CrossKernelContinuation,
    pub(super) continuation_sha256: String,
    pub(super) lineage_bundle: ReceiptLineageBundle,
    pub(super) lineage_bundle_sha256: String,
    pub(super) bilateral_invocation: BilateralInvocation,
    pub(super) bilateral_invocation_sha256: String,
    pub(super) bilateral_dsse_id: String,
    pub(super) bilateral_dsse: chio_federation::bilateral_dsse::DsseEnvelope,
    pub(super) bilateral_dsse_sha256: String,
}

pub(super) fn allow_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some("allow".to_string()),
    }
}

pub(super) fn unanimous_deny_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        joint_disposition: Some("deny".to_string()),
    }
}

pub(super) fn treaty_runtime_fixture() -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_policy(allow_policy_evaluation_summary())
}

pub(super) fn treaty_runtime_fixture_with_policy(
    policy_evaluation_summary: PolicyEvaluationSummary,
) -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_signers(
        policy_evaluation_summary,
        Keypair::generate(),
        Keypair::generate(),
    )
}

pub(super) fn treaty_runtime_fixture_with_signers(
    policy_evaluation_summary: PolicyEvaluationSummary,
    signer_a: Keypair,
    signer_b: Keypair,
) -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let mut treaty_scope = treaty_scope();
    treaty_scope.participant_public_keys = vec![signer_a.public_key(), signer_b.public_key()];
    treaty_scope.ladder_manifest_sha256s = vec![
        runtime_api::governance_ladder_manifest_sha256(&buyer)?,
        runtime_api::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let treaty_scope_sha256 = runtime_api::treaty_scope_sha256(&treaty_scope)?;
    let ladder_intersection =
        compute_ladder_intersection(&treaty_scope, &[buyer, vendor], 1_800_000_001_000)?;
    let ladder_intersection_sha256 = runtime_api::ladder_intersection_sha256(&ladder_intersection)?;
    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-runtime-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-runtime-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    let mut bilateral_invocation = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-runtime-1".to_string(),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: tool_args_sha256(&serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        }))?,
        outcome_sha256: "5".repeat(64),
        local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        remote_receipt_sha256: String::new(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: bilateral_invocation.invocation_id.clone(),
            timestamp: 1_800_000_001,
            capability_id: bilateral_invocation.capability_id.clone(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "record": "vendor-ledger-7",
                "value": "closed"
            }))?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:chio-runtime/admission".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: bilateral_invocation.outcome_sha256.clone(),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: signer_b.public_key(),
            bbs_projection_version: None,
        },
        &signer_b,
    )?;
    bilateral_invocation.remote_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&receipt)?,
    );
    let bilateral_invocation_binding_sha256 =
        runtime_api::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    let lineage = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-runtime-1".to_string(),
        parent_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-runtime-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    };
    let lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage_bundle)?,
    );
    let rebound_bilateral_invocation_sha256 =
        runtime_api::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    assert_eq!(
        rebound_bilateral_invocation_sha256,
        bilateral_invocation_binding_sha256
    );
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256;
    let dsse_consistency_model =
        runtime_api::bilateral_dsse_consistency_model(&bilateral_invocation.consistency_model)?
            .to_string();
    let bilateral_dsse = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &signer_a,
        &signer_b,
        &bilateral_invocation.signer_kernel_ids[0],
        &bilateral_invocation.signer_kernel_ids[1],
        "close_account",
        1_800_000_001_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-live-1".to_string(),
                issuer: bilateral_invocation.signer_kernel_ids[0].clone(),
                expires_at_unix_ms: 1_800_003_600_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(policy_evaluation_summary),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-live-1".to_string(),
                kernel_id: bilateral_invocation.signer_kernel_ids[1].clone(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some(dsse_consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: bilateral_invocation.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256.clone(),
                ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                admission_report_sha256: "6".repeat(64),
                continuation_sha256: continuation_sha256.clone(),
                lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                action_class_id: bilateral_invocation.action_class_id.clone(),
                consistency_model: dsse_consistency_model,
                request_sha256: bilateral_invocation.request_sha256.clone(),
                outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                lease_refs: vec!["lease-live-1".to_string()],
                governance_refs: vec!["gov-live-1".to_string()],
                signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
            }),
        },
    )?;
    let bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_dsse)?,
    );
    Ok(TreatyRuntimeFixture {
        treaty_scope,
        treaty_scope_sha256,
        ladder_intersection,
        ladder_intersection_sha256,
        continuation,
        continuation_sha256,
        lineage_bundle,
        lineage_bundle_sha256,
        bilateral_invocation,
        bilateral_invocation_sha256,
        bilateral_dsse_id: "bilateral-dsse-runtime-1".to_string(),
        bilateral_dsse,
        bilateral_dsse_sha256,
    })
}

pub(super) fn insert_treaty_runtime_fixture(
    store: &SqliteRuntimeOrchestrationStore,
    fixture: &TreatyRuntimeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    Ok(())
}

pub(super) fn insert_in_memory_treaty_runtime_fixture(
    store: &InMemoryRuntimeAdmissionStore,
    fixture: &TreatyRuntimeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    Ok(())
}

pub(super) fn deny_policy_bilateral_dsse(
    envelope: &DsseEnvelope,
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = envelope.decode_statement()?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture DSSE missing policy summary"))?;
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            statement.canonical_bytes()?,
        ),
        signatures: envelope.signatures.clone(),
    })
}

pub(super) fn treaty_runtime_context(fixture: &TreatyRuntimeFixture) -> serde_json::Value {
    serde_json::json!({
        "treatyScopeId": fixture.treaty_scope.treaty_id,
        "treatyScopeSha256": fixture.treaty_scope_sha256,
        "ladderIntersectionId": fixture.ladder_intersection.intersection_id,
        "ladderIntersectionSha256": fixture.ladder_intersection_sha256,
        "actionClassId": "workflow.destructive.vendor_call",
        "crossKernelContinuation": {
            "id": fixture.continuation.continuation_id,
            "sha256": fixture.continuation_sha256
        },
        "receiptLineageBundle": {
            "id": fixture.lineage_bundle.bundle_id,
            "sha256": fixture.lineage_bundle_sha256
        },
        "bilateralInvocation": {
            "id": fixture.bilateral_invocation.invocation_id,
            "sha256": fixture.bilateral_invocation_sha256
        },
        "bilateralDsse": {
            "id": fixture.bilateral_dsse_id,
            "sha256": fixture.bilateral_dsse_sha256
        }
    })
}

pub(super) fn treaty_runtime_request(
    args: serde_json::Value,
    bundle_hash: String,
    treaty_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let cap = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
        declassification_grant: None,
    };
    request.governed_intent = Some(GovernedTransactionIntent {
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
            "chioTreaty": treaty_context
        })),
        body: Default::default(),
    });
    Ok(request)
}

pub(super) fn swarm_route_metadata() -> serde_json::Value {
    serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-runtime",
            "selectedRoute": "mcp:task-child-a"
        }
    })
}

pub(super) fn runtime_swarm_bundle(
    stale_continuation: bool,
) -> Result<SwarmAuthorityBundle, Box<dyn std::error::Error>> {
    let parent_scope = runtime_swarm_scope(3);
    let child_scope = runtime_swarm_scope(1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let scope_subset_proof = compute_attenuation_witness(&parent_scope, &child_scope)?;
    let revocation_root = runtime_swarm_revocation_root(&[], &[])?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        root_transaction_ref: "passport-runtime".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_depth: 1,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            SwarmGraphNode {
                task_id: "task-root".to_string(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: parent_scope_hash.clone(),
                depth: 0,
            },
            SwarmGraphNode {
                task_id: "task-child-a".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-a".to_string()),
                continuation_token_ref: Some("continuation-child-a".to_string()),
                budget_allocation_ref: Some("budget-child-a".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
            SwarmGraphNode {
                task_id: "task-child-b".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-b".to_string()),
                continuation_token_ref: Some("continuation-child-b".to_string()),
                budget_allocation_ref: Some("budget-child-b".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
        ],
        edges: vec![
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-a".to_string(),
                edge_type: "delegates".to_string(),
            },
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-b".to_string(),
                edge_type: "delegates".to_string(),
            },
        ],
        joins: vec![SwarmGraphJoin {
            join_id: "join-child-results".to_string(),
            parent_task_ids: vec!["task-child-a".to_string(), "task-child-b".to_string()],
            next_task_id: "task-root".to_string(),
        }],
        budget_pool_ref: "budget-pool-runtime".to_string(),
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        route_plan_refs: vec!["route-child-a".to_string(), "route-child-b".to_string()],
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    let graph_sha256 = canonical_test_hash(&task_graph)?;
    let mut continuation_a = runtime_swarm_continuation(
        "continuation-child-a",
        "task-child-a",
        "route-child-a",
        "budget-child-a",
        &graph_sha256,
        &revocation_root,
        stale_continuation,
    )?;
    let mut continuation_b = runtime_swarm_continuation(
        "continuation-child-b",
        "task-child-b",
        "route-child-b",
        "budget-child-b",
        &graph_sha256,
        &revocation_root,
        false,
    )?;
    task_graph.nodes[1].continuation_token_ref = Some(continuation_a.token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_b.token_id.clone());
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    continuation_a.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let witness_chain_a = runtime_swarm_witness_chain(
        "witness-child-a",
        "task-child-a",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof.clone(),
    )?;
    let witness_chain_b = runtime_swarm_witness_chain(
        "witness-child-b",
        "task-child-b",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof,
    )?;
    continuation_a.witness_chain_ref = Some(witness_chain_a.chain_id.clone());
    continuation_a.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_a)?);
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.witness_chain_ref = Some(witness_chain_b.chain_id.clone());
    continuation_b.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_b)?);
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let mut join_receipt = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-child-results".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        parent_set_hash: runtime_swarm_join_parent_set_hash(
            "swarm-chain-swarm-graph-runtime",
            &["receipt-child-a", "receipt-child-b"],
        )?,
        dag_ordinal: 2,
        hlc_unix_ms: 1_800_000_000_500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: "task-child-a".to_string(),
                receipt_id: "receipt-child-a".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: "task-child-b".to_string(),
                receipt_id: "receipt-child-b".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        next_task_id: "task-root".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    join_receipt.signature = sign_swarm_join_receipt(&join_receipt, &swarm_witness_keypair())?;

    let mut revocation_epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: "revocation-epoch-runtime".to_string(),
        root_hash: revocation_root,
        issued_at_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    revocation_epoch.signature =
        sign_swarm_revocation_epoch(&revocation_epoch, &swarm_witness_keypair())?;

    let bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens: vec![continuation_a, continuation_b],
        witness_chains: vec![witness_chain_a, witness_chain_b],
        join_receipts: vec![join_receipt],
        route_plan_receipts: vec![
            runtime_swarm_route_plan_receipt(
                "route-child-a",
                "task-child-a",
                "mcp",
                "mcp://provider-runtime",
                b"runtime-swarm-candidates",
            )?,
            runtime_swarm_route_plan_receipt(
                "route-child-b",
                "task-child-b",
                "a2a",
                "a2a://provider-runtime",
                b"runtime-swarm-candidates-b",
            )?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-runtime".to_string(),
            graph_id: "swarm-graph-runtime".to_string(),
            currency: "USD".to_string(),
            total_units: 10_000,
            allocations: vec![
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-a".to_string(),
                    task_id: "task-child-a".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
            ],
        },
        revocation_epoch,
        terminal_receipts: vec![runtime_swarm_terminal_graph_receipt()?],
        now_unix_ms: 1_800_000_001_000,
    };

    if !stale_continuation {
        verify_swarm_authority_bundle(&bundle, &trusted_swarm_witness_keys()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("runtime swarm fixture invalid: {}", error.runtime_detail()),
            )
        })?;
    }

    Ok(bundle)
}
