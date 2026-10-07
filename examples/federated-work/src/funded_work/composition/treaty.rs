//! Example operator provisioning with the existing treaty constructors. These
//! are bilateral admission commitments, not receipts proving completed work.
use super::*;
use chio_core_types::{
    capability::governance::GovernedTransactionIntent,
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
        metadata::ActorRef,
    },
};
use chio_federation::bilateral_dsse::{
    sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use chio_runtime_core::*;

pub(in crate::funded_work) fn attach(
    state: &Path,
    config: &Config,
    request: &mut ToolCallRequest,
    buyer: &Keypair,
    receiver: &Keypair,
) -> Result<()> {
    if buyer.public_key() != config.peer.public_key
        || kernel_id(&receiver.public_key()) != config.profile.local_kernel_id
    {
        return Err("operator treaty keys differ from protected receiver configuration".into());
    }
    let from = config.profile.issued_at_unix_ms;
    let until = config
        .profile
        .expires_at_unix_ms
        .min(request.capability.expires_at * 1000);
    let now = super::super::now_ms()?;
    let local = &config.profile.local_kernel_id;
    let origin = &config.peer.kernel_id;
    let id = |kind: &str| format!("{kind}-{}", request.request_id);
    let action = "work.review";
    let manifest = |kernel: &str| GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.into(),
        manifest_id: format!("ladder-{kernel}"),
        kernel_id: kernel.into(),
        issuer: kernel.into(),
        key_id: "local-owner".into(),
        issued_at_unix_ms: from,
        expires_at_unix_ms: until,
        destructive_floor: "receipt_backed".into(),
        default_unknown_mode: "deny".into(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: action.into(),
            mode: "receipt_backed".into(),
            destructive: false,
            consistency_model: "totally-ordered".into(),
            co_sign: "bilateral_required".into(),
            co_sign_quorum: None,
            evidence_required: vec![
                "bilateral_dsse".into(),
                "bilateral_invocation".into(),
                "receipt_lineage".into(),
            ],
            aliases: vec![],
        }],
    };
    let manifests = [manifest(origin), manifest(local)];
    let trust = digest(&(origin, local, buyer.public_key(), receiver.public_key()))?;
    let scope = TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.into(),
        treaty_id: id("treaty"),
        participant_kernel_ids: vec![origin.clone(), local.clone()],
        participant_public_keys: vec![buyer.public_key(), receiver.public_key()],
        ladder_manifest_sha256s: manifests
            .iter()
            .map(governance_ladder_manifest_sha256)
            .collect::<std::result::Result<_, _>>()?,
        allowed_action_classes: vec![action.into()],
        issued_at_unix_ms: from,
        expires_at_unix_ms: until,
        revocation_epoch_sha256: digest(&"local-unrevoked-epoch")?,
        trust_bundle_sha256: trust.clone(),
    };
    let intersection = compute_ladder_intersection(&scope, &manifests, now)?;
    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.into(),
        continuation_id: id("treaty-continuation"),
        source_kernel_id: origin.clone(),
        target_kernel_id: local.clone(),
        parent_receipt_sha256: digest(&("bilateral-review-consent", &request.arguments))?,
        parent_session_anchor_sha256: digest(&config.peer)?,
        capability_id: request.capability.id.clone(),
        action_class_id: action.into(),
        audience_tool: format!("{}.{}", request.server_id, request.tool_name),
        nonce: id("treaty-nonce"),
        issued_at_unix_ms: from,
        expires_at_unix_ms: until,
    };
    let mut invocation = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.into(),
        invocation_id: id("permission"),
        treaty_id: scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256(&intersection)?,
        continuation_sha256: digest(&continuation)?,
        lineage_statement_sha256: String::new(),
        action_class_id: action.into(),
        consistency_model: "totally-ordered".into(),
        capability_id: request.capability.id.clone(),
        request_sha256: tool_args_sha256(&request.arguments)?,
        outcome_sha256: digest(&"permission to perform review; no completed output asserted")?,
        local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        remote_receipt_sha256: String::new(),
        signer_kernel_ids: vec![origin.clone(), local.clone()],
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: invocation.invocation_id.clone(),
            timestamp: now / 1000,
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action: ToolCallAction::from_parameters(request.arguments.clone())?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "local-treaty-provisioner".into(),
                actor_kind: Some("operator".into()),
            }],
            content_hash: invocation.outcome_sha256.clone(),
            policy_hash: digest(config)?,
            evidence: vec![],
            metadata: Some(json!({"purpose":"pre-execution bilateral permission"})),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: receiver.public_key(),
            bbs_projection_version: None,
        },
        receiver,
    )?;
    invocation.remote_receipt_sha256 = digest(&receipt)?;
    let lineage = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.into(),
        statement_id: id("lineage"),
        parent_receipt_sha256: invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: invocation.remote_receipt_sha256.clone(),
        continuation_sha256: digest(&continuation)?,
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256(&invocation)?,
        evidence_class: "verified".into(),
        source_kernel_id: origin.clone(),
        target_kernel_id: local.clone(),
    };
    invocation.lineage_statement_sha256 = digest(&lineage)?;
    let lineage = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.into(),
        bundle_id: id("lineage-bundle"),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    };
    let verdict = |name: &str| PolicyVerdict {
        verdict: "allow".into(),
        policy_id: name.into(),
        policy_version: "1".into(),
        rationale_code: None,
    };
    let consistency = bilateral_dsse_consistency_model(&invocation.consistency_model)?.to_owned();
    let lease = CapabilityLeaseRef {
        lease_id: id("lease"),
        issuer: origin.clone(),
        expires_at_unix_ms: until,
        scope_digest: None,
    };
    let governance = GovernanceReceiptRef {
        receipt_id: id("governance"),
        kernel_id: local.clone(),
        digest: HashRecord {
            alg: "sha256".into(),
            value: digest(config)?,
        },
    };
    let dsse = sign_chio_bilateral_dsse_envelope(
        &receipt,
        buyer,
        receiver,
        origin,
        local,
        &request.tool_name,
        now,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(lease.clone()),
            governance_receipt_ref: Some(governance.clone()),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: verdict(origin),
                server_b_verdict: verdict(local),
                joint_disposition: Some("allow".into()),
            }),
            consistency_anchor: Some(id("anchor")),
            consistency_model: Some(consistency.clone()),
            cross_org_visibility: Some("treaty_only".into()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: scope.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256(&scope)?,
                ladder_intersection_sha256: invocation.ladder_intersection_sha256.clone(),
                admission_report_sha256: digest(&config.profile)?,
                continuation_sha256: digest(&continuation)?,
                lineage_bundle_sha256: digest(&lineage)?,
                action_class_id: action.into(),
                consistency_model: consistency,
                request_sha256: invocation.request_sha256.clone(),
                outcome_sha256: invocation.outcome_sha256.clone(),
                local_receipt_sha256: invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: invocation.remote_receipt_sha256.clone(),
                lease_refs: vec![lease.lease_id.clone()],
                governance_refs: vec![governance.receipt_id.clone()],
                signer_kernel_ids: invocation.signer_kernel_ids.clone(),
            }),
        },
    )?;
    let store = super::open_store(state)?;
    store.insert_treaty_runtime_artifact(
        "capability_lease",
        &lease.lease_id,
        &RuntimeTreatyLeaseRecord {
            lease: lease.clone(),
            valid_from_unix_ms: from,
        },
    )?;
    store.insert_treaty_runtime_artifact(
        "governance_receipt",
        &governance.receipt_id,
        &RuntimeTreatyGovernanceRecord {
            receipt: governance.clone(),
            valid_from_unix_ms: from,
            valid_until_unix_ms: until,
        },
    )?;
    for (kind, name, value) in [
        ("treaty_scope", scope.treaty_id.clone(), json!(scope)),
        (
            "ladder_intersection",
            intersection.intersection_id.clone(),
            json!(intersection),
        ),
        (
            "cross_kernel_continuation",
            continuation.continuation_id.clone(),
            json!(continuation),
        ),
        (
            "receipt_lineage_bundle",
            lineage.bundle_id.clone(),
            json!(lineage),
        ),
        (
            "bilateral_invocation",
            invocation.invocation_id.clone(),
            json!(invocation),
        ),
        ("bilateral_dsse_envelope", id("dsse"), json!(dsse)),
    ] {
        store.insert_treaty_runtime_artifact(kind, &name, &value)?;
    }
    request.federated_origin_kernel_id = Some(origin.clone());
    let admission = RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.into(),
        admission_id: id("admission"),
        binding: RuntimeRequestBinding::from_tool_call_request(request, local)?,
        workflow_id: config.program_id.clone(),
        workflow_grant_id: id("grant"),
        step_index: 0,
        destructive: false,
        lease_id: Some(lease.lease_id),
        governance_receipt_id: Some(governance.receipt_id),
        trust_bundle_sha256: trust,
        verification_context_sha256: digest(config)?,
    };
    store.insert_bundle(admission.clone())?;
    request.governed_intent = Some(GovernedTransactionIntent {
        id: id("intent"),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "perform a funded review under receiver-owned admission".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        body: Default::default(),
        context: Some(json!({
            "chioAdmission":{"admissionId":admission.admission_id,"bundleSha256":runtime_admission_bundle_sha256(&admission)?},
            "chioTreaty":{"treatyScopeId":scope.treaty_id,"treatyScopeSha256":treaty_scope_sha256(&scope)?,
                "ladderIntersectionId":intersection.intersection_id,"ladderIntersectionSha256":ladder_intersection_sha256(&intersection)?,
                "actionClassId":action,"crossKernelContinuation":{"id":continuation.continuation_id,"sha256":digest(&continuation)?},
                "receiptLineageBundle":{"id":lineage.bundle_id,"sha256":digest(&lineage)?},
                "bilateralInvocation":{"id":invocation.invocation_id,"sha256":bilateral_invocation_binding_sha256(&invocation)?},
                "bilateralDsse":{"id":id("dsse"),"sha256":digest(&dsse)?}}
        })),
    });
    Ok(())
}
