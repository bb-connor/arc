//! Serialization controls for the private authorization proof boundary.
//! The existing test carrier supplies provenance; these tests do not claim
//! end-to-end capability admission, effect execution or completion qualification.
use super::*;
use crate::kernel::active_response_executor::test_support::{
    execution_request, ExecutionRequestFixture,
};
use crate::kernel::{
    ActiveResponseExecutionEvidenceParts, ActiveResponseExecutionOrigin,
    ActiveResponseExecutionOutcome, ActiveResponseExecutorAuthorityIdentity,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::Keypair;
use chio_security_types::ports::{
    ActionId, CanonicalBody, LeaseOwnerId, OpaqueReceiptRef, ResponseDispatchAuthorization,
    ResponseDispatchLease, ResponsePlanRecord, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponseExecutionBinding, ResponseExecutionMode, ResponsePlanInput, ResponseTarget,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn id(value: &str) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(value)?)
}

fn fixture(
    legacy: bool,
) -> Result<
    (
        ActiveResponseExecutionRequest,
        ActiveResponseExecutionEvidence,
        ResponseSnapshot,
    ),
    Box<dyn std::error::Error>,
> {
    let key = Keypair::from_seed(&[0x67; 32]);
    let identity = ActiveResponseExecutorAuthorityIdentity::new(key.public_key(), 1)?;
    let contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())?;
    let plan = chio_response_model::state::build_response_plan(ResponsePlanInput {
        execution: ResponseExecutionBinding::new(ResponseExecutionMode::Live),
        tenant_id: TenantId::new("proof-cross-binding-tenant")?,
        action_id: ActionId::new("proof-cross-binding-action")?,
        trigger_finding_id: id("proof-cross-binding-finding")?,
        trigger_finding_hash: Digest32::new([31; 32]),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-receipt")?,
        policy_version: id("proof-cross-binding-policy")?,
        policy_hash: Digest32::new([32; 32]),
        affected_ids: vec![id("proof-cross-binding-session")?],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("proof-cross-binding-session")?,
            },
            contribution_hash: Digest32::new(*sha256(contribution.as_bytes()).as_bytes()),
            canonical_contribution: contribution,
            observed_base_version_hash: Digest32::new([20; 32]),
        }],
        ttl_ms: 20_000,
        created_at_unix_ms: 40_000,
        operator_capability: OperatorCapabilityBinding {
            capability_id: id("proof-cross-binding-capability")?,
            capability_digest: Digest32::new([30; 32]),
            expires_at_unix_ms: 70_000,
            executor_subject: id(&identity.subject().to_hex())?,
        },
        approval_requirement: ResponseApprovalRequirement::Governed {
            policy_id: id("proof-cross-binding-governance")?,
        },
        submitter: id("proof-cross-binding-submitter")?,
        reason_hash: Digest32::new([31; 32]),
    })?;
    let authorization_capability_hash = Hash::from_bytes([30; 32]).to_hex();
    let governed_intent_hash = Hash::from_bytes([32; 32]).to_hex();
    let policy_decision_hash = Hash::from_bytes([33; 32]).to_hex();
    let approval = ActiveResponseExecutionApproval::Governed {
        admission_operation_id: "proof-cross-binding-admission".to_owned(),
        admission_operation_version: 3,
        approval_set_hash: Hash::from_bytes([34; 32]).to_hex(),
    };
    let authorized_at_unix_ms = 40_001;
    let legacy_id = crate::derive_active_response_dispatch_id(
        &plan,
        &identity,
        &authorization_capability_hash,
        &governed_intent_hash,
        &policy_decision_hash,
        authorized_at_unix_ms,
        &approval,
    )?;
    let fingerprint = if legacy {
        None
    } else {
        Some(Digest32::new([35; 32]))
    };
    let dispatch_id = match fingerprint {
        Some(value) => crate::bind_active_response_dispatch_id_to_artifact(&legacy_id, &value)?,
        None => legacy_id,
    };
    let request = execution_request(ExecutionRequestFixture {
        request_id: plan.action_id.as_str().to_owned(),
        plan_body_hash: Hash::from_bytes(*plan.plan_hash.as_bytes()).to_hex(),
        expires_at_unix_ms: plan.expires_at_unix_ms,
        response_plan: plan.clone(),
        dispatch_id,
        executor_authority: identity,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        admission_artifact_fingerprint: fingerprint,
        approval,
        authorized_at_unix_ms,
        origin: if legacy {
            ActiveResponseExecutionOrigin::CommittedAdmission
        } else {
            ActiveResponseExecutionOrigin::Fresh
        },
    });
    let prepared = request.prepare_dispatch(
        ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("proof-cross-binding-worker")?,
            lease_expires_at_unix_ms: 50_000,
        },
        42_000,
    )?;
    let snapshot = chio_response_model::state::decode_response_record(&prepared.response_plan)?;
    let action =
        ToolCallAction::from_parameters(serde_json::json!({"serialization_control": true}))?;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "proof-cross-binding-receipt".to_owned(),
            timestamp: 42,
            capability_id: "proof-cross-binding-capability".to_owned(),
            tool_server: "proof-cross-binding-server".to_owned(),
            tool_name: "proof-cross-binding-tool".to_owned(),
            content_hash: action.parameter_hash.clone(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            policy_hash: Hash::from_bytes([32; 32]).to_hex(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: Default::default(),
            tenant_id: Some(plan.tenant_id.as_str().to_owned()),
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        },
        &key,
    )?;
    assert!(receipt.verify_signature()?);
    let evidence = make_evidence(
        &request,
        prepared.authorization,
        prepared.response_plan,
        &snapshot,
        receipt,
    )?;
    Ok((request, evidence, snapshot))
}

fn make_evidence(
    request: &ActiveResponseExecutionRequest,
    authorization: ResponseDispatchAuthorization,
    response: ResponsePlanRecord,
    snapshot: &ResponseSnapshot,
    receipt: ChioReceipt,
) -> Result<ActiveResponseExecutionEvidence, Box<dyn std::error::Error>> {
    let transition = snapshot
        .mutations
        .as_slice()
        .last()
        .ok_or("applying transition absent")?;
    Ok(ActiveResponseExecutionEvidence::new(
        ActiveResponseExecutionEvidenceParts {
            outcome: ActiveResponseExecutionOutcome::Activated,
            dispatch_id: request.dispatch_id().clone(),
            tenant_id: snapshot.plan.tenant_id.clone(),
            action_id: snapshot.plan.action_id.clone(),
            plan_hash: snapshot.plan.plan_hash,
            executor_authority_generation: request.executor_authority_generation(),
            response_generation: response.generation,
            response_transition_id: transition.transition_id().clone(),
            response_body_hash: response.body_hash,
            response_record: response,
            dispatch_authorization: authorization,
            proof_evidence_id: OpaqueReceiptRef::new(receipt.id.clone())?,
            proof_body_hash: Digest32::new(*sha256(&canonical_json_bytes(&receipt)?).as_bytes()),
            completion_receipt: receipt,
            effects: Vec::new(),
            failure: None,
            recovered: false,
        },
    ))
}

#[test]
fn proof_authorization_rejects_fingerprint_different_from_sealed_execution() -> TestResult {
    let (request, original, snapshot) = fixture(false)?;
    let expected =
        active_response_execution_dispatch_binding(&request, request.authorized_at_unix_ms())?;
    assert_eq!(snapshot.execution_dispatch.as_ref(), Some(&expected));
    assert_eq!(
        verify_active_response_dispatch_authorization(&request, &original, &snapshot, &expected)?,
        original.dispatch_authorization().body_hash
    );
    let before = canonical_json_bytes(&expected)?;
    let mut authorization = original.dispatch_authorization().clone();
    authorization.body.admission_artifact_fingerprint = Some(Digest32::new([36; 32]));
    let bytes = canonical_json_bytes(&authorization.body)?;
    authorization.body_hash = Digest32::new(*sha256(&bytes).as_bytes());
    authorization.canonical_body = CanonicalBody::new(bytes)?;
    let mut alternate_snapshot = snapshot.clone();
    alternate_snapshot.dispatch_authorization_hash = Some(authorization.body_hash);
    assert_eq!(
        alternate_snapshot.execution_dispatch.as_ref(),
        Some(&expected)
    );
    let response_bytes = canonical_json_bytes(&alternate_snapshot)?;
    let mut response = original.response_record().clone();
    response.body_hash = Digest32::new(*sha256(&response_bytes).as_bytes());
    response.canonical_body = CanonicalBody::new(response_bytes)?;
    let alternate = make_evidence(
        &request,
        authorization,
        response,
        &alternate_snapshot,
        original.completion_receipt().clone(),
    )?;
    let refused = verify_active_response_dispatch_authorization(
        &request,
        &alternate,
        &alternate_snapshot,
        &expected,
    );
    assert!(
        matches!(&refused, Err(KernelError::Internal(reason))
        if reason == "active-response admission failed: active-response dispatch authorization does not match its durable proof"),
        "different authorization fingerprint was accepted: {refused:?}"
    );
    assert_eq!(canonical_json_bytes(&expected)?, before);
    assert_eq!(snapshot.execution_dispatch.as_ref(), Some(&expected));
    Ok(())
}

#[test]
fn proof_authorization_accepts_coherent_legacy_schema_one() -> TestResult {
    let (request, evidence, snapshot) = fixture(true)?;
    let expected =
        active_response_execution_dispatch_binding(&request, request.authorized_at_unix_ms())?;
    assert_eq!(expected.schema_version, 1);
    assert_eq!(expected.admission_artifact_fingerprint, None);
    assert!(
        !std::str::from_utf8(evidence.dispatch_authorization().canonical_body.as_bytes())?
            .contains("admission_artifact_fingerprint")
    );
    assert_eq!(
        verify_active_response_dispatch_authorization(&request, &evidence, &snapshot, &expected)?,
        evidence.dispatch_authorization().body_hash
    );
    Ok(())
}

// Signed serialization controls for the completed operation/anchor boundary.
// These exercise the private durable-consistency validator. They do not run
// effects, persist a terminal outbox, or claim public end-to-end qualification.

fn terminal_executor_binding_fixture(
    legacy: bool,
) -> Result<
    (
        crate::security_admission_operation::AdmissionOperation,
        crate::kernel::active_response_operation_binding::ActiveResponseOperationAnchor,
        ChioReceipt,
    ),
    Box<dyn std::error::Error>,
> {
    use crate::kernel::active_response_operation_binding::{
        bind_active_response_operation_request_hash_to_artifact,
        build_active_response_operation_anchor,
        derive_active_response_operation_request_binding_hash,
    };
    use crate::security_admission_operation::{
        AdmissionDispatchState, AdmissionOperation, AdmissionOperationKind,
        AdmissionOperationState, PreparedAdmissionOperation,
    };
    use chio_core::receipt::security::{
        ActiveDefenseEffectOutcome, ActiveDefenseEffectOutcomeCommitment,
        ActiveDefenseEffectOutcomeCommitments, ActiveDefenseReceiptBody,
        ActiveDefenseReceiptHeader, ResponseCompletionReceiptBody,
    };

    // Reuse the existing kernel proof carrier and its deterministic signing key.
    // The closed completion is a genuine signed validator fixture, without a
    // claim that an executor produced or stored its lifecycle/effect history.
    let (request, applying_evidence, snapshot) = fixture(legacy)?;
    let plan = request.response_plan();
    let fingerprint = request.admission_artifact_fingerprint();
    let approval_set_hash = match request.approval() {
        crate::ActiveResponseExecutionApproval::Governed {
            approval_set_hash, ..
        } => approval_set_hash.clone(),
        _ => return Err("terminal binding fixture requires governed approval".into()),
    };
    let legacy_request_hash = derive_active_response_operation_request_binding_hash(
        request.plan_body_hash(),
        request.executor_authority_id(),
        request.executor_authority_generation(),
        request.authorization_capability_hash(),
        request.governed_intent_hash(),
        &approval_set_hash,
        &Hash::from_bytes(*plan.policy_hash.as_bytes()).to_hex(),
    )?;
    let request_binding_hash =
        bind_active_response_operation_request_hash_to_artifact(&legacy_request_hash, fingerprint)?;
    let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: request.executor_authority_id().to_owned(),
        request_id: request.request_id().to_owned(),
        capability_id: plan.operator_capability.capability_id.as_str().to_owned(),
        authorization_capability_hash: request.authorization_capability_hash().to_owned(),
        request_binding_hash,
        policy_hash: Hash::from_bytes(*plan.policy_hash.as_bytes()).to_hex(),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some(approval_set_hash.clone()),
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })?;
    let reserved = prepared.transition_checked(
        AdmissionOperationState::ApprovalReserved,
        AdmissionDispatchState::NotStarted,
        1,
        None,
    )?;
    let committed = reserved.transition_checked(
        AdmissionOperationState::DispatchCommitted,
        AdmissionDispatchState::Committed,
        1,
        None,
    )?;
    let completed = committed.transition_checked(
        AdmissionOperationState::Completed,
        AdmissionDispatchState::EffectCompleted,
        1,
        None,
    )?;
    let mut anchor = build_active_response_operation_anchor(
        plan,
        request.executor_authority(),
        request.authorized_at_unix_ms(),
        request.authorization_capability_hash(),
        request.governed_intent_hash(),
        request.policy_decision_hash(),
        &approval_set_hash,
    )?;
    anchor.admission_artifact_fingerprint = fingerprint;
    assert!(anchor.is_valid());

    let mut binding =
        active_response_execution_dispatch_binding(&request, request.authorized_at_unix_ms())?;
    binding.approval = ResponseDispatchApproval::Governed {
        admission_operation_id: id(completed.operation_id())?,
        admission_operation_version: committed.version(),
        approval_set_hash: Digest32::new(*Hash::from_hex(&approval_set_hash)?.as_bytes()),
    };
    let execution_approval = crate::ActiveResponseExecutionApproval::Governed {
        admission_operation_id: completed.operation_id().to_owned(),
        admission_operation_version: committed.version(),
        approval_set_hash,
    };
    let original_id = crate::derive_active_response_dispatch_id(
        plan,
        request.executor_authority(),
        request.authorization_capability_hash(),
        request.governed_intent_hash(),
        request.policy_decision_hash(),
        request.authorized_at_unix_ms(),
        &execution_approval,
    )?;
    binding.dispatch_id = match fingerprint {
        Some(value) => crate::bind_active_response_dispatch_id_to_artifact(&original_id, &value)?,
        None => original_id,
    };
    binding.validate_for_plan(plan)?;
    let effects = plan
        .effects
        .as_slice()
        .iter()
        .map(|effect| ActiveDefenseEffectOutcomeCommitment {
            effect: active_response_effect_commitment(effect),
            outcome: ActiveDefenseEffectOutcome::Applied {
                resulting_version_hash: Digest32::new([39; 32]),
            },
        })
        .collect::<Vec<_>>();
    let body = ActiveDefenseReceiptBody::ResponseCompletion(ResponseCompletionReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            42_001,
            plan.tenant_id.clone(),
            id("terminal-binding-completion")?,
            vec![OpaqueReceiptRef::new("terminal-binding-prior")?],
        )?,
        response: active_response_response_binding(plan),
        execution_dispatch: Some(binding),
        dispatch_authorization_hash: Some(applying_evidence.dispatch_authorization().body_hash),
        response_generation: snapshot
            .generation
            .checked_add(3)
            .ok_or("fixture generation")?,
        response_body_hash: applying_evidence.response_record().body_hash,
        final_state: ResponseState::Active,
        error_code: None,
        effects: ActiveDefenseEffectOutcomeCommitments::new(effects)?,
    });
    let receipt = sign_terminal_executor_binding_body(&body)?;
    assert_terminal_executor_original_predicates(&completed, &anchor, &receipt)?;
    Ok((completed, anchor, receipt))
}

fn sign_terminal_executor_binding_body(
    body: &chio_core::receipt::security::ActiveDefenseReceiptBody,
) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core::receipt::security::ActiveDefenseReceiptBody;
    body.validate()?;
    let response = match body {
        ActiveDefenseReceiptBody::ResponseCompletion(completion) => &completion.response,
        _ => return Err("terminal binding fixture requires response completion".into()),
    };
    let evidence_id = body.evidence_id()?;
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": body.kind().as_str(),
        "transition_id": body.header().transition_id.as_str(),
    }))?;
    let key = Keypair::from_seed(&[0x67; 32]);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: body.header().occurred_at_unix_ms / 1_000,
            capability_id: "chio.active-defense.system".to_owned(),
            tool_server: "chio.kernel".to_owned(),
            tool_name: body.kind().as_str().to_owned(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: Hash::from_bytes(*body.body_digest()?.as_bytes()).to_hex(),
            policy_hash: Hash::from_bytes(*response.policy.policy_hash.as_bytes()).to_hex(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "active_defense_body": body,
                "active_defense_evidence_id": evidence_id.as_str(),
                "occurred_at_unix_ms": body.header().occurred_at_unix_ms,
            })),
            trust_level: TrustLevel::Verified,
            tenant_id: Some(body.header().tenant_id.as_str().to_owned()),
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        },
        &key,
    )?;
    assert!(receipt.verify_signature()?);
    Ok(receipt)
}

// Setup diagnostics only. Negative cases still call the production validator
// and retain their original rejection assertions and immutable controls.
fn assert_terminal_executor_original_predicates(
    operation: &crate::security_admission_operation::AdmissionOperation,
    anchor: &crate::kernel::active_response_operation_binding::ActiveResponseOperationAnchor,
    receipt: &ChioReceipt,
) -> TestResult {
    use crate::security_admission_operation::{
        AdmissionDispatchState, AdmissionOperationKind, AdmissionOperationState,
    };
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core::receipt::security::ActiveDefenseReceiptBody;
    use chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY;

    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or("original fixture metadata")?;
    let body: ActiveDefenseReceiptBody = serde_json::from_value(
        metadata
            .get("active_defense_body")
            .ok_or("original fixture closed body")?
            .clone(),
    )?;
    let (response, binding) = match &body {
        ActiveDefenseReceiptBody::ResponseCompletion(completion) => (
            &completion.response,
            completion
                .execution_dispatch
                .as_ref()
                .ok_or("original fixture dispatch binding")?,
        ),
        _ => return Err("original fixture requires response completion".into()),
    };
    let identity = ActiveResponseExecutorAuthorityIdentity::new(
        receipt.kernel_key.clone(),
        anchor.executor_authority_generation,
    )?;
    let evidence_id = body.evidence_id()?;
    let digest = body.body_digest()?;
    let expected_action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": body.kind().as_str(),
        "transition_id": body.header().transition_id.as_str(),
    }))?;
    let expected_metadata = serde_json::json!({
        "active_defense_body": &body,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": body.header().occurred_at_unix_ms,
    });
    let dispatch_version = operation
        .version()
        .checked_sub(1)
        .ok_or("original dispatch version")?;
    let approval_hash = operation
        .approval_set_hash()
        .ok_or("original approval hash")?;
    let mut failed = Vec::<String>::new();
    macro_rules! setup_check {
        ($label:expr, $actual:expr, $expected:expr) => {{
            let actual = $actual;
            let expected = $expected;
            if actual != expected {
                failed.push(format!(
                    "{}: actual={actual:?}, expected={expected:?}",
                    $label
                ));
            }
        }};
    }
    let hex = |digest: &Digest32| Hash::from_bytes(*digest.as_bytes()).to_hex();

    setup_check!(
        "operation kind",
        operation.kind(),
        AdmissionOperationKind::GovernedActiveResponse
    );
    setup_check!(
        "operation state",
        operation.state(),
        AdmissionOperationState::Completed
    );
    setup_check!(
        "operation dispatch state",
        operation.dispatch_state(),
        AdmissionDispatchState::EffectCompleted
    );
    setup_check!("genuine signature", receipt.verify_signature()?, true);
    setup_check!(
        "identity vs operation authority",
        identity.authority_id().to_owned(),
        operation.coordinator_authority_id().to_owned()
    );
    setup_check!(
        "identity vs anchor authority",
        identity.authority_id().to_owned(),
        anchor.executor_authority_id.clone()
    );
    setup_check!(
        "binding vs operation authority",
        binding.executor_authority_id.as_str().to_owned(),
        operation.coordinator_authority_id().to_owned()
    );
    setup_check!(
        "binding authority generation",
        binding.executor_authority_generation,
        anchor.executor_authority_generation
    );
    setup_check!(
        "binding capability hash",
        hex(&binding.authorization_capability_hash),
        operation.authorization_capability_hash().to_owned()
    );
    setup_check!(
        "binding intent hash",
        hex(&binding.governed_intent_hash),
        anchor.governed_intent_hash.clone()
    );
    setup_check!(
        "binding policy decision hash",
        hex(&binding.policy_decision_hash),
        anchor.policy_decision_hash.clone()
    );
    setup_check!(
        "binding plan hash",
        hex(&binding.plan_hash),
        anchor.plan_hash.clone()
    );
    setup_check!(
        "binding authorization time",
        binding.authorized_at_unix_ms,
        anchor.authorized_at_unix_ms
    );
    match &binding.approval {
        ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => {
            setup_check!(
                "approval operation id",
                admission_operation_id.as_str().to_owned(),
                operation.operation_id().to_owned()
            );
            setup_check!(
                "approval operation version",
                *admission_operation_version,
                dispatch_version
            );
            setup_check!(
                "approval set hash",
                hex(approval_set_hash),
                approval_hash.to_owned()
            );
        }
        other => failed.push(format!(
            "approval mode: actual={other:?}, expected=governed"
        )),
    }
    setup_check!(
        "standalone dispatch binding",
        binding
            .validate_for_response(
                &body.header().tenant_id,
                &response.action_id,
                &response.plan_hash,
                response.plan_expires_at_unix_ms
            )
            .is_ok(),
        true
    );
    setup_check!(
        "response action id",
        response.action_id.as_str().to_owned(),
        operation.request_id().to_owned()
    );
    setup_check!(
        "response plan hash",
        hex(&response.plan_hash),
        anchor.plan_hash.clone()
    );
    setup_check!(
        "response policy hash",
        hex(&response.policy.policy_hash),
        operation.policy_hash().to_owned()
    );
    setup_check!(
        "receipt capability",
        receipt.capability_id.clone(),
        "chio.active-defense.system".to_owned()
    );
    setup_check!(
        "receipt tool server",
        receipt.tool_server.clone(),
        "chio.kernel".to_owned()
    );
    setup_check!(
        "receipt tool name",
        receipt.tool_name.clone(),
        body.kind().as_str().to_owned()
    );
    setup_check!(
        "receipt action parameters",
        receipt.action.parameters.clone(),
        expected_action.parameters.clone()
    );
    setup_check!(
        "receipt action parameter hash",
        receipt.action.parameter_hash.clone(),
        expected_action.parameter_hash.clone()
    );
    setup_check!(
        "receipt kind",
        receipt.receipt_kind,
        ReceiptKind::TraceObservation
    );
    setup_check!(
        "receipt boundary",
        receipt.boundary_class,
        BoundaryClass::DetectOnly
    );
    setup_check!(
        "receipt observation outcome",
        receipt.observation_outcome,
        Some(ObservationOutcome::Observed)
    );
    setup_check!("receipt decision absent", receipt.decision.is_none(), true);
    setup_check!(
        "receipt tool origin",
        receipt.tool_origin,
        ToolOrigin::ChioInternal
    );
    setup_check!(
        "receipt redaction",
        receipt.redaction_mode,
        RedactionMode::Redacted
    );
    setup_check!("receipt trust", receipt.trust_level, TrustLevel::Verified);
    setup_check!("receipt actor chain empty", receipt.actor_chain.len(), 0);
    setup_check!("receipt evidence empty", receipt.evidence.len(), 0);
    setup_check!(
        "receipt BBS projection absent",
        receipt.bbs_projection_version.is_none(),
        true
    );
    setup_check!(
        "receipt BBS signature absent",
        receipt.bbs_signature.is_none(),
        true
    );
    setup_check!(
        "receipt exact native metadata",
        metadata.clone(),
        expected_metadata
    );
    setup_check!(
        "receipt timestamp",
        receipt.timestamp,
        body.header().occurred_at_unix_ms / 1_000
    );
    setup_check!(
        "receipt tenant",
        receipt.tenant_id.clone(),
        Some(body.header().tenant_id.as_str().to_owned())
    );
    setup_check!(
        "receipt content hash",
        receipt.content_hash.clone(),
        hex(&digest)
    );
    setup_check!(
        "receipt policy hash",
        receipt.policy_hash.clone(),
        operation.policy_hash().to_owned()
    );

    // Healthy fixture controls for the separately reviewed omitted equalities.
    setup_check!(
        "original artifact fingerprint",
        binding.admission_artifact_fingerprint,
        anchor.admission_artifact_fingerprint
    );
    setup_check!(
        "original artifact schema",
        binding.schema_version,
        if anchor.admission_artifact_fingerprint.is_some() {
            2
        } else {
            1
        }
    );
    setup_check!(
        "native producer supplies no signing nonce",
        metadata
            .get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
            .is_none(),
        true
    );
    setup_check!(
        "authoritative signed receipt ID exists",
        receipt.id.is_empty(),
        false
    );
    assert!(
        failed.is_empty(),
        "terminal Original fixture setup predicates failed:\n{}",
        failed.join("\n")
    );
    Ok(())
}

fn reject_terminal_executor_artifact_mismatch(
    schema_version: u8,
    fingerprint: Option<Digest32>,
) -> TestResult {
    use crate::kernel::active_response_coordinator::validate_active_response_terminal_executor_receipt;
    use chio_core::receipt::security::ActiveDefenseReceiptBody;
    let (operation, anchor, original) = terminal_executor_binding_fixture(false)?;
    validate_active_response_terminal_executor_receipt(&operation, &anchor, &original)?;
    let before = (
        operation.clone(),
        canonical_json_bytes(&anchor)?,
        canonical_json_bytes(&original)?,
    );
    let mut body: ActiveDefenseReceiptBody = serde_json::from_value(
        original
            .metadata
            .as_ref()
            .ok_or("original metadata")?
            .get("active_defense_body")
            .ok_or("original closed body")?
            .clone(),
    )?;
    let ActiveDefenseReceiptBody::ResponseCompletion(completion) = &mut body else {
        return Err("original completion body missing".into());
    };
    let binding = completion
        .execution_dispatch
        .as_mut()
        .ok_or("original execution binding")?;
    assert_eq!(binding.schema_version, 2);
    assert_eq!(
        binding.admission_artifact_fingerprint,
        anchor.admission_artifact_fingerprint
    );
    binding.schema_version = schema_version;
    binding.admission_artifact_fingerprint = fingerprint;
    assert_ne!(
        binding.admission_artifact_fingerprint,
        anchor.admission_artifact_fingerprint
    );
    // Revalidate the closed native shape and re-sign the exact changed body.
    // The expected refusal belongs to the operation/anchor equality boundary.
    let alternate = sign_terminal_executor_binding_body(&body)?;
    let refused =
        validate_active_response_terminal_executor_receipt(&operation, &anchor, &alternate);
    assert!(
        matches!(&refused, Err(KernelError::Internal(reason))
        if reason == "active-response admission failed: active-response terminal executor receipt binding is inconsistent"),
        "signed terminal artifact mismatch was accepted: {refused:?}"
    );
    assert_eq!(
        (
            operation.clone(),
            canonical_json_bytes(&anchor)?,
            canonical_json_bytes(&original)?,
        ),
        before
    );
    validate_active_response_terminal_executor_receipt(&operation, &anchor, &original)?;
    Ok(())
}

#[test]
fn terminal_executor_rejects_other_signed_artifact_fingerprint() -> TestResult {
    reject_terminal_executor_artifact_mismatch(2, Some(Digest32::new([36; 32])))
}

#[test]
fn terminal_executor_rejects_signed_legacy_binding_beside_bound_anchor() -> TestResult {
    reject_terminal_executor_artifact_mismatch(1, None)
}

#[test]
fn terminal_executor_rejects_signed_other_original_dispatch_id() -> TestResult {
    use crate::kernel::active_response_coordinator::validate_active_response_terminal_executor_receipt;
    use chio_core::receipt::security::ActiveDefenseReceiptBody;
    let (operation, anchor, original) = terminal_executor_binding_fixture(false)?;
    validate_active_response_terminal_executor_receipt(&operation, &anchor, &original)?;
    let before = (
        operation.clone(),
        canonical_json_bytes(&anchor)?,
        canonical_json_bytes(&original)?,
    );
    // The other identifier comes from the existing coherent legacy control's
    // real producer derivation. Only the bound receipt's dispatch ID changes.
    let (_, _, other_receipt) = terminal_executor_binding_fixture(true)?;
    let other_body: ActiveDefenseReceiptBody = serde_json::from_value(
        other_receipt
            .metadata
            .as_ref()
            .ok_or("other metadata")?
            .get("active_defense_body")
            .ok_or("other closed body")?
            .clone(),
    )?;
    let ActiveDefenseReceiptBody::ResponseCompletion(other_completion) = other_body else {
        return Err("other completion body missing".into());
    };
    let other_id = other_completion
        .execution_dispatch
        .ok_or("other execution binding")?
        .dispatch_id;
    let mut body: ActiveDefenseReceiptBody = serde_json::from_value(
        original
            .metadata
            .as_ref()
            .ok_or("original metadata")?
            .get("active_defense_body")
            .ok_or("original closed body")?
            .clone(),
    )?;
    let ActiveDefenseReceiptBody::ResponseCompletion(completion) = &mut body else {
        return Err("original completion body missing".into());
    };
    let binding = completion
        .execution_dispatch
        .as_mut()
        .ok_or("original execution binding")?;
    assert_ne!(binding.dispatch_id, other_id);
    assert_eq!(binding.schema_version, 2);
    assert_eq!(
        binding.admission_artifact_fingerprint,
        anchor.admission_artifact_fingerprint
    );
    binding.dispatch_id = other_id;
    let alternate = sign_terminal_executor_binding_body(&body)?;
    let refused =
        validate_active_response_terminal_executor_receipt(&operation, &anchor, &alternate);
    assert!(
        matches!(&refused, Err(KernelError::Internal(reason))
        if reason == "active-response admission failed: active-response terminal executor receipt binding is inconsistent"),
        "signed other original dispatch ID was accepted: {refused:?}"
    );
    assert_eq!(
        (
            operation.clone(),
            canonical_json_bytes(&anchor)?,
            canonical_json_bytes(&original)?,
        ),
        before
    );
    validate_active_response_terminal_executor_receipt(&operation, &anchor, &original)?;
    Ok(())
}

#[test]
fn terminal_executor_accepts_exact_signed_bound_anchor() -> TestResult {
    let (operation, anchor, receipt) = terminal_executor_binding_fixture(false)?;
    crate::kernel::active_response_coordinator::validate_active_response_terminal_executor_receipt(
        &operation, &anchor, &receipt,
    )?;
    Ok(())
}

#[test]
fn terminal_executor_accepts_exact_signed_legacy_anchor() -> TestResult {
    let (operation, anchor, receipt) = terminal_executor_binding_fixture(true)?;
    assert_eq!(anchor.admission_artifact_fingerprint, None);
    let encoded = canonical_json_bytes(&receipt)?;
    assert!(!std::str::from_utf8(&encoded)?.contains("admission_artifact_fingerprint"));
    crate::kernel::active_response_coordinator::validate_active_response_terminal_executor_receipt(
        &operation, &anchor, &receipt,
    )?;
    Ok(())
}
