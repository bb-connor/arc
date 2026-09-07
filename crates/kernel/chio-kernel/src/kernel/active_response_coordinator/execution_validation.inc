fn build_governed_active_response_operation(
    bindings: &VerifiedActiveResponseBindings,
    requirement: &VerifiedActiveResponseRequirement,
    verified_approvals: &VerifiedThresholdApprovalSet,
) -> Result<(AdmissionOperation, ApprovalSetReservationInput), KernelError> {
    let approval_set_hash = verified_approvals
        .approval_set_hash()
        .map_err(|error| active_response_denied(error.to_string()))?;
    let request_binding_hash = derive_active_response_operation_request_binding_hash(
        bindings.plan_body_hash(),
        requirement.executor_authority().authority_id(),
        requirement.executor_authority().generation(),
        bindings.authorization_capability_hash(),
        bindings.governed_intent_hash(),
        &approval_set_hash,
        requirement.policy_hash(),
    )
    .map_err(|error| active_response_denied(error.to_string()))?;
    let operation = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: requirement.executor_authority().authority_id().to_string(),
        request_id: bindings.request_id().to_string(),
        capability_id: bindings.authorization_capability_id().to_string(),
        authorization_capability_hash: bindings.authorization_capability_hash().to_string(),
        request_binding_hash,
        policy_hash: requirement.policy_hash().to_string(),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some(approval_set_hash),
        execution_nonce_id: None,
        coordinator_lease_epoch: ACTIVE_RESPONSE_COORDINATOR_LEASE_EPOCH,
    })
    .map_err(|error| active_response_denied(format!("operation is invalid: {error}")))?;
    let approval_set = verified_approvals
        .reservation_input()
        .map_err(|error| active_response_denied(format!("approval replay is invalid: {error}")))?;
    Ok((operation, approval_set))
}

pub(super) fn build_active_response_execution_request(
    request: &ActiveResponseAdmissionRequest,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
    policy_decision_hash: &str,
    authorized_at_unix_ms: u64,
    approval: ActiveResponseExecutionApproval,
) -> Result<ActiveResponseExecutionRequest, KernelError> {
    let response_plan = request.response_plan();
    if authorized_at_unix_ms < response_plan.created_at_unix_ms
        || authorized_at_unix_ms >= response_plan.expires_at_unix_ms
    {
        return Err(active_response_denied(
            "active-response stable authorization time is outside the plan window",
        ));
    }
    let authorization_capability_hash = crate::threshold_approval::authorization_capability_hash(
        request.authorization().operator_capability(),
    )
    .map_err(|error| {
        active_response_denied(format!(
            "active-response capability hashing failed: {error}"
        ))
    })?;
    let governed_intent_hash = request
        .authorization()
        .governed_intent()
        .binding_hash()
        .map_err(|error| {
            active_response_denied(format!(
                "active-response governed intent hashing failed: {error}"
            ))
        })?;
    let plan_body_hash = digest_hex(&response_plan.plan_hash);
    let dispatch_id = derive_active_response_dispatch_id(
        response_plan,
        &executor_authority,
        &authorization_capability_hash,
        &governed_intent_hash,
        policy_decision_hash,
        authorized_at_unix_ms,
        &approval,
    )
    .map_err(|error| active_response_denied(error.to_string()))?;
    Ok(ActiveResponseExecutionRequest::new(
        ActiveResponseExecutionRequestParts {
            response_plan: response_plan.clone(),
            dispatch_id,
            executor_authority,
            request_id: response_plan.action_id.as_str().to_string(),
            plan_body_hash,
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash: policy_decision_hash.to_string(),
            approval,
            authorized_at_unix_ms,
            expires_at_unix_ms: response_plan.expires_at_unix_ms,
            dispatch_committed_resume: false,
        },
    ))
}

fn validate_active_response_execution_evidence(
    request: &ActiveResponseExecutionRequest,
    evidence: &ActiveResponseExecutionEvidence,
) -> Result<(), KernelError> {
    let plan = request.response_plan();
    if evidence.dispatch_id() != request.dispatch_id()
        || evidence.tenant_id() != &plan.tenant_id
        || evidence.action_id() != &plan.action_id
        || evidence.plan_hash() != &plan.plan_hash
        || evidence.executor_authority_generation() != request.executor_authority_generation()
    {
        return Err(active_response_internal(
            "active-response execution evidence does not match the authorized dispatch",
        ));
    }
    if evidence.response_generation() == 0 {
        return Err(active_response_internal(
            "active-response execution evidence has a zero response generation",
        ));
    }
    let snapshot = verify_active_response_record_readback(request, evidence)?;
    validate_active_response_failure_evidence(&snapshot, evidence)?;
    let signed_body = verify_active_response_completion_receipt(request, evidence)?;
    let expected_dispatch = active_response_execution_dispatch_binding(
        request,
        evidence.dispatch_authorization().body.authorized_at_unix_ms,
    )?;
    if snapshot.execution_dispatch.as_ref() != Some(&expected_dispatch) {
        return Err(active_response_internal(
            "active-response readback does not bind the exact execution dispatch",
        ));
    }
    let dispatch_authorization_hash = verify_active_response_dispatch_authorization(
        request,
        evidence,
        &snapshot,
        &expected_dispatch,
    )?;
    let last_mutation = snapshot
        .mutations
        .as_slice()
        .last()
        .ok_or_else(|| active_response_internal("active-response proof mutation is missing"))?;
    let (
        header,
        response,
        execution_dispatch,
        signed_dispatch_authorization_hash,
        response_generation,
        response_body_hash,
        effects,
        lift,
    ) = match (evidence.outcome(), &signed_body, last_mutation) {
        (
            ActiveResponseExecutionOutcome::Activated,
            ActiveDefenseReceiptBody::ResponseCompletion(completion),
            ResponseMutationRecord::Transition(transition),
        ) if snapshot.state == ResponseState::Active
            && transition.to_state == ResponseState::Active
            && transition.generation == snapshot.generation
            && completion.final_state == ResponseState::Active =>
        {
            (
                &completion.header,
                &completion.response,
                completion.execution_dispatch.as_ref(),
                completion.dispatch_authorization_hash,
                completion.response_generation,
                completion.response_body_hash,
                completion.effects.as_slice(),
                false,
            )
        }
        (
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect,
            ActiveDefenseReceiptBody::ResponseCompletion(completion),
            ResponseMutationRecord::Failed(failure),
        ) if snapshot.state == ResponseState::Failed
            && failure.to_state == ResponseState::Failed
            && failure.generation == snapshot.generation
            && snapshot.terminal_failure_effects_are_exact(&failure.error_code)
            && completion.error_code.as_ref() == Some(&failure.error_code)
            && completion.final_state == ResponseState::Failed =>
        {
            (
                &completion.header,
                &completion.response,
                completion.execution_dispatch.as_ref(),
                completion.dispatch_authorization_hash,
                completion.response_generation,
                completion.response_body_hash,
                completion.effects.as_slice(),
                false,
            )
        }
        (
            ActiveResponseExecutionOutcome::RolledBackAfterPartial,
            ActiveDefenseReceiptBody::LiftRollbackCompletion(completion),
            ResponseMutationRecord::Final(final_record),
        ) if snapshot.state == ResponseState::Lifted
            && final_record.final_state == ResponseState::Lifted
            && final_record.generation == snapshot.generation
            && completion.final_state == ResponseState::Lifted =>
        {
            (
                &completion.header,
                &completion.response,
                completion.execution_dispatch.as_ref(),
                completion.dispatch_authorization_hash,
                completion.response_generation,
                completion.response_body_hash,
                completion.effects.as_slice(),
                true,
            )
        }
        _ => {
            return Err(active_response_internal(
                "active-response signed proof contradicts its durable outcome",
            ))
        }
    };
    if evidence.response_transition_id() != last_mutation.transition_id()
        || &header.transition_id != last_mutation.transition_id()
        || header.occurred_at_unix_ms != last_mutation.occurred_at_unix_ms()
        || header.prior_receipt_ids.as_slice()
            != core::slice::from_ref(last_mutation.prior_receipt_id())
        || response != &active_response_response_binding(plan)
        || execution_dispatch != Some(&expected_dispatch)
        || signed_dispatch_authorization_hash != Some(dispatch_authorization_hash)
        || response_generation != snapshot.generation
        || response_body_hash != evidence.response_record().body_hash
        || effects.len() != plan.effects.len()
    {
        return Err(active_response_internal(
            "active-response completion proof does not bind the exact durable record",
        ));
    }

    let mut applied_count = 0_usize;
    let mut transition_ids = Vec::with_capacity(evidence.effects().len());
    let mut applied_evidence = evidence.effects().iter();
    for (planned, completed) in plan.effects.as_slice().iter().zip(effects) {
        if completed.effect != active_response_effect_commitment(planned)
            || completed.outcome
                != active_response_expected_effect_outcome(&snapshot, planned, lift)?
        {
            return Err(active_response_internal(
                "active-response signed effect outcome contradicts durable readback",
            ));
        }
        let mut durable_applied =
            snapshot
                .mutations
                .as_slice()
                .iter()
                .filter_map(|mutation| match mutation {
                    ResponseMutationRecord::EffectApplied(record)
                        if record.effect_id == planned.effect_id =>
                    {
                        Some(record)
                    }
                    _ => None,
                });
        let Some(exact_applied) = durable_applied.next() else {
            continue;
        };
        applied_count = applied_count.saturating_add(1);
        let applied = applied_evidence.next().ok_or_else(|| {
            active_response_internal("active-response applied-effect evidence is incomplete")
        })?;
        let Some(effect_transition_id) = exact_applied.effect_transition_id.as_ref() else {
            return Err(active_response_internal(
                "active-response readback effect lacks its durable transition identifier",
            ));
        };
        let expected_effect_generation = applied.generation().checked_add(1).ok_or_else(|| {
            active_response_internal("active-response effect generation overflowed")
        })?;
        if applied.effect_id() != &planned.effect_id
            || applied.generation() == 0
            || applied.transition_id() != effect_transition_id
            || exact_applied.effect_generation != expected_effect_generation
            || applied.resulting_version_hash() != &exact_applied.resulting_version_hash
            || durable_applied.next().is_some()
        {
            return Err(active_response_internal(
                "active-response effect evidence does not match signed durable readback",
            ));
        }
        if transition_ids
            .iter()
            .any(|existing: &&str| *existing == applied.transition_id().as_str())
        {
            return Err(active_response_internal(
                "active-response effect evidence repeats a transition identifier",
            ));
        }
        transition_ids.push(applied.transition_id().as_str());
    }
    if applied_evidence.next().is_some()
        || match evidence.outcome() {
            ActiveResponseExecutionOutcome::Activated => applied_count != plan.effects.len(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect => applied_count != 0,
            ActiveResponseExecutionOutcome::RolledBackAfterPartial => applied_count == 0,
        }
    {
        return Err(active_response_internal(
            "active-response applied-effect evidence contradicts its terminal outcome",
        ));
    }
    if transition_ids
        .iter()
        .any(|transition_id| *transition_id == evidence.response_transition_id().as_str())
    {
        return Err(active_response_internal(
            "active-response completion transition duplicates an effect transition",
        ));
    }
    Ok(())
}

fn validate_active_response_failure_evidence(
    snapshot: &ResponseSnapshot,
    evidence: &ActiveResponseExecutionEvidence,
) -> Result<(), KernelError> {
    match (evidence.outcome(), evidence.failure()) {
        (ActiveResponseExecutionOutcome::FailedBeforeAnyEffect, Some(supplied)) => {
            let exact = snapshot.terminal_failure_evidence().ok_or_else(|| {
                active_response_internal(
                    "active-response terminal failure evidence is not exact durable readback",
                )
            })?;
            if supplied.error_code() != exact.error_code() {
                return Err(active_response_internal(
                    "active-response terminal error does not match durable readback",
                ));
            }
            match (supplied.failed_effect(), exact.failed_effect()) {
                (None, None) => {}
                (Some(supplied_effect), Some(exact_effect))
                    if supplied_effect.effect_id() == exact_effect.effect_id()
                        && supplied_effect.transition_id() == exact_effect.transition_id()
                        && supplied_effect.generation() == exact_effect.generation()
                        && supplied_effect.transition_id() != evidence.response_transition_id() => {
                }
                _ => {
                    return Err(active_response_internal(
                        "active-response failed-effect evidence does not match durable readback",
                    ))
                }
            }
        }
        (ActiveResponseExecutionOutcome::FailedBeforeAnyEffect, None) => {
            return Err(active_response_internal(
                "active-response terminal failure evidence is missing",
            ))
        }
        (_, Some(_)) => {
            return Err(active_response_internal(
                "active-response non-failure outcome carries terminal failure evidence",
            ))
        }
        (_, None) => {}
    }
    Ok(())
}

fn verify_active_response_record_readback(
    request: &ActiveResponseExecutionRequest,
    evidence: &ActiveResponseExecutionEvidence,
) -> Result<ResponseSnapshot, KernelError> {
    let record = evidence.response_record();
    let snapshot: ResponseSnapshot = serde_json::from_slice(record.canonical_body.as_bytes())
        .map_err(|error| {
            active_response_internal(format!(
                "active-response record readback is malformed: {error}"
            ))
        })?;
    let canonical = canonical_json_bytes(&snapshot).map_err(|error| {
        active_response_internal(format!(
            "active-response record readback canonicalization failed: {error}"
        ))
    })?;
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    if canonical.as_slice() != record.canonical_body.as_bytes()
        || body_hash != record.body_hash
        || body_hash != *evidence.response_body_hash()
        || &snapshot.plan != request.response_plan()
        || snapshot.plan.tenant_id != record.tenant_id
        || snapshot.plan.action_id != record.action_id
        || snapshot.generation != record.generation
        || snapshot.generation != evidence.response_generation()
        || record.state.as_str() != snapshot.state.as_str()
        || snapshot.due_at_unix_ms != record.due_at_unix_ms
    {
        return Err(active_response_internal(
            "active-response canonical record readback is inconsistent",
        ));
    }
    validate_response_snapshot_lifecycle(&snapshot, false).map_err(|error| {
        active_response_internal(format!(
            "active-response durable lifecycle readback is invalid: {error}"
        ))
    })?;
    Ok(snapshot)
}

fn verify_active_response_completion_receipt(
    request: &ActiveResponseExecutionRequest,
    evidence: &ActiveResponseExecutionEvidence,
) -> Result<ActiveDefenseReceiptBody, KernelError> {
    let receipt = evidence.completion_receipt();
    let signature_valid = receipt.verify_signature().map_err(|error| {
        active_response_internal(format!(
            "active-response completion receipt signature failed: {error}"
        ))
    })?;
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        active_response_internal("active-response completion receipt metadata is missing")
    })?;
    let body_value = metadata
        .get("active_defense_body")
        .cloned()
        .ok_or_else(|| {
            active_response_internal("active-response completion receipt body is missing")
        })?;
    let active_body: ActiveDefenseReceiptBody =
        serde_json::from_value(body_value).map_err(|error| {
            active_response_internal(format!(
                "active-response completion receipt body is malformed: {error}"
            ))
        })?;
    let response = match &active_body {
        ActiveDefenseReceiptBody::ResponseCompletion(completion) => &completion.response,
        ActiveDefenseReceiptBody::LiftRollbackCompletion(completion) => &completion.response,
        _ => {
            return Err(active_response_internal(
                "active-response execution proof is not a terminal response receipt",
            ))
        }
    };
    let evidence_id = active_body.evidence_id().map_err(|error| {
        active_response_internal(format!(
            "active-response completion evidence ID derivation failed: {error}"
        ))
    })?;
    let body_digest = active_body.body_digest().map_err(|error| {
        active_response_internal(format!(
            "active-response completion body digest failed: {error}"
        ))
    })?;
    let expected_action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": active_body.kind().as_str(),
        "transition_id": active_body.header().transition_id.as_str(),
    }))
    .map_err(|error| {
        active_response_internal(format!(
            "active-response completion action derivation failed: {error}"
        ))
    })?;
    let expected_metadata = serde_json::json!({
        "active_defense_body": &active_body,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": active_body.header().occurred_at_unix_ms,
    });
    if !signature_valid
        || &receipt.kernel_key != request.executor_subject()
        || receipt.capability_id != "chio.active-defense.system"
        || receipt.tool_server != "chio.kernel"
        || receipt.tool_name != active_body.kind().as_str()
        || receipt.action.parameters != expected_action.parameters
        || receipt.action.parameter_hash != expected_action.parameter_hash
        || receipt.receipt_kind != ReceiptKind::TraceObservation
        || receipt.boundary_class != BoundaryClass::DetectOnly
        || receipt.observation_outcome != Some(ObservationOutcome::Observed)
        || receipt.decision.is_some()
        || receipt.tool_origin != ToolOrigin::ChioInternal
        || receipt.redaction_mode != RedactionMode::Redacted
        || receipt.trust_level != TrustLevel::Verified
        || !receipt.actor_chain.is_empty()
        || !receipt.evidence.is_empty()
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
        || metadata != &expected_metadata
        || receipt.timestamp != active_body.header().occurred_at_unix_ms / 1_000
        || receipt.tenant_id.as_deref() != Some(active_body.header().tenant_id.as_str())
        || receipt.content_hash != digest_hex(&body_digest)
        || receipt.policy_hash != digest_hex(&response.policy.policy_hash)
        || active_body.header().tenant_id != request.response_plan().tenant_id
        || response != &active_response_response_binding(request.response_plan())
        || evidence.proof_evidence_id() != &evidence_id
        || evidence.proof_body_hash() != &body_digest
    {
        return Err(active_response_internal(
            "active-response completion receipt binding is inconsistent",
        ));
    }
    Ok(active_body)
}

pub(super) fn validate_active_response_terminal_executor_receipt(
    operation: &AdmissionOperation,
    anchor: &ActiveResponseOperationAnchor,
    receipt: &ChioReceipt,
) -> Result<(), KernelError> {
    if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
        || operation.state() != AdmissionOperationState::Completed
        || operation.dispatch_state() != AdmissionDispatchState::EffectCompleted
    {
        return Err(active_response_internal(
            "executor receipt validation requires a completed governed operation",
        ));
    }
    let signature_valid = receipt.verify_signature().map_err(|error| {
        active_response_internal(format!(
            "active-response terminal executor signature failed: {error}"
        ))
    })?;
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        active_response_internal("active-response terminal executor metadata is missing")
    })?;
    let body_value = metadata
        .get("active_defense_body")
        .cloned()
        .ok_or_else(|| {
            active_response_internal("active-response terminal executor body is missing")
        })?;
    let active_body: ActiveDefenseReceiptBody =
        serde_json::from_value(body_value).map_err(|error| {
            active_response_internal(format!(
                "active-response terminal executor body is malformed: {error}"
            ))
        })?;
    let (response, execution_dispatch) = match &active_body {
        ActiveDefenseReceiptBody::ResponseCompletion(completion) => {
            (&completion.response, completion.execution_dispatch.as_ref())
        }
        ActiveDefenseReceiptBody::LiftRollbackCompletion(completion) => {
            (&completion.response, completion.execution_dispatch.as_ref())
        }
        _ => {
            return Err(active_response_internal(
                "active-response terminal executor proof is not a completion receipt",
            ))
        }
    };
    let execution_dispatch = execution_dispatch.ok_or_else(|| {
        active_response_internal(
            "active-response terminal executor proof lacks its governed dispatch binding",
        )
    })?;
    let executor_identity = ActiveResponseExecutorAuthorityIdentity::new(
        receipt.kernel_key.clone(),
        anchor.executor_authority_generation,
    )
    .map_err(|error| {
        active_response_internal(format!(
            "active-response terminal executor identity is invalid: {error}"
        ))
    })?;
    let evidence_id = active_body.evidence_id().map_err(|error| {
        active_response_internal(format!(
            "active-response terminal executor evidence ID failed: {error}"
        ))
    })?;
    let body_digest = active_body.body_digest().map_err(|error| {
        active_response_internal(format!(
            "active-response terminal executor body digest failed: {error}"
        ))
    })?;
    let expected_action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": active_body.kind().as_str(),
        "transition_id": active_body.header().transition_id.as_str(),
    }))
    .map_err(|error| {
        active_response_internal(format!(
            "active-response terminal executor action derivation failed: {error}"
        ))
    })?;
    let expected_metadata = serde_json::json!({
        "active_defense_body": &active_body,
        "active_defense_evidence_id": evidence_id.as_str(),
        "occurred_at_unix_ms": active_body.header().occurred_at_unix_ms,
    });
    let expected_dispatch_version = operation.version().checked_sub(1).ok_or_else(|| {
        active_response_internal("completed active-response version cannot project dispatch")
    })?;
    let persisted_approval_set_hash = operation.approval_set_hash().ok_or_else(|| {
        active_response_internal("completed active-response operation lacks an approval set hash")
    })?;
    let approval_binding_valid = matches!(
        &execution_dispatch.approval,
        ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } if admission_operation_id.as_str() == operation.operation_id()
            && *admission_operation_version == expected_dispatch_version
            && digest_hex(approval_set_hash) == persisted_approval_set_hash
    );
    let dispatch_binding_valid = execution_dispatch
        .validate_for_response(
            &active_body.header().tenant_id,
            &response.action_id,
            &response.plan_hash,
            response.plan_expires_at_unix_ms,
        )
        .is_ok();
    if !signature_valid
        || executor_identity.authority_id() != operation.coordinator_authority_id()
        || executor_identity.authority_id() != anchor.executor_authority_id.as_str()
        || execution_dispatch.executor_authority_id.as_str() != operation.coordinator_authority_id()
        || execution_dispatch.executor_authority_generation != anchor.executor_authority_generation
        || digest_hex(&execution_dispatch.authorization_capability_hash)
            != operation.authorization_capability_hash()
        || digest_hex(&execution_dispatch.governed_intent_hash)
            != anchor.governed_intent_hash.as_str()
        || digest_hex(&execution_dispatch.policy_decision_hash)
            != anchor.policy_decision_hash.as_str()
        || digest_hex(&execution_dispatch.plan_hash) != anchor.plan_hash.as_str()
        || execution_dispatch.authorized_at_unix_ms != anchor.authorized_at_unix_ms
        || !approval_binding_valid
        || !dispatch_binding_valid
        || response.action_id.as_str() != operation.request_id()
        || digest_hex(&response.plan_hash) != anchor.plan_hash.as_str()
        || digest_hex(&response.policy.policy_hash) != operation.policy_hash()
        || receipt.capability_id != "chio.active-defense.system"
        || receipt.tool_server != "chio.kernel"
        || receipt.tool_name != active_body.kind().as_str()
        || receipt.action.parameters != expected_action.parameters
        || receipt.action.parameter_hash != expected_action.parameter_hash
        || receipt.receipt_kind != ReceiptKind::TraceObservation
        || receipt.boundary_class != BoundaryClass::DetectOnly
        || receipt.observation_outcome != Some(ObservationOutcome::Observed)
        || receipt.decision.is_some()
        || receipt.tool_origin != ToolOrigin::ChioInternal
        || receipt.redaction_mode != RedactionMode::Redacted
        || receipt.trust_level != TrustLevel::Verified
        || !receipt.actor_chain.is_empty()
        || !receipt.evidence.is_empty()
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
        || metadata != &expected_metadata
        || receipt.timestamp != active_body.header().occurred_at_unix_ms / 1_000
        || receipt.tenant_id.as_deref() != Some(active_body.header().tenant_id.as_str())
        || receipt.content_hash != digest_hex(&body_digest)
        || receipt.policy_hash != operation.policy_hash()
    {
        return Err(active_response_internal(
            "active-response terminal executor receipt binding is inconsistent",
        ));
    }
    Ok(())
}

fn validate_executable_response_plan(
    request: &ActiveResponseAdmissionRequest,
) -> Result<(), KernelError> {
    let plan = request.response_plan();
    if plan.authorization_body() != *request.authorization().plan_body() {
        return Err(active_response_denied(
            "full response plan no longer matches the compact authorization body",
        ));
    }
    validate_executable_response_plan_value(plan)
}

pub(super) fn validate_executable_response_plan_value(
    plan: &ResponsePlan,
) -> Result<(), KernelError> {
    plan.validate_shape().map_err(|error| {
        active_response_denied(format!("full response plan is invalid: {error}"))
    })?;

    let affected_set_hash = domain_digest(
        AFFECTED_SET_HASH_DOMAIN,
        &AffectedSetCommitment {
            tenant_id: plan.tenant_id.as_str(),
            affected_ids: plan.affected_ids.as_slice(),
        },
    )?;
    if plan.affected_set_hash != affected_set_hash {
        return Err(active_response_denied(
            "full response plan affected-set hash is invalid",
        ));
    }
    for effect in plan.effects.as_slice() {
        validate_executable_effect(plan, effect)?;
    }

    let body = serde_json::to_value(plan.authorization_body()).map_err(|error| {
        active_response_denied(format!("response-plan serialization failed: {error}"))
    })?;
    let plan_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_digest(&body).map_err(|error| {
            active_response_denied(format!("response-plan hashing failed: {error}"))
        })?;
    if plan.plan_hash.as_bytes() != plan_hash.as_bytes() {
        return Err(active_response_denied(
            "full response plan hash does not match its authorization body",
        ));
    }
    Ok(())
}

fn validate_executable_effect(
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
) -> Result<(), KernelError> {
    let value: serde_json::Value = serde_json::from_slice(effect.canonical_contribution.as_bytes())
        .map_err(|error| {
            active_response_denied(format!("response contribution is not JSON: {error}"))
        })?;
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        active_response_denied(format!("response contribution is not canonical: {error}"))
    })?;
    if canonical.as_slice() != effect.canonical_contribution.as_bytes()
        || Digest32::new(*sha256(&canonical).as_bytes()) != effect.contribution_hash
    {
        return Err(active_response_denied(
            "response contribution hash or canonical bytes are invalid",
        ));
    }
    let spec = ResponseEffectSpec {
        kind: effect.kind,
        target: effect.target.clone(),
        canonical_contribution: effect.canonical_contribution.clone(),
        contribution_hash: effect.contribution_hash,
        observed_base_version_hash: effect.observed_base_version_hash,
    };
    let expected = derive_effect_id(plan, effect.ordinal, &spec)?;
    if effect.effect_id != expected {
        return Err(active_response_denied(
            "response effect ID does not match its executable contribution",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct AffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [chio_security_types::ports::RecordId],
}

#[derive(Serialize)]
struct EffectCommitment<'a> {
    action_id: &'a str,
    ordinal: u16,
    spec: &'a ResponseEffectSpec,
}

fn derive_effect_id(
    plan: &ResponsePlan,
    ordinal: u16,
    spec: &ResponseEffectSpec,
) -> Result<EffectId, KernelError> {
    let digest = domain_digest(
        EFFECT_ID_DOMAIN,
        &EffectCommitment {
            action_id: plan.action_id.as_str(),
            ordinal,
            spec,
        },
    )?;
    EffectId::new(format!("response_effect_{}", digest_hex(&digest)))
        .map_err(|error| active_response_denied(format!("response effect ID failed: {error}")))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, KernelError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        active_response_denied(format!(
            "response commitment canonicalization failed: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&preimage).as_bytes()))
}

pub(super) fn digest_hex(digest: &Digest32) -> String {
    Hash::from_bytes(*digest.as_bytes()).to_hex()
}

pub(super) fn bounded_admission_error(reason: &str) -> String {
    let trimmed = reason.trim();
    let source = if trimmed.is_empty() {
        "active-response admission cancelled"
    } else {
        trimmed
    };
    let mut bounded = String::with_capacity(source.len().min(1_024));
    for character in source.chars().filter(|character| *character != '\0') {
        if bounded.len().saturating_add(character.len_utf8()) > 1_024 {
            break;
        }
        bounded.push(character);
    }
    if bounded.is_empty() {
        "active-response admission cancelled".to_string()
    } else {
        bounded
    }
}

pub(super) fn active_response_denied(reason: impl Into<String>) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response admission denied: {}",
        reason.into()
    ))
}

pub(super) fn active_response_internal(reason: impl Into<String>) -> KernelError {
    KernelError::Internal(format!(
        "active-response admission failed: {}",
        reason.into()
    ))
}
