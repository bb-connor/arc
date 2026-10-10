//! Native admission, capture and closure use the same physical transaction.
use super::*;
use chio_core::recovery::RecoveryDigestDomain;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;
use chio_security_types::ports::FlowStateSnapshot;

#[cfg(feature = "admission-test-support")]
#[path = "native_begin_test_support.rs"]
mod native_begin_test_support;
#[path = "native/private_settlement.rs"]
mod private_settlement;
pub(super) use private_settlement::verified_private_settlement;

pub(in crate::admission_operation_store) fn located(
    tx: &Connection,
    operation: &AdmissionOperationBindingV1,
) -> Result<Option<RecoveryWorkflowRecordV1>, AdmissionOperationStoreError> {
    let key:Option<String>=tx.query_row("SELECT record_key FROM admission_operation_recovery_records WHERE native_namespace=?1 AND native_request=?2",
        params![operation.request_namespace_digest().as_str(),operation.request_id().as_str()],|row|row.get(0)).optional().map_err(sqlite_error)?;
    key.map(|key| {
        let row = raw(tx, &key)?.ok_or_else(|| invariant("recovery ownership disappeared"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        if row.kind != "workflow"
            || row.scope != scope_key(&record.scope)?
            || key != workflow_key(&record.scope, &record.workflow_id)?
            || record.revision.get() != row.version
        {
            return Err(invariant(
                "recovery original ownership scope or version changed",
            ));
        }
        Ok(record)
    })
    .transpose()
}
pub(super) fn operation_ref(
    operation: &AdmissionOperationV1,
) -> Result<OperationRef, AdmissionOperationStoreError> {
    let digest = operation.binding().request_binding_hash().as_str();
    let bytes = decode_hex(digest)?;
    OperationRef::new(
        OperationId::new(operation.binding().operation_id().as_str())
            .map_err(|_| invariant("recovery operation refused"))?,
        NativeAdmissionDigest::from_bytes(bytes),
        SafeInteger::new(operation.version()).map_err(|_| invariant("recovery version refused"))?,
    )
    .map_err(|_| invariant("recovery operation refused"))
}
pub(super) fn decode_hex(value: &str) -> Result<[u8; 32], AdmissionOperationStoreError> {
    if value.len() != 64 {
        return Err(invariant("recovery digest refused"));
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        }
        bytes[index] = nibble(pair[0])
            .and_then(|high| nibble(pair[1]).map(|low| (high << 4) | low))
            .ok_or_else(|| invariant("recovery digest refused"))?;
    }
    Ok(bytes)
}
/// A private affine permit carries the unchanged workflow across native begin.
/// It cannot be deserialized or constructed by a caller outside this module.
pub(in crate::admission_operation_store) struct RecoveryNativeBeginPermit {
    record: RecoveryWorkflowRecordV1,
    binding: AdmissionOperationBindingV1,
}

/// Keep fresh authority checks before core admission and publish no ownership.
pub(in crate::admission_operation_store) fn prepare_begin_tx(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<Option<RecoveryNativeBeginPermit>, AdmissionOperationStoreError> {
    let Some(record) = located(tx, operation.binding())? else {
        return Ok(None);
    };
    historical_holds::require_unheld(tx, &record)?;
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery admission intent is absent"))?;
    if intent.native_binding != operation.binding().to_persisted() {
        return Err(invariant("recovery native admission binding changed"));
    }
    let original = load_by_operation_id_tx(tx, operation.binding().operation_id())?;
    if original.is_none() {
        require_active(&record)?;
        require_current_original_owner(tx, &record)?;
        let profile = deployment_tx(tx, &record.scope)?;
        fresh_basis(tx, &profile, &record, now)?;
        let grant = record
            .signed_grant
            .as_ref()
            .ok_or_else(|| invariant("recovery grant is absent"))?;
        validate_body(&record, grant.body(), &profile, now)?;
    }
    if record
        .native_link
        .as_ref()
        .is_some_and(|link| link.as_str() != operation.binding().operation_id().as_str())
    {
        return Err(invariant("recovery original operation changed"));
    }
    Ok(Some(RecoveryNativeBeginPermit {
        record,
        binding: operation.binding().clone(),
    }))
}

/// Only a successful Created/ExactReplay core begin may publish the link/debit.
pub(in crate::admission_operation_store) fn publish_begin_tx(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    permit: Option<RecoveryNativeBeginPermit>,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(permit) = permit else {
        return Ok(false);
    };
    let mut record = workflow_tx(tx, &permit.record.scope, &permit.record.workflow_id)?;
    if encode(&record)? != encode(&permit.record)? {
        return Err(invariant("recovery native begin custody changed"));
    }
    historical_holds::require_unheld(tx, &record)?;
    let original = load_by_operation_id_tx(tx, permit.binding.operation_id())?
        .ok_or_else(|| invariant("recovery native begin operation absent"))?;
    if original.operation.binding() != &permit.binding {
        return Err(invariant("recovery native begin operation changed"));
    }
    let linked = OperationId::new(permit.binding.operation_id().as_str())
        .map_err(|_| invariant("recovery operation refused"))?;
    match &record.native_link {
        Some(existing) if *existing == linked => Ok(false),
        Some(_) => Err(invariant("recovery original operation changed")),
        None => {
            require_current_original_owner(tx, &record)?;
            record.native_link = Some(linked);
            save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
            Ok(true)
        }
    }
}
pub(super) fn context(
    tx: &Transaction<'_>,
    id: &AdmissionOperationId,
    now: u64,
) -> Result<Option<RecoveryVerificationContextV1>, AdmissionOperationStoreError> {
    let Some(operation) = load_by_operation_id_tx(tx, id)? else {
        return Ok(None);
    };
    let Some(record) = located(tx, operation.operation.binding())? else {
        return Ok(None);
    };
    let deployment = deployment_tx(tx, &record.scope)?;
    historical_holds::require_unheld(tx, &record)?;
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    fresh_basis(tx, &deployment, &record, now)?;
    let grant = record
        .signed_grant
        .clone()
        .ok_or_else(|| invariant("recovery grant is absent"))?;
    validate_body(&record, grant.body(), &deployment, now)?;
    Ok(Some(RecoveryVerificationContextV1 {
        action: record
            .action
            .ok_or_else(|| invariant("recovery action is absent"))?,
        approval: record
            .approval
            .ok_or_else(|| invariant("recovery approval is absent"))?,
        grant,
        deployment,
        original_flow: record
            .original_flow
            .ok_or_else(|| invariant("recovery basis is absent"))?,
    }))
}
pub(super) fn historical_release(
    tx: &Transaction<'_>,
    id: &AdmissionOperationId,
    fence: &StoreMutationFence,
) -> Result<Option<RecoveryWorkflowRecordV1>, AdmissionOperationStoreError> {
    let Some(native) = load_by_operation_id_tx(tx, id)? else {
        return Ok(None);
    };
    let Some(mut record) = located(tx, native.operation.binding())? else {
        return Ok(None);
    };
    let Some((_, custody)) = captured_custody(tx, id, fence)? else {
        return Err(invariant("recovery historical capture custody absent"));
    };
    if !matches!(custody, RecoveryCapturedDeploymentV1::Verified(_))
        || historical_holds::blocks_original_private_settlement(tx, &record)?
    {
        return Err(invariant(
            "legacy recovery deployment verifier is unavailable",
        ));
    }
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery original intent is absent"))?;
    if !record.captured
        || record.admission_closed
        || native.operation.state() != AdmissionOperationState::Finalizing
        || intent.native_binding != native.operation.binding().to_persisted()
        || record.native_link.as_ref().map(OperationId::as_str) != Some(id.as_str())
        || record.envelope.is_none()
        || record.original_flow.is_none()
        || record.signed_grant.as_ref().map(|grant| grant.body()) != record.issuance.as_ref()
    {
        return Err(invariant("recovery historical release custody refused"));
    }
    // Only data is returned. This exact authenticated hold cannot authorize
    // dispatch or result delivery, but the private signer must attest it.
    record.historical_hold = historical_holds::effective(tx, &record)?;
    Ok(Some(record))
}

/// Verify the physical captured original before selecting any historical root.
/// No current grant, actor or deployment is admitted through this lookup.
pub(super) fn captured_custody(
    tx: &Transaction<'_>,
    id: &AdmissionOperationId,
    fence: &StoreMutationFence,
) -> Result<
    Option<(RecoveryWorkflowRecordV1, RecoveryCapturedDeploymentV1)>,
    AdmissionOperationStoreError,
> {
    let Some(native) = load_by_operation_id_tx(tx, id)? else {
        return Ok(None);
    };
    let operation = &native.operation;
    let Some(record) = located(tx, operation.binding())? else {
        return Ok(None);
    };
    if !record.captured {
        return Ok(None);
    }
    let _ = historical_holds::effective(tx, &record)?;
    let original = verify_physical_capture(tx, &record, operation)?;
    let custody = super::deployment_history::lookup(tx, &record, fence)?;
    if let RecoveryCapturedDeploymentV1::Verified(profile) = &custody {
        verify_captured_roots(tx, &record, operation, &original, profile)?;
    }
    Ok(Some((record, custody)))
}

/// Pure retained-root checks are shared with auxiliary terminal authentication.
/// They never consult workflow quota, holds or an effective workflow view.
pub(in crate::admission_operation_store) fn verify_captured_roots(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    profile: &RecoveryDeploymentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let grant = record
        .signed_grant
        .as_ref()
        .ok_or_else(|| invariant("captured recovery grant absent"))?;
    original.validate_native_security_authority(&profile.native_authority)?;
    original.validate_native_security_context(&profile.security_context)?;
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("captured recovery action absent"))?;
    if action.policy_digest != profile.policy_digest
        || action.contract_digest != profile.contract_digest
        || action.authority_scope != profile.authority_scope
        || grant.authority_key() != &profile.aggregate_issuer
    {
        return Err(invariant("captured recovery original roots changed"));
    }
    // Preparation time is immutable native ledger evidence. Historical
    // grant and coverage expiry is checked there, never against today.
    let prepared_at: i64 = tx.query_row(
        "SELECT json_extract(canonical_record,'$.decision_at') FROM admission_operation_native_dispatch_ledger WHERE operation_id=?1",
        [operation.binding().operation_id().as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    validate_historical_body(
        record,
        grant.body(),
        profile,
        stored_u64(prepared_at, "captured recovery preparation time")?,
    )
}

/// Data-only captured identity verification never reads quota or current policy.
pub(super) fn verify_physical_capture(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    operation: &AdmissionOperationV1,
) -> Result<RetainedToolAdmissionRequestV1, AdmissionOperationStoreError> {
    let id = operation.binding().operation_id();
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("captured recovery intent absent"))?;
    let grant = record
        .signed_grant
        .as_ref()
        .ok_or_else(|| invariant("captured recovery grant absent"))?;
    let envelope = record
        .envelope
        .as_ref()
        .ok_or_else(|| invariant("captured recovery envelope absent"))?;
    if !record.captured
        || intent.native_binding != operation.binding().to_persisted()
        || intent.native_operation_id.as_str() != id.as_str()
        || record.native_link.as_ref().map(OperationId::as_str) != Some(id.as_str())
        || operation.dispatch_commit().is_none()
        || operation.native_dispatch_ledger_digest().is_none()
        || record.original_flow.is_none()
        || record.issuance.as_ref() != Some(grant.body())
        || !grant
            .verify_signature()
            .map_err(|_| invariant("captured recovery signature refused"))?
    {
        return Err(invariant("captured recovery physical identity changed"));
    }
    super::super::security_participant_state::dispatch_ledger::verify_capture_attachment(
        tx, operation,
    )?;
    let original = super::super::retained_request::load_retained_request_tx(tx, operation)?
        .ok_or_else(|| invariant("captured recovery original request absent"))?;
    let request: ToolCallRequest = decode(envelope.request.as_str().as_bytes())?;
    original.validate_request_material(&request)?;
    if request
        .declassification_grant
        .as_ref()
        .and_then(|grant| grant.recovery_v2())
        != Some(grant)
    {
        return Err(invariant("captured recovery exact grant changed"));
    }
    Ok(original)
}

pub(super) fn quarantine_historical(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    id: &AdmissionOperationId,
    reason: RecoveryHistoricalHoldReasonV1,
) -> Result<(), AdmissionOperationStoreError> {
    let Some((record, custody)) = captured_custody(tx, id, &owner.fence)? else {
        return Err(invariant(
            "historical quarantine requires physical captured custody",
        ));
    };
    if reason == RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable
        && !matches!(custody, RecoveryCapturedDeploymentV1::LegacyUnavailable)
    {
        return Err(invariant(
            "historical quarantine reason differs from custody",
        ));
    }
    if matches!(
        reason,
        RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable
            | RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
    ) && !matches!(custody, RecoveryCapturedDeploymentV1::Verified(_))
    {
        return Err(invariant(
            "historical frozen verifier hold requires retained verification roots",
        ));
    }
    let native = load_by_operation_id_tx(tx, id)?.ok_or(AdmissionOperationStoreError::NotFound)?;
    if reason == RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
        && native.operation.state() != AdmissionOperationState::Finalizing
    {
        return Err(invariant(
            "historical signing hold requires unfinished authenticated return",
        ));
    }
    let hold = RecoveryHistoricalHoldV1 {
        operation: operation_ref(&native.operation)?,
        reason,
    };
    if let Some(existing) = historical_holds::effective(tx, &record)? {
        if existing.operation.operation_id() != hold.operation.operation_id()
            || existing.operation.native_admission_digest()
                != hold.operation.native_admission_digest()
            || existing.reason != hold.reason
        {
            return Err(invariant("historical quarantine custody changed"));
        }
        return Ok(());
    }
    save_auxiliary_historical_hold(tx, owner, &record, &hold)
}
pub(crate) fn verify_capture_tx(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    request: &ToolCallRequest,
    now: u64,
) -> Result<Option<u64>, AdmissionOperationStoreError> {
    let Some(record) = located(tx, operation.binding())? else {
        if request
            .declassification_grant
            .as_ref()
            .is_some_and(|grant| grant.recovery_v2().is_some())
        {
            return Err(invariant("recovery v2 has no retained admission intent"));
        }
        return Ok(None);
    };
    super::resources::check_committing(tx)?;
    historical_holds::require_unheld(tx, &record)?;
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    let profile = deployment_tx(tx, &record.scope)?;
    fresh_basis(tx, &profile, &record, now)?;
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery intent is absent"))?;
    let grant = record
        .signed_grant
        .as_ref()
        .ok_or_else(|| invariant("recovery grant is absent"))?;
    validate_body(&record, grant.body(), &profile, now)?;
    if grant.authority_key() != &profile.aggregate_issuer
        || !grant
            .verify_signature()
            .map_err(|_| invariant("recovery signature refused"))?
    {
        return Err(invariant("recovery aggregate issuer changed"));
    }
    if intent.native_binding != operation.binding().to_persisted()
        || record.captured
        || record.native_link.as_ref().map(OperationId::as_str)
            != Some(operation.binding().operation_id().as_str())
        || request
            .declassification_grant
            .as_ref()
            .and_then(|grant| grant.recovery_v2())
            != Some(grant)
    {
        return Err(invariant("recovery capture ownership changed"));
    }
    let mut initial = request.clone();
    initial.execution_nonce = None;
    let envelope = record
        .envelope
        .as_ref()
        .ok_or_else(|| invariant("recovery caller custody is absent"))?;
    if encode(&initial)? != envelope.request.as_str().as_bytes() {
        return Err(invariant("recovery caller envelope changed"));
    }
    let approval = record
        .approval
        .as_ref()
        .ok_or_else(|| invariant("recovery approval is absent"))?;
    require_finalized_workflow_headroom(&record)?;
    let mut deadline = grant.body().claims.expires_at_unix_seconds() * 1000;
    deadline = deadline.min(approval.intent.expires_at_unix_ms.get());
    for contributor in approval.coverage.as_slice() {
        deadline = deadline.min(contributor.body().expires_at_unix_ms.get());
    }
    Ok(Some(deadline))
}
pub(crate) fn capture_tx(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(mut record) = located(tx, operation.binding())? else {
        return Ok(());
    };
    historical_holds::require_unheld(tx, &record)?;
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    require_current_original_owner(tx, &record)?;
    if record.captured {
        return Err(invariant("recovery continuation is already captured"));
    }
    let profile = deployment_tx(tx, &record.scope)?;
    if record.deployment_digest
        != DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, &profile)?)
    {
        return Err(invariant("recovery capture deployment changed"));
    }
    save_captured_deployment_history(tx, owner, &record, operation, &profile)?;
    record.captured_deployment = Some(RecoveryCapturedDeploymentRefV1 {
        deployment_digest: record.deployment_digest,
        record_version: SafeInteger::new(1)
            .map_err(|_| invariant("recovery custody version refused"))?,
    });
    record.captured = true;
    record.effect = EffectObservationV1::InFlight {
        operation: operation_ref(operation)?,
    };
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)
}
pub(super) fn proves_same_call_basis(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    profile: &RecoveryDeploymentV1,
    original: &FlowStateSnapshot,
    current: &FlowStateSnapshot,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(intent) = &record.admission else {
        return Ok(false);
    };
    let operation = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
    let source = &record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?
        .authorization_requirements
        .source_label;
    super::super::security_participant_state::prove_recovery_source_history(
        tx,
        &profile.native_authority,
        &operation,
        original,
        current,
        source,
    )
}
pub(super) fn settle(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    profile: &RecoveryDeploymentV1,
    _now: u64,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    if !matches!(
        actor.permission(),
        RecoveryPermission::Settle | RecoveryPermission::Resume
    ) {
        return Err(invariant("recovery settlement scope refused"));
    }
    let mut record = workflow_preview_tx(tx, actor, profile, id)?;
    if historical_holds::effective(tx, &record)?.is_some() {
        let intent = record
            .admission
            .as_ref()
            .ok_or_else(|| invariant("historical settlement native intent absent"))?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        captured_custody(tx, binding.operation_id(), &owner.fence)?
            .ok_or_else(|| invariant("historical settlement captured custody absent"))?;
        return historical_holds::view(tx, record);
    }
    if auxiliary_captured_terminal(tx, &record)?.is_some() {
        return historical_holds::view(tx, record);
    }
    if record.provider_finality.is_some() && record.effect.is_settled() {
        return Ok(record);
    }
    let Some(intent) = &record.admission else {
        return Ok(record);
    };
    let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
    let operation = load_by_operation_id_tx(tx, binding.operation_id())?;
    let next = match operation {
        None => {
            // The tombstone and authoritative lookup share this writer. Both
            // begin and capture consult it, fencing delayed original submissions.
            if record.control != WorkflowControlV1::Active {
                record.admission_closed = true;
                record.control = WorkflowControlV1::Cancelled;
                EffectObservationV1::NeverAdmitted
            } else {
                record.effect.clone()
            }
        }
        Some(stored) => {
            if stored.operation.binding() != &binding {
                return Err(invariant(
                    "recovery lookup returned another original operation",
                ));
            }
            let operation = &stored.operation;
            let reference = operation_ref(operation)?;
            if operation.state().is_terminal() {
                super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
            }
            match operation.state() {
                AdmissionOperationState::ApprovalRequired => {
                    EffectObservationV1::AwaitingApproval {
                        operation: reference,
                    }
                }
                AdmissionOperationState::AwaitingCallerReport => {
                    EffectObservationV1::AwaitingCallerReport {
                        operation: reference,
                    }
                }
                AdmissionOperationState::DeniedAfterDelivery => {
                    if verified_private_settlement(tx, &record, operation, &owner.fence)? {
                        super::terminal_custody::publish_completed(tx, owner, operation)?;
                        return historical_holds::view(tx, record);
                    }
                    EffectObservationV1::Unknown {
                        operation: reference,
                    }
                }
                AdmissionOperationState::OutcomeUnknownAfterDispatch
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
                    EffectObservationV1::Unknown {
                        operation: reference,
                    }
                }
                AdmissionOperationState::Completed => {
                    super::terminal_custody::publish_completed(tx, owner, operation)?;
                    return historical_holds::view(tx, record);
                }
                AdmissionOperationState::CompensatedBeforeDispatch if !record.captured => {
                    record.admission_closed = true;
                    EffectObservationV1::ClosedBeforeEffect {
                        operation: reference,
                        closure: EvidenceRef::new(&format!(
                            "closure:{}",
                            binding.operation_id().as_str()
                        ))
                        .map_err(|_| invariant("recovery identity refused"))?,
                    }
                }
                _ => EffectObservationV1::InFlight {
                    operation: reference,
                },
            }
        }
    };
    if record.effect.is_settled() && record.effect != next {
        return Err(invariant("recovery settlement is immutable"));
    }
    if record.effect != next {
        record.effect = next;
        save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
    }
    Ok(record)
}

pub(super) fn attach_provider_finality(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    finality: &chio_core_types::recovery::SignedRecoveryProviderFinalityV1,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::Settle {
        return Err(invariant("recovery provider settlement scope refused"));
    }
    let mut record = workflow_tx(tx, actor.scope(), id)?;
    verify_status(actor, profile, &record)?;
    if let Some(existing) = &record.provider_finality {
        if existing == finality {
            return historical_holds::view(tx, record);
        }
        return Err(invariant("recovery provider finality conflict"));
    }
    historical_holds::require_unheld(tx, &record)?;
    super::terminal_custody::require_unfinished(tx, &record)?;
    if !record.captured || record.provider_lookups.get() == 0 {
        return Err(invariant("recovery provider observation was not reserved"));
    }
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery original intent absent"))?;
    let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
    let stored = load_by_operation_id_tx(tx, binding.operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let operation = &stored.operation;
    if operation.binding() != &binding
        || !operation.state().is_terminal()
        || operation.dispatch_commit().is_none()
    {
        return Err(invariant("recovery native participants are not closed"));
    }
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    let body = finality.body();
    let historical = match captured_custody(tx, binding.operation_id(), &owner.fence)?
        .ok_or_else(|| invariant("provider finality captured custody absent"))?
        .1
    {
        RecoveryCapturedDeploymentV1::Verified(historical) => historical,
        RecoveryCapturedDeploymentV1::LegacyUnavailable
        | RecoveryCapturedDeploymentV1::Quarantined => {
            return Err(invariant(
                "provider finality historical verifier unavailable",
            ))
        }
    };
    let provider = operation
        .provider_attempt()
        .ok_or_else(|| invariant("recovery original provider attempt absent"))?;
    if body.scope != record.scope
        || body.workflow_id != record.workflow_id
        || body.continuation_id != record.continuation_id
        || body.operation_id.as_str() != binding.operation_id().as_str()
        || body.native_admission_digest.as_bytes()
            != &decode_hex(binding.request_binding_hash().as_str())?
        || body.attempt_id.as_str() != provider.attempt_id
        || body.provider != historical.effect_contract.provider
        || body.account != historical.effect_contract.account
        || body.resource_digest
            != ResourceDigest::from_bytes(hash(
                RecoveryDigestDomain::ProviderResource,
                &historical.effect_contract.resource,
            )?)
        || body.contract_digest
            != record
                .action
                .as_ref()
                .ok_or_else(|| invariant("recovery action absent"))?
                .contract_digest
        || body.contract_digest != historical.contract_digest
        || body.observed_at_unix_ms.get() > now
        || body.expires_at_unix_ms.get() <= now
        || body.applied_effects != record.effect_cardinality
        || finality.authority_key() != &profile.effect_contract.observation_key
        || !finality
            .verify_signature()
            .map_err(|_| invariant("recovery provider signature refused"))?
    {
        return Err(invariant("recovery provider finality refused"));
    }
    let reference = operation_ref(operation)?;
    let effect = match body.disposition {
        RecoveryEffectDisposition::Succeeded => EffectObservationV1::Complete {
            operation: reference,
            effect_count: body.applied_effects,
        },
        RecoveryEffectDisposition::PartiallyApplied => EffectObservationV1::Partial {
            operation: reference,
            applied_effects: body.applied_effects,
        },
        RecoveryEffectDisposition::FailedAfterEffect => EffectObservationV1::FailedAfterEffect {
            operation: reference,
            applied_effects: body.applied_effects,
        },
    };
    if record.effect.is_settled() && record.effect != effect {
        return Err(invariant("recovery immutable effect conflict"));
    }
    require_provider_finality_headroom(finality)?;
    record.effect = effect;
    record.provider_finality = Some(finality.clone());
    record.admission_closed = true;
    record.release = ReleaseDispositionV1::NotAvailable;
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
    Ok(record)
}

pub(super) fn release_result(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    profile: &RecoveryDeploymentV1,
    basis: &RecoveryResultReleaseBasis,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(
        actor.permission(),
        RecoveryPermission::Resume | RecoveryPermission::Inspect
    ) {
        return Err(invariant("recovery result scope refused"));
    }
    let record = workflow_tx(tx, actor.scope(), id)?;
    verify_preview(actor, profile, &record)?;
    historical_holds::require_unheld(tx, &record)?;
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery original result intent absent"))?;
    let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
    let stored = load_by_operation_id_tx(tx, binding.operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let operation = &stored.operation;
    if operation.binding() != &binding
        || operation.state() != AdmissionOperationState::Completed
        || basis.operation_id() != binding.operation_id()
        || basis.request_binding_hash() != binding.request_binding_hash()
        || basis.operation_version() != operation.version()
        || basis.deployment_digest()
            != DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, profile)?)
    {
        return Err(invariant("recovery current result release basis changed"));
    }
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    if verified_private_settlement(tx, &record, operation, &owner.fence)? {
        return Err(invariant(
            "private recovery settlement permanently withholds its result",
        ));
    }
    let historical = match captured_custody(tx, binding.operation_id(), &owner.fence)?
        .ok_or_else(|| invariant("recovery captured result custody absent"))?
        .1
    {
        RecoveryCapturedDeploymentV1::Verified(profile) => profile,
        RecoveryCapturedDeploymentV1::LegacyUnavailable
        | RecoveryCapturedDeploymentV1::Quarantined => {
            return Err(invariant("recovery historical output verifier unavailable"))
        }
    };
    if historical.policy_digest != profile.policy_digest {
        return Err(invariant(
            "recovery result withheld under changed current policy",
        ));
    }
    let output = super::super::security_participant_state::output::captured_output(
        tx,
        binding.operation_id(),
    )?;
    if output.join.binding != historical.native_authority
        || output.join.operation_id != *binding.operation_id()
        || output.output.key() != &recovery_flow_key(&historical.security_context)
    {
        return Err(invariant("recovery captured output taint changed identity"));
    }
    let mut source = basis.classified_output().clone();
    {
        let snapshot = &output.join.snapshot;
        source = source
            .join_restrictions(&snapshot.principal_label)
            .and_then(|label| label.join_restrictions(&snapshot.lineage_label))
            .and_then(|label| label.join_restrictions(&snapshot.session_label))
            .map_err(|_| invariant("recovery captured output labels refused"))?;
    }
    source = source
        .join_restrictions(output.output.output_label())
        .map_err(|_| invariant("recovery captured output label refused"))?;
    for deployment in [historical.as_ref(), profile] {
        let (current, _) = crate::security_state::observe_native_flow_state(
            tx,
            deployment.native_authority.security_authority_id().as_str(),
            &recovery_flow_key(&deployment.security_context),
        )
        .map_err(|_| invariant("recovery current inherited source unavailable"))?;
        let current =
            current.ok_or_else(|| invariant("recovery current inherited source absent"))?;
        source = source
            .join_restrictions(&current.principal_label)
            .and_then(|label| label.join_restrictions(&current.lineage_label))
            .and_then(|label| label.join_restrictions(&current.session_label))
            .map_err(|_| invariant("recovery current inherited labels refused"))?;
    }
    let assignment = profile
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor.principal())
        .ok_or_else(|| invariant("recovery result audience revoked"))?;
    if matches!(source, chio_security_types::InformationLabel::Top)
        || !source.flows_to(&assignment.preview_clearance)
    {
        return Err(invariant("recovery result audience refused"));
    }
    super::terminal_custody::publish_release(tx, owner, &record, actor, profile, operation)
}
