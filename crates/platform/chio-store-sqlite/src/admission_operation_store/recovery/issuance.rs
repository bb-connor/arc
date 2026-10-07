//! Reserve exact unsigned bytes before signing. Attach and publish are distinct
//! fenced transitions; a lost acknowledgement never renews body or expiry.
use super::retained_host_reply::{authenticate_retained_host_reply, RetainedHostReplyRequest};
use super::*;
use chio_core::recovery::RecoveryDigestDomain;
use chio_core_types::recovery::{RecoveryGrantBodyV2, SignedRecoveryGrantV2};

pub(super) struct Materialization<'a> {
    pub(super) action: &'a ActionIntentV1,
    pub(super) observation: &'a NativeSecurityFlowObservationV1,
}

pub(super) struct Finalization<'a> {
    pub(super) envelope: &'a FinalizedRequestEnvelopeV1,
    pub(super) identity: &'a RecoveryNativeIdentity,
}

pub(super) fn materialize(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    evidence: Materialization<'_>,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let Materialization {
        action,
        observation,
    } = evidence;
    if !matches!(
        actor.permission(),
        RecoveryPermission::Create | RecoveryPermission::Select | RecoveryPermission::Resume
    ) {
        return Err(invariant("recovery materialization refused"));
    }
    let mut record = workflow_tx(tx, actor.scope(), id)?;
    historical_holds::require_unheld(tx, &record)?;
    if let Some(reply) = authenticate_retained_host_reply(
        tx,
        owner,
        actor,
        profile,
        now,
        &record,
        RetainedHostReplyRequest::Materialization(action),
    )? {
        reply.verify_current(tx)?;
        return Ok(record);
    }
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    origins::verify(tx, &record, profile, now)?;
    if action.origin.is_none() || action.origin != record.origin {
        return Err(invariant("recovery action original binding refused"));
    }
    let original = observation
        .snapshot()
        .ok_or_else(|| invariant("recovery flow basis is absent"))?;
    let key = chio_kernel::recovery::recovery_flow_key(&profile.security_context);
    let (current, generation) = crate::security_state::observe_native_flow_state(
        tx,
        profile.native_authority.security_authority_id().as_str(),
        &key,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if observation.binding() != &profile.native_authority
        || observation.key() != &key
        || current.as_ref() != Some(original)
        || observation.stored_context_generation() != generation
    {
        return Err(invariant("recovery observation is stale"));
    }
    let mut materialized = record.seed.clone();
    materialized.request_id = action.request_id.as_str().to_owned();
    let semantics = materialized
        .recovery_review_projection()
        .canonical_semantics()
        .map_err(|_| invariant("recovery semantic request refused"))?;
    let requirements = &action.authorization_requirements;
    let inherited = original
        .principal_label
        .join_restrictions(&original.lineage_label)
        .and_then(|label| label.join_restrictions(&original.session_label))
        .map_err(|_| invariant("recovery source refused"))?;
    if action.scope != record.scope
        || action.workflow_id != record.workflow_id
        || action.step_id != record.step_id
        || action.continuation_id != record.continuation_id
        || action.capability_id.as_str() != record.seed.capability.id
        || action.capability_body
            != CapabilityBodyDigest::from_bytes(hash(
                RecoveryDigestDomain::CapabilityBody,
                &record.seed.capability.signing_body(),
            )?)
        || action.semantic_request.as_bytes()
            != chio_core_types::sha256(semantics.as_bytes()).as_bytes()
        || action.source_generation.get() != original.context_generation
        || action.isolation_epoch.get() == 0
        || action.basis
            != BasisDigest::from_bytes(hash(
                RecoveryDigestDomain::Basis,
                &(
                    original,
                    profile.policy_digest,
                    profile.contract_digest,
                    profile.authority_scope,
                ),
            )?)
        || requirements.scope != record.scope
        || !inherited.flows_to(&requirements.source_label)
        || requirements.admitted_target != profile.target_label
        || requirements.recipient != profile.recipient
        || requirements.purpose != profile.purpose
        || requirements.issuer_scope != profile.authority_scope
        || requirements.attachment_profile != profile.attachment_profile
        || requirements.source_join
            != SourceDigest::from_bytes(hash(
                RecoveryDigestDomain::Source,
                &requirements.source_label,
            )?)
        || requirements.influence_basis
            != SourceDigest::from_bytes(hash(RecoveryDigestDomain::Influence, original)?)
        || requirements.validity_ceiling_unix_ms.get() <= now
        || requirements
            .validity_ceiling_unix_ms
            .get()
            .saturating_sub(now)
            > MAX_RECOVERY_REVIEW_MS
    {
        return Err(invariant("recovery action binding refused"));
    }
    let expected = chio_flow::required_recovery_disclosure_obligations(
        &requirements.source_label,
        &requirements.admitted_target,
    )
    .map_err(|_| invariant("recovery obligations refused"))?;
    if expected != requirements.obligations {
        return Err(invariant("recovery obligations changed"));
    }
    record.seed = materialized;
    record.action = Some(action.clone());
    record.original_flow = Some(original.clone());
    verify_preview(actor, profile, &record)?;
    fresh_basis(tx, profile, &record, now)?;
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
    Ok(record)
}
pub(super) fn reserve(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    body: &RecoveryGrantBodyV2,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<RecoveryGrantBodyV2, AdmissionOperationStoreError> {
    if !matches!(
        actor.permission(),
        RecoveryPermission::Approve | RecoveryPermission::Resume
    ) {
        return Err(invariant("recovery issuer scope refused"));
    }
    let mut record = workflow_tx(tx, actor.scope(), id)?;
    historical_holds::require_unheld(tx, &record)?;
    if let Some(reply) = authenticate_retained_host_reply(
        tx,
        owner,
        actor,
        profile,
        now,
        &record,
        RetainedHostReplyRequest::Issuance(body),
    )? {
        reply.verify_current(tx)?;
        return record
            .issuance
            .ok_or_else(|| invariant("retained issuance disappeared"));
    }
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    if !record.selected {
        return Err(invariant("recovery identity is not reserved"));
    }
    fresh_basis(tx, profile, &record, now)?;
    validate_body(&record, body, profile, now)?;
    record.issuance = Some(body.clone());
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
    Ok(body.clone())
}
pub(super) fn attach(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    grant: &SignedRecoveryGrantV2,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(
        actor.permission(),
        RecoveryPermission::Approve | RecoveryPermission::Resume
    ) {
        return Err(invariant("recovery issuer scope refused"));
    }
    let mut record = workflow_tx(tx, actor.scope(), id)?;
    historical_holds::require_unheld(tx, &record)?;
    if let Some(reply) = authenticate_retained_host_reply(
        tx,
        owner,
        actor,
        profile,
        now,
        &record,
        RetainedHostReplyRequest::Signature(grant),
    )? {
        reply.verify_current(tx)?;
        return Ok(());
    }
    super::terminal_custody::require_unfinished(tx, &record)?;
    if record.issuance.as_ref() != Some(grant.body())
        || grant.authority_key() != &profile.aggregate_issuer
        || !grant
            .verify_signature()
            .map_err(|_| invariant("recovery signature refused"))?
    {
        return Err(invariant("recovery signing attachment refused"));
    }
    // Attaching a signature to its exact reservation is not publication. The
    // subsequent publication still checks cancellation, time and fresh basis.
    record.signed_grant = Some(grant.clone());
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)?;
    let _ = now;
    Ok(())
}
pub(super) fn finalize(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    id: &WorkflowId,
    finalized: Finalization<'_>,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let Finalization { envelope, identity } = finalized;
    if actor.permission() != RecoveryPermission::Resume {
        return Err(invariant("recovery publication scope refused"));
    }
    let mut record = workflow_tx(tx, actor.scope(), id)?;
    historical_holds::require_unheld(tx, &record)?;
    if let Some(reply) = authenticate_retained_host_reply(
        tx,
        owner,
        actor,
        profile,
        now,
        &record,
        RetainedHostReplyRequest::Envelope { envelope, identity },
    )? {
        reply.verify_current(tx)?;
        return Ok(());
    }
    super::terminal_custody::require_unfinished(tx, &record)?;
    require_active(&record)?;
    fresh_basis(tx, profile, &record, now)?;
    let grant = record
        .signed_grant
        .as_ref()
        .ok_or_else(|| invariant("recovery signature is absent"))?;
    validate_body(&record, grant.body(), profile, now)?;
    let mut expected = record.seed.clone();
    expected.declassification_grant = Some(grant.clone().into());
    let request: ToolCallRequest = decode(envelope.request.as_str().as_bytes())?;
    if encode(&request)? != encode(&expected)?
        || envelope.action_intent != grant.body().recovery.action_intent
        || envelope.authorization_requirements != grant.body().recovery.authorization_requirements
        || identity.binding().request_id().as_str() != request.request_id
        || identity.binding().capability_id().as_str() != request.capability.id
        || identity.binding().authorization_capability_hash().as_str()
            != sha256_hex(&encode(&request.capability)?)
        || identity.binding().request_namespace_digest().as_str()
            != hex(grant.body().recovery.request_namespace.as_bytes())
        || identity
            .binding()
            .participant_requirements()
            .execution_nonce
            != (profile.attachment_profile == RecoveryAttachmentProfile::OperationOwnedNonce)
        || identity.binding().policy_hash().as_str() != hex(profile.policy_digest.as_bytes())
    {
        return Err(invariant("recovery exact envelope refused"));
    }
    let operation = OperationId::new(identity.binding().operation_id().as_str())
        .map_err(|_| invariant("recovery native identity refused"))?;
    record.envelope = Some(envelope.clone());
    record.admission = Some(RecoveryAdmissionIntentV1 {
        intent: AdmissionIntentRef::new(&format!("admission:{}", operation.as_str()))
            .map_err(|_| invariant("recovery identity refused"))?,
        native_binding: identity.binding().to_persisted(),
        native_operation_id: operation,
        process_request_digest: envelope.process_request_digest,
        process_binding_digest: envelope.process_binding_digest,
    });
    record.effect = EffectObservationV1::AdmissionUnresolved {
        admission_intent: record
            .admission
            .as_ref()
            .ok_or_else(|| invariant("recovery intent is absent"))?
            .intent
            .clone(),
    };
    require_finalized_workflow_headroom(&record)?;
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Native)
}
