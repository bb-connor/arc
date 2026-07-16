use chio_core_types::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicEffectStateV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1, VerifiedEconomicEffectCancellationAdvance,
    VerifiedEconomicEffectNotDispatched,
};

use super::*;

const ECONOMIC_CANCELLATION_REPLAY_DOMAIN: &[u8] = b"chio.economic-cancellation-replay.v1\0";

#[derive(Serialize)]
struct EconomicCancellationReplayBinding<'a> {
    slot: &'a chio_core_types::economic_continuity::EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
    checkpoint_sequence: u64,
    checkpoint_digest: &'a str,
}

fn cancellation_replay_digest_from_parts(
    slot: &chio_core_types::economic_continuity::EconomicEffectSlotV1,
    kind: EconomicNoEffectKindV1,
    checkpoint_sequence: u64,
    checkpoint_digest: &str,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    let binding = EconomicCancellationReplayBinding {
        slot,
        kind,
        checkpoint_sequence,
        checkpoint_digest,
    };
    let bytes = canonical_json_bytes(&binding)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage = Vec::with_capacity(ECONOMIC_CANCELLATION_REPLAY_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(ECONOMIC_CANCELLATION_REPLAY_DOMAIN);
    preimage.extend_from_slice(&bytes);
    AdmissionDigest::try_new("economic_cancellation_replay_digest", sha256_hex(&preimage))
}

fn cancellation_replay_digest(
    cancellation: &VerifiedEconomicEffectNotDispatched,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    cancellation_replay_digest_from_parts(
        cancellation.slot(),
        cancellation.kind(),
        cancellation.checkpoint_sequence(),
        cancellation.checkpoint_digest(),
    )
}

pub fn verify_economic_cancellation_terminal_replay(
    operation: &AdmissionOperationV1,
    cancellation: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<(), AdmissionOperationError> {
    let replay_digest = cancellation_replay_digest_from_parts(
        cancellation.slot(),
        cancellation.kind(),
        cancellation.batch().checkpoint_sequence,
        &cancellation.batch().checkpoint_digest,
    )?;
    let slot = cancellation.slot();
    let handoff_version_matches = slot
        .admission_handoff
        .operation_version
        .checked_add(1)
        .is_some_and(|version| version == operation.version());
    let binding_matches = slot.operation_id == operation.binding().operation_id().as_str()
        && slot.request.request_namespace_digest
            == operation.replay_key().request_namespace_digest.as_str()
        && slot.request.request_id == operation.replay_key().request_id.as_str()
        && slot.request.request_binding_digest
            == operation.binding().request_binding_hash().as_str()
        && handoff_version_matches
        && slot.admission_handoff.lifecycle_fence == operation.coordinator_lease_epoch();
    let replay_matches = match (
        operation.binding().kind(),
        operation.state(),
        cancellation.kind(),
        operation.terminal_replay(),
    ) {
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
            EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
            Some(AdmissionTerminalReplay::Incident { incident_id, .. }),
        ) => incident_id.as_str() == replay_digest.as_str(),
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            AdmissionOperationState::EconomicMutationNotApplied,
            EconomicNoEffectKindV1::PermanentlyNotApplied,
            Some(AdmissionTerminalReplay::EconomicMutation {
                result_id,
                result_digest,
                ..
            }),
        ) => {
            result_id.as_str() == replay_digest.as_str()
                && result_digest.as_str() == replay_digest.as_str()
        }
        _ => false,
    };
    if !binding_matches || !replay_matches {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

pub fn verified_economic_cancellation_projection(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    cancellation: &VerifiedEconomicEffectNotDispatched,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let Some(EconomicEffectTerminalV1::NoEffect {
        proof_id: _,
        proof_digest: _,
        ..
    }) = &cancellation.slot().terminal
    else {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    };
    let replay_digest = cancellation_replay_digest(cancellation)?;
    match (operation.binding().kind(), cancellation.kind()) {
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
        ) => {
            let proof = VerifiedTransportNotAccepted::from_verified_economic_effect(
                cancellation,
                operation,
                &context,
            )
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
            let evidence = AdmissionIncident {
                binding: AdmissionExactProjectionBindingV1::from_verified(
                    operation,
                    &context,
                    AdmissionOperationState::NotAcceptedAfterDispatchCommit,
                )?,
                record_id: AdmissionIdentifier::try_new(
                    "economic_cancellation_incident_id",
                    replay_digest.as_str().to_owned(),
                )?,
                record_digest: replay_digest,
            };
            Ok(
                AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit {
                    context,
                    proof: Box::new(proof),
                    evidence: Box::new(AdmissionReceiptOrIncident::Incident(Box::new(evidence))),
                },
            )
        }
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            EconomicNoEffectKindV1::PermanentlyNotApplied,
        ) => mutation_not_applied(operation, context, cancellation, replay_digest),
        _ => Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
}

fn mutation_not_applied(
    operation: &AdmissionOperationV1,
    context: AdmissionProjectionContext,
    cancellation: &VerifiedEconomicEffectNotDispatched,
    replay_digest: AdmissionDigest,
) -> Result<AdmissionTerminalProjection, AdmissionOperationError> {
    let slot = cancellation.slot();
    if operation.state() != AdmissionOperationState::MutationSubmitted
        || slot.state != EconomicEffectStateV1::NoEffect
        || slot.operation_id != operation.binding().operation_id().as_str()
        || slot.request.request_namespace_digest
            != operation.replay_key().request_namespace_digest.as_str()
        || slot.request.request_id != operation.replay_key().request_id.as_str()
        || slot.request.request_binding_digest
            != operation.binding().request_binding_hash().as_str()
        || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::MutationSubmitted
        || slot.admission_handoff.operation_version != operation.version()
        || slot.admission_handoff.lifecycle_fence != operation.coordinator_lease_epoch()
        || slot.admission_handoff.store_fence != context.store_fence
        || cancellation.resulting_head_version() <= cancellation.expected_head_version()
    {
        return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
    }
    let result_binding = GovernedEconomicMutationResultBinding {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::EconomicMutationNotApplied,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "economic_mutation_cancellation_record_id",
            replay_digest.as_str().to_owned(),
        )?,
        record_digest: replay_digest.clone(),
        participant_id: AdmissionIdentifier::try_new(
            "economic_mutation_participant_id",
            slot.target.target_id.clone(),
        )?,
        participant_key_epoch: slot.target.target_key_epoch,
        resource_id: AdmissionIdentifier::try_new(
            "economic_mutation_resource_id",
            slot.slot_id.clone(),
        )?,
        expected_resource_version: cancellation.expected_head_version(),
        resulting_resource_version: cancellation.resulting_head_version(),
        expected_resource_fence: AdmissionIdentifier::try_new(
            "economic_mutation_expected_resource_fence",
            format!(
                "effect-slot-fence:{}",
                cancellation.expected_lifecycle_fence()
            ),
        )?,
        resulting_resource_fence: AdmissionIdentifier::try_new(
            "economic_mutation_resulting_resource_fence",
            format!(
                "effect-slot-fence:{}",
                cancellation.resulting_lifecycle_fence()
            ),
        )?,
        immutable_request_digest: operation.binding().request_binding_hash().clone(),
        signature_digest: AdmissionDigest::try_new(
            "economic_mutation_cancellation_signature_digest",
            cancellation.checkpoint_digest().to_owned(),
        )?,
        status: EconomicMutationTerminalStatus::PermanentlyNotApplied,
    };
    result_binding.validate_against(operation, &context)?;
    let audit_event = GovernedMutationAuditEvent {
        binding: AdmissionExactProjectionBindingV1::from_verified(
            operation,
            &context,
            AdmissionOperationState::EconomicMutationNotApplied,
        )?,
        record_id: AdmissionIdentifier::try_new(
            "economic_mutation_cancellation_audit_id",
            format!("{}:audit", replay_digest.as_str()),
        )?,
        record_digest: AdmissionDigest::try_new(
            "economic_mutation_cancellation_audit_digest",
            cancellation.checkpoint_digest().to_owned(),
        )?,
    };
    Ok(AdmissionTerminalProjection::EconomicMutationNotApplied {
        context,
        result: Box::new(VerifiedEconomicMutationNotApplied(result_binding)),
        audit_event: Box::new(audit_event),
    })
}
