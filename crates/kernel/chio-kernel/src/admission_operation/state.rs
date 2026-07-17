use super::*;

pub(super) fn next_version(version: u64) -> Result<u64, AdmissionOperationError> {
    version
        .checked_add(1)
        .filter(|next| *next <= I_JSON_MAX_SAFE_INTEGER)
        .ok_or(AdmissionOperationError::VersionOverflow)
}

pub(super) fn dispatch_committed_version_from_prepared(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    prepared_version: u64,
) -> Result<u64, AdmissionOperationError> {
    validate_positive_ijson("prepared_operation_version", prepared_version)?;
    if !kind.uses_dispatch() {
        return Err(AdmissionOperationError::StateKindMismatch {
            kind,
            state: AdmissionOperationState::DispatchCommitted,
        });
    }
    let mut state = AdmissionOperationState::Prepared;
    let mut version = prepared_version;
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ApprovalReserved,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
    ] {
        if is_legal_transition(kind, requirements, state, next) {
            state = next;
            version = next_version(version)?;
        }
    }
    if state != AdmissionOperationState::DispatchCommitted {
        return Err(AdmissionOperationError::StateKindMismatch {
            kind,
            state: AdmissionOperationState::DispatchCommitted,
        });
    }
    Ok(version)
}

pub(super) fn validate_positive_ijson(
    field: &'static str,
    value: u64,
) -> Result<(), AdmissionOperationError> {
    if value == 0 {
        return Err(AdmissionOperationError::ZeroVersionOrEpoch);
    }
    if value > I_JSON_MAX_SAFE_INTEGER {
        return Err(AdmissionOperationError::UnsafeInteger { field });
    }
    Ok(())
}

pub(super) fn validate_store_fence(
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationError> {
    if validate_positive_ijson("store_owner_epoch", fence.owner_epoch).is_err()
        || BoundedAdmissionText::<MAX_ADMISSION_IDENTIFIER_BYTES>::try_new(
            "store_uuid",
            fence.store_uuid.clone(),
        )
        .is_err()
        || BoundedAdmissionText::<MAX_ADMISSION_IDENTIFIER_BYTES>::try_new(
            "store_lease_id",
            fence.lease_id.clone(),
        )
        .is_err()
    {
        return Err(AdmissionOperationError::InvalidStoreFence);
    }
    Ok(())
}

pub(super) fn validate_artifact_digests(
    digests: &[AdmissionDigest],
) -> Result<(), AdmissionOperationError> {
    if digests.len() > MAX_AUTHORIZATION_ARTIFACT_DIGESTS
        || digests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AdmissionOperationError::InvalidAuthorizationArtifactDigests);
    }
    Ok(())
}

pub(super) fn attachment_supported(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    attachment: &AdmissionAttachment,
) -> bool {
    if kind == AdmissionOperationKind::GovernedEconomicMutation {
        return false;
    }
    match attachment {
        AdmissionAttachment::ThresholdProposalHash(_) => requirements.approval,
        AdmissionAttachment::SupplementalAuthorizationDigest(_) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        AdmissionAttachment::BrokerAttempt(_) => requirements.broker_attempt,
        AdmissionAttachment::BudgetHoldId(_) => requirements.budget_capture,
        AdmissionAttachment::ApprovalSetHash(_) => requirements.approval,
        AdmissionAttachment::ExecutionNonceId(_) => requirements.execution_nonce,
        AdmissionAttachment::OutcomeEligibilityDigest(_) => requirements.outcome_eligibility,
        AdmissionAttachment::PaymentParticipantId(_) => requirements.payment,
        AdmissionAttachment::ToolOutcomeId(_) => kind == AdmissionOperationKind::ToolDispatch,
        AdmissionAttachment::ChannelReservationProposalDigest(_)
        | AdmissionAttachment::ChannelReservationDigest(_) => requirements.channel,
    }
}

pub(super) fn attachment_allowed(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    state: AdmissionOperationState,
    attachment: &AdmissionAttachment,
) -> bool {
    if !attachment_supported(kind, requirements, attachment) {
        return false;
    }
    match attachment {
        AdmissionAttachment::ToolOutcomeId(_) => matches!(
            state,
            AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Finalizing
        ),
        AdmissionAttachment::ChannelReservationProposalDigest(_) => {
            state == AdmissionOperationState::Prepared
        }
        AdmissionAttachment::ChannelReservationDigest(_) => matches!(
            state,
            AdmissionOperationState::BudgetAuthorized | AdmissionOperationState::ApprovalReserved
        ),
        _ => matches!(
            state,
            AdmissionOperationState::Prepared
                | AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::ApprovalReserved
        ),
    }
}

pub(super) fn validate_state_attachments(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    state: AdmissionOperationState,
    attachments: &AdmissionOperationAttachmentsV1,
) -> Result<(), AdmissionOperationError> {
    if let Some(attachment) = attachments.0.iter().find(|attachment| {
        !attachment_supported(kind, requirements, attachment)
            || match attachment {
                AdmissionAttachment::ToolOutcomeId(_) => !matches!(
                    state,
                    AdmissionOperationState::DispatchCommitted
                        | AdmissionOperationState::Finalizing
                        | AdmissionOperationState::Completed
                        | AdmissionOperationState::OutcomeUnknownAfterDispatch
                ),
                AdmissionAttachment::ChannelReservationDigest(_) => !matches!(
                    state,
                    AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                        | AdmissionOperationState::DispatchCommitted
                        | AdmissionOperationState::Finalizing
                        | AdmissionOperationState::Completed
                        | AdmissionOperationState::CompensatedBeforeDispatch
                        | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                        | AdmissionOperationState::OutcomeUnknownAfterDispatch
                ),
                _ => false,
            }
    }) {
        return Err(AdmissionOperationError::ForbiddenAttachment {
            field: attachment.field_name(),
        });
    }
    if kind == AdmissionOperationKind::ToolDispatch
        && matches!(
            state,
            AdmissionOperationState::Finalizing | AdmissionOperationState::Completed
        )
        && !attachments.has_slot(AdmissionAttachmentKind::ToolOutcome.slot())
    {
        return Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "tool_outcome_id",
        });
    }
    let reached = |milestone| match milestone {
        AdmissionOperationState::BrokerAttemptRegistered => matches!(
            state,
            AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        ),
        AdmissionOperationState::BudgetAuthorized => matches!(
            state,
            AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        ),
        AdmissionOperationState::ApprovalReserved => matches!(
            state,
            AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        ),
        _ => matches!(
            state,
            AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
                | AdmissionOperationState::MutationReady
                | AdmissionOperationState::MutationSubmitted
                | AdmissionOperationState::EconomicMutationApplied
        ),
    };
    let required = [
        (
            requirements.broker_attempt
                && reached(AdmissionOperationState::BrokerAttemptRegistered),
            2,
            "broker_attempt",
        ),
        (
            requirements.budget_capture && reached(AdmissionOperationState::BudgetAuthorized),
            3,
            "budget_hold_id",
        ),
        (
            requirements.approval && reached(AdmissionOperationState::ApprovalReserved),
            0,
            "threshold_proposal_hash",
        ),
        (
            requirements.approval && reached(AdmissionOperationState::ApprovalReserved),
            4,
            "approval_set_hash",
        ),
        (
            requirements.execution_nonce && reached(AdmissionOperationState::ReadyToDispatch),
            5,
            "execution_nonce_id",
        ),
        (
            requirements.outcome_eligibility && reached(AdmissionOperationState::ReadyToDispatch),
            6,
            "outcome_eligibility_digest",
        ),
        (
            requirements.payment && reached(AdmissionOperationState::ReadyToDispatch),
            7,
            "payment_participant_id",
        ),
        (
            requirements.channel && reached(AdmissionOperationState::BrokerAttemptRegistered),
            9,
            "channel_reservation_proposal_digest",
        ),
        (
            requirements.channel && reached(AdmissionOperationState::ReadyToDispatch),
            10,
            "channel_reservation_digest",
        ),
    ];
    if let Some((_, _, field)) = required
        .into_iter()
        .find(|(needed, slot, _)| *needed && !attachments.has_slot(*slot))
    {
        return Err(AdmissionOperationError::MissingParticipantAttachment { field });
    }
    Ok(())
}

pub(super) fn validate_state_requirements(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    let valid = if kind == AdmissionOperationKind::GovernedEconomicMutation {
        matches!(
            state,
            AdmissionOperationState::Prepared
                | AdmissionOperationState::MutationReady
                | AdmissionOperationState::MutationSubmitted
                | AdmissionOperationState::EconomicMutationApplied
                | AdmissionOperationState::EconomicMutationNotApplied
        )
    } else {
        match state {
            AdmissionOperationState::BrokerAttemptRegistered => requirements.broker_attempt,
            AdmissionOperationState::BudgetAuthorized | AdmissionOperationState::CapturePending => {
                requirements.budget_capture
            }
            AdmissionOperationState::ApprovalReserved => requirements.approval,
            AdmissionOperationState::MutationReady
            | AdmissionOperationState::MutationSubmitted
            | AdmissionOperationState::EconomicMutationApplied
            | AdmissionOperationState::EconomicMutationNotApplied => false,
            _ => true,
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AdmissionOperationError::StateKindMismatch { kind, state })
    }
}

pub(super) fn predispatch_state_enabled(
    requirements: AdmissionParticipantRequirements,
    state: AdmissionOperationState,
) -> bool {
    match state {
        AdmissionOperationState::Prepared | AdmissionOperationState::ReadyToDispatch => true,
        AdmissionOperationState::BrokerAttemptRegistered => requirements.broker_attempt,
        AdmissionOperationState::BudgetAuthorized | AdmissionOperationState::CapturePending => {
            requirements.budget_capture
        }
        AdmissionOperationState::ApprovalReserved => requirements.approval,
        _ => false,
    }
}

pub(super) fn dispatch_state_for(
    kind: AdmissionOperationKind,
    state: AdmissionOperationState,
) -> Result<AdmissionDispatchState, AdmissionOperationError> {
    if kind == AdmissionOperationKind::GovernedEconomicMutation {
        return if matches!(
            state,
            AdmissionOperationState::Prepared
                | AdmissionOperationState::MutationReady
                | AdmissionOperationState::MutationSubmitted
                | AdmissionOperationState::EconomicMutationApplied
                | AdmissionOperationState::EconomicMutationNotApplied
        ) {
            Ok(AdmissionDispatchState::NotApplicable)
        } else {
            Err(AdmissionOperationError::StateKindMismatch { kind, state })
        };
    }
    if !kind.uses_dispatch() {
        return Err(AdmissionOperationError::StateKindMismatch { kind, state });
    }
    match state {
        AdmissionOperationState::Prepared
        | AdmissionOperationState::BrokerAttemptRegistered
        | AdmissionOperationState::BudgetAuthorized
        | AdmissionOperationState::ApprovalReserved
        | AdmissionOperationState::ReadyToDispatch => Ok(AdmissionDispatchState::NotCommitted),
        AdmissionOperationState::CapturePending => Ok(AdmissionDispatchState::CapturePending),
        AdmissionOperationState::DispatchCommitted => Ok(AdmissionDispatchState::Committed),
        AdmissionOperationState::Finalizing => Ok(AdmissionDispatchState::Finalizing),
        AdmissionOperationState::Completed
        | AdmissionOperationState::CompensatedBeforeDispatch
        | AdmissionOperationState::NotAcceptedAfterDispatchCommit
        | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            Ok(AdmissionDispatchState::Terminal)
        }
        _ => Err(AdmissionOperationError::StateKindMismatch { kind, state }),
    }
}

pub(super) fn validate_dispatch_commit(
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationError> {
    let requires_commit = operation.binding.kind.uses_dispatch()
        && matches!(
            operation.state,
            AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Finalizing
                | AdmissionOperationState::Completed
                | AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
    match (&operation.dispatch_commit, requires_commit) {
        (Some(binding), true)
            if binding.coordinator_lease_epoch == operation.coordinator_lease_epoch
                && binding.committed_version <= operation.version
                && match operation.binding.kind {
                    AdmissionOperationKind::ToolDispatch => {
                        binding.provider_attempt.as_ref() == operation.provider_attempt()
                            && binding.provider_attempt.as_ref().is_some_and(|attempt| {
                                attempt.operation_id == operation.binding.operation_id().as_str()
                            })
                    }
                    AdmissionOperationKind::GovernedActiveResponse => {
                        binding.provider_attempt.is_none()
                    }
                    AdmissionOperationKind::GovernedEconomicMutation => false,
                }
                && (operation.state != AdmissionOperationState::DispatchCommitted
                    || binding.committed_version == operation.version) =>
        {
            binding.validate()
        }
        (None, false) => Ok(()),
        _ => Err(AdmissionOperationError::DispatchStateMismatch),
    }
}

pub(super) fn is_legal_transition(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    from: AdmissionOperationState,
    to: AdmissionOperationState,
) -> bool {
    if kind == AdmissionOperationKind::GovernedEconomicMutation {
        return matches!(
            (from, to),
            (
                AdmissionOperationState::Prepared,
                AdmissionOperationState::MutationReady
            ) | (
                AdmissionOperationState::MutationReady,
                AdmissionOperationState::MutationSubmitted
            ) | (
                AdmissionOperationState::Prepared
                    | AdmissionOperationState::MutationReady
                    | AdmissionOperationState::MutationSubmitted,
                AdmissionOperationState::EconomicMutationNotApplied
            ) | (
                AdmissionOperationState::MutationSubmitted,
                AdmissionOperationState::EconomicMutationApplied
            )
        );
    }
    if !kind.uses_dispatch() {
        return false;
    }
    if to == AdmissionOperationState::CompensatedBeforeDispatch {
        return from.is_pre_dispatch() && predispatch_state_enabled(requirements, from);
    }
    let ready_source = if requirements.approval {
        AdmissionOperationState::ApprovalReserved
    } else if requirements.budget_capture {
        AdmissionOperationState::BudgetAuthorized
    } else {
        AdmissionOperationState::Prepared
    };
    match to {
        AdmissionOperationState::BrokerAttemptRegistered => {
            requirements.broker_attempt && from == AdmissionOperationState::Prepared
        }
        AdmissionOperationState::BudgetAuthorized => {
            requirements.budget_capture
                && from
                    == if requirements.broker_attempt {
                        AdmissionOperationState::BrokerAttemptRegistered
                    } else {
                        AdmissionOperationState::Prepared
                    }
        }
        AdmissionOperationState::ApprovalReserved => {
            requirements.approval
                && from
                    == if requirements.budget_capture {
                        AdmissionOperationState::BudgetAuthorized
                    } else {
                        AdmissionOperationState::Prepared
                    }
        }
        AdmissionOperationState::ReadyToDispatch => from == ready_source,
        AdmissionOperationState::CapturePending => {
            requirements.budget_capture && from == AdmissionOperationState::ReadyToDispatch
        }
        AdmissionOperationState::DispatchCommitted => {
            from == if requirements.budget_capture {
                AdmissionOperationState::CapturePending
            } else {
                AdmissionOperationState::ReadyToDispatch
            }
        }
        AdmissionOperationState::Finalizing
        | AdmissionOperationState::NotAcceptedAfterDispatchCommit
        | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            from == AdmissionOperationState::DispatchCommitted
                || (to == AdmissionOperationState::OutcomeUnknownAfterDispatch
                    && from == AdmissionOperationState::Finalizing)
        }
        AdmissionOperationState::Completed => from == AdmissionOperationState::Finalizing,
        _ => false,
    }
}
