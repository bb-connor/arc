//! Required participant evidence for terminal projections.
use super::*;

/// The presence rule for the denied-after-delivery terminal, the analogue
/// of [`validate_completed_participant_presence`]: a paid operation must
/// carry the payment evidence binding its released journal, an observed
/// operation must carry its observation attempt, and a requirement this
/// terminal cannot represent (authorization consumption, outcome
/// eligibility, obligation, channel) denies the projection outright.
pub(in crate::admission_operation) fn validate_denied_after_delivery_participant_presence(
    requirements: AdmissionParticipantRequirements,
    payment_evidence: Option<&PaymentTerminalEvidence>,
    observer_work: Option<&ObservationAttemptZero>,
) -> Result<(), AdmissionOperationError> {
    if requirements.authorization_consumption
        || requirements.outcome_eligibility
        || requirements.obligation
        || requirements.channel
        || payment_evidence.is_some() != requirements.payment
        || observer_work.is_some() != requirements.observation_attempt_zero
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

pub(in crate::admission_operation) fn validate_completed_participant_presence(
    requirements: AdmissionParticipantRequirements,
    completed: &AdmissionCompletedProjection,
) -> Result<(), AdmissionOperationError> {
    let obligation_required = if requirements.channel {
        completed
            .channel_terminal
            .as_ref()
            .is_some_and(|channel| channel.actual_charge().units > 0)
    } else {
        requirements.obligation
    };
    if completed.payment_evidence.is_some() != requirements.payment
        || completed.authorization.is_some() != requirements.authorization_consumption
        || completed.eligibility.is_some() != requirements.outcome_eligibility
        || completed.observer_work.is_some() != requirements.observation_attempt_zero
        || completed.channel_terminal.is_some() != requirements.channel
        || completed.obligation.is_some() != obligation_required
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}
