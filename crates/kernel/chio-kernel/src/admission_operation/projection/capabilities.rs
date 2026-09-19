//! Atomic terminal projections a store can commit for an operation's participants.

use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionProjectionCapabilities {
    pub operation_terminal: bool,
    pub incident_terminal: bool,
    pub tool_outcome: bool,
    pub payment_terminal: bool,
    pub authorization_consumption: bool,
    pub outcome_eligibility: bool,
    pub observation_attempt_zero: bool,
    pub obligation: bool,
    pub channel_terminal: bool,
    pub credit_exposure_terminal: bool,
    pub economic_mutation_terminal: bool,
    /// The store implements the operation-owned execution nonce participant:
    /// preflight ownership, write-ahead issuance, reservation and capture.
    pub execution_nonce_participant: bool,
}

impl AdmissionProjectionCapabilities {
    pub fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        projection: &AdmissionTerminalProjection,
    ) -> Result<(), AdmissionOperationError> {
        let requirements = operation.binding.participant_requirements();
        let require = |supported, capability| {
            if supported {
                Ok(())
            } else {
                Err(AdmissionOperationError::MissingProjectionCapability { capability })
            }
        };
        require(self.operation_terminal, "operation_terminal")?;
        require(
            !requirements.credit_exposure || self.credit_exposure_terminal,
            "credit_exposure_terminal",
        )?;
        match projection {
            AdmissionTerminalProjection::Completed(_) => {
                require(
                    operation.binding.kind != AdmissionOperationKind::ToolDispatch
                        || self.tool_outcome,
                    "tool_outcome",
                )?;
                require(
                    !requirements.payment || self.payment_terminal,
                    "payment_terminal",
                )?;
                require(
                    !requirements.authorization_consumption || self.authorization_consumption,
                    "authorization_consumption",
                )?;
                require(
                    !requirements.outcome_eligibility || self.outcome_eligibility,
                    "outcome_eligibility",
                )?;
                require(
                    !requirements.observation_attempt_zero || self.observation_attempt_zero,
                    "observation_attempt_zero",
                )?;
                require(!requirements.obligation || self.obligation, "obligation")?;
                require(
                    !requirements.channel || self.channel_terminal,
                    "channel_terminal",
                )
            }
            AdmissionTerminalProjection::CompensatedBeforeDispatch { evidence, .. }
            | AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit { evidence, .. } => {
                require(
                    !matches!(evidence.as_ref(), AdmissionReceiptOrIncident::Incident(_))
                        || self.incident_terminal,
                    "incident_terminal",
                )
            }
            AdmissionTerminalProjection::DeniedAfterDelivery { evidence, .. } => {
                require(
                    !matches!(evidence.as_ref(), AdmissionReceiptOrIncident::Incident(_))
                        || self.incident_terminal,
                    "incident_terminal",
                )?;
                require(
                    !requirements.payment || self.payment_terminal,
                    "payment_terminal",
                )?;
                require(
                    !requirements.observation_attempt_zero || self.observation_attempt_zero,
                    "observation_attempt_zero",
                )
            }
            AdmissionTerminalProjection::OutcomeUnknownAfterDispatch { .. } => {
                require(self.incident_terminal, "incident_terminal")
            }
            AdmissionTerminalProjection::EconomicMutationApplied { .. }
            | AdmissionTerminalProjection::EconomicMutationNotApplied { .. } => require(
                self.economic_mutation_terminal,
                "economic_mutation_terminal",
            ),
        }
    }
}

impl AdmissionProjectionCapabilities {
    /// Every projection, including the operation-owned execution nonce participant.
    pub const ALL: Self = Self {
        operation_terminal: true,
        incident_terminal: true,
        tool_outcome: true,
        payment_terminal: true,
        authorization_consumption: true,
        outcome_eligibility: true,
        observation_attempt_zero: true,
        obligation: true,
        channel_terminal: true,
        credit_exposure_terminal: true,
        economic_mutation_terminal: true,
        execution_nonce_participant: true,
    };
}
