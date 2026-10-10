//! Immutable references selected before dispatch, never participant authority.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenDispatchParticipants {
    threshold_proposal_hash: Option<AdmissionDigest>,
    threshold_proposal_body_digest: Option<AdmissionDigest>,
    supplemental_authorization_digest: Option<AdmissionDigest>,
    provider_attempt: Option<ProviderAttemptBindingV1>,
    budget_hold_id: Option<AdmissionIdentifier>,
    approval_set_hash: Option<AdmissionDigest>,
    execution_nonce_id: Option<AdmissionIdentifier>,
    execution_nonce_issuance_digest: Option<AdmissionDigest>,
    execution_nonce_preflight_digest: Option<AdmissionDigest>,
    outcome_eligibility_digest: Option<AdmissionDigest>,
    payment_participant_id: Option<AdmissionIdentifier>,
    channel_reservation_proposal_digest: Option<AdmissionDigest>,
    channel_reservation_digest: Option<AdmissionDigest>,
    credit_exposure_reservation_digest: Option<AdmissionDigest>,
    runtime_participant_ledger_digest: Option<AdmissionDigest>,
    governed_approval_ledger_digest: Option<AdmissionDigest>,
    dpop_replay_ledger_digest: Option<AdmissionDigest>,
    native_dispatch_ledger_digest: Option<AdmissionDigest>,
}

impl FrozenDispatchParticipants {
    pub(super) fn from_operation(operation: &AdmissionOperationV1) -> Result<Self, KernelError> {
        let mut snapshot = Self::default();
        // An exhaustive match makes every new attachment require an explicit
        // retention decision. Absence is frozen just as strictly as presence.
        for attachment in operation.attachments() {
            match attachment {
                AdmissionAttachment::ThresholdProposalHash(value) => {
                    snapshot.threshold_proposal_hash = Some(value.clone());
                }
                AdmissionAttachment::ThresholdProposal(value) => {
                    // Retain a reference, not the signed proposal or its input.
                    snapshot.threshold_proposal_body_digest =
                        Some(admission_digest("frozen_threshold_proposal_digest", value)?);
                }
                AdmissionAttachment::SupplementalAuthorizationDigest(value) => {
                    snapshot.supplemental_authorization_digest = Some(value.clone());
                }
                AdmissionAttachment::BrokerAttempt(value) => {
                    snapshot.provider_attempt = Some(value.clone());
                }
                AdmissionAttachment::BudgetHoldId(value) => {
                    snapshot.budget_hold_id = Some(value.clone());
                }
                AdmissionAttachment::ApprovalSetHash(value) => {
                    snapshot.approval_set_hash = Some(value.clone());
                }
                AdmissionAttachment::ExecutionNonceId(value) => {
                    snapshot.execution_nonce_id = Some(value.clone());
                }
                AdmissionAttachment::ExecutionNonceIssuanceDigest(value) => {
                    snapshot.execution_nonce_issuance_digest = Some(value.clone());
                }
                AdmissionAttachment::ExecutionNoncePreflightDigest(value) => {
                    snapshot.execution_nonce_preflight_digest = Some(value.clone());
                }
                AdmissionAttachment::OutcomeEligibilityDigest(value) => {
                    snapshot.outcome_eligibility_digest = Some(value.clone());
                }
                AdmissionAttachment::PaymentParticipantId(value) => {
                    snapshot.payment_participant_id = Some(value.clone());
                }
                AdmissionAttachment::ChannelReservationProposalDigest(value) => {
                    snapshot.channel_reservation_proposal_digest = Some(value.clone());
                }
                AdmissionAttachment::ChannelReservationDigest(value) => {
                    snapshot.channel_reservation_digest = Some(value.clone());
                }
                AdmissionAttachment::CreditExposureReservationDigest(value) => {
                    snapshot.credit_exposure_reservation_digest = Some(value.clone());
                }
                AdmissionAttachment::RuntimeParticipantLedgerDigest(value) => {
                    snapshot.runtime_participant_ledger_digest = Some(value.clone());
                }
                AdmissionAttachment::GovernedApprovalLedgerDigest(value) => {
                    snapshot.governed_approval_ledger_digest = Some(value.clone());
                }
                AdmissionAttachment::DpopReplayLedgerDigest(value) => {
                    snapshot.dpop_replay_ledger_digest = Some(value.clone());
                }
                AdmissionAttachment::NativeDispatchLedgerDigest(value) => {
                    snapshot.native_dispatch_ledger_digest = Some(value.clone());
                }
                // The caller frame encloses this snapshot; including its digest
                // would be recursive. Tool outcome is a later return observation.
                AdmissionAttachment::CallerDispatchContextDigest(_)
                | AdmissionAttachment::ToolOutcomeId(_) => {}
            }
        }
        Ok(snapshot)
    }

    pub(super) fn validate(&self, operation: &AdmissionOperationV1) -> Result<(), KernelError> {
        if self != &Self::from_operation(operation)? {
            return Err(KernelError::DurableAdmission(
                "frozen return context changed its dispatch participant references".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn bind_native_dispatch(
        &mut self,
        digest: &AdmissionDigest,
    ) -> Result<(), KernelError> {
        if self.native_dispatch_ledger_digest.is_some() {
            return Err(KernelError::DurableAdmission(
                "frozen return context already selected a native dispatch ledger".into(),
            ));
        }
        self.native_dispatch_ledger_digest = Some(digest.clone());
        Ok(())
    }
}
