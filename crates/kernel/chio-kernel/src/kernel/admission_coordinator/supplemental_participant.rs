//! Register the original supplemental attempt before either physical hold.
use super::*;
use crate::budget_store::BudgetAuthorizeHoldRequest;
use crate::supplemental_admission::{
    SupplementalAdmissionAuthorityBindingV1, SupplementalAdmissionParticipant,
    SupplementalAdmissionParticipantRuntime, SupplementalAdmissionRegistrationContext,
};

impl ChioKernel {
    /// Install registration alongside its independently configured pure verifier.
    /// Both configuration generations are retained in every original profile.
    pub fn set_supplemental_admission_participant(
        &mut self,
        participant: Arc<dyn SupplementalAdmissionParticipant>,
        binding: SupplementalAdmissionAuthorityBindingV1,
    ) -> Result<(), KernelError> {
        if self
            .supplemental_quota_verifier
            .as_ref()
            .is_none_or(|verifier| !binding.matches_verifier(verifier.binding()))
        {
            return Err(invalid(
                "supplemental participant requires its configured verifier",
            ));
        }
        self.supplemental_admission_participant = Some(SupplementalAdmissionParticipantRuntime {
            participant,
            binding,
        });
        Ok(())
    }

    pub fn clear_supplemental_admission_participant(&mut self) {
        self.supplemental_admission_participant = None;
    }

    pub(super) fn register_supplemental_admission(
        &self,
        admission: &DurableToolAdmission,
        budget: &BudgetAuthorizeHoldRequest,
        observed_at: u64,
    ) -> Result<(), KernelError> {
        self.validate_live_admission_authority_profile(Some(admission))?;
        let Some(participant) = self.supplemental_admission_participant.as_ref() else {
            return Ok(());
        };
        let original = admission
            .retained_request
            .as_ref()
            .ok_or_else(|| invalid("supplemental registration has no original request"))?;
        original
            .validate_binding(admission.operation.binding())
            .map_err(durable_store_error)?;
        let Some(claim) = admission.supplemental_quota.as_ref() else {
            let request = original.request_for_revalidation();
            let required = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                participant
                    .participant
                    .requires_registration(&request.server_id, &request.tool_name)
            }))
            .map_err(|_| invalid("supplemental route selection panicked (fail-closed)"))?;
            return if required {
                Err(invalid(
                    "tool route requires verified supplemental authority",
                ))
            } else {
                Ok(())
            };
        };
        if original
            .authority_profile()
            .and_then(|profile| profile.supplemental_participant())
            != Some(&participant.binding)
            || !participant
                .binding
                .matches_verifier(claim.verifier_binding())
            || claim.operation_id() != admission.operation.binding().operation_id().as_str()
            || budget.capability_id != admission.operation.binding().capability_id().as_str()
        {
            return Err(invalid(
                "supplemental registration differs from original admission",
            ));
        }
        // IPC is outside the mutation sequencer. No budget mutation is possible
        // on this path until registration and the subsequent readback succeed.
        let context = SupplementalAdmissionRegistrationContext {
            operation: &admission.operation,
            request: original.request_for_revalidation(),
            budget,
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            participant.participant.register_original(&context)
        }))
        .map_err(|_| invalid("supplemental registration panicked (fail-closed)"))?
        .map_err(|_| invalid("supplemental registration was not durably acknowledged"))?;
        self.validate_live_admission_authority_profile(Some(admission))?;
        let retained = self
            .load_original_request_for_finalization(&admission.operation, observed_at)?
            .ok_or_else(|| invalid("supplemental registration lost its original request"))?;
        if retained.canonical_bytes() != original.canonical_bytes() {
            return Err(invalid(
                "supplemental registration changed its original request",
            ));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> KernelError {
    KernelError::DurableAdmission(message.into())
}
