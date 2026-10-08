//! Only authenticated original source roles implement the pricing interface.
use super::*;

pub(super) mod sealed {
    pub trait Sealed {}
}

/// A common original-source interface does not manufacture a phase account.
/// Both implementations recheck their exact physical operation and initial
/// owner cut. Neither envelopes nor a caller-defined wrapper implement it.
pub(in crate::admission_operation_store) trait NativeToolOutcomeSourcePlan:
    sealed::Sealed
{
    fn verify_before(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'_>,
    ) -> Result<(), AdmissionOperationStoreError>;
    fn original(&self) -> &RetainedToolAdmissionRequestV1;
    fn operation(&self) -> &AdmissionOperationV1;
    fn frozen_steps(&self) -> &[FrozenEvaluationStepV1];
    fn tool_outcome_envelope(&self) -> &NativeToolOutcomeEnvelopeData;
    fn physical_write_profile(&self) -> &ToolOutcomeWriteProfileData;
    fn global_commit_envelope(&self) -> &NativeToolOutcomeGlobalEnvelopeData;
}

impl sealed::Sealed for VerifiedNativeFinishingPlan<'_, '_> {}

impl NativeToolOutcomeSourcePlan for VerifiedNativeFinishingPlan<'_, '_> {
    fn verify_before(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        origin: &NativeSourceTransactionOrigin<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        VerifiedNativeFinishingPlan::verify_before(self, tx, owner, origin)
    }
    fn original(&self) -> &RetainedToolAdmissionRequestV1 {
        VerifiedNativeFinishingPlan::original(self)
    }
    fn operation(&self) -> &AdmissionOperationV1 {
        VerifiedNativeFinishingPlan::operation(self)
    }
    fn frozen_steps(&self) -> &[FrozenEvaluationStepV1] {
        VerifiedNativeFinishingPlan::frozen_steps(self)
    }
    fn tool_outcome_envelope(&self) -> &NativeToolOutcomeEnvelopeData {
        VerifiedNativeFinishingPlan::tool_outcome_envelope(self)
    }
    fn physical_write_profile(&self) -> &ToolOutcomeWriteProfileData {
        VerifiedNativeFinishingPlan::physical_write_profile(self)
    }
    fn global_commit_envelope(&self) -> &NativeToolOutcomeGlobalEnvelopeData {
        VerifiedNativeFinishingPlan::global_commit_envelope(self)
    }
}
