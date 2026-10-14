//! The physical original supplies a finishing footprint, never a bank loan.
use super::super::raw_custody_liability::ToolOutcomeWriteProfileData;
use super::*;
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_kernel::admission_operation::{
    RetainedToolAdmissionRequestV1, MAX_ADMISSION_IDENTIFIER_BYTES,
};
use chio_kernel::tool_outcome::FrozenEvaluationStepV1;
use chio_security_types::ports::FlowStateKey;

mod global_envelope;
mod initial;
mod seal_allowance;
pub(in crate::admission_operation_store) use global_envelope::NativeToolOutcomeGlobalEnvelopeData;
pub(in crate::admission_operation_store) use initial::{
    prepare_native_initial_finishing_plan, NativeInitialFinishingCustody,
    NativeInitialFinishingPhase as StoreNativeInitialFinishingPhase,
    VerifiedNativeInitialFinishingPlan,
};
pub(in crate::admission_operation_store) use seal_allowance::{
    describe_native_seal_allowance, NativeSealAllowanceData, VerifiedNativeSealAllowance,
};

/// Source-bound envelope DATA. A scalar or decoded copy cannot construct the
/// original-source role, fund a purpose, or permit capture or authorization.
pub(in crate::admission_operation_store) struct NativeToolOutcomeEnvelopeData {
    raw: u64,
    outcome_json: u64,
    evaluation: u64,
    resolved: u64,
    receipt: u64,
}

impl NativeToolOutcomeEnvelopeData {
    pub(in crate::admission_operation_store) fn raw_bytes(&self) -> u64 {
        self.raw
    }
    pub(in crate::admission_operation_store) fn outcome_bytes(&self) -> u64 {
        self.outcome_json
    }
    pub(in crate::admission_operation_store) fn evaluation_bytes(&self) -> u64 {
        self.evaluation
    }
    pub(in crate::admission_operation_store) fn resolved_bytes(&self) -> u64 {
        self.resolved
    }
    pub(in crate::admission_operation_store) fn receipt_bytes(&self) -> u64 {
        self.receipt
    }
    pub(in crate::admission_operation_store) fn claimant_maximum_bytes(&self) -> usize {
        MAX_ADMISSION_IDENTIFIER_BYTES
    }
}
