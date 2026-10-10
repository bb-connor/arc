//! Recovery bookkeeping carries no caller-selected mutation time.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionRecoveryFailureKind, AdmissionRecoveryPhase,
    AdmissionRecoveryStatusV1,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPageRequest {
    pub(crate) candidate_limit: usize,
    pub(crate) after_operation_id: Option<AdmissionOperationId>,
    pub(crate) fence: StoreMutationFence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPageResponse {
    pub(crate) operations: Vec<PersistedAdmissionOperationV1>,
    pub(crate) scanned_candidates: usize,
    pub(crate) next_cursor: Option<AdmissionOperationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryStatusRequest {
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) fence: StoreMutationFence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDeferralRequest {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: RecoveryClaimWire,
    pub(crate) expected: Option<AdmissionRecoveryStatusV1>,
    pub(crate) phase: AdmissionRecoveryPhase,
    pub(crate) failure_kind: AdmissionRecoveryFailureKind,
    pub(crate) diagnostic_digest: AdmissionDigest,
    pub(crate) fence: StoreMutationFence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDeferralClearRequest {
    pub(crate) operation: PersistedAdmissionOperationV1,
    pub(crate) recovery_claim: Option<RecoveryClaimWire>,
    pub(crate) expected: AdmissionRecoveryStatusV1,
    pub(crate) fence: StoreMutationFence,
}
