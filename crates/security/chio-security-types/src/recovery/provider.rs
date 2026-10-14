//! A provider's signed finality claim is data until the native owner verifies it.
//!
//! Provider and account identities have separate meanings even when equal.
//! ```compile_fail
//! use chio_security_types::recovery::RecoveryProviderFinalityV1;
//! fn substitute(finality: &mut RecoveryProviderFinalityV1) {
//!     finality.provider = finality.account.clone();
//! }
//! ```
//!
//! A resource identity cannot replace the pinned effect contract.
//! ```compile_fail
//! use chio_security_types::recovery::RecoveryProviderFinalityV1;
//! fn substitute(finality: &mut RecoveryProviderFinalityV1) {
//!     finality.contract_digest = finality.resource_digest;
//! }
//! ```
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryProviderFinalitySchema {
    #[serde(rename = "chio.recovery.provider-finality.v1")]
    V1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEffectDisposition {
    Succeeded,
    PartiallyApplied,
    FailedAfterEffect,
}
/// Positive finality covers the entire original single-submission operation.
/// The pinned provider must attest that no later effect remains possible. native recovery
/// refuses zero-effect post-dispatch claims rather than inventing compensation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProviderFinalityV1 {
    pub schema: RecoveryProviderFinalitySchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub continuation_id: ContinuationId,
    pub operation_id: OperationId,
    pub native_admission_digest: NativeAdmissionDigest,
    pub attempt_id: ProviderAttemptId,
    pub provider: RecoveryEffectProviderId,
    pub account: RecoveryEffectAccountId,
    pub resource_digest: ResourceDigest,
    pub contract_digest: ContractDigest,
    pub observed_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
    pub disposition: RecoveryEffectDisposition,
    pub applied_effects: SafeInteger,
}

impl core::fmt::Debug for RecoveryProviderFinalityV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryProviderFinalityV1([redacted])")
    }
}
