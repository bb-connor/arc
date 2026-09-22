//! Original-operation registration before supplemental budget custody.
//!
//! The pure quota verifier establishes permission. A separately installed
//! participant may persist the corresponding broker attempt, but cannot acquire
//! a second budget hold, materialize a credential or dispatch a provider call.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::admission_operation::{AdmissionDigest, AdmissionIdentifier, AdmissionOperationV1};
use crate::budget_store::BudgetAuthorizeHoldRequest;
use crate::supplemental_quota::{SupplementalQuotaVerifierBinding, SupplementalQuotaVerifierError};
use crate::ToolCallRequest;

/// Composition-root identities retained with the original admission. The
/// participant digest includes its independently selected broker peer, tenant,
/// transport and authorization configuration; request data cannot select them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplementalAdmissionAuthorityBindingV1 {
    participant_identity: AdmissionIdentifier,
    participant_configuration_digest: AdmissionDigest,
    verifier_identity: AdmissionIdentifier,
    verifier_configuration_digest: AdmissionDigest,
}

impl SupplementalAdmissionAuthorityBindingV1 {
    #[must_use]
    pub fn new(
        participant_identity: AdmissionIdentifier,
        participant_configuration_digest: AdmissionDigest,
        verifier_identity: AdmissionIdentifier,
        verifier_configuration_digest: AdmissionDigest,
    ) -> Self {
        Self {
            participant_identity,
            participant_configuration_digest,
            verifier_identity,
            verifier_configuration_digest,
        }
    }

    #[must_use]
    pub fn matches_verifier(&self, verifier: &SupplementalQuotaVerifierBinding) -> bool {
        self.verifier_identity.as_str() == verifier.verifier_identity
            && self.verifier_configuration_digest.as_str() == verifier.configuration_digest
    }
}

/// A borrowed view constructed only after kernel verification. The original
/// operation identity is distinct from the temporary nonce-preflight hold.
/// Reading this context grants no authority to capture or execute.
pub struct SupplementalAdmissionRegistrationContext<'a> {
    pub(crate) operation: &'a AdmissionOperationV1,
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) budget: &'a BudgetAuthorizeHoldRequest,
}

impl SupplementalAdmissionRegistrationContext<'_> {
    #[must_use]
    pub fn operation(&self) -> &AdmissionOperationV1 {
        self.operation
    }

    #[must_use]
    pub fn request(&self) -> &ToolCallRequest {
        self.request
    }

    #[must_use]
    pub fn budget(&self) -> &BudgetAuthorizeHoldRequest {
        self.budget
    }
}

/// Trusted composition port, separate from pure supplemental verification.
pub trait SupplementalAdmissionParticipant: Send + Sync {
    /// Pure selection from installed routing. A required route must deny when
    /// the caller omits supplemental authority. Other routes may opt out.
    fn requires_registration(&self, _server_id: &str, _tool_name: &str) -> bool {
        true
    }

    /// Return success only after authenticating durable registration of the
    /// exact original attempt. Exact retries must be idempotent, including the
    /// later dispatch request after nonce issuance. Failure or a lost
    /// acknowledgement must not fall back to execution or a new attempt.
    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> Result<(), SupplementalQuotaVerifierError>;
}

pub(crate) struct SupplementalAdmissionParticipantRuntime {
    pub(crate) participant: Arc<dyn SupplementalAdmissionParticipant>,
    pub(crate) binding: SupplementalAdmissionAuthorityBindingV1,
}
