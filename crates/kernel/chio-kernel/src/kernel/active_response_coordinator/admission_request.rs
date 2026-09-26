//! The immutable admission request envelope and the permits verification
//! issues for it.

use super::{
    active_response_denied, ActiveResponseArtifactAuthorityAttestation,
    ActiveResponseAuthorizationRequest, AdmissionArtifactRef, AdmissionOperation,
    ApprovalSetReservationInput, GovernedApprovalToken, KernelError, RecordId, ResponsePlan,
    ThresholdApprovalProposal,
};

/// Complete immutable envelope presented to the active-response admission seam.
#[derive(Clone, Debug)]
pub struct ActiveResponseAdmissionRequest {
    response_plan: ResponsePlan,
    authorization: ActiveResponseAuthorizationRequest,
    admission_artifact_ref: AdmissionArtifactRef,
    artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    threshold_proposal: Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
}

impl ActiveResponseAdmissionRequest {
    pub fn new(
        response_plan: ResponsePlan,
        authorization: ActiveResponseAuthorizationRequest,
        admission_artifact_ref: AdmissionArtifactRef,
        artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
        threshold_proposal: Option<ThresholdApprovalProposal>,
        approval_tokens: Vec<GovernedApprovalToken>,
    ) -> Result<Self, KernelError> {
        if response_plan.authorization_body() != *authorization.plan_body() {
            return Err(active_response_denied(
                "full response plan does not reproduce the compact authorization body",
            ));
        }
        Ok(Self {
            response_plan,
            authorization,
            admission_artifact_ref,
            artifact_authority_attestation,
            threshold_proposal,
            approval_tokens,
        })
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn authorization(&self) -> &ActiveResponseAuthorizationRequest {
        &self.authorization
    }

    #[must_use]
    pub const fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        &self.admission_artifact_ref
    }

    #[must_use]
    pub const fn artifact_authority_attestation(
        &self,
    ) -> &ActiveResponseArtifactAuthorityAttestation {
        &self.artifact_authority_attestation
    }

    #[must_use]
    pub const fn threshold_proposal(&self) -> Option<&ThresholdApprovalProposal> {
        self.threshold_proposal.as_ref()
    }

    pub(in crate::kernel) const fn threshold_proposal_option(
        &self,
    ) -> &Option<ThresholdApprovalProposal> {
        &self.threshold_proposal
    }

    #[must_use]
    pub fn approval_tokens(&self) -> &[GovernedApprovalToken] {
        &self.approval_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticActiveResponsePermit {
    pub(in crate::kernel) dispatch_id: RecordId,
    pub(in crate::kernel) request_id: String,
    pub(in crate::kernel) plan_body_hash: String,
    pub(in crate::kernel) authorization_capability_hash: String,
    pub(in crate::kernel) governed_intent_hash: String,
    pub(in crate::kernel) policy_decision_hash: String,
    pub(in crate::kernel) executor_authority_id: String,
    pub(in crate::kernel) executor_authority_generation: u64,
    pub(in crate::kernel) authorized_at_unix_ms: u64,
    pub(in crate::kernel) expires_at_unix_ms: u64,
}

impl AutomaticActiveResponsePermit {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn plan_body_hash(&self) -> &str {
        &self.plan_body_hash
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn policy_decision_hash(&self) -> &str {
        &self.policy_decision_hash
    }

    #[must_use]
    pub fn executor_authority_id(&self) -> &str {
        &self.executor_authority_id
    }

    #[must_use]
    pub const fn executor_authority_generation(&self) -> u64 {
        self.executor_authority_generation
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedActiveResponseReservation {
    pub(in crate::kernel) operation: Box<AdmissionOperation>,
    pub(in crate::kernel) approval_set: Box<ApprovalSetReservationInput>,
    pub(in crate::kernel) policy_decision_hash: String,
    pub(in crate::kernel) authorization_capability_hash: String,
    pub(in crate::kernel) governed_intent_hash: String,
    pub(in crate::kernel) executor_authority_id: String,
    pub(in crate::kernel) executor_authority_generation: u64,
    pub(in crate::kernel) authorized_at_unix_ms: u64,
    pub(in crate::kernel) dispatch_operation_version: u64,
    pub(in crate::kernel) dispatch_id: RecordId,
}

impl GovernedActiveResponseReservation {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.operation.operation_id()
    }

    #[must_use]
    pub fn approval_set_hash(&self) -> &str {
        self.approval_set.approval_set_hash()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedActiveResponseAdmission {
    Automatic(AutomaticActiveResponsePermit),
    Governed(GovernedActiveResponseReservation),
}

impl PreparedActiveResponseAdmission {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        match self {
            Self::Automatic(permit) => permit.dispatch_id(),
            Self::Governed(reservation) => reservation.dispatch_id(),
        }
    }
}
