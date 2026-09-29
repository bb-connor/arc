//! Read-only authorization for signed response simulations. This path cannot
//! produce an admission reservation or a live execution permit.

use chio_core::capability::governance::GovernedApprovalToken;
use chio_security_types::ports::AdmissionArtifactRef;
use chio_security_types::{ResponseApprovalRequirement, ResponseExecutionMode, ResponsePlan};

use super::active_response_coordinator::validate_executable_response_plan_value;
use super::{
    ActiveResponseAdmissionRequest, ActiveResponseArtifactAuthorityAttestation,
    ActiveResponseAuthorizationRequest, ChioKernel, KernelError, VerifiedActiveResponseBindings,
};
use crate::threshold_approval::ThresholdApprovalProposal;

pub(super) trait ActiveResponseApprovalInputs {
    fn response_plan(&self) -> &ResponsePlan;
    fn authorization(&self) -> &ActiveResponseAuthorizationRequest;
    fn admission_artifact_ref(&self) -> &AdmissionArtifactRef;
    fn artifact_authority_attestation(&self) -> &ActiveResponseArtifactAuthorityAttestation;
    fn threshold_proposal_option(&self) -> &Option<ThresholdApprovalProposal>;
    fn approval_tokens(&self) -> &[GovernedApprovalToken];
    fn threshold_proposal(&self) -> Option<&ThresholdApprovalProposal> {
        self.threshold_proposal_option().as_ref()
    }
}

impl ActiveResponseApprovalInputs for ActiveResponseAdmissionRequest {
    fn response_plan(&self) -> &ResponsePlan {
        self.response_plan()
    }
    fn authorization(&self) -> &ActiveResponseAuthorizationRequest {
        self.authorization()
    }
    fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        self.admission_artifact_ref()
    }
    fn artifact_authority_attestation(&self) -> &ActiveResponseArtifactAuthorityAttestation {
        self.artifact_authority_attestation()
    }
    fn threshold_proposal_option(&self) -> &Option<ThresholdApprovalProposal> {
        self.threshold_proposal_option()
    }
    fn approval_tokens(&self) -> &[GovernedApprovalToken] {
        self.approval_tokens()
    }
}

#[derive(Clone, Debug)]
pub struct ActiveResponseSimulationRequest {
    response_plan: ResponsePlan,
    authorization: ActiveResponseAuthorizationRequest,
    admission_artifact_ref: AdmissionArtifactRef,
    artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    threshold_proposal: Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
}

impl ActiveResponseSimulationRequest {
    pub fn new(
        response_plan: ResponsePlan,
        authorization: ActiveResponseAuthorizationRequest,
        admission_artifact_ref: AdmissionArtifactRef,
        artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
        threshold_proposal: Option<ThresholdApprovalProposal>,
        approval_tokens: Vec<GovernedApprovalToken>,
    ) -> Result<Self, KernelError> {
        if response_plan.execution.mode() != ResponseExecutionMode::DryRun
            || response_plan.authorization_body() != *authorization.plan_body()
        {
            return Err(denied("simulation requires an exactly bound dry-run plan"));
        }
        validate_executable_response_plan_value(&response_plan)?;
        Ok(Self {
            response_plan,
            authorization,
            admission_artifact_ref,
            artifact_authority_attestation,
            threshold_proposal,
            approval_tokens,
        })
    }

    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }
}

impl ActiveResponseApprovalInputs for ActiveResponseSimulationRequest {
    fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }
    fn authorization(&self) -> &ActiveResponseAuthorizationRequest {
        &self.authorization
    }
    fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        &self.admission_artifact_ref
    }
    fn artifact_authority_attestation(&self) -> &ActiveResponseArtifactAuthorityAttestation {
        &self.artifact_authority_attestation
    }
    fn threshold_proposal_option(&self) -> &Option<ThresholdApprovalProposal> {
        &self.threshold_proposal
    }
    fn approval_tokens(&self) -> &[GovernedApprovalToken] {
        &self.approval_tokens
    }
}

/// Kernel-derived facts for a report, deliberately not serializable or usable
/// at any live admission or dispatch seam.
#[derive(Clone, Debug)]
pub struct VerifiedResponseSimulationAuthorization {
    bindings: VerifiedActiveResponseBindings,
    policy_decision_hash: String,
    approval_set_hash: Option<String>,
    authorized_at_unix_ms: u64,
}

impl VerifiedResponseSimulationAuthorization {
    pub const fn bindings(&self) -> &VerifiedActiveResponseBindings {
        &self.bindings
    }
    pub fn policy_decision_hash(&self) -> &str {
        &self.policy_decision_hash
    }
    pub fn approval_set_hash(&self) -> Option<&str> {
        self.approval_set_hash.as_deref()
    }
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.authorized_at_unix_ms
    }
}

impl ChioKernel {
    pub fn verify_active_response_simulation(
        &self,
        request: &ActiveResponseSimulationRequest,
    ) -> Result<VerifiedResponseSimulationAuthorization, KernelError> {
        let now = self.read_authority_time()?.get();
        let bindings = self.verify_active_response_authorization_at(&request.authorization, now)?;
        self.verify_active_response_artifact_authority_attestation(request, &bindings, now)?;
        let requirement = self.resolve_active_response_requirement(&bindings)?;
        let approval_set_hash = match requirement.approval_requirement() {
            ResponseApprovalRequirement::Automatic => {
                if request.threshold_proposal.is_some() || !request.approval_tokens.is_empty() {
                    return Err(denied(
                        "automatic simulation cannot carry threshold approvals",
                    ));
                }
                None
            }
            ResponseApprovalRequirement::Governed { .. } => {
                let approvals = self.verify_active_response_threshold(
                    request,
                    &bindings,
                    &requirement,
                    now / 1_000,
                )?;
                Some(
                    approvals
                        .approval_set_hash()
                        .map_err(|error| denied(&error.to_string()))?,
                )
            }
        };
        Ok(VerifiedResponseSimulationAuthorization {
            bindings,
            policy_decision_hash: requirement.policy_decision_hash().to_owned(),
            approval_set_hash,
            authorized_at_unix_ms: now,
        })
    }
}

fn denied(reason: &str) -> KernelError {
    KernelError::GovernedTransactionDenied(format!("active-response simulation denied: {reason}"))
}
