//! Bounded product evidence. Decoding reports or signatures grants no live power.
use super::*;
use crate::knowledge::ArtifactVersionRefV1;
use serde::{Deserialize, Serialize};

/// Audience-checked report projection. It is evidence, not a grant.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReportViewV1 {
    pub domain_version: VersionV1,
    pub id: EvidenceRef,
    pub digest: CommandDigest,
    pub report: DecisionReportV1,
    pub label: crate::flow::InformationLabel,
    pub influence: crate::knowledge::ArtifactInfluenceV1,
}
impl DecisionReportViewV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.report.validate()
    }
}
/// Audience-checked maintenance proposal projection, without deployment power.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMaintenanceViewV1 {
    pub domain_version: VersionV1,
    pub digest: CanonicalPayloadDigest,
    pub proposal: PolicyMaintenanceProposalV1,
    pub label: crate::flow::InformationLabel,
    pub influence: crate::knowledge::ArtifactInfluenceV1,
}
impl PolicyMaintenanceViewV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.proposal.validate()
    }
}

/// Reporter input is classified by the native owner, never by this DTO.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReportV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub expected_revision: SafeInteger,
    pub decision: RecoveryReportedDecision,
    pub reporter_text: ProtectedText<4096>,
    pub desired_outcome: ProtectedText<1024>,
    pub attachments: BoundedList<ArtifactVersionRefV1, 8>,
}
impl DecisionReportV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_text(&self.reporter_text)?;
        require_text(&self.desired_outcome)?;
        if self.expected_revision.get() == 0 {
            return Err(ContractError::InvalidState);
        }
        for (index, artifact) in self.attachments.as_slice().iter().enumerate() {
            require_artifact_scope(&self.scope, artifact)?;
            if self.attachments.as_slice()[..index].contains(artifact) {
                return Err(ContractError::DuplicateIdentity);
            }
        }
        Ok(())
    }
}

/// A case within an immutable, classified trajectory artifact.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrajectoryRefV1 {
    pub artifact: ArtifactVersionRefV1,
    pub case_id: EvidenceRef,
}

/// Maintenance evidence is untrusted input to the independent operator review.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMaintenanceProposalV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub proposal_id: ReviewId,
    pub report_id: EvidenceRef,
    pub base_deployment: DeploymentDigest,
    pub base_policy: PolicyDigest,
    pub target_policy: PolicyDigest,
    pub rationale: ProtectedText<4096>,
    /// Installed semantic contract-package identities affected by the review.
    pub affected_contracts: NonEmptyBoundedList<SemanticPackageDigest, 16>,
    pub benign_trajectories: NonEmptyBoundedList<PolicyTrajectoryRefV1, 16>,
    pub adversarial_trajectories: NonEmptyBoundedList<PolicyTrajectoryRefV1, 16>,
    pub expected_effects: ProtectedText<4096>,
    pub rollback_policy: PolicyDigest,
    pub rollback_plan: ProtectedText<4096>,
}
impl PolicyMaintenanceProposalV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        for text in [&self.rationale, &self.expected_effects, &self.rollback_plan] {
            require_text(text)?;
        }
        if self.base_policy == self.target_policy {
            return Err(ContractError::BindingMismatch);
        }
        require_unique(self.affected_contracts.as_slice())?;
        for cases in [&self.benign_trajectories, &self.adversarial_trajectories] {
            require_unique(cases.as_slice())?;
            for case in cases.as_slice() {
                require_artifact_scope(&self.scope, &case.artifact)?;
            }
        }
        if self
            .benign_trajectories
            .as_slice()
            .iter()
            .any(|case| self.adversarial_trajectories.as_slice().contains(case))
        {
            return Err(ContractError::DuplicateIdentity);
        }
        Ok(())
    }
}

/// Whole exact operator selection. Native state selects the operator root.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentChangeV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub proposal_id: ReviewId,
    pub proposal_digest: CanonicalPayloadDigest,
    pub base_deployment: DeploymentDigest,
    pub base_policy: PolicyDigest,
    pub target_deployment: DeploymentDigest,
    pub target_policy: PolicyDigest,
    pub base_generation: PolicyGeneration,
    pub target_generation: PolicyGeneration,
    /// Commitment to the entire owning store UUID, lease ID and owner epoch.
    pub writer_fence: SourceDigest,
}
impl PolicyDeploymentChangeV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.base_policy == self.target_policy
            || self.base_deployment == self.target_deployment
            || self.base_generation >= self.target_generation
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

/// Operator-pinned model-free probe. A signature alone does not establish setup.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySetupProbeV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub probe_id: ChallengeId,
    pub native_authority: SourceDigest,
    pub deployment: DeploymentDigest,
    pub source_profile: SourceDigest,
    pub required_coverage: CoverageDigest,
    pub benign_workflow: WorkflowId,
    pub denied_command: CommandId,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
}
impl RecoverySetupProbeV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms.get() - self.issued_at_unix_ms.get() > 900_000
        {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}

/// Retained native evidence from benign, denied and fresh-writer restart cases.
/// The native owner bounds first acceptance by the probe deadline. Re-attesting
/// an already accepted self-test may use a later writer after that deadline.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySetupReportV1 {
    pub domain_version: VersionV1,
    pub probe: RecoverySetupProbeV1,
    pub benign_operation: OperationId,
    pub benign_receipt: SourceDigest,
    pub denied_command_digest: CommandDigest,
    pub previous_serving_fence: SourceDigest,
    pub current_serving_fence: SourceDigest,
    pub qualified_at_unix_ms: SafeInteger,
}
impl RecoverySetupReportV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.probe.validate()?;
        if self.previous_serving_fence == self.current_serving_fence
            || self.qualified_at_unix_ms < self.probe.issued_at_unix_ms
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

fn require_text<const N: usize>(value: &ProtectedText<N>) -> Result<(), ContractError> {
    if value.as_str().trim().is_empty() {
        return Err(ContractError::InvalidState);
    }
    Ok(())
}
fn require_unique<T: PartialEq>(values: &[T]) -> Result<(), ContractError> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ContractError::DuplicateIdentity);
        }
    }
    Ok(())
}
fn require_artifact_scope(
    scope: &RecoveryScopeV1,
    artifact: &ArtifactVersionRefV1,
) -> Result<(), ContractError> {
    if artifact.scope.tenant_id != scope.tenant_id
        || artifact.scope.authority_domain != scope.authority_domain
    {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}
macro_rules! protected_debug {
    ($($name:ident),+ $(,)?) => { $(
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    )+ };
}
protected_debug!(
    DecisionReportViewV1,
    PolicyMaintenanceViewV1,
    DecisionReportV1,
    PolicyTrajectoryRefV1,
    PolicyMaintenanceProposalV1,
    PolicyDeploymentChangeV1,
    RecoverySetupProbeV1,
    RecoverySetupReportV1,
);

#[cfg(test)]
mod setup_report_tests;
