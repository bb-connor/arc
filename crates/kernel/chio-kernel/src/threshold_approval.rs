use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_core::crypto::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApproverIdentity {
    pub identifier: String,
    pub public_key: PublicKey,
    pub directory_version: String,
}

pub trait ApproverDirectory: Send + Sync {
    fn resolve_approver(&self, identifier: &str) -> Result<ResolvedApproverIdentity, String>;
}

pub trait ThresholdApprovalRequirementResolver: Send + Sync {
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        server_id: &str,
        tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String>;
}
