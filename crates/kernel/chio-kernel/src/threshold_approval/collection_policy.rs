use crate::admission_operation::AdmissionDigest;
use crate::approval::ApprovalStoreError;

/// Operator-owned collection rules, bound to the kernel's active policy hash.
/// These are composition inputs, never fields accepted from an approval client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalCollectionPolicy {
    policy_hash: AdmissionDigest,
    require_submitter_separation: bool,
}

impl ThresholdApprovalCollectionPolicy {
    pub fn new(
        policy_hash: String,
        require_submitter_separation: bool,
    ) -> Result<Self, ApprovalStoreError> {
        Ok(Self {
            policy_hash: AdmissionDigest::try_new("policy_hash", policy_hash)
                .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?,
            require_submitter_separation,
        })
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        self.policy_hash.as_str()
    }

    #[must_use]
    pub fn require_submitter_separation(&self) -> bool {
        self.require_submitter_separation
    }
}
