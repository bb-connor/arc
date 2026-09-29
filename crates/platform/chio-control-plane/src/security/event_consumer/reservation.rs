use super::{
    AdmissionArtifactRef, AttestedFindingAdmissionArtifacts, AttestedFindingBatchBinding,
    AttestedFindingResponsePolicySelection, AuthoritativeCorrelatedFindingEvidence, Digest32,
    PortError, PortResult, PublicKey, RecordId, ReservedAttestedFindingResponsePlan, ResponsePlan,
};

impl ReservedAttestedFindingResponsePlan {
    #[must_use]
    pub const fn batch_id(&self) -> &RecordId {
        &self.batch_id
    }

    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub const fn finding(&self) -> &AuthoritativeCorrelatedFindingEvidence {
        &self.finding
    }

    #[must_use]
    pub const fn binding(&self) -> &AttestedFindingBatchBinding {
        &self.binding
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn reservation_id(&self) -> &RecordId {
        &self.binding.reservation_id
    }

    #[must_use]
    pub const fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        &self.admission_artifact_ref
    }

    #[must_use]
    pub const fn admission_artifact_digest(&self) -> Option<&Digest32> {
        self.admission_artifact_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedAttestedFindingResponseBatch {
    batch_id: RecordId,
    plans: Vec<ReservedAttestedFindingResponsePlan>,
}

impl ReservedAttestedFindingResponseBatch {
    #[must_use]
    pub const fn batch_id(&self) -> &RecordId {
        &self.batch_id
    }

    #[must_use]
    pub fn plans(&self) -> &[ReservedAttestedFindingResponsePlan] {
        self.plans.as_slice()
    }
}

/// Downstream response policy and authorization-artifact boundary.
///
/// The policy selects effects, TTL, approval, affected set, and operator
/// authority without authoring action or dispatch identities. It may retrieve
/// signed authorization artifacts for the complete trusted plan, but only the
/// private production coordinator can turn those artifacts into execution.
pub trait AttestedFindingResponsePolicyPlanner: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;

    fn trusted_artifact_authority(&self) -> PortResult<PublicKey> {
        Err(PortError::integrity_failure())
    }

    fn select_response_policy(
        &self,
        _finding: &AuthoritativeCorrelatedFindingEvidence,
        _binding: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponsePolicySelection> {
        Err(PortError::integrity_failure())
    }

    fn load_admission_artifacts(
        &self,
        _plan: &ReservedAttestedFindingResponsePlan,
        _artifact_ref: &AdmissionArtifactRef,
    ) -> PortResult<AttestedFindingAdmissionArtifacts> {
        Err(PortError::integrity_failure())
    }
}
