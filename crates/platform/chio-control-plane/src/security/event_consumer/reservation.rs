use super::{
    build_response_plan, canonical_json_bytes, sha256, validate_authoritative_finding_binding,
    AttestedFindingResponseOutboxRecord, AttestedFindingResponsePlanBody, ResponsePlanInput,
    ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION, MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN,
};
use super::{
    AdmissionArtifactRef, AttestedFindingAdmissionArtifacts, AttestedFindingBatchBinding,
    AttestedFindingResponsePolicySelection, AuthoritativeCorrelatedFindingEvidence, Digest32,
    PortError, PortResult, PublicKey, RecordId, ResponsePlan,
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

/// Trusted response plan assembled from one durable reserved identity and one
/// policy selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedAttestedFindingResponsePlan {
    finding: AuthoritativeCorrelatedFindingEvidence,
    batch_id: RecordId,
    ordinal: u32,
    binding: AttestedFindingBatchBinding,
    response_plan: ResponsePlan,
    admission_artifact_ref: AdmissionArtifactRef,
    admission_artifact_digest: Option<Digest32>,
}

pub(super) fn build_reserved_response_plan(
    finding: &AuthoritativeCorrelatedFindingEvidence,
    batch_id: &RecordId,
    ordinal: u32,
    binding: &AttestedFindingBatchBinding,
    policy: &dyn AttestedFindingResponsePolicyPlanner,
) -> PortResult<ReservedAttestedFindingResponsePlan> {
    validate_authoritative_finding_binding(finding, binding)?;
    let receipt = finding.body();
    let AttestedFindingResponsePolicySelection {
        execution,
        affected_ids,
        effects,
        ttl_ms,
        created_at_unix_ms,
        operator_capability,
        approval_requirement,
        submitter,
        reason_hash,
        admission_artifact_ref,
    } = policy.select_response_policy(finding, binding)?;
    let response_plan = build_response_plan(ResponsePlanInput {
        execution,
        action_id: binding.action_id.clone(),
        trigger_finding_id: receipt.finding_id.clone(),
        trigger_finding_hash: receipt.finding_hash,
        trigger_finding_receipt_id: binding.evidence_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        policy_version: receipt.policy.policy_version.clone(),
        policy_hash: receipt.policy.policy_hash,
        affected_ids,
        effects,
        ttl_ms,
        created_at_unix_ms,
        operator_capability,
        approval_requirement,
        submitter,
        reason_hash,
    })
    .map_err(|_| PortError::invalid_data())?;
    if response_plan.action_id != binding.action_id
        || response_plan.trigger_finding_receipt_id != binding.evidence_id
        || response_plan.trigger_finding_id != binding.finding_id
        || response_plan.trigger_finding_hash != binding.finding_hash
        || response_plan.tenant_id != binding.tenant_id
    {
        return Err(PortError::integrity_failure());
    }
    Ok(ReservedAttestedFindingResponsePlan {
        finding: finding.clone(),
        batch_id: batch_id.clone(),
        ordinal,
        binding: binding.clone(),
        response_plan,
        admission_artifact_ref,
        admission_artifact_digest: None,
    })
}

impl ReservedAttestedFindingResponsePlan {
    pub(super) fn reconstruct(
        finding: AuthoritativeCorrelatedFindingEvidence,
        record: &AttestedFindingResponseOutboxRecord,
    ) -> PortResult<Self> {
        let publication = record
            .publication
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        let canonical =
            canonical_json_bytes(&publication.body).map_err(|_| PortError::invalid_data())?;
        if publication.body.batch_id != record.batch_id
            || publication.body.ordinal != record.ordinal
            || publication.body.binding != record.binding
            || canonical.as_slice() != publication.canonical_body.as_bytes()
            || Digest32::new(*sha256(&canonical).as_bytes()) != publication.body_hash
        {
            return Err(PortError::integrity_failure());
        }
        Self::from_publication(finding, &publication.body, record.admission_artifact_digest)
    }

    fn from_publication(
        finding: AuthoritativeCorrelatedFindingEvidence,
        body: &AttestedFindingResponsePlanBody,
        admission_artifact_digest: Option<Digest32>,
    ) -> PortResult<Self> {
        validate_authoritative_finding_binding(&finding, &body.binding)?;
        let plan = &body.response_plan;
        if body.schema_version != ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION
            || body.ordinal >= MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN
            || plan.action_id != body.binding.action_id
            || plan.trigger_finding_receipt_id != body.binding.evidence_id
            || plan.trigger_finding_id != body.binding.finding_id
            || plan.trigger_finding_hash != body.binding.finding_hash
            || plan.tenant_id != body.binding.tenant_id
        {
            return Err(PortError::integrity_failure());
        }
        plan.validate_shape()
            .map_err(|_| PortError::integrity_failure())?;
        Ok(Self {
            finding,
            batch_id: body.batch_id.clone(),
            ordinal: body.ordinal,
            binding: body.binding.clone(),
            response_plan: plan.clone(),
            admission_artifact_ref: body.admission_artifact_ref.clone(),
            admission_artifact_digest,
        })
    }

    pub(super) fn bind_admission_artifacts(
        mut self,
        artifacts: &AttestedFindingAdmissionArtifacts,
        authority: &PublicKey,
        now_unix_ms: u64,
    ) -> PortResult<(Self, Digest32)> {
        let digest = artifacts.verify_authority_attestation(
            self.admission_artifact_ref(),
            self.response_plan(),
            authority,
            now_unix_ms,
        )?;
        if self
            .admission_artifact_digest
            .is_some_and(|expected| expected != digest)
        {
            return Err(PortError::integrity_failure());
        }
        self.admission_artifact_digest = Some(digest);
        Ok((self, digest))
    }

    #[cfg(test)]
    pub(super) fn test_from_publication(
        finding: AuthoritativeCorrelatedFindingEvidence,
        body: &AttestedFindingResponsePlanBody,
        digest: Option<Digest32>,
    ) -> PortResult<Self> {
        Self::from_publication(finding, body, digest)
    }
}
