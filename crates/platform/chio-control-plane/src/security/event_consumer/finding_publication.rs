use super::{
    canonical_json_bytes, derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, sha256, validate_attested_finding_batch_body,
    AttestedFindingBatchBinding, AttestedFindingBatchBindings, AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication, AttestedFindingResponsePlanBody,
    AttestedFindingResponsePlanPublication, AuthoritativeCorrelatedFindingEvidence, CanonicalBody,
    Digest32, PortError, PortResult, ReservedAttestedFindingResponsePlan,
    ATTESTED_FINDING_BATCH_SCHEMA_VERSION, ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
};

pub trait AttestedFindingBatchPlanner: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;

    fn ensure_bootstrap_ready(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    /// Atomically publishes one complete set of authoritative findings.
    ///
    /// Implementations must treat the ordered evidence-id set as the
    /// idempotency key and publish all reserved action and dispatch identities
    /// or none. Raw correlation output is intentionally absent from this
    /// interface.
    fn publish_attested_batch(
        &self,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
    ) -> PortResult<()>;

    /// Read back the exact durable batch published under its tenant-scoped key.
    /// Implementations that cannot prove durable publication must fail closed
    /// rather than acknowledge and drop findings.
    fn load_published_attested_batch(
        &self,
        _key: &AttestedFindingBatchKey,
    ) -> PortResult<AttestedFindingBatchPublication> {
        Err(PortError::integrity_failure())
    }
}

pub(super) fn build_attested_finding_batch_publication(
    findings: &[AuthoritativeCorrelatedFindingEvidence],
) -> PortResult<AttestedFindingBatchPublication> {
    let ordered_evidence_ids = findings
        .iter()
        .map(|finding| finding.evidence_id().clone())
        .collect::<Vec<_>>();
    let batch_id = derive_attested_finding_batch_id(&ordered_evidence_ids)?;
    let tenant_id = findings
        .first()
        .map(|finding| finding.body().header.tenant_id.clone())
        .ok_or_else(PortError::invalid_data)?;
    let mut bindings = Vec::with_capacity(findings.len());
    for (ordinal, finding) in findings.iter().enumerate() {
        let evidence_id = finding.evidence_id().clone();
        let receipt = finding.body();
        let action_id = derive_attested_finding_action_id(
            &batch_id,
            ordinal,
            &receipt.header.tenant_id,
            &evidence_id,
            &receipt.finding_id,
            &receipt.finding_hash,
        )?;
        let reservation_id =
            derive_attested_finding_reservation_id(&batch_id, &action_id, &evidence_id)?;
        bindings.push(AttestedFindingBatchBinding {
            tenant_id: receipt.header.tenant_id.clone(),
            evidence_id,
            finding_id: receipt.finding_id.clone(),
            finding_hash: receipt.finding_hash,
            action_id,
            reservation_id,
        });
    }
    let body = AttestedFindingBatchBody {
        schema_version: ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
        batch_id,
        tenant_id,
        bindings: AttestedFindingBatchBindings::new(bindings)
            .map_err(|_| PortError::invalid_data())?,
    };
    validate_attested_finding_batch_body(&body)?;
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    Ok(AttestedFindingBatchPublication {
        body,
        canonical_body: CanonicalBody::new(canonical).map_err(|_| PortError::invalid_data())?,
        body_hash,
    })
}

pub(super) fn validate_authoritative_finding_binding(
    finding: &AuthoritativeCorrelatedFindingEvidence,
    binding: &AttestedFindingBatchBinding,
) -> PortResult<()> {
    let receipt = finding.body();
    if binding.evidence_id != *finding.evidence_id()
        || binding.tenant_id != receipt.header.tenant_id
        || binding.finding_id != receipt.finding_id
        || binding.finding_hash != receipt.finding_hash
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn build_attested_finding_response_plan_publication(
    plan: &ReservedAttestedFindingResponsePlan,
) -> PortResult<AttestedFindingResponsePlanPublication> {
    let body = AttestedFindingResponsePlanBody {
        schema_version: ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
        batch_id: plan.batch_id().clone(),
        ordinal: plan.ordinal(),
        binding: plan.binding().clone(),
        response_plan: plan.response_plan().clone(),
        admission_artifact_ref: plan.admission_artifact_ref().clone(),
    };
    let canonical = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
    Ok(AttestedFindingResponsePlanPublication {
        body,
        body_hash: Digest32::new(*sha256(&canonical).as_bytes()),
        canonical_body: CanonicalBody::new(canonical).map_err(|_| PortError::invalid_data())?,
    })
}
