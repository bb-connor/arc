//! A fresh native writer binds the complete immutable product source before appending it.
use super::super::knowledge::references::ProductEvidenceOwner;
use super::*;

/// Private, transaction-bound pre-save admission. Descriptions of an owner or
/// individual references cannot reconstruct this proof or narrow its batch.
pub(in crate::admission_operation_store) struct VerifiedProductReferenceIntake<'tx, 'conn> {
    writer: ProductReferenceWriter<'tx, 'conn>,
    candidate: Candidate<'tx>,
    owner: ProductEvidenceOwner,
    source_key: String,
    source_scope_key: String,
    source_payload: Vec<u8>,
    references: Vec<ArtifactVersionRefV1>,
}

/// This local writer context is not an allowance. Only the private intake
/// factory can verify it and bind the complete immutable source.
pub(super) struct ProductReferenceWriter<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    serving_owner: &'tx SqliteServingOwner,
    actor: &'tx AuthenticatedRecoveryActor,
    reader: Option<&'tx AuthenticatedRecoveryActor>,
    profile: &'tx RecoveryDeploymentV1,
    observed_at: u64,
}

impl<'tx, 'conn> ProductReferenceWriter<'tx, 'conn> {
    pub(super) fn new(
        transaction: &'tx Transaction<'conn>,
        serving_owner: &'tx SqliteServingOwner,
        actor: &'tx AuthenticatedRecoveryActor,
        reader: Option<&'tx AuthenticatedRecoveryActor>,
        profile: &'tx RecoveryDeploymentV1,
        observed_at: u64,
    ) -> Self {
        Self {
            transaction,
            serving_owner,
            actor,
            reader,
            profile,
            observed_at,
        }
    }
}

enum Candidate<'a> {
    Report {
        command: CommandId,
        value: &'a StoredDecisionReportV1,
    },
    Proposal(&'a StoredPolicyMaintenanceProposalV1),
}

impl<'tx, 'conn> VerifiedProductReferenceIntake<'tx, 'conn> {
    pub(super) fn report(
        writer: ProductReferenceWriter<'tx, 'conn>,
        command: &CommandId,
        value: &'tx StoredDecisionReportV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let tx = writer.transaction;
        let actor = writer.actor;
        let mut references = Vec::new();
        for reference in value.report.attachments.as_slice() {
            if !references.contains(reference) {
                references.push(reference.clone());
            }
        }
        let proof = Self {
            writer,
            candidate: Candidate::Report {
                command: command.clone(),
                value,
            },
            owner: ProductEvidenceOwner::Report {
                scope: actor.scope().clone(),
                id: value.id.clone(),
                digest: value.digest,
            },
            source_key: reports::key(actor.scope(), &value.id)?,
            source_scope_key: protected::scope_key(actor.scope())?,
            source_payload: protected::encode(value)?,
            references,
        };
        proof.verify(tx)?;
        Ok(proof)
    }

    pub(super) fn proposal(
        writer: ProductReferenceWriter<'tx, 'conn>,
        value: &'tx StoredPolicyMaintenanceProposalV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let tx = writer.transaction;
        let actor = writer.actor;
        let mut references = Vec::new();
        for case in value
            .proposal
            .benign_trajectories
            .as_slice()
            .iter()
            .chain(value.proposal.adversarial_trajectories.as_slice())
        {
            if !references.contains(&case.artifact) {
                references.push(case.artifact.clone());
            }
        }
        let proof = Self {
            writer,
            candidate: Candidate::Proposal(value),
            owner: ProductEvidenceOwner::Proposal {
                scope: actor.scope().clone(),
                id: value.proposal.proposal_id.clone(),
                digest: value.digest,
            },
            source_key: proposal_key(actor.scope(), &value.proposal.proposal_id)?,
            source_scope_key: protected::scope_key(actor.scope())?,
            source_payload: protected::encode(value)?,
            references,
        };
        proof.verify(tx)?;
        Ok(proof)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &Transaction<'conn> {
        self.writer.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        self.writer.actor.scope()
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> &ProductEvidenceOwner {
        &self.owner
    }
    pub(in crate::admission_operation_store) fn source_key(&self) -> &str {
        &self.source_key
    }
    pub(in crate::admission_operation_store) fn source_scope_key(&self) -> &str {
        &self.source_scope_key
    }
    pub(in crate::admission_operation_store) fn source_payload(&self) -> &[u8] {
        &self.source_payload
    }
    pub(in crate::admission_operation_store) fn references(&self) -> &[ArtifactVersionRefV1] {
        &self.references
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !core::ptr::eq(tx, self.writer.transaction)
            || self.source_key.len() > 512
            || self.source_scope_key != protected::scope_key(self.scope())?
            || protected::raw_checked(tx, &self.source_key)?.is_some()
        {
            return Err(refused("product intake source is not a fresh exact writer"));
        }
        self.verify_current_candidate(tx)
    }

    /// A real immutable append advances the reserved intake proof. The bound
    /// source must be this exact staged body under its ordinary framing.
    pub(in crate::admission_operation_store) fn verify_saved_source(
        &self,
        tx: &Transaction<'_>,
        source: &protected::ProtectedSourceReference,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !core::ptr::eq(tx, self.writer.transaction)
            || source.record_key() != self.source_key
            || source.scope_key() != self.source_scope_key
            || source.kind() != "command"
            || source.version() != 1
        {
            return Err(refused(
                "product saved source changed its reserved identity",
            ));
        }
        protected::verify_source_reference(tx, source)?;
        let stored = protected::raw_checked(tx, &self.source_key)?
            .ok_or_else(|| refused("product reserved source is absent"))?;
        let ordinary: bool = tx
            .query_row(
                "SELECT native_namespace IS NULL AND native_request IS NULL
                 FROM admission_operation_recovery_records WHERE record_key=?1",
                [&self.source_key],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !ordinary || stored.payload != self.source_payload {
            return Err(refused(
                "product saved source changed its reserved complete body",
            ));
        }
        self.verify_current_candidate(tx)
    }

    fn verify_current_candidate(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        verify_active_owner(
            tx,
            self.writer.serving_owner,
            Some(&self.writer.serving_owner.fence),
        )?;
        let current = protected::deployment_tx(tx, self.scope())?;
        if protected::encode(&current)? != protected::encode(self.writer.profile)? {
            return Err(refused("product intake native deployment changed"));
        }
        let now = schema::observe_authority_time(tx)?;
        super::super::recovery::verify_actor(tx, self.writer.actor, &current, now)?;
        require_finite_intake_audience(self.writer.actor, &current)?;
        match &self.candidate {
            Candidate::Report { command, value } => {
                value.report.validate().map_err(refused)?;
                let expected_id = EvidenceRef::new(&format!(
                    "report:{}",
                    sha256_hex(&protected::encode(&(
                        self.scope(),
                        self.writer.actor.principal(),
                        command
                    ))?),
                ))
                .map_err(refused)?;
                let digest = CommandDigest::from_bytes(hash(
                    RecoveryDigestDomain::DecisionReport,
                    &value.report,
                )?);
                if self.writer.actor.permission() != RecoveryPermission::Report
                    || value.report.scope != *self.scope()
                    || value.id != expected_id
                    || value.digest != digest
                    || value.reporter != *self.writer.actor.principal()
                    || value.reporter_subject != self.writer.actor.capability().subject
                    || value.submitted_at_unix_ms.get() != self.writer.observed_at
                    || value.influence.commitment
                        != CanonicalPayloadDigest::from_bytes(*digest.as_bytes())
                    || !value.influence.externally_influenced
                    || !value.influence.unknown
                    || self.owner
                        != (ProductEvidenceOwner::Report {
                            scope: self.scope().clone(),
                            id: value.id.clone(),
                            digest,
                        })
                    || self.source_key != reports::key(self.scope(), &value.id)?
                    || self.source_payload != protected::encode(value)?
                    || self.references.len() > 8
                {
                    return Err(refused("product report intake binding"));
                }
                let mut declared = Vec::new();
                for reference in value.report.attachments.as_slice() {
                    if !declared.contains(reference) {
                        declared.push(reference.clone());
                    }
                }
                if declared != self.references {
                    return Err(refused("product report evidence set changed"));
                }
                let current_label = reports::label(
                    tx,
                    self.writer.actor,
                    self.writer.reader,
                    &current,
                    &value.report,
                    now,
                )?;
                if current_label != value.label
                    || protected::workflow_tx(tx, self.scope(), &value.report.workflow_id)?.revision
                        != value.report.expected_revision
                {
                    return Err(refused("product report intake basis changed"));
                }
            }
            Candidate::Proposal(value) => {
                value.proposal.validate().map_err(refused)?;
                let digest = CanonicalPayloadDigest::from_bytes(hash(
                    RecoveryDigestDomain::PolicyMaintenanceProposal,
                    &value.proposal,
                )?);
                if self.writer.actor.permission() != RecoveryPermission::Maintain
                    || value.proposal.scope != *self.scope()
                    || value.digest != digest
                    || value.maintainer != *self.writer.actor.principal()
                    || value.maintainer_subject != self.writer.actor.capability().subject
                    || value.submitted_at_unix_ms.get() != self.writer.observed_at
                    || value.influence.commitment != digest
                    || !value.influence.externally_influenced
                    || !value.influence.unknown
                    || self.owner
                        != (ProductEvidenceOwner::Proposal {
                            scope: self.scope().clone(),
                            id: value.proposal.proposal_id.clone(),
                            digest,
                        })
                    || self.source_key != proposal_key(self.scope(), &value.proposal.proposal_id)?
                    || self.source_payload != protected::encode(value)?
                    || self.references.len() > 32
                {
                    return Err(refused("product proposal intake binding"));
                }
                let mut declared = Vec::new();
                for case in value
                    .proposal
                    .benign_trajectories
                    .as_slice()
                    .iter()
                    .chain(value.proposal.adversarial_trajectories.as_slice())
                {
                    if !declared.contains(&case.artifact) {
                        declared.push(case.artifact.clone());
                    }
                }
                if declared != self.references {
                    return Err(refused("product proposal evidence set changed"));
                }
                let reader = self
                    .writer
                    .reader
                    .ok_or_else(|| refused("proposal intake lacks current reader"))?;
                if proposals::label(
                    tx,
                    self.writer.actor,
                    reader,
                    &current,
                    &value.proposal,
                    now,
                )? != value.label
                {
                    return Err(refused("product proposal intake audience changed"));
                }
                let policy =
                    super::super::semantic::installation(tx, self.scope())?.policy_basis()?;
                if policy.policy != value.proposal.base_policy
                    || policy.deployment != value.proposal.base_deployment
                {
                    return Err(refused("product proposal intake policy changed"));
                }
            }
        }
        for reference in &self.references {
            if reference.scope.authority_domain != self.scope().authority_domain
                || reference.scope.tenant_id != self.scope().tenant_id
            {
                return Err(refused("product intake foreign reference"));
            }
            super::super::knowledge::verify_product_reference_available(tx, reference)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for VerifiedProductReferenceIntake<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedProductReferenceIntake([redacted])")
    }
}
