//! The actual finite current writer appends a terminal before minting its affine proof.
use super::*;

pub(in crate::admission_operation_store::product) struct ProductReclamationWriter<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    serving_owner: &'tx SqliteServingOwner,
    actor: &'tx AuthenticatedRecoveryActor,
    reader: &'tx AuthenticatedRecoveryActor,
    profile: &'tx RecoveryDeploymentV1,
    observed_at: u64,
}

impl<'tx, 'conn> ProductReclamationWriter<'tx, 'conn> {
    pub(in crate::admission_operation_store::product) fn new(
        transaction: &'tx Transaction<'conn>,
        serving_owner: &'tx SqliteServingOwner,
        actor: &'tx AuthenticatedRecoveryActor,
        reader: &'tx AuthenticatedRecoveryActor,
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

    fn verify_current_authorization(
        &self,
        proposal: &StoredPolicyMaintenanceProposalV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let tx = self.transaction;
        verify_active_owner(tx, self.serving_owner, Some(&self.serving_owner.fence))?;
        let current = protected::deployment_tx(tx, self.actor.scope())?;
        if protected::encode(&current)? != protected::encode(self.profile)?
            || self.actor.permission() != RecoveryPermission::Maintain
            || proposal.proposal.scope != *self.actor.scope()
        {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        let now = schema::observe_authority_time(tx)?;
        if now < self.observed_at {
            return Err(refused("proposal reclamation clock changed"));
        }
        super::super::super::recovery::verify_actor(tx, self.actor, &current, now)?;
        require_finite_intake_audience(self.actor, &current)?;
        let label = proposals::retained_label(
            tx,
            self.actor,
            self.reader,
            &current,
            &proposal.proposal,
            now,
        )?;
        require_clearance(
            self.actor,
            &current,
            &label.join_restrictions(&proposal.label).map_err(refused)?,
        )
    }
}

pub(in crate::admission_operation_store) struct VerifiedProductEvidenceReclamation<'tx, 'conn> {
    writer: ProductReclamationWriter<'tx, 'conn>,
    source: ProductEvidenceReclamationSource,
    terminal_payload: Vec<u8>,
}

pub(in crate::admission_operation_store::product) fn append_reclamation<'tx, 'conn>(
    writer: ProductReclamationWriter<'tx, 'conn>,
    proposal: &StoredPolicyMaintenanceProposalV1,
) -> Result<VerifiedProductEvidenceReclamation<'tx, 'conn>, AdmissionOperationStoreError> {
    writer.verify_current_authorization(proposal)?;
    let tx = writer.transaction;
    let scope = writer.actor.scope();
    let owner = ProductEvidenceOwner::Proposal {
        scope: scope.clone(),
        id: proposal.proposal.proposal_id.clone(),
        digest: proposal.digest,
    };
    let key = reclamation_key(scope, &proposal.proposal.proposal_id)?;
    if protected::raw_checked(tx, &key)?.is_some() {
        return Err(refused(
            "reclamation writer cannot replace a retained terminal",
        ));
    }
    let (original, references) = product_evidence_source(tx, &owner)?;
    if references.is_empty() || references.len() > 32 {
        return Err(refused(
            "reclamation needs complete declared Proposal evidence",
        ));
    }
    let (archive, archived_at) = lifecycle::archived_proposal_source(tx, proposal)?
        .ok_or_else(|| refused("reclamation requires a genuine Proposal archive"))?;
    let original = immutable_local_source(tx, scope, original.record_key())?;
    let archive = immutable_local_source(tx, scope, archive.record_key())?;
    if writer.observed_at < archived_at {
        return Err(refused("reclamation cannot precede its actual archive"));
    }
    let value = ReclaimedProposalEvidence {
        domain_version: VersionV1,
        scope: scope.clone(),
        proposal_id: proposal.proposal.proposal_id.clone(),
        proposal_digest: proposal.digest,
        original: SourceAnchor::capture(&original),
        archive: SourceAnchor::capture(&archive),
        reclaimer: writer.actor.principal().clone(),
        reclaimer_subject: writer.actor.capability().subject.clone(),
        reclaimed_at_unix_ms: SafeInteger::new(writer.observed_at).map_err(refused)?,
    };
    let terminal_payload = protected::encode(&value)?;
    save(tx, writer.serving_owner, scope, &key, &value)?;
    let source = product_reclamation_source(tx, &owner)?
        .ok_or_else(|| refused("actual reclamation append has no authenticated terminal"))?;
    let proof = VerifiedProductEvidenceReclamation {
        writer,
        source,
        terminal_payload,
    };
    proof.verify_current(tx)?;
    Ok(proof)
}

impl<'tx, 'conn> VerifiedProductEvidenceReclamation<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.writer.transaction
    }
    pub(in crate::admission_operation_store) fn serving_owner(&self) -> &SqliteServingOwner {
        self.writer.serving_owner
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> &ProductEvidenceOwner {
        self.source.owner()
    }
    pub(in crate::admission_operation_store) fn original(
        &self,
    ) -> &protected::ProtectedSourceReference {
        self.source.original()
    }
    pub(in crate::admission_operation_store) fn archive(
        &self,
    ) -> &protected::ProtectedSourceReference {
        self.source.archive()
    }
    pub(in crate::admission_operation_store) fn terminal(
        &self,
    ) -> &protected::ProtectedSourceReference {
        self.source.terminal()
    }
    pub(in crate::admission_operation_store) fn references(&self) -> &[ArtifactVersionRefV1] {
        self.source.references()
    }
    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !core::ptr::eq(tx, self.writer.transaction) {
            return Err(refused("reclamation changed its actual transaction"));
        }
        self.source.verify(tx)?;
        let ProductEvidenceOwner::Proposal { scope, id, .. } = self.owner() else {
            return Err(refused("reclamation cannot consume a Report owner"));
        };
        let proposal = stored_proposal(tx, scope, id)?;
        let terminal = protected::raw_checked(tx, self.terminal().record_key())?
            .ok_or_else(|| refused("reclamation terminal disappeared"))?;
        if terminal.payload != self.terminal_payload {
            return Err(refused("reclamation changed its actual writer terminal"));
        }
        self.writer.verify_current_authorization(&proposal)
    }
}

impl core::fmt::Debug for VerifiedProductEvidenceReclamation<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedProductEvidenceReclamation([redacted])")
    }
}
