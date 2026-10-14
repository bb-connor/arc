//! One admitted Product source consumes one complete logical reference plan.
use super::super::product::evidence_reclamation::VerifiedProductEvidenceReclamation;
use super::reference_custody::VerifiedKnowledgeReferenceRetain;
use super::reference_retirement::VerifiedKnowledgeReferenceRetirement;
use super::references::{prepare_reference_retain, ProductEvidenceOwner};
use super::*;

/// New evidence custody cannot begin after irreversible collection admission.
/// Historical census uses its own authenticated retained-source adapter.
pub(in crate::admission_operation_store) fn verify_product_reference_available(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<(), AdmissionOperationStoreError> {
    let record = selected_product_artifact(tx, reference)?;
    record.metadata.validate().map_err(refused)?;
    let scope = scope_key(&reference.scope)?;
    let publication_key = record_publication_key(&record)?;
    let pointer_key = version_key(reference)?;
    let publication = protected::source_reference(tx, &publication_key)?;
    let pointer = protected::source_reference(tx, &pointer_key)?;
    if publication.kind() != "command"
        || publication.scope_key() != scope
        || pointer.kind() != "command"
        || pointer.scope_key() != scope
        || pointer.version() != 1
    {
        return Err(refused("product artifact changed protected source"));
    }
    let seal = record
        .seal
        .as_ref()
        .ok_or_else(|| refused("product artifact has no retained byte seal"))?;
    if seal.object != record.object
        || seal.process != record.metadata.scope.process_id
        || seal.content != record.metadata.content
        || seal.bytes != record.metadata.size_bytes
    {
        return Err(refused("product artifact changed retained byte identity"));
    }
    let key = if seal
        .generation
        .as_str()
        .strip_prefix("object:")
        .is_some_and(|identity| uuid::Uuid::parse_str(identity).is_ok())
    {
        format!(
            "knowledge-object-sweep:{}",
            hex::encode(
                knowledge_digest(
                    RecoveryDigestDomain::KnowledgeObjectCustody,
                    &(&record.metadata.scope, seal),
                )
                .map_err(refused)?,
            )
        )
    } else {
        format!(
            "knowledge-sweep:{}",
            sha256_hex(&protected::encode(&(
                &record.metadata.scope.authority_domain,
                &record.metadata.scope.tenant_id,
                &record.metadata.scope.process_id,
                &seal.runtime,
                seal.content,
            ))?),
        )
    };
    if protected::raw_checked(tx, &key)?.is_some() {
        protected::source_reference(tx, &key)?;
        // Either owning sweep state is already irreversible. Its existence is
        // a refusal barrier, never a decoded permission to acquire new pins.
        return Err(refused("product artifact collection is already admitted"));
    }
    Ok(())
}

/// Called after the real immutable report or proposal append in the same
/// fenced writer. The private reservation was admitted before that append.
/// This logical slice supplies no global physical finishing guarantee.
pub(in crate::admission_operation_store) fn retain_product_evidence<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    source_owner: ProductEvidenceOwner,
    reserved: protected::ReservedProductReferenceIntake<'tx, 'conn>,
) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
    let source = VerifiedKnowledgeReferenceRetain::product(tx, source_owner)?;
    let plan = prepare_reference_retain(tx, source)?;
    let allowance = protected::bind_product_reference_source(tx, reserved, plan.owner_source())?;
    protected::persist_knowledge_reference_progress(tx, owner, plan, allowance)
}

/// Only the Product writer's current affine terminal proof can retire its
/// complete Proposal evidence owner set. Archive alone has no such role.
/// Logical retirement changes no publication or physical byte allocation.
pub(in crate::admission_operation_store) fn retire_product_evidence<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedProductEvidenceReclamation<'tx, 'conn>,
) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
    if !std::ptr::eq(owner, proof.serving_owner()) {
        return Err(refused(
            "Product retirement changed its actual serving owner",
        ));
    }
    let source = VerifiedKnowledgeReferenceRetirement::product_proposal(tx, proof)?;
    protected::persist_product_reference_retirement(tx, owner, source)
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Observe exact retired custody using two genuine retained Proposal
    /// terminals. The scoped selectors are data only and cannot mutate a leaf.
    pub fn inspect_retired_proposal_terminal_custody(
        &self,
        scope: &RecoveryScopeV1,
        proposal_id: &ReviewId,
        terminal_proposal_id: &ReviewId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        use super::super::product::{evidence_reclamation, stored_proposal};
        use super::references::{ReferenceOwner, SourceAnchor};

        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        if scope.authority_domain.as_str() != fence.store_uuid {
            return Err(refused("retired Proposal observer changed authority"));
        }
        let proposal = stored_proposal(&tx, scope, proposal_id)?;
        let terminal_proposal = stored_proposal(&tx, scope, terminal_proposal_id)?;
        let owner = ProductEvidenceOwner::Proposal {
            scope: scope.clone(),
            id: proposal_id.clone(),
            digest: proposal.digest,
        };
        let terminal_owner = ProductEvidenceOwner::Proposal {
            scope: scope.clone(),
            id: terminal_proposal_id.clone(),
            digest: terminal_proposal.digest,
        };
        let original = evidence_reclamation::product_reclamation_source(&tx, &owner)?
            .ok_or_else(|| refused("retired Proposal observer lost its source tuple"))?;
        let terminal = evidence_reclamation::product_reclamation_source(&tx, &terminal_owner)?
            .ok_or_else(|| refused("retired Proposal observer lost its terminal tuple"))?;
        original.verify(&tx)?;
        terminal.verify(&tx)?;
        let owner = ReferenceOwner::from(owner);
        let original_anchor = SourceAnchor::capture(original.original());
        let terminal_anchor = SourceAnchor::capture(terminal.terminal());
        for reference in original.references() {
            references::require_retired_reference_owner(
                &tx,
                reference,
                &owner,
                &original_anchor,
                &terminal_anchor,
            )?;
        }
        tx.commit().map_err(sqlite_error)
    }
}
