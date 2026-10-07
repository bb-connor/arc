//! One admitted Product source consumes one complete logical reference plan.
use super::reference_custody::VerifiedKnowledgeReferenceRetain;
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
