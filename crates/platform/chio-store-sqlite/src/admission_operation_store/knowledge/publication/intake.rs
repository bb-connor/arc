//! The closed write set of one nonterminal publication transition, derived from
//! the stored parent record and the publication's live slot.
use super::super::closure::DerivedWrite;
use super::*;

pub(in crate::admission_operation_store::knowledge) type Derived =
    (Vec<DerivedWrite>, Vec<protected::ProtectedSourceReference>);

/// Version pointer, spent certificate and the publication record.
pub(in crate::admission_operation_store::knowledge) const MAX_PROGRESS_WRITES: usize = 3;

/// A transition that is lawful for its stored parent. Metadata commitment also
/// owns the immutable version pointer and the spent certificate it names.
pub(in crate::admission_operation_store::knowledge) fn progress(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    after: &NativeArtifactRecordV1,
) -> Result<Derived, AdmissionOperationStoreError> {
    if !matches!(
        actor.permission(),
        RecoveryPermission::KnowledgeRead
            | RecoveryPermission::KnowledgeWrite
            | RecoveryPermission::KnowledgeAdopt
            | RecoveryPermission::KnowledgeAdmin
    ) || after.metadata.scope != *actor.scope()
        || after.state == ArtifactPublicationStateV1::Retired
    {
        return Err(refused("publication progress authority"));
    }
    let key = record_publication_key(after)?;
    let before: NativeArtifactRecordV1 =
        load(tx, &key)?.ok_or_else(|| refused("publication progress source absent"))?;
    super::super::publication_source::VerifiedKnowledgePublicationProgress::new(
        tx,
        protected::source_reference(tx, &key)?,
        after.clone(),
    )?;
    super::super::publication_capacity::validate_existing_allocation(tx, after)?;
    let scope = scope_key(&after.metadata.scope)?;
    let mut writes = Vec::with_capacity(MAX_PROGRESS_WRITES);
    if before.state == ArtifactPublicationStateV1::Staged
        && after.state == ArtifactPublicationStateV1::MetadataCommitted
    {
        let reference = artifact_version_reference(&after.metadata).map_err(refused)?;
        let pointer = version_key(&reference)?;
        if load::<String>(tx, &pointer)?.is_some() {
            return Err(refused("version collision"));
        }
        writes.push(DerivedWrite {
            key: pointer,
            scope_key: scope.clone(),
            expected: None,
            payload: protected::encode(&key)?,
        });
        if let Some(certificate) = &after.certificate {
            let spent = format!(
                "knowledge-certificate:{scope}:{}",
                certificate.body().evidence.as_str()
            );
            match load::<ArtifactVersionRefV1>(tx, &spent)? {
                Some(prior) if prior == reference => {}
                Some(_) => return Err(refused("certificate replay")),
                None => writes.push(DerivedWrite {
                    key: spent,
                    scope_key: scope.clone(),
                    expected: None,
                    payload: protected::encode(&reference)?,
                }),
            }
        }
    }
    writes.push(DerivedWrite {
        key: key.clone(),
        scope_key: scope,
        expected: Some(protected::source_reference(tx, &key)?),
        payload: protected::encode(after)?,
    });
    let witnesses = vec![
        protected::source_reference(tx, &key)?,
        super::super::publication_capacity::retained_allocation_source(tx, after)?,
    ];
    Ok((writes, witnesses))
}
