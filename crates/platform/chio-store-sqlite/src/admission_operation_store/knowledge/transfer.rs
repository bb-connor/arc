//! Signed, self-contained archive provenance is owned by the publication that cites it.
use super::*;
mod baseline;
pub(crate) use baseline::publish_import_manifest_baseline_at_startup;
#[cfg(any(test, feature = "admission-test-support"))]
pub use baseline::PriorFormatImportStartupGuard;
pub(in crate::admission_operation_store) use baseline::VerifiedImportManifestBaseline;
#[cfg(feature = "admission-test-support")]
mod test_support;

const MANIFEST_PREFIX: &str = "knowledge-import:";
pub(super) fn manifest_key(
    scope: &RecoveryScopeV1,
    digest: ProvenanceDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "{MANIFEST_PREFIX}{}:{}",
        scope_key(scope)?,
        hex::encode(digest.as_bytes())
    ))
}
pub(super) fn map_key(
    scope: &RecoveryScopeV1,
    digest: ProvenanceDigest,
    origin: &ArtifactVersionRefV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-import-map:{}:{}:{}",
        scope_key(scope)?,
        hex::encode(digest.as_bytes()),
        sha256_hex(&protected::encode(origin)?)
    ))
}
/// Pure derivation of an Import producer's source version. The borrowed
/// manifest authenticates a reservation before it is retained; without one the
/// retained manifest is read.
pub(super) fn import_source(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    input: &ArtifactPublicationInputV1,
    borrowed: Option<&SignedArtifactArchiveManifestV1>,
) -> Result<ArtifactVersionV1, AdmissionOperationStoreError> {
    let ArtifactProducerV1::Import { manifest, origin } = &input.producer else {
        return Err(refused("import source"));
    };
    let retained: SignedArtifactArchiveManifestV1;
    let signed = match borrowed {
        Some(signed) => signed,
        None => {
            retained = load(tx, &manifest_key(&profile.scope, *manifest)?)?
                .ok_or_else(|| refused("import manifest"))?;
            &retained
        }
    };
    if signed.authority_key() != &profile.archive_root
        || !signed.verify_signature().map_err(refused)?
        || artifact_archive_digest(signed.body()).map_err(refused)? != *manifest
    {
        return Err(refused("import root"));
    }
    let source = signed
        .body()
        .versions
        .as_slice()
        .iter()
        .find(|source| {
            artifact_version_reference(source).is_ok_and(|reference| reference == *origin)
        })
        .ok_or_else(|| refused("import origin"))?;
    if source.content != input.content
        || source.size_bytes != input.size_bytes
        || source.schema != input.schema
        || source.media_type != input.media_type
        || source.retention != input.retention
        || source.scope != profile.scope
    {
        return Err(refused("import content"));
    }
    let mut mapped = Vec::new();
    for dependency in source.dependencies.as_slice() {
        let reference: ArtifactVersionRefV1 =
            load(tx, &map_key(&profile.scope, *manifest, dependency)?)?
                .ok_or_else(|| refused("import prerequisite"))?;
        artifact(tx, &reference)?;
        mapped.push(reference);
    }
    if mapped.as_slice() != input.dependencies.as_slice() {
        return Err(refused("import dependency substitution"));
    }
    Ok(source.clone())
}
/// Root, signature, scope, complete ordered DAG and native provenance of a
/// signed archive. Nothing is persisted here.
pub(super) fn authenticate_import_manifest(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    manifest: &SignedArtifactArchiveManifestV1,
) -> Result<ProvenanceDigest, AdmissionOperationStoreError> {
    verify_artifact_archive(manifest, &profile.archive_root, &profile.scope).map_err(refused)?;
    let versions = manifest.body().versions.as_slice();
    let references = versions
        .iter()
        .map(artifact_version_reference)
        .collect::<chio_core::Result<Vec<_>>>()
        .map_err(refused)?;
    if !references.contains(&manifest.body().root) {
        return Err(refused("archive root absent"));
    }
    for (index, version) in versions.iter().enumerate() {
        let reference = artifact_version_reference(version).map_err(refused)?;
        let source_key: String = load(tx, &version_key(&reference)?)?
            .ok_or_else(|| refused("archive lacks native provenance"))?;
        let source: NativeArtifactRecordV1 =
            load(tx, &source_key)?.ok_or_else(|| refused("archive native origin absent"))?;
        if source.metadata != *version {
            return Err(refused("archive relabelled native origin"));
        }
        if !version
            .dependencies
            .as_slice()
            .iter()
            .all(|reference| references[..index].contains(reference))
        {
            return Err(refused("archive not complete ordered DAG"));
        }
    }
    artifact_archive_digest(manifest.body()).map_err(refused)
}

/// An Import producer is reserved only against the signed manifest it cites,
/// and every other producer against none. A refusal here precedes any write.
pub(super) fn require_matching_source(
    input: &ArtifactPublicationInputV1,
    source: ArtifactReservationSource<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    match (&input.producer, source) {
        (ArtifactProducerV1::Import { .. }, ArtifactReservationSource::Import { .. }) => Ok(()),
        (ArtifactProducerV1::Import { .. }, _) | (_, ArtifactReservationSource::Import { .. }) => {
            Err(refused("import source"))
        }
        _ => Ok(()),
    }
}

/// The authenticated manifest a new Import reservation cites, derived from the
/// borrowed signed bytes without persisting them.
pub(super) fn cited_manifest<'a>(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    input: &ArtifactPublicationInputV1,
    source: ArtifactReservationSource<'a>,
) -> Result<&'a SignedArtifactArchiveManifestV1, AdmissionOperationStoreError> {
    let (
        ArtifactProducerV1::Import {
            manifest: cited, ..
        },
        ArtifactReservationSource::Import { manifest },
    ) = (&input.producer, source)
    else {
        return Err(refused("import source"));
    };
    if authenticate_import_manifest(tx, profile, manifest)? != *cited {
        return Err(refused("import manifest citation"));
    }
    Ok(manifest)
}

/// Retains the manifest an already admitted Import reservation cites. The exact
/// retained row, including one kept before manifests had owners, is adopted
/// without a write; any other bytes for the digest refuse.
pub(super) fn persist_import_manifest(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
    publication: &CommandId,
    manifest: &SignedArtifactArchiveManifestV1,
) -> Result<(), AdmissionOperationStoreError> {
    baseline::require_authority_baseline(tx, owner)?;
    if let Some(intake) = super::intake::AuthenticatedKnowledgeIntakeSource::import_manifest(
        tx,
        actor,
        profile,
        now,
        publication,
        manifest,
    )? {
        protected::persist_knowledge_intake(tx, owner, intake)?;
    }
    Ok(())
}

/// Replaying an existing Import reservation presents the one retained manifest.
pub(super) fn verify_import_replay(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    input: &ArtifactPublicationInputV1,
    source: ArtifactReservationSource<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let (
        ArtifactProducerV1::Import {
            manifest: cited, ..
        },
        ArtifactReservationSource::Import { manifest },
    ) = (&input.producer, source)
    else {
        return Err(refused("import source"));
    };
    let retained: Option<SignedArtifactArchiveManifestV1> =
        load(tx, &manifest_key(&profile.scope, *cited)?)?;
    if artifact_archive_digest(manifest.body()).map_err(refused)? != *cited
        || retained.as_ref() != Some(manifest)
    {
        return Err(refused("import manifest citation"));
    }
    Ok(())
}

/// Written in the transaction that makes an Import publication Available, for
/// exactly the origin its stored producer cites.
pub(super) fn retain_import_map(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(record.metadata.producer, ArtifactProducerV1::Import { .. }) {
        return Ok(());
    }
    let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
    if let Some(intake) = super::intake::AuthenticatedKnowledgeIntakeSource::import_map(
        tx, actor, profile, now, &reference,
    )? {
        protected::persist_knowledge_intake(tx, owner, intake)?;
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    pub fn artifact_transfer_inventory(
        &self,
        actor: &AuthenticatedRecoveryActor,
        root: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<ArtifactVersionRefV1>, AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeRead | RecoveryPermission::KnowledgeWrite
        ) {
            return Err(refused("transfer inventory authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            if root.scope != *actor.scope() {
                return Err(refused("transfer scope"));
            }
            let mut records =
                traversal::dependencies(&tx, actor.scope(), std::slice::from_ref(root))?;
            if records.len() > MAX_ARCHIVE_VERSIONS {
                return Err(refused("archive version bound"));
            }
            records.sort_by_key(|record| record.metadata.creation_sequence);
            for record in &records {
                traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            }
            let references = records
                .iter()
                .map(|record| artifact_version_reference(&record.metadata).map_err(refused))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((tx, references))
        })
    }
}
