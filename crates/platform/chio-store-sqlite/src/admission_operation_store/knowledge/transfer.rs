//! Signed, self-contained archive provenance is retained independently of bytes.
use super::*;
fn manifest_key(
    scope: &RecoveryScopeV1,
    digest: ProvenanceDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-import:{}:{}",
        scope_key(scope)?,
        hex::encode(digest.as_bytes())
    ))
}
fn map_key(
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
pub(super) fn import_source(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    input: &ArtifactPublicationInputV1,
) -> Result<ArtifactVersionV1, AdmissionOperationStoreError> {
    let ArtifactProducerV1::Import { manifest, origin } = &input.producer else {
        return Err(refused("import source"));
    };
    let signed: SignedArtifactArchiveManifestV1 =
        load(tx, &manifest_key(&profile.scope, *manifest)?)?
            .ok_or_else(|| refused("import manifest"))?;
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
impl SqliteAdmissionOperationStore {
    pub fn retain_import_manifest(
        &self,
        actor: &AuthenticatedRecoveryActor,
        manifest: &SignedArtifactArchiveManifestV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProvenanceDigest, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeWrite {
            return Err(refused("import authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            verify_artifact_archive(manifest, &profile.archive_root, &profile.scope)
                .map_err(refused)?;
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
                let source_key: String = load(&tx, &version_key(&reference)?)?
                    .ok_or_else(|| refused("archive lacks native provenance"))?;
                let source: NativeArtifactRecordV1 = load(&tx, &source_key)?
                    .ok_or_else(|| refused("archive native origin absent"))?;
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
            let digest = artifact_archive_digest(manifest.body()).map_err(refused)?;
            let key = manifest_key(actor.scope(), digest)?;
            if let Some(old) = load::<SignedArtifactArchiveManifestV1>(&tx, &key)? {
                if old != *manifest {
                    return Err(refused("archive identity"));
                }
                return Ok((tx, digest));
            }
            save(&tx, &self.serving_owner, actor.scope(), &key, manifest)?;
            Ok((tx, digest))
        })
    }
    pub fn retain_import_mapping(
        &self,
        actor: &AuthenticatedRecoveryActor,
        digest: ProvenanceDigest,
        origin: &ArtifactVersionRefV1,
        reference: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeWrite {
            return Err(refused("import mapping authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let record = artifact(&tx, reference)?;
            if record.metadata.producer
                != (ArtifactProducerV1::Import {
                    manifest: digest,
                    origin: origin.clone(),
                })
            {
                return Err(refused("import provenance"));
            }
            let key = map_key(&profile.scope, digest, origin)?;
            if let Some(old) = load::<ArtifactVersionRefV1>(&tx, &key)? {
                if old != *reference {
                    return Err(refused("import identity"));
                }
                return Ok((tx, ()));
            }
            save(&tx, &self.serving_owner, actor.scope(), &key, reference)?;
            Ok((tx, ()))
        })
    }
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
