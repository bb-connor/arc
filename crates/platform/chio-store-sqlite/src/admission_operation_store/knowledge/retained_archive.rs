//! Exact retained archive bytes are separate from ended process execution.
use super::*;

/// Host-selected archive request. This description grants no read authority.
pub struct NativeRetainedArchiveRequest<'a> {
    pub root: &'a ArtifactHandleV1,
    pub request: &'a RequestId,
    pub recipient: &'a ArtifactRecipientV1,
}

/// Private source custody returned only after the owning writer retains the
/// complete original DAG. Dropping this value does not release durable owners.
///
/// ```compile_fail
/// use chio_store_sqlite::admission_operation_store::NativeRetainedArchivePreparation;
/// let _: Result<NativeRetainedArchivePreparation, _> = serde_json::from_str("{}");
/// ```
pub struct NativeRetainedArchivePreparation {
    profile: NativeKnowledgeInstallationV1,
    records: Vec<NativeArtifactRecordV1>,
    root: ArtifactVersionRefV1,
    recipient: NativeKnowledgeRecipientV1,
    request: RequestId,
    authorization: ReleaseAuthorizationDigest,
    reservation: CanonicalPayloadDigest,
}

impl NativeRetainedArchivePreparation {
    pub fn profile(&self) -> &NativeKnowledgeInstallationV1 {
        &self.profile
    }

    pub fn records(&self) -> &[NativeArtifactRecordV1] {
        &self.records
    }

    pub fn root(&self) -> &ArtifactVersionRefV1 {
        &self.root
    }

    pub fn recipient(&self) -> &NativeKnowledgeRecipientV1 {
        &self.recipient
    }

    pub fn request(&self) -> &RequestId {
        &self.request
    }

    /// Recheck the captured private description before encoding. This neither
    /// refreshes authority nor replaces fresh validation in the owning writer.
    pub fn validate_sources(&self) -> Result<(), AdmissionOperationStoreError> {
        let versions = self
            .records
            .iter()
            .map(|record| record.metadata.clone())
            .collect::<Vec<_>>();
        let inventory = validate_inventory(&self.profile.scope, &self.root, &versions)?;
        let selected = self
            .profile
            .recipients
            .as_slice()
            .iter()
            .find(|selection| selection.recipient.recipient == self.recipient.recipient.recipient)
            .ok_or_else(|| refused("retained archive recipient absent"))?;
        if self.recipient.recipient.scope != self.profile.scope
            || self.recipient.recipient.sink != ArtifactSinkV1::Archive
            || self.recipient.recipient.clearance == InformationLabel::Top
            || !inventory
                .label
                .flows_to(&self.recipient.recipient.clearance)
            || protected::encode(selected)? != protected::encode(&self.recipient)?
        {
            return Err(refused("retained archive recipient"));
        }
        for record in &self.records {
            let seal = record
                .seal
                .as_ref()
                .ok_or_else(|| refused("retained archive source seal"))?;
            if record.state != ArtifactPublicationStateV1::Available
                || record.metadata.policy != self.profile.policy
                || record.metadata.contract != self.profile.contract
                || record.input.producer != record.metadata.producer
                || record.input.content != record.metadata.content
                || record.input.size_bytes != record.metadata.size_bytes
                || record.input.media_type != record.metadata.media_type
                || record.input.schema != record.metadata.schema
                || record.input.dependencies != record.metadata.dependencies
                || record.input.retention != record.metadata.retention
                || seal.object != record.object
                || seal.process != self.profile.scope.process_id
                || seal.runtime.as_str()
                    != self.profile.producer_context.as_v1().session_id().as_str()
                || seal.content != record.metadata.content
                || seal.bytes != record.metadata.size_bytes
            {
                return Err(refused("retained archive exact source"));
            }
        }
        Ok(())
    }
}

/// Exact private frame submitted to the owning writer. The writer recomputes
/// every byte commitment; the signed manifest alone cannot authorize a read.
pub struct NativeRetainedArchiveInput<'a> {
    pub manifest: &'a SignedArtifactArchiveManifestV1,
    pub bytes: &'a [u8],
}

impl NativeRetainedArchiveInput<'_> {
    pub const FRAME_MAGIC: &'static [u8; 8] = b"CHIOAK1\0";
    pub const HEADER_BYTES: usize = 12;
    pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
}

impl std::fmt::Debug for NativeRetainedArchiveRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeRetainedArchiveRequest([redacted])")
    }
}

impl std::fmt::Debug for NativeRetainedArchivePreparation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeRetainedArchivePreparation([redacted])")
    }
}

impl std::fmt::Debug for NativeRetainedArchiveInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeRetainedArchiveInput([redacted])")
    }
}

struct ArchiveInventory {
    references: Vec<ArtifactVersionRefV1>,
    label: InformationLabel,
    total_bytes: u64,
}

fn validate_inventory(
    scope: &RecoveryScopeV1,
    root: &ArtifactVersionRefV1,
    versions: &[ArtifactVersionV1],
) -> Result<ArchiveInventory, AdmissionOperationStoreError> {
    if root.scope != *scope || versions.is_empty() || versions.len() > MAX_ARCHIVE_VERSIONS {
        return Err(refused("retained archive inventory"));
    }
    let mut references = Vec::<ArtifactVersionRefV1>::with_capacity(versions.len());
    let mut total_bytes = 0_u64;
    let mut label = InformationLabel::bottom();
    let mut last_sequence = 0;
    for version in versions {
        version.validate().map_err(refused)?;
        if version.scope != *scope
            || version.label == InformationLabel::Top
            || version.creation_sequence.get() <= last_sequence
            || references.iter().any(|prior| {
                prior.scope == version.scope
                    && prior.artifact == version.artifact
                    && prior.version == version.version
            })
            || !version
                .dependencies
                .as_slice()
                .iter()
                .all(|dependency| references.contains(dependency))
        {
            return Err(refused("retained archive provenance"));
        }
        last_sequence = version.creation_sequence.get();
        total_bytes = total_bytes
            .checked_add(version.size_bytes.get())
            .filter(|total| *total <= MAX_ARTIFACT_BYTES as u64)
            .ok_or_else(|| refused("retained archive content bound"))?;
        label = label.join_restrictions(&version.label).map_err(refused)?;
        references.push(artifact_version_reference(version).map_err(refused)?);
    }
    if !references.contains(root) || label == InformationLabel::Top {
        return Err(refused("retained archive root"));
    }
    Ok(ArchiveInventory {
        references,
        label,
        total_bytes,
    })
}

fn validate_frame(
    archive_root: &PublicKey,
    scope: &RecoveryScopeV1,
    root: &ArtifactVersionRefV1,
    versions: &[ArtifactVersionV1],
    input: &NativeRetainedArchiveInput<'_>,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    let inventory = validate_inventory(scope, root, versions)?;
    let manifest = input.manifest;
    manifest.body().validate().map_err(refused)?;
    if manifest.authority_key() != archive_root
        || !manifest.verify_signature().map_err(refused)?
        || manifest.body().scope != *scope
        || manifest.body().root != *root
        || manifest.body().versions.as_slice() != versions
        || manifest.body().total_bytes.get() != inventory.total_bytes
        || input.bytes.len() > MAX_ARTIFACT_BYTES
        || input.bytes.get(..8) != Some(NativeRetainedArchiveInput::FRAME_MAGIC.as_slice())
    {
        return Err(refused("retained archive binding"));
    }
    let length: [u8; 4] = input
        .bytes
        .get(8..NativeRetainedArchiveInput::HEADER_BYTES)
        .ok_or_else(|| refused("retained archive header"))?
        .try_into()
        .map_err(refused)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(refused)?;
    if length == 0 || length > NativeRetainedArchiveInput::MAX_MANIFEST_BYTES {
        return Err(refused("retained archive manifest bound"));
    }
    let manifest_end = NativeRetainedArchiveInput::HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| refused("retained archive manifest overflow"))?;
    let encoded = input
        .bytes
        .get(NativeRetainedArchiveInput::HEADER_BYTES..manifest_end)
        .ok_or_else(|| refused("retained archive manifest truncated"))?;
    if chio_core::canonical_json_bytes(manifest)
        .map_err(refused)?
        .as_slice()
        != encoded
    {
        return Err(refused("retained archive canonical manifest"));
    }
    let mut offset = manifest_end;
    for version in versions {
        let end = offset
            .checked_add(usize::try_from(version.size_bytes.get()).map_err(refused)?)
            .ok_or_else(|| refused("retained archive byte overflow"))?;
        let bytes = input
            .bytes
            .get(offset..end)
            .ok_or_else(|| refused("retained archive content truncated"))?;
        if knowledge_content_digest(bytes) != version.content {
            return Err(refused("retained archive content changed"));
        }
        offset = end;
    }
    if offset != input.bytes.len() {
        return Err(refused("retained archive trailing bytes"));
    }
    Ok(knowledge_content_digest(input.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::{crypto::Ed25519Backend, Keypair};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn version(bytes: &[u8]) -> Result<ArtifactVersionV1, Box<dyn std::error::Error>> {
        Ok(ArtifactVersionV1 {
            domain_version: VersionV1,
            scope: RecoveryScopeV1 {
                authority_domain: AuthorityDomainId::new("retained-archive-authority")?,
                tenant_id: RecoveryTenantId::new("retained-archive-tenant")?,
                process_id: ProcessId::new("retained-archive-owner")?,
            },
            artifact: ArtifactId::new("retained-archive-source")?,
            version: ArtifactRevisionId::new("source-version")?,
            content: knowledge_content_digest(bytes),
            size_bytes: SafeInteger::new(u64::try_from(bytes.len())?)?,
            media_type: ProtectedText::new("application/octet-stream")?,
            schema: knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1"),
            producer: ArtifactProducerV1::Derivation {
                operation: OperationId::new("retained-archive-source-operation")?,
            },
            dependencies: BoundedList::new(vec![])?,
            label: InformationLabel::bottom(),
            influence: ArtifactInfluenceV1 {
                commitment: knowledge_content_digest(b"retained-archive-influence"),
                externally_influenced: true,
                unknown: false,
            },
            lineage: IsolationLineageId::new("retained-archive-lineage")?,
            isolation_epoch: ProtectedText::new("retained-archive-epoch")?,
            evidence: BoundedList::new(vec![])?,
            policy: PolicyDigest::from_bytes([1; 32]),
            contract: ContractDigest::from_bytes([2; 32]),
            creation_sequence: SafeInteger::new(1)?,
            retention: ArtifactRetentionV1::Evidence,
        })
    }

    fn signed_frame(
        versions: &[ArtifactVersionV1],
        contents: &[&[u8]],
        key: &Keypair,
    ) -> Result<(SignedArtifactArchiveManifestV1, Vec<u8>), Box<dyn std::error::Error>> {
        let root = versions.last().ok_or("archive root")?;
        let manifest = SignedArtifactArchiveManifestV1::sign_with_backend(
            ArtifactArchiveManifestV1 {
                domain_version: VersionV1,
                scope: root.scope.clone(),
                root: artifact_version_reference(root)?,
                versions: NonEmptyBoundedList::new(versions.to_vec())?,
                total_bytes: SafeInteger::new(
                    versions
                        .iter()
                        .map(|version| version.size_bytes.get())
                        .sum(),
                )?,
            },
            &Ed25519Backend::new(key.clone()),
        )?;
        let encoded = chio_core::canonical_json_bytes(&manifest)?;
        let mut bytes = NativeRetainedArchiveInput::FRAME_MAGIC.to_vec();
        bytes.extend_from_slice(&u32::try_from(encoded.len())?.to_be_bytes());
        bytes.extend_from_slice(&encoded);
        for content in contents {
            bytes.extend_from_slice(content);
        }
        Ok((manifest, bytes))
    }

    #[test]
    fn retained_archive_frame_recomputes_signed_manifest_and_exact_contents() -> TestResult {
        let payload = b"retained archive content";
        let mut source = version(payload)?;
        // Archive custody preserves uncertain integrity without inventing trust.
        // Its finite confidentiality label still governs the selected audience.
        source.influence.unknown = true;
        let root = artifact_version_reference(&source)?;
        let key = Keypair::from_seed(&[29; 32]);
        let versions = vec![source];
        let (manifest, mut bytes) = signed_frame(&versions, &[payload], &key)?;
        let verify = |bytes: &[u8]| {
            validate_frame(
                &key.public_key(),
                &root.scope,
                &root,
                &versions,
                &NativeRetainedArchiveInput {
                    manifest: &manifest,
                    bytes,
                },
            )
        };
        assert!(manifest.body().versions.as_slice()[0].influence.unknown);
        assert_eq!(verify(&bytes)?, knowledge_content_digest(&bytes));
        let last = bytes.last_mut().ok_or("archive bytes")?;
        *last ^= 1;
        assert!(verify(&bytes).is_err());
        *bytes.last_mut().ok_or("archive bytes")? ^= 1;
        bytes.push(0);
        assert!(verify(&bytes).is_err());
        bytes.truncate(bytes.len() - 1);
        assert!(verify(&bytes[..bytes.len() - 1]).is_err());
        let wrong_key = Keypair::from_seed(&[30; 32]);
        assert!(validate_frame(
            &wrong_key.public_key(),
            &root.scope,
            &root,
            &versions,
            &NativeRetainedArchiveInput {
                manifest: &manifest,
                bytes: &bytes
            },
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn retained_archive_inventory_refuses_foreign_process_top_and_incomplete_dag() -> TestResult {
        let source = version(b"source")?;
        let root = artifact_version_reference(&source)?;
        assert!(validate_inventory(&root.scope, &root, std::slice::from_ref(&source)).is_ok());
        let mut changed = source.clone();
        changed.scope.process_id = ProcessId::new("another-ended-owner")?;
        assert!(validate_inventory(&root.scope, &root, &[changed]).is_err());
        let mut changed = source.clone();
        changed.influence.unknown = true;
        let changed_root = artifact_version_reference(&changed)?;
        assert!(validate_inventory(&changed_root.scope, &changed_root, &[changed]).is_ok());
        let mut changed = source.clone();
        changed.label = InformationLabel::Top;
        assert!(validate_inventory(&root.scope, &root, &[changed]).is_err());
        let mut changed = source.clone();
        let mut missing = root.clone();
        missing.artifact = ArtifactId::new("missing-dependency")?;
        changed.dependencies = BoundedList::new(vec![missing])?;
        assert!(validate_inventory(&root.scope, &root, &[changed]).is_err());
        assert!(validate_inventory(&root.scope, &root, &[source.clone(), source]).is_err());
        Ok(())
    }

    #[test]
    fn retained_archive_frame_counts_manifest_overhead_against_blob_capacity() -> TestResult {
        let payload = vec![0_u8; MAX_ARTIFACT_BYTES];
        let source = version(&payload)?;
        let root = artifact_version_reference(&source)?;
        let key = Keypair::from_seed(&[31; 32]);
        let versions = vec![source];
        let (manifest, bytes) = signed_frame(&versions, &[&payload], &key)?;
        assert!(manifest.verify_signature()?);
        assert_eq!(
            manifest.body().total_bytes.get(),
            u64::try_from(MAX_ARTIFACT_BYTES)?
        );
        assert!(bytes.len() > MAX_ARTIFACT_BYTES);
        assert!(validate_frame(
            &key.public_key(),
            &root.scope,
            &root,
            &versions,
            &NativeRetainedArchiveInput {
                manifest: &manifest,
                bytes: &bytes
            },
        )
        .is_err());
        Ok(())
    }
}
