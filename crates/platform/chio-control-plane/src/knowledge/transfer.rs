use super::*;
impl NativeKnowledgeRuntime {
    pub fn copy(
        &self,
        capability: &CapabilityToken,
        source: &ArtifactHandleV1,
        publication: &CommandId,
    ) -> Result<ArtifactVersionRefV1, KernelError> {
        let prepared = self.prepare_read(capability, source)?;
        let reference =
            artifact_version_reference(&prepared.record.metadata).map_err(unavailable)?;
        let input = ArtifactPublicationInputV1 {
            publication: publication.clone(),
            producer: ArtifactProducerV1::Derivation {
                operation: OperationId::new(publication.as_str()).map_err(unavailable)?,
            },
            content: prepared.record.metadata.content,
            size_bytes: prepared.record.metadata.size_bytes,
            media_type: prepared.record.metadata.media_type.clone(),
            schema: prepared.record.metadata.schema,
            dependencies: BoundedList::new(vec![reference]).map_err(unavailable)?,
            retention: prepared.record.metadata.retention,
        };
        self.publish(capability, &input, &prepared.bytes, None)
    }
}

const ARCHIVE_MAGIC: &[u8; 8] = b"CHIOAK1\0";
impl NativeKnowledgeRuntime {
    /// Archives contain every required provenance path and classified bytes.
    /// The archive artifact itself joins the restrictions of all exported bytes.
    pub fn export_into(
        &self,
        capability: &CapabilityToken,
        root: &ArtifactHandleV1,
        request: &RequestId,
        signer: &dyn chio_core_types::SigningBackend,
        sink: &dyn ArtifactReleaseSink,
    ) -> Result<ArtifactDeliveryOutcomeV1, KernelError> {
        if sink.recipient().sink != ArtifactSinkV1::Archive {
            return Err(unavailable("archive sink required"));
        }
        let prepared = self.prepare_read(capability, root)?;
        let reference =
            artifact_version_reference(&prepared.record.metadata).map_err(unavailable)?;
        let actor = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        let profile = self.current(&actor)?;
        let references = self
            .store
            .artifact_transfer_inventory(&actor, &reference, &self.fence, now()?)
            .map_err(unavailable)?;
        let mut records = Vec::with_capacity(references.len());
        let mut total = 0_u64;
        for reference in references {
            let handle = self.handle(capability, &reference, &sink.recipient().recipient)?;
            let prepared = self.prepare_read(capability, &handle)?;
            total = total
                .checked_add(prepared.record.metadata.size_bytes.get())
                .ok_or_else(|| unavailable("archive overflow"))?;
            if total > MAX_ARTIFACT_BYTES as u64 {
                return Err(unavailable("archive bytes"));
            }
            records.push(prepared);
        }
        let manifest = SignedArtifactArchiveManifestV1::sign_with_backend(
            ArtifactArchiveManifestV1 {
                domain_version: VersionV1,
                scope: self.profile.scope.clone(),
                root: reference.clone(),
                versions: NonEmptyBoundedList::new(
                    records
                        .iter()
                        .map(|prepared| prepared.record.metadata.clone())
                        .collect(),
                )
                .map_err(unavailable)?,
                total_bytes: SafeInteger::new(total).map_err(unavailable)?,
            },
            signer,
        )
        .map_err(unavailable)?;
        if manifest.authority_key() != &profile.archive_root
            || !manifest.verify_signature().map_err(unavailable)?
        {
            return Err(unavailable("archive signing role"));
        }
        let encoded = chio_core_types::canonical_json_bytes(&manifest).map_err(unavailable)?;
        if encoded.len() > 64 * 1024 {
            return Err(unavailable("archive manifest bound"));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(ARCHIVE_MAGIC);
        bytes.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(unavailable)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&encoded);
        let mut dependencies = Vec::new();
        for prepared in records {
            let reference =
                artifact_version_reference(&prepared.record.metadata).map_err(unavailable)?;
            bytes.extend_from_slice(&prepared.bytes);
            dependencies.push(reference);
        }
        // The bounded single-buffer backend includes manifest overhead in its
        // one-MiB quota. Larger exports refuse before release or publication.
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(unavailable("archive total bound"));
        }
        let publication = CommandId::new(&format!(
            "export:{}",
            chio_core_types::sha256_hex(request.as_str().as_bytes())
        ))
        .map_err(unavailable)?;
        let input = ArtifactPublicationInputV1 {
            publication: publication.clone(),
            producer: ArtifactProducerV1::Derivation {
                operation: OperationId::new(publication.as_str()).map_err(unavailable)?,
            },
            content: knowledge_content_digest(&bytes),
            size_bytes: SafeInteger::new(bytes.len() as u64).map_err(unavailable)?,
            media_type: ProtectedText::new("application/octet-stream").map_err(unavailable)?,
            schema: knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1"),
            dependencies: BoundedList::new(dependencies).map_err(unavailable)?,
            retention: ArtifactRetentionV1::Ephemeral,
        };
        let archive = self.publish(capability, &input, &bytes, None)?;
        let handle = self.handle(capability, &archive, &sink.recipient().recipient)?;
        self.release_into(
            capability,
            request,
            self.prepare_read(capability, &handle)?,
            sink,
        )
    }
    /// Verify the entire archive before creating any available version. Import
    /// identities are stable per signed manifest; replay never revives retirement.
    pub fn import_archive(
        &self,
        capability: &CapabilityToken,
        bytes: &[u8],
    ) -> Result<ArtifactVersionRefV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeWrite)?;
        let profile = self.current(&actor)?;
        let archive = parse_archive(bytes)?;
        if archive.manifest.authority_key() != &profile.archive_root
            || !archive.manifest.verify_signature().map_err(unavailable)?
            || archive.manifest.body().scope != profile.scope
        {
            return Err(unavailable("archive authority"));
        }
        let digest = self
            .store
            .retain_import_manifest(&actor, &archive.manifest, &self.fence, now()?)
            .map_err(unavailable)?;
        let mut mapping = Vec::<(ArtifactVersionRefV1, ArtifactVersionRefV1)>::new();
        for (index, (original, raw)) in archive
            .manifest
            .body()
            .versions
            .as_slice()
            .iter()
            .zip(&archive.contents)
            .enumerate()
        {
            let origin = artifact_version_reference(original).map_err(unavailable)?;
            let mut dependencies = Vec::new();
            for dependency in original.dependencies.as_slice() {
                dependencies.push(
                    mapping
                        .iter()
                        .find(|(old, _)| old == dependency)
                        .ok_or_else(|| unavailable("archive incomplete"))?
                        .1
                        .clone(),
                );
            }
            let publication = CommandId::new(&format!(
                "import:{}:{index}",
                chio_core_types::sha256_hex(digest.as_bytes())
            ))
            .map_err(unavailable)?;
            let input = ArtifactPublicationInputV1 {
                publication,
                producer: ArtifactProducerV1::Import {
                    manifest: digest,
                    origin: origin.clone(),
                },
                content: original.content,
                size_bytes: original.size_bytes,
                media_type: original.media_type.clone(),
                schema: original.schema,
                dependencies: BoundedList::new(dependencies).map_err(unavailable)?,
                retention: original.retention,
            };
            let imported = self.publish(capability, &input, raw, None)?;
            self.store
                .retain_import_mapping(&actor, digest, &origin, &imported, &self.fence, now()?)
                .map_err(unavailable)?;
            mapping.push((origin, imported));
        }
        mapping
            .into_iter()
            .find(|(old, _)| old == &archive.manifest.body().root)
            .map(|(_, new)| new)
            .ok_or_else(|| unavailable("archive root"))
    }
    /// Legacy bytes are read privately by exact certificate commitments. They
    /// remain unavailable if signature, identity, size, label or storage differs.
    pub fn adopt_legacy(
        &self,
        capability: &CapabilityToken,
        input: &ArtifactPublicationInputV1,
        certificate: &SignedArtifactCertificateV1,
    ) -> Result<ArtifactVersionRefV1, KernelError> {
        if !matches!(input.producer, ArtifactProducerV1::Adoption { .. }) {
            return Err(unavailable("adoption role"));
        }
        let actor = self.actor(capability, RecoveryPermission::KnowledgeAdopt)?;
        let profile = self.current(&actor)?;
        let reservation = self
            .store
            .reserve_artifact(&actor, input, &self.fence, now()?)
            .map_err(unavailable)?;
        let body = certificate.body();
        if certificate.authority_key() != &profile.certificate_root
            || !certificate.verify_signature().map_err(unavailable)?
            || body.artifact != reservation.metadata.artifact
            || body.version != reservation.metadata.version
            || body.content != input.content
            || body.scope != profile.scope
        {
            return Err(unavailable("adoption certificate"));
        }
        let seal = self.broker.resolve_private(
            &reservation.object,
            &profile.scope.process_id,
            input.content,
            input.size_bytes,
        )?;
        let bytes = Zeroizing::new(self.broker.read_private(&seal)?);
        self.publish(capability, input, &bytes, Some(certificate))
    }
}
struct PrivateArchive {
    manifest: SignedArtifactArchiveManifestV1,
    contents: Vec<Zeroizing<Vec<u8>>>,
}
fn parse_archive(bytes: &[u8]) -> Result<PrivateArchive, KernelError> {
    if bytes.len() > MAX_ARTIFACT_BYTES || bytes.get(..8) != Some(ARCHIVE_MAGIC.as_slice()) {
        return Err(unavailable("archive frame"));
    }
    let size_bytes: [u8; 4] = bytes
        .get(8..12)
        .ok_or_else(|| unavailable("archive truncated"))?
        .try_into()
        .map_err(unavailable)?;
    let length = u32::from_be_bytes(size_bytes) as usize;
    if length == 0 || length > 64 * 1024 {
        return Err(unavailable("archive manifest bound"));
    }
    let end = 12usize
        .checked_add(length)
        .ok_or_else(|| unavailable("archive length overflow"))?;
    let encoded = bytes
        .get(12..end)
        .ok_or_else(|| unavailable("archive manifest truncated"))?;
    let manifest: SignedArtifactArchiveManifestV1 =
        decode_contract(encoded).map_err(unavailable)?;
    if chio_core_types::canonical_json_bytes(&manifest).map_err(unavailable)? != encoded {
        return Err(unavailable("archive canonical manifest"));
    }
    manifest.body().validate().map_err(unavailable)?;
    let mut contents = Vec::new();
    let mut offset = end;
    for version in manifest.body().versions.as_slice() {
        let next = offset
            .checked_add(usize::try_from(version.size_bytes.get()).map_err(unavailable)?)
            .ok_or_else(|| unavailable("archive byte overflow"))?;
        let raw = bytes
            .get(offset..next)
            .ok_or_else(|| unavailable("archive content truncated"))?;
        if knowledge_content_digest(raw) != version.content {
            return Err(unavailable("archive content changed"));
        }
        contents.push(Zeroizing::new(raw.to_vec()));
        offset = next;
    }
    if offset != bytes.len() {
        return Err(unavailable("archive trailing data"));
    }
    Ok(PrivateArchive { manifest, contents })
}
