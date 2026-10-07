//! Fresh storage authority can archive exact custody after execution ends.
use super::*;
use chio_store_sqlite::admission_operation_store::{
    NativeRetainedArchiveInput, NativeRetainedArchivePreparation,
};

struct PreparedRetainedArchiveFrame {
    manifest: SignedArtifactArchiveManifestV1,
    bytes: Zeroizing<Vec<u8>>,
}

impl PreparedRetainedArchiveFrame {
    fn input(&self) -> NativeRetainedArchiveInput<'_> {
        NativeRetainedArchiveInput {
            manifest: &self.manifest,
            bytes: &self.bytes,
        }
    }
}

impl NativeKnowledgeRuntime {
    /// Preparation is native retained custody, not a caller-selected read view.
    /// Private reads never renew the original process or its execution token.
    fn assemble_retained_archive(
        &self,
        preparation: &NativeRetainedArchivePreparation,
        signer: &dyn chio_core_types::SigningBackend,
    ) -> Result<PreparedRetainedArchiveFrame, KernelError> {
        preparation.validate_sources().map_err(unavailable)?;
        let records = preparation.records();
        if records.is_empty() || records.len() > MAX_ARCHIVE_VERSIONS {
            return Err(unavailable("retained archive version bound"));
        }
        let mut total = 0_u64;
        let mut versions = Vec::with_capacity(records.len());
        for record in records {
            total = total
                .checked_add(record.metadata.size_bytes.get())
                .filter(|total| *total <= MAX_ARTIFACT_BYTES as u64)
                .ok_or_else(|| unavailable("retained archive content bound"))?;
            versions.push(record.metadata.clone());
        }
        let manifest = SignedArtifactArchiveManifestV1::sign_with_backend(
            ArtifactArchiveManifestV1 {
                domain_version: VersionV1,
                scope: preparation.profile().scope.clone(),
                root: preparation.root().clone(),
                versions: NonEmptyBoundedList::new(versions).map_err(unavailable)?,
                total_bytes: SafeInteger::new(total).map_err(unavailable)?,
            },
            signer,
        )
        .map_err(unavailable)?;
        if manifest.authority_key() != &preparation.profile().archive_root
            || !manifest.verify_signature().map_err(unavailable)?
        {
            return Err(unavailable("retained archive signing role"));
        }
        let encoded = chio_core_types::canonical_json_bytes(&manifest).map_err(unavailable)?;
        if encoded.is_empty() || encoded.len() > NativeRetainedArchiveInput::MAX_MANIFEST_BYTES {
            return Err(unavailable("retained archive manifest bound"));
        }
        let frame_size = NativeRetainedArchiveInput::HEADER_BYTES
            .checked_add(encoded.len())
            .and_then(|size| size.checked_add(usize::try_from(total).ok()?))
            .filter(|size| *size <= MAX_ARTIFACT_BYTES)
            .ok_or_else(|| unavailable("retained archive total bound"))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(frame_size));
        bytes.extend_from_slice(NativeRetainedArchiveInput::FRAME_MAGIC);
        bytes.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(unavailable)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&encoded);
        for record in records {
            let seal = record
                .seal
                .as_ref()
                .ok_or_else(|| unavailable("retained archive seal"))?;
            if seal.object != record.object
                || seal.process != record.metadata.scope.process_id
                || seal.runtime.as_str()
                    != preparation
                        .profile()
                        .producer_context
                        .as_v1()
                        .session_id()
                        .as_str()
                || seal.content != record.metadata.content
                || seal.bytes != record.metadata.size_bytes
            {
                return Err(unavailable("retained archive exact custody"));
            }
            let content = Zeroizing::new(self.broker.read_retained_private(seal)?);
            validate_bytes(&record.input, &content)?;
            if content.len() as u64 != record.metadata.size_bytes.get()
                || knowledge_content_digest(&content) != record.metadata.content
            {
                return Err(unavailable("retained archive exact bytes"));
            }
            bytes.extend_from_slice(&content);
        }
        if bytes.len() != frame_size {
            return Err(unavailable("retained archive frame changed"));
        }
        Ok(PreparedRetainedArchiveFrame { manifest, bytes })
    }
}
