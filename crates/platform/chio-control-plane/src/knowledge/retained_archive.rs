//! Fresh storage authority can archive exact custody after execution ends.
use super::*;
use chio_store_sqlite::admission_operation_store::{
    NativeRetainedArchiveInput, NativeRetainedArchivePreparation, NativeRetainedArchiveRequest,
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
        let body = ArtifactArchiveManifestV1 {
            domain_version: VersionV1,
            scope: preparation.profile().scope.clone(),
            root: preparation.root().clone(),
            versions: NonEmptyBoundedList::new(versions).map_err(unavailable)?,
            total_bytes: SafeInteger::new(total).map_err(unavailable)?,
        };
        // Signing need not be deterministic. Reuse the original signature and
        // verify it against the current root and freshly reconstructed body.
        let manifest = match preparation.prior_manifest() {
            Some(prior) => {
                if prior.body() != &body {
                    return Err(unavailable("retained archive original manifest changed"));
                }
                prior.clone()
            }
            None => SignedArtifactArchiveManifestV1::sign_with_backend(body, signer)
                .map_err(unavailable)?,
        };
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

    /// Explicit fresh-admin export of a retained (ended) owner, selected by
    /// the authorized host for exactly this purpose: the ordinary export
    /// path never routes here, so an execution failure cannot be silenced
    /// into a retained success. The archive frame is ephemeral: it is
    /// assembled from the original retained custody into a private
    /// buffer, admitted through the standard release ownership (the native
    /// knowledge observation joins before any byte can be delivered), and
    /// exists nowhere else. No Process copy is staged, so no failure can
    /// leak one. Only the bounded originally signed manifest (already
    /// bounded by MAX_MANIFEST_BYTES) is retained by the release owner so a
    /// replay reproduces the exact frame without a second signing call.
    ///
    /// An uncertain acknowledgement retains the release identity, its source
    /// pins and that original manifest for a deterministic replay, which
    /// rebuilds the frame bytes from the still-pinned sources and
    /// revalidates everything fresh. A delivered request is terminal: its
    /// replay returns the stable delivered outcome under fresh authority
    /// without a new join and without re-delivering bytes. Pending delivery
    /// is recorded as uncertain before sink I/O so interruption preserves
    /// its replay custody.
    pub fn export_retained_archive(
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
        let actor = self.actor(capability, RecoveryPermission::KnowledgeAdmin)?;
        self.current_retained(&actor)?;
        // A request that already reached Delivered under this exact identity
        // returns its stable outcome: no new join, no re-staging, no
        // re-delivery of terminal bytes. Collected sources are not required.
        if let Some(intent) = self
            .store
            .delivered_retained_release(
                &actor,
                request,
                root,
                sink.recipient(),
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?
        {
            return Ok(ArtifactDeliveryOutcomeV1::delivered(&intent));
        }
        let preparation = self
            .store
            .prepare_retained_archive(
                &actor,
                NativeRetainedArchiveRequest {
                    root,
                    request,
                    recipient: sink.recipient(),
                },
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        // Rebuild the private frame from the original manifest and pinned sources.
        let frame = self.assemble_retained_archive(&preparation, signer)?;
        let intent = self
            .store
            .admit_retained_archive(
                &actor,
                &preparation,
                root,
                frame.input(),
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        if intent.state == ArtifactDeliveryStateV1::Delivered {
            // Another export may have finished after the initial status read.
            return Ok(ArtifactDeliveryOutcomeV1::delivered(&intent));
        }
        // Delivery may complete before the host can retain its acknowledgement.
        self.store
            .acknowledge_retained_archive_delivery(
                &actor,
                request,
                &intent,
                false,
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        let delivered = sink.deliver(&intent, &frame.bytes).is_ok();
        self.store
            .acknowledge_retained_archive_delivery(
                &actor,
                request,
                &intent,
                delivered,
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        if !delivered {
            // An uncertain acknowledgement retains the release identity and
            // its source pins for a deterministic replay of this same request.
            return Err(unavailable("delivery uncertain"));
        }
        Ok(ArtifactDeliveryOutcomeV1::delivered(&intent))
    }
}
