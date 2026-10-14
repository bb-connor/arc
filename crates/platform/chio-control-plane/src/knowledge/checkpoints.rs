use super::*;

impl NativeKnowledgeRuntime {
    /// Retire an exact revision under fresh native administrator authority.
    pub fn retire_checkpoint_revision(
        &self,
        capability: &CapabilityToken,
        checkpoint: &CheckpointId,
        revision: u64,
    ) -> Result<(), KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeAdmin)?;
        self.current_retained(&actor)?;
        self.store
            .retire_checkpoint_revision(&actor, checkpoint, revision, &self.fence, now()?)
            .map_err(unavailable)
    }

    pub fn checkpoint(
        &self,
        capability: &CapabilityToken,
        id: &CheckpointId,
        expected_revision: u64,
        artifacts: &[ArtifactVersionRefV1],
        models: &[ModelContextV1],
    ) -> Result<LabeledCheckpointV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeWrite)?;
        self.current(&actor)?;
        self.store
            .save_labeled_checkpoint(
                &actor,
                chio_store_sqlite::admission_operation_store::NativeCheckpointUpdate {
                    checkpoint: id,
                    expected_revision,
                    artifacts,
                    model_contexts: models,
                },
                &self.fence,
                now()?,
            )
            .map_err(unavailable)
    }
}
impl NativeKnowledgeRuntime {
    /// Restoration emits a bounded protected checkpoint envelope and exact bytes into
    /// a host-selected sink only after the native monotone observation commits.
    pub fn restore_into(
        &self,
        capability: &CapabilityToken,
        id: &CheckpointId,
        revision: u64,
        request: &RequestId,
        sink: &dyn ArtifactReleaseSink,
    ) -> Result<ArtifactDeliveryOutcomeV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        let profile = self.current(&actor)?;
        let checkpoint = self
            .store
            .read_labeled_checkpoint(&actor, id, revision, &self.fence, now()?)
            .map_err(unavailable)?;
        let selection = profile
            .recipients
            .as_slice()
            .iter()
            .find(|entry| &entry.recipient == sink.recipient())
            .ok_or_else(|| unavailable("restore recipient"))?;
        self.broker
            .validate_process(&selection.recipient.scope.process_id, &selection.context)?;
        let mut body = Zeroizing::new(Vec::new());
        let envelope = chio_core_types::canonical_json_bytes(&checkpoint).map_err(unavailable)?;
        if envelope.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
            return Err(unavailable("restore envelope bound"));
        }
        body.extend_from_slice(
            &u32::try_from(envelope.len())
                .map_err(unavailable)?
                .to_be_bytes(),
        );
        body.extend_from_slice(&envelope);
        let mut material = checkpoint.artifacts.as_slice().to_vec();
        for model in checkpoint.model_contexts.as_slice() {
            for reference in model.side_files.as_slice() {
                if !material.contains(reference) {
                    material.push(reference.clone());
                }
            }
        }
        let mut reads = Vec::new();
        for reference in &material {
            let (record, bytes) = self.read_for_recipient(
                &actor,
                &profile,
                reference,
                &selection.recipient.recipient,
            )?;
            let next = body
                .len()
                .checked_add(4)
                .and_then(|size| size.checked_add(bytes.len()))
                .ok_or_else(|| unavailable("restore byte overflow"))?;
            if next > MAX_ARTIFACT_BYTES + MAX_CHECKPOINT_ENVELOPE_BYTES {
                return Err(unavailable("restore byte bound"));
            }
            body.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(unavailable)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(&bytes);
            reads.push((record, bytes));
        }
        self.current(&actor)?;
        self.broker
            .validate_process(&selection.recipient.scope.process_id, &selection.context)?;
        for (record, bytes) in &reads {
            let exact = Zeroizing::new(
                self.broker.read_private(
                    record
                        .seal
                        .as_ref()
                        .ok_or_else(|| unavailable("restore seal"))?,
                )?,
            );
            if exact.as_slice() != bytes.as_slice() {
                return Err(unavailable("restore object changed"));
            }
        }
        let intent = self
            .store
            .admit_checkpoint_restore(
                &actor,
                chio_store_sqlite::admission_operation_store::NativeCheckpointRestore {
                    checkpoint: &checkpoint,
                    recipient: &selection.recipient,
                    request,
                    installation_generation: profile.generation,
                },
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        self.cutpoint(KnowledgeCutpoint::ReleaseCommitted)?;
        self.cutpoint(KnowledgeCutpoint::BeforeDelivery)?;
        self.store
            .acknowledge_checkpoint_delivery(&actor, request, &intent, false, &self.fence, now()?)
            .map_err(unavailable)?;
        let delivered = sink.deliver(&intent, &body).is_ok();
        self.cutpoint(KnowledgeCutpoint::DeliveryCompleted)?;
        self.store
            .acknowledge_checkpoint_delivery(
                &actor,
                request,
                &intent,
                delivered,
                &self.fence,
                now()?,
            )
            .map_err(unavailable)?;
        if !delivered {
            return Err(unavailable("restore delivery uncertain"));
        }
        Ok(ArtifactDeliveryOutcomeV1::delivered(&intent))
    }
}
