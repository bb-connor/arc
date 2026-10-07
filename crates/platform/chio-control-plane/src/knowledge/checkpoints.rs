use super::*;

#[cfg(test)]
#[path = "checkpoints/restore_phase_test_support.rs"]
pub(super) mod restore_phase_test_support;

// Test instrumentation evaluates each original Result once. Production builds
// expand directly to the original expression and include no observer state.
macro_rules! checkpoint_restore_phase {
    ($runtime:expr, $stage:ident, $operation:expr) => {{
        #[cfg(test)]
        {
            $crate::knowledge::checkpoints::restore_phase_test_support::observe(
                $runtime,
                $crate::knowledge::checkpoints::restore_phase_test_support::RestoreStage::$stage,
                || $operation,
            )
        }
        #[cfg(not(test))]
        {
            $operation
        }
    }};
}
pub(super) use checkpoint_restore_phase;

#[cfg(test)]
impl NativeKnowledgeRuntime {
    pub(crate) fn observe_checkpoint_restore_stages_for_test(
        &self,
        request: &RequestId,
    ) -> Result<impl Drop, KernelError> {
        restore_phase_test_support::register(self, request)
    }
}
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
        #[cfg(test)]
        let _restore_call_trace = restore_phase_test_support::begin(self, request);
        let actor = checkpoint_restore_phase!(
            self,
            AuthenticateActor,
            self.actor(capability, RecoveryPermission::KnowledgeRead)
        )?;
        let profile = checkpoint_restore_phase!(self, InitialCurrent, self.current(&actor))?;
        let checkpoint = checkpoint_restore_phase!(
            self,
            CheckpointLookup,
            self.store
                .read_labeled_checkpoint(&actor, id, revision, &self.fence, now()?)
                .map_err(unavailable)
        )?;
        let selection = checkpoint_restore_phase!(
            self,
            RecipientSelection,
            profile
                .recipients
                .as_slice()
                .iter()
                .find(|entry| &entry.recipient == sink.recipient())
                .ok_or_else(|| unavailable("restore recipient"))
        )?;
        checkpoint_restore_phase!(
            self,
            InitialRecipientValidation,
            self.broker
                .validate_process(&selection.recipient.scope.process_id, &selection.context)
        )?;
        let mut body = Zeroizing::new(Vec::new());
        let envelope = checkpoint_restore_phase!(
            self,
            CheckpointCanonicalEnvelope,
            chio_core_types::canonical_json_bytes(&checkpoint).map_err(unavailable)
        )?;
        if envelope.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
            return checkpoint_restore_phase!(
                self,
                EnvelopeBound,
                Err(unavailable("restore envelope bound"))
            );
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
            let handle = checkpoint_restore_phase!(
                self,
                ArtifactHandle,
                self.handle(capability, reference, &selection.recipient.recipient)
            )?;
            let prepared = checkpoint_restore_phase!(
                self,
                ArtifactPreparedRead,
                self.prepare_read(capability, &handle)
            )?;
            let next = body
                .len()
                .checked_add(4)
                .and_then(|size| size.checked_add(prepared.bytes.len()))
                .ok_or_else(|| unavailable("restore byte overflow"))?;
            if next > MAX_ARTIFACT_BYTES + MAX_CHECKPOINT_ENVELOPE_BYTES {
                return checkpoint_restore_phase!(
                    self,
                    FrameByteBound,
                    Err(unavailable("restore byte bound"))
                );
            }
            body.extend_from_slice(
                &u32::try_from(prepared.bytes.len())
                    .map_err(unavailable)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(&prepared.bytes);
            reads.push(prepared);
        }
        checkpoint_restore_phase!(self, CurrentRecheck, self.current(&actor))?;
        checkpoint_restore_phase!(
            self,
            FinalRecipientValidation,
            self.broker
                .validate_process(&selection.recipient.scope.process_id, &selection.context)
        )?;
        for prepared in &reads {
            let exact = Zeroizing::new(checkpoint_restore_phase!(
                self,
                PrivateSealRead,
                self.broker.read_private(
                    prepared
                        .record
                        .seal
                        .as_ref()
                        .ok_or_else(|| unavailable("restore seal"))?,
                )
            )?);
            if exact.as_slice() != prepared.bytes.as_slice() {
                return checkpoint_restore_phase!(
                    self,
                    PrivateSealEquality,
                    Err(unavailable("restore object changed"))
                );
            }
        }
        let intent = checkpoint_restore_phase!(
            self,
            RetainedAdmission,
            self.store
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
                .map_err(unavailable)
        )?;
        checkpoint_restore_phase!(
            self,
            ReleaseCommittedCutpoint,
            self.cutpoint(KnowledgeCutpoint::ReleaseCommitted)
        )?;
        checkpoint_restore_phase!(
            self,
            BeforeDeliveryCutpoint,
            self.cutpoint(KnowledgeCutpoint::BeforeDelivery)
        )?;
        checkpoint_restore_phase!(
            self,
            UncertainAcknowledgement,
            self.store
                .acknowledge_checkpoint_delivery(
                    &actor,
                    request,
                    &intent,
                    false,
                    &self.fence,
                    now()?
                )
                .map_err(unavailable)
        )?;
        let delivered =
            checkpoint_restore_phase!(self, SinkDelivery, sink.deliver(&intent, &body)).is_ok();
        checkpoint_restore_phase!(
            self,
            DeliveryCompletedCutpoint,
            self.cutpoint(KnowledgeCutpoint::DeliveryCompleted)
        )?;
        checkpoint_restore_phase!(
            self,
            DeliveryAcknowledgement,
            self.store
                .acknowledge_checkpoint_delivery(
                    &actor,
                    request,
                    &intent,
                    delivered,
                    &self.fence,
                    now()?,
                )
                .map_err(unavailable)
        )?;
        if !delivered {
            return checkpoint_restore_phase!(
                self,
                DeliveryResult,
                Err(unavailable("restore delivery uncertain"))
            );
        }
        Ok(ArtifactDeliveryOutcomeV1::delivered(&intent))
    }
}
