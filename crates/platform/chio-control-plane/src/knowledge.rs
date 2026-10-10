//! Host-selected durable knowledge composition over the original native authority.
#![forbid(unsafe_code)]
use chio_core_types::{capability::token::CapabilityToken, recovery::*};
use chio_kernel::{knowledge::*, recovery::*, ChioKernel, KernelError};
use chio_security_types::{knowledge::*, recovery::*};
use chio_store_sqlite::admission_operation_store::{
    ArtifactPublicationInputV1, ArtifactPublicationViewV1, NativeArtifactRecordV1,
    NativeKnowledgeInstallationV1, SqliteAdmissionOperationStore,
};
use std::sync::Arc;
use zeroize::Zeroizing;

mod checkpoints;
mod outcome;
mod transfer;
pub use outcome::ArtifactDeliveryOutcomeV1;

/// Local profile owns bytes and native metadata separately. Every public action
/// reauthenticates against the kernel; the writer repeats current checks.
#[derive(Clone)]
pub struct NativeKnowledgeRuntime {
    kernel: Arc<ChioKernel>,
    store: Arc<SqliteAdmissionOperationStore>,
    broker: Arc<dyn ArtifactBlobPort>,
    profile: NativeKnowledgeInstallationV1,
    fence: chio_kernel::admission_operation::StoreMutationFence,
    #[cfg(test)]
    test_cutpoint: Option<KnowledgeFaultObserver>,
}
/// Private verified buffer. It cannot be cloned, decoded, or accessed before
/// the serving authority records its native observation and release intent.
///
/// ```compile_fail
/// use chio_control_plane::knowledge::PreparedArtifactRead;
/// let _: PreparedArtifactRead = serde_json::from_str("{}").unwrap_or_else(|e|panic!("{e}"));
/// ```
/// ```compile_fail
/// use chio_control_plane::knowledge::PreparedArtifactRead;
/// fn duplicate(read: PreparedArtifactRead) { let _ = read.clone(); }
/// ```
pub struct PreparedArtifactRead {
    record: NativeArtifactRecordV1,
    handle: ArtifactHandleV1,
    bytes: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for PreparedArtifactRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedArtifactRead([redacted])")
    }
}
fn unavailable(_error: impl std::fmt::Display) -> KernelError {
    KernelError::DurableAdmission("durable knowledge unavailable".into())
}
fn now() -> Result<u64, KernelError> {
    #[cfg(test)]
    if let Some(seconds) = chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        return seconds
            .checked_mul(1_000)
            .ok_or_else(|| unavailable("selected clock overflow"));
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(unavailable)
        .and_then(|time| u64::try_from(time.as_millis()).map_err(unavailable))
}
impl NativeKnowledgeRuntime {
    pub(crate) fn same_setup_mediator(&self, other: &Self) -> Result<bool, KernelError> {
        Ok(Arc::ptr_eq(&self.kernel, &other.kernel)
            && Arc::ptr_eq(&self.broker, &other.broker)
            && self.fence == other.fence
            && chio_core_types::canonical_json_bytes(&self.profile).map_err(unavailable)?
                == chio_core_types::canonical_json_bytes(&other.profile).map_err(unavailable)?)
    }
    pub(crate) fn validate_setup_binding(
        &self,
        scope: &RecoveryScopeV1,
        native: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    ) -> Result<(), KernelError> {
        if &self.profile.scope != scope || &self.profile.native_authority != native {
            return Err(unavailable("setup broker binding"));
        }
        self.broker.validate_process(
            &self.profile.scope.process_id,
            &self.profile.producer_context,
        )?;
        self.store
            .validate_current_knowledge_installation(&self.profile, &self.fence, now()?)
            .map_err(unavailable)
    }
    pub fn new(
        kernel: Arc<ChioKernel>,
        store: Arc<SqliteAdmissionOperationStore>,
        broker: Arc<dyn ArtifactBlobPort>,
        profile: NativeKnowledgeInstallationV1,
        fence: chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<Self, KernelError> {
        if kernel.durable_authority_id() != Some(profile.scope.authority_domain.as_str())
            || profile.scope.authority_domain.as_str() != fence.store_uuid
            || broker.runtime_id() != profile.producer_context.as_v1().session_id().as_str()
        {
            return Err(unavailable("authority selection"));
        }
        broker.validate_process(&profile.scope.process_id, &profile.producer_context)?;
        store.configure_knowledge(&profile).map_err(unavailable)?;
        Ok(Self {
            kernel,
            store,
            broker,
            profile,
            fence,
            #[cfg(test)]
            test_cutpoint: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn with_test_cutpoint(mut self, observer: KnowledgeFaultObserver) -> Self {
        self.test_cutpoint = Some(observer);
        self
    }
    fn cutpoint(&self, stage: KnowledgeCutpoint) -> Result<(), KernelError> {
        #[cfg(test)]
        if let Some(observer) = &self.test_cutpoint {
            return observer(stage);
        }
        let _ = stage;
        Ok(())
    }
    fn actor(
        &self,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, KernelError> {
        self.kernel
            .authenticate_recovery_actor(&self.profile.scope, capability, permission)
            .map_err(unavailable)
    }
    fn current(
        &self,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<NativeKnowledgeInstallationV1, KernelError> {
        checkpoints::checkpoint_restore_phase!(
            self,
            ProducerBrokerValidation,
            self.broker.validate_process(
                &self.profile.scope.process_id,
                &self.profile.producer_context,
            )
        )?;
        checkpoints::checkpoint_restore_phase!(
            self,
            ProducerInstallationLookup,
            self.store
                .knowledge_installation(actor, &self.fence, now()?)
                .map_err(unavailable)
        )
    }

    fn current_retained(
        &self,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<NativeKnowledgeInstallationV1, KernelError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(unavailable("retained storage authority"));
        }
        let current = self
            .store
            .retained_knowledge_installation(actor, &self.fence, now()?)
            .map_err(unavailable)?;
        self.broker
            .validate_retained_owner(&current.scope.process_id, &current.producer_context)?;
        Ok(current)
    }
    /// Reservations precede all byte storage. Reconciliation reuses the exact
    /// original publication key, metadata and stage, including lost acknowledgements.
    pub fn reserve(
        &self,
        capability: &CapabilityToken,
        input: &ArtifactPublicationInputV1,
    ) -> Result<ArtifactPublicationViewV1, KernelError> {
        let permission = if matches!(input.producer, ArtifactProducerV1::Adoption { .. }) {
            RecoveryPermission::KnowledgeAdopt
        } else {
            RecoveryPermission::KnowledgeWrite
        };
        let actor = self.actor(capability, permission)?;
        self.current(&actor)?;
        self.store
            .reserve_artifact(&actor, input, &self.fence, now()?)
            .map(ArtifactPublicationViewV1::from)
            .map_err(unavailable)
    }
    pub fn publish(
        &self,
        capability: &CapabilityToken,
        input: &ArtifactPublicationInputV1,
        bytes: &[u8],
        certificate: Option<&SignedArtifactCertificateV1>,
    ) -> Result<ArtifactVersionRefV1, KernelError> {
        validate_bytes(input, bytes)?;
        let permission = if matches!(input.producer, ArtifactProducerV1::Adoption { .. }) {
            RecoveryPermission::KnowledgeAdopt
        } else {
            RecoveryPermission::KnowledgeWrite
        };
        let actor = self.actor(capability, permission)?;
        self.current(&actor)?;
        let record = self
            .store
            .reserve_artifact(&actor, input, &self.fence, now()?)
            .map_err(unavailable)?;
        if matches!(
            record.state,
            ArtifactPublicationStateV1::Quarantined | ArtifactPublicationStateV1::Retired
        ) {
            return Err(unavailable("quarantined"));
        }
        self.cutpoint(KnowledgeCutpoint::Reserved)?;
        let seal = match record.seal {
            Some(seal) => {
                let retained = match self.broker.read_private(&seal) {
                    Ok(bytes) => Zeroizing::new(bytes),
                    Err(_) => {
                        self.store
                            .quarantine_artifact(&actor, input, &self.fence, now()?)
                            .map_err(unavailable)?;
                        return Err(unavailable("existing object missing or corrupt"));
                    }
                };
                if retained.as_slice() != bytes {
                    return Err(unavailable("existing object differs"));
                }
                seal
            }
            None => self
                .broker
                .stage(&record.object, &self.profile.scope.process_id, bytes)?,
        };
        self.cutpoint(KnowledgeCutpoint::BlobStaged)?;
        self.store
            .stage_artifact(&actor, input, &seal, &self.fence, now()?)
            .map_err(unavailable)?;
        self.cutpoint(KnowledgeCutpoint::StageRetained)?;
        self.store
            .commit_artifact_metadata(&actor, input, certificate, &self.fence, now()?)
            .map_err(unavailable)?;
        self.cutpoint(KnowledgeCutpoint::MetadataCommitted)?;
        let staged = match self.broker.read_private(&seal) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => {
                self.store
                    .quarantine_artifact(&actor, input, &self.fence, now()?)
                    .map_err(unavailable)?;
                return Err(unavailable("sealed object missing"));
            }
        };
        if staged.as_slice() != bytes {
            self.store
                .quarantine_artifact(&actor, input, &self.fence, now()?)
                .map_err(unavailable)?;
            return Err(unavailable("sealed bytes differ"));
        }
        self.current(&actor)?;
        let reference = self
            .store
            .finalize_artifact(&actor, input, &seal, &self.fence, now()?)
            .map_err(unavailable)?;
        self.cutpoint(KnowledgeCutpoint::AvailabilityCommitted)?;
        Ok(reference)
    }
    pub fn handle(
        &self,
        capability: &CapabilityToken,
        reference: &ArtifactVersionRefV1,
        recipient: &ArtifactRecipientId,
    ) -> Result<ArtifactHandleV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        self.current(&actor)?;
        self.store
            .issue_artifact_handle(&actor, reference, recipient, &self.fence, now()?)
            .map_err(unavailable)
    }
    pub fn prepare_read(
        &self,
        capability: &CapabilityToken,
        handle: &ArtifactHandleV1,
    ) -> Result<PreparedArtifactRead, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        let profile = self.current(&actor)?;
        let (record, recipient) = self
            .store
            .prepare_artifact_read(&actor, handle, &self.fence, now()?)
            .map_err(unavailable)?;
        self.broker
            .validate_process(&recipient.recipient.scope.process_id, &recipient.context)?;
        let seal = record
            .seal
            .as_ref()
            .ok_or_else(|| unavailable("missing immutable object"))?;
        let bytes = match self.broker.read_private(seal) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => {
                self.store
                    .quarantine_artifact_version(
                        &actor,
                        &artifact_version_reference(&record.metadata).map_err(unavailable)?,
                        &self.fence,
                        now()?,
                    )
                    .map_err(unavailable)?;
                return Err(unavailable("missing immutable object"));
            }
        };
        if profile.policy != record.metadata.policy || profile.contract != record.metadata.contract
        {
            return Err(unavailable("stale record policy"));
        }
        validate_bytes(&record.input, &bytes)?;
        Ok(PreparedArtifactRead {
            record,
            handle: handle.clone(),
            bytes,
        })
    }
    pub fn release_into(
        &self,
        capability: &CapabilityToken,
        request: &RequestId,
        prepared: PreparedArtifactRead,
        sink: &dyn ArtifactReleaseSink,
    ) -> Result<ArtifactDeliveryOutcomeV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        let profile = self.current(&actor)?;
        let selection = profile
            .recipients
            .as_slice()
            .iter()
            .find(|selection| selection.recipient.recipient == prepared.handle.recipient)
            .ok_or_else(|| unavailable("recipient"))?;
        if &selection.recipient != sink.recipient() {
            return Err(unavailable("sink identity"));
        }
        self.broker
            .validate_process(&selection.recipient.scope.process_id, &selection.context)?;
        let seal = prepared
            .record
            .seal
            .as_ref()
            .ok_or_else(|| unavailable("seal"))?;
        let exact = Zeroizing::new(self.broker.read_private(seal)?);
        if exact.as_slice() != prepared.bytes.as_slice() {
            return Err(unavailable("object mutation"));
        }
        // This writer either commits and acknowledges the exact original intent,
        // or withholds. Repeating the same request performs anchored readback.
        let intent = self
            .store
            .admit_artifact_release(&actor, &prepared.handle, request, seal, &self.fence, now()?)
            .map_err(unavailable)?;
        self.cutpoint(KnowledgeCutpoint::ReleaseCommitted)?;
        self.cutpoint(KnowledgeCutpoint::BeforeDelivery)?;
        // Sink I/O may complete before the host can retain its acknowledgement.
        // Persist unknown delivery before crossing that independently owned boundary.
        self.store
            .acknowledge_artifact_delivery(&actor, request, &intent, false, &self.fence, now()?)
            .map_err(unavailable)?;
        let delivered = sink.deliver(&intent, &prepared.bytes).is_ok();
        self.cutpoint(KnowledgeCutpoint::DeliveryCompleted)?;
        self.store
            .acknowledge_artifact_delivery(&actor, request, &intent, delivered, &self.fence, now()?)
            .map_err(unavailable)?;
        if !delivered {
            return Err(unavailable("delivery uncertain"));
        }
        Ok(ArtifactDeliveryOutcomeV1::delivered(&intent))
    }
    pub fn abort_publication(
        &self,
        capability: &CapabilityToken,
        input: &ArtifactPublicationInputV1,
    ) -> Result<(), KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeAdmin)?;
        self.current_retained(&actor)?;
        let record = self
            .store
            .artifact_publication_for_collection(&actor, input, &self.fence, now()?)
            .map_err(unavailable)?;
        let orphan = record.seal.or_else(|| {
            self.broker
                .resolve_retained_private(
                    &record.object,
                    &self.profile.scope.process_id,
                    input.content,
                    input.size_bytes,
                )
                .ok()
        });
        if let Some(seal) = self
            .store
            .abort_artifact_publication(&actor, input, orphan.as_ref(), &self.fence, now()?)
            .map_err(unavailable)?
        {
            self.broker.collect_private(&seal)?;
            self.store
                .finish_artifact_collection(&actor, &seal, &self.fence, now()?)
                .map_err(unavailable)?;
        }
        Ok(())
    }
    pub fn collect(
        &self,
        capability: &CapabilityToken,
        reference: &ArtifactVersionRefV1,
    ) -> Result<(), KernelError> {
        let actor = self.actor(capability, RecoveryPermission::KnowledgeAdmin)?;
        self.current_retained(&actor)?;
        if let Some(seal) = self
            .store
            .retire_artifact(&actor, reference, &self.fence, now()?)
            .map_err(unavailable)?
        {
            self.cutpoint(KnowledgeCutpoint::CollectionRetired)?;
            self.broker.collect_private(&seal)?;
            self.cutpoint(KnowledgeCutpoint::BlobCollected)?;
            self.store
                .finish_artifact_collection(&actor, &seal, &self.fence, now()?)
                .map_err(unavailable)?;
        }
        Ok(())
    }
}
fn validate_bytes(input: &ArtifactPublicationInputV1, bytes: &[u8]) -> Result<(), KernelError> {
    if bytes.len() > MAX_ARTIFACT_BYTES
        || bytes.len() as u64 != input.size_bytes.get()
        || knowledge_content_digest(bytes) != input.content
    {
        return Err(unavailable("byte commitment"));
    }
    match input.media_type.as_str() {
        "application/octet-stream"
            if input.schema == knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1") => {}
        "application/json"
            if input.schema == knowledge_content_digest(b"chio.knowledge.canonical-json.v1") =>
        {
            let value: serde_json::Value = decode_contract(bytes).map_err(unavailable)?;
            if chio_core_types::canonical_json_bytes(&value).map_err(unavailable)? != bytes {
                return Err(unavailable("canonical JSON"));
            }
        }
        _ => return Err(unavailable("unsupported schema")),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KnowledgeCutpoint {
    Reserved,
    BlobStaged,
    StageRetained,
    MetadataCommitted,
    AvailabilityCommitted,
    ReleaseCommitted,
    BeforeDelivery,
    DeliveryCompleted,
    CollectionRetired,
    BlobCollected,
}

#[cfg(test)]
type KnowledgeFaultObserver =
    Arc<dyn Fn(KnowledgeCutpoint) -> Result<(), KernelError> + Send + Sync>;
