//! Host-only immutable blob broker. Activation disables legacy release routes.
use crate::{ProcessError, ProcessRuntime};
use chio_core_types::recovery::knowledge_content_digest;
use chio_kernel::recovery::RecoveryPermission;
use chio_kernel::{knowledge::*, KernelError, SecurityInvocationContext};
use chio_security_types::{knowledge::MAX_ARTIFACT_BYTES, recovery::*};

mod confined_delivery;
mod confined_returns;

#[cfg(feature = "admission-test-support")]
#[path = "knowledge/process_validation_test_support.rs"]
mod process_validation_test_support;

// The feature-only observer runs each original operation once before its
// existing refusal mapping. Feature-off expansion is the original expression.
macro_rules! process_validation_phase {
    ($broker:expr, $process:expr, $stage:ident, $index:expr, $operation:expr) => {{
        #[cfg(feature = "admission-test-support")]
        {
            process_validation_test_support::observe(
                $broker,
                $process,
                process_validation_test_support::ValidationStage::$stage,
                $index,
                || $operation,
            )
        }
        #[cfg(not(feature = "admission-test-support"))]
        {
            $operation
        }
    }};
}
macro_rules! process_validation_identity {
    ($broker:expr, $process:expr, $comparison:expr) => {{
        #[cfg(feature = "admission-test-support")]
        {
            process_validation_test_support::observe_identity($broker, $process, || $comparison)
        }
        #[cfg(not(feature = "admission-test-support"))]
        {
            $comparison
        }
    }};
}

#[cfg(feature = "admission-test-support")]
impl ProcessArtifactBroker {
    /// Enable closed process-validation diagnostics for one checkpoint fixture.
    pub fn observe_checkpoint_process_validation_fixture(
        &self,
        process: &ProcessId,
        request: &RequestId,
    ) -> Result<impl Drop, KernelError> {
        process_validation_test_support::register(self, process, request)
    }
}

/// Trusted host implementation of the private blob staging port. Workers receive
/// only the native mediated runtime, never this broker.
#[derive(Clone)]
pub struct ProcessArtifactBroker {
    runtime: ProcessRuntime,
}
impl ProcessArtifactBroker {
    /// Host-only accounting inspection. This never exposes checkpoint or object bytes.
    pub fn storage_usage(&self, process: &ProcessId) -> Result<crate::ProcessStorage, KernelError> {
        self.runtime
            .with_store(|store| store.knowledge_storage_usage(process.as_str()))
            .map_err(refused)
    }
}
impl ProcessRuntime {
    pub(crate) fn require_raw_knowledge(&self) -> Result<(), ProcessError> {
        if self.kernel.durable_knowledge_enforced(&self.namespace)? {
            return Err(ProcessError::Configuration(
                "durable knowledge requires mediated release",
            ));
        }
        Ok(())
    }
    pub fn enable_durable_knowledge(&self) -> Result<ProcessArtifactBroker, ProcessError> {
        if self.security_profile.is_none() {
            return Err(ProcessError::Configuration(
                "native information flow is required",
            ));
        }
        self.with_store(|store| store.enable_knowledge())?;
        Ok(ProcessArtifactBroker {
            runtime: self.clone(),
        })
    }
}
fn refused(_error: impl std::fmt::Display) -> KernelError {
    KernelError::DurableAdmission("durable knowledge unavailable".into())
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn same_context(left: &SecurityInvocationContext, right: &SecurityInvocationContext) -> bool {
    let left = left.as_v1();
    let right = right.as_v1();
    left.tenant_id() == right.tenant_id()
        && left.session_id() == right.session_id()
        && left.principal_id() == right.principal_id()
        && left.lineage_root_id() == right.lineage_root_id()
        && left.isolation_epoch_id() == right.isolation_epoch_id()
        && left.context_generation() == right.context_generation()
}
impl ArtifactBlobPort for ProcessArtifactBroker {
    fn runtime_id(&self) -> &str {
        self.runtime.runtime_id()
    }
    fn validate_confined_attachment(
        &self,
        boundary: &chio_security_types::confinement::IsolationBoundaryV1,
    ) -> Result<(), KernelError> {
        self.runtime
            .with_store(|store| store.require_enforced_knowledge())
            .map_err(refused)?;
        let lineage = self
            .runtime
            .with_store(|store| store.lineage(boundary.child.as_str()))
            .map_err(refused)?;
        let snapshot = self
            .runtime
            .process(boundary.child.as_str())
            .map_err(refused)?;
        if self.runtime.runtime_id() != boundary.parent.runtime.as_str()
            || lineage.len() != 2
            || snapshot.parent_id.as_deref() != Some(boundary.scope.process_id.as_str())
            || chio_core_types::recovery::confined_capability_digest(&lineage[0])
                .map_err(refused)?
                != boundary.parent_capability
            || chio_core_types::recovery::confined_capability_digest(&lineage[1])
                .map_err(refused)?
                != boundary.child_capability
        {
            return Err(refused("confined attachment"));
        }
        for capability in &lineage {
            self.runtime
                .kernel
                .verify_retained_capability_liveness(&capability.id, &capability.subject)
                .map_err(refused)?;
        }
        Ok(())
    }
    fn validate_process(
        &self,
        process: &ProcessId,
        context: &SecurityInvocationContext,
    ) -> Result<(), KernelError> {
        #[cfg(feature = "admission-test-support")]
        let _validation_call_trace = process_validation_test_support::begin(self, process);
        process_validation_phase!(
            self,
            process,
            EnforcedKnowledge,
            None,
            self.runtime
                .with_store(|store| store.require_enforced_knowledge())
        )
        .map_err(refused)?;
        let current = process_validation_phase!(
            self,
            process,
            RecoverySecurityContext,
            None,
            self.runtime.recovery_security_context(process.as_str())
        )
        .map_err(refused)?;
        if process_validation_identity!(
            self,
            process,
            current.as_v1().tenant_id() != context.as_v1().tenant_id()
                || current.as_v1().session_id() != context.as_v1().session_id()
                || current.as_v1().principal_id() != context.as_v1().principal_id()
                || current.as_v1().lineage_root_id() != context.as_v1().lineage_root_id()
                || current.as_v1().isolation_epoch_id() != context.as_v1().isolation_epoch_id()
                || current.as_v1().context_generation() != context.as_v1().context_generation()
        ) {
            return Err(refused("process identity"));
        }
        let lineage = process_validation_phase!(
            self,
            process,
            RetainedLineage,
            None,
            self.runtime
                .with_store(|store| store.lineage(process.as_str()))
        )
        .map_err(refused)?;
        #[cfg(feature = "admission-test-support")]
        let mut lineage_index = 0usize;
        for capability in &lineage {
            process_validation_phase!(
                self,
                process,
                CapabilityLiveness,
                Some(lineage_index),
                self.runtime
                    .kernel
                    .verify_retained_capability_liveness(&capability.id, &capability.subject)
            )
            .map_err(refused)?;
            #[cfg(feature = "admission-test-support")]
            {
                lineage_index = lineage_index.saturating_add(1);
            }
        }
        // Cancellation uses this same journal serialization. Sample activity
        // last, after native context/liveness reads, so their latency cannot
        // turn an already completed cancellation into release permission.
        process_validation_phase!(
            self,
            process,
            RunningState,
            None,
            self.runtime
                .with_store(|store| store.require_running(process.as_str()))
        )
        .map_err(refused)?;
        Ok(())
    }

    fn reserve_confined_return(
        &self,
        boundary: &chio_security_types::confinement::IsolationBoundaryV1,
    ) -> Result<(), KernelError> {
        let digest = chio_core_types::sha256_hex(
            &chio_core_types::canonical_json_bytes(boundary).map_err(refused)?,
        );
        if self
            .runtime
            .with_store(|store| {
                store.confined_return_slot_matches(
                    boundary.child.as_str(),
                    boundary.scope.process_id.as_str(),
                    boundary.boundary.as_str(),
                    &digest,
                )
            })
            .map_err(refused)?
        {
            return Ok(());
        }
        self.validate_confined_attachment(boundary)?;
        self.runtime
            .with_store(|store| {
                store.reserve_confined_return_slot(
                    boundary.child.as_str(),
                    boundary.scope.process_id.as_str(),
                    boundary.boundary.as_str(),
                    &digest,
                )
            })
            .map_err(refused)
    }

    fn validate_retained_owner(
        &self,
        process: &ProcessId,
        context: &SecurityInvocationContext,
    ) -> Result<(), KernelError> {
        let (snapshot, lineage) = self
            .runtime
            .with_store(|store| {
                store.require_enforced_knowledge()?;
                store.retained_lineage(process.as_str())
            })
            .map_err(refused)?;
        let actual = match self.runtime.enforcement.confined_context(
            self.runtime.runtime_id(),
            &snapshot.root_id,
            &snapshot.id,
            &lineage,
        )? {
            Some(actual) => actual,
            None => {
                let profile = self
                    .runtime
                    .security_profile
                    .as_ref()
                    .ok_or_else(|| refused("retained native profile"))?;
                let root = lineage.first().ok_or_else(|| refused("retained lineage"))?;
                profile
                    .context(
                        self.runtime.runtime_id(),
                        snapshot.capability.subject.to_hex(),
                        &root.id,
                    )
                    .map_err(refused)?
            }
        };
        if !same_context(&actual, context) {
            return Err(refused("retained process identity"));
        }
        Ok(())
    }

    fn stage_confined_return(
        &self,
        actor: &chio_kernel::recovery::AuthenticatedRecoveryActor,
        boundary: &chio_security_types::confinement::IsolationBoundaryV1,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        self.stage_verified_confined_return(actor, boundary, bytes)
    }

    fn begin_confined_delivery(
        &self,
        actor: &chio_kernel::recovery::AuthenticatedRecoveryActor,
        request: &RequestId,
        seal: &ArtifactBlobSealV1,
        admission: &chio_security_types::confinement::ReturnAdmissionV1,
    ) -> Result<(), KernelError> {
        self.begin_verified_confined_delivery(actor, request, seal, admission)
    }

    fn stage_retained_archive(
        &self,
        actor: &chio_kernel::recovery::AuthenticatedRecoveryActor,
        context: &SecurityInvocationContext,
        object: &ArtifactObjectId,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || bytes.len() > MAX_ARTIFACT_BYTES
        {
            return Err(refused("retained archive authority"));
        }
        let fresh = self
            .runtime
            .kernel
            .authenticate_recovery_actor(
                actor.scope(),
                actor.capability(),
                RecoveryPermission::KnowledgeAdmin,
            )
            .map_err(refused)?;
        if fresh.principal() != actor.principal() || fresh.scope() != actor.scope() {
            return Err(refused("retained archive actor"));
        }
        self.validate_retained_owner(&actor.scope().process_id, context)?;
        let generation = self
            .runtime
            .with_store(|store| {
                store.stage_retained_archive_object(
                    actor.scope().process_id.as_str(),
                    object.as_str(),
                    bytes,
                )
            })
            .map_err(refused)?;
        Ok(ArtifactBlobSealV1 {
            object: object.clone(),
            runtime: ProtectedText::new(self.runtime_id()).map_err(refused)?,
            process: actor.scope().process_id.clone(),
            content: knowledge_content_digest(bytes),
            bytes: SafeInteger::new(bytes.len() as u64).map_err(refused)?,
            generation: ProtectedText::new(&format!("object:{generation}")).map_err(refused)?,
        })
    }
    fn stage(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(refused("byte bound"));
        }
        let (snapshot, lineage) = self
            .runtime
            .with_store(|store| {
                Ok((
                    store.process(process.as_str())?,
                    store.lineage(process.as_str())?,
                ))
            })
            .map_err(refused)?;
        if self
            .runtime
            .enforcement
            .confined_context(
                self.runtime.runtime_id(),
                &snapshot.root_id,
                &snapshot.id,
                &lineage,
            )?
            .is_some()
        {
            return Err(refused("confined objects require verified return staging"));
        }
        let generation = self
            .runtime
            .with_store(|store| {
                store.stage_knowledge_object(process.as_str(), object.as_str(), bytes)
            })
            .map_err(refused)?;
        Ok(ArtifactBlobSealV1 {
            object: object.clone(),
            runtime: ProtectedText::new(self.runtime_id()).map_err(refused)?,
            process: process.clone(),
            content: knowledge_content_digest(bytes),
            bytes: SafeInteger::new(bytes.len() as u64).map_err(refused)?,
            generation: ProtectedText::new(&format!("object:{generation}")).map_err(refused)?,
        })
    }
    fn resolve_private(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        content: CanonicalPayloadDigest,
        bytes: SafeInteger,
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        let generation = self
            .runtime
            .with_store(|store| {
                match store.object_generation(
                    process.as_str(),
                    object.as_str(),
                    &hex(content.as_bytes()),
                )? {
                    Some(generation) => Ok(format!("object:{generation}")),
                    None => store.knowledge_generation(process.as_str(), &hex(content.as_bytes())),
                }
            })
            .map_err(refused)?;
        let seal = ArtifactBlobSealV1 {
            object: object.clone(),
            runtime: ProtectedText::new(self.runtime_id()).map_err(refused)?,
            process: process.clone(),
            content,
            bytes,
            generation: ProtectedText::new(&generation).map_err(refused)?,
        };
        self.read_private(&seal)?;
        Ok(seal)
    }
    fn read_private(&self, seal: &ArtifactBlobSealV1) -> Result<Vec<u8>, KernelError> {
        if seal.generation.as_str().starts_with("confined:") {
            return self.read_confined_slot(seal, false);
        }
        if seal.runtime.as_str() != self.runtime_id()
            || seal.bytes.get() > MAX_ARTIFACT_BYTES as u64
        {
            return Err(refused("seal"));
        }
        let bytes = self
            .runtime
            .with_store(|store| {
                store.require_enforced_knowledge()?;
                match store.read_knowledge_object(
                    seal.process.as_str(),
                    seal.object.as_str(),
                    &hex(seal.content.as_bytes()),
                    seal.generation.as_str(),
                )? {
                    Some(bytes) => Ok(bytes),
                    None if seal.generation.as_str().starts_with("object:") => {
                        Err(ProcessError::BlobMissing)
                    }
                    None => store.read_knowledge_blob(
                        seal.process.as_str(),
                        &hex(seal.content.as_bytes()),
                        seal.generation.as_str(),
                    ),
                }
            })
            .map_err(refused)?;
        if bytes.len() as u64 != seal.bytes.get()
            || knowledge_content_digest(&bytes) != seal.content
        {
            return Err(refused("immutable bytes"));
        }
        Ok(bytes)
    }

    fn resolve_retained_private(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        content: CanonicalPayloadDigest,
        bytes: SafeInteger,
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        let generation = self
            .runtime
            .with_store(|store| {
                match store.retained_object_generation(
                    process.as_str(),
                    object.as_str(),
                    &hex(content.as_bytes()),
                )? {
                    Some(generation) => Ok(format!("object:{generation}")),
                    None => store
                        .retained_knowledge_generation(process.as_str(), &hex(content.as_bytes())),
                }
            })
            .map_err(refused)?;
        let seal = ArtifactBlobSealV1 {
            object: object.clone(),
            runtime: ProtectedText::new(self.runtime_id()).map_err(refused)?,
            process: process.clone(),
            content,
            bytes,
            generation: ProtectedText::new(&generation).map_err(refused)?,
        };
        self.read_retained_private(&seal)?;
        Ok(seal)
    }

    fn read_retained_private(&self, seal: &ArtifactBlobSealV1) -> Result<Vec<u8>, KernelError> {
        if seal.generation.as_str().starts_with("confined:") {
            return self.read_confined_slot(seal, true);
        }
        if seal.runtime.as_str() != self.runtime_id()
            || seal.bytes.get() > MAX_ARTIFACT_BYTES as u64
        {
            return Err(refused("retained seal"));
        }
        let bytes = self
            .runtime
            .with_store(|store| {
                match store.read_retained_knowledge_object(
                    seal.process.as_str(),
                    seal.object.as_str(),
                    &hex(seal.content.as_bytes()),
                    seal.generation.as_str(),
                )? {
                    Some(bytes) => Ok(bytes),
                    None if seal.generation.as_str().starts_with("object:") => {
                        Err(ProcessError::BlobMissing)
                    }
                    None => store.read_retained_knowledge_blob(
                        seal.process.as_str(),
                        &hex(seal.content.as_bytes()),
                        seal.generation.as_str(),
                    ),
                }
            })
            .map_err(refused)?;
        if bytes.len() as u64 != seal.bytes.get()
            || knowledge_content_digest(&bytes) != seal.content
        {
            return Err(refused("retained immutable bytes"));
        }
        Ok(bytes)
    }
    fn collect_private(&self, seal: &ArtifactBlobSealV1) -> Result<(), KernelError> {
        if seal.runtime.as_str() != self.runtime_id() {
            return Err(refused("runtime"));
        }
        if seal.generation.as_str().starts_with("confined:") {
            return Err(refused(
                "confined slot custody cannot use generic collection",
            ));
        }
        self.runtime
            .with_store(|store| {
                if store.collect_knowledge_object(
                    seal.process.as_str(),
                    seal.object.as_str(),
                    &hex(seal.content.as_bytes()),
                    seal.generation.as_str(),
                )? {
                    Ok(())
                } else {
                    store.collect_blob(
                        seal.process.as_str(),
                        &hex(seal.content.as_bytes()),
                        seal.generation.as_str(),
                    )
                }
            })
            .map_err(refused)
    }
}
