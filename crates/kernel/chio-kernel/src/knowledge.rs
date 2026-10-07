//! Trusted host seams for durable bytes. Descriptions never confer read authority.
#![forbid(unsafe_code)]
use chio_security_types::{knowledge::*, recovery::*};
use serde::{Deserialize, Serialize};

/// Read-only anchored profile probe. Native process services retain the serving
/// port and fence, rather than an Arc back to the kernel that owns them.
#[derive(Clone)]
pub struct DurableKnowledgeEnforcement {
    pub(crate) store: std::sync::Arc<dyn crate::admission_operation::AdmissionOperationStore>,
    pub(crate) fence: crate::admission_operation::StoreMutationFence,
}
impl DurableKnowledgeEnforcement {
    pub fn verify_confined_attachment(
        &self,
        input: crate::admission_operation::ConfinedProcessAttachment<'_>,
    ) -> Result<(), crate::KernelError> {
        if !self.enforced(input.runtime)? {
            return Ok(());
        }
        self.store
            .verify_confined_process_attachment(
                input,
                &self.fence,
                crate::kernel::current_unix_timestamp_ms(),
            )
            .map_err(|_| {
                crate::KernelError::DurableAdmission("confined attachment unavailable".into())
            })
    }
    pub fn confined_context(
        &self,
        runtime: &str,
        root_process: &str,
        process: &str,
        lineage: &[chio_core::capability::token::CapabilityToken],
    ) -> Result<Option<crate::SecurityInvocationContext>, crate::KernelError> {
        self.store
            .confined_process_context(
                runtime,
                root_process,
                process,
                lineage,
                &self.fence,
                crate::kernel::current_unix_timestamp_ms(),
            )
            .map_err(|_| {
                crate::KernelError::DurableAdmission("confined context unavailable".into())
            })
    }
    pub fn enforced(&self, runtime: &str) -> Result<bool, crate::KernelError> {
        self.store
            .durable_knowledge_enforced(
                runtime,
                &self.fence,
                crate::kernel::current_unix_timestamp_ms(),
            )
            .map_err(|_| {
                crate::KernelError::DurableAdmission("durable knowledge unavailable".into())
            })
    }
}

/// Private backend locator, carried only inside protected serving records.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBlobSealV1 {
    pub object: ArtifactObjectId,
    pub runtime: ProtectedText<128>,
    pub process: ProcessId,
    pub content: CanonicalPayloadDigest,
    pub bytes: SafeInteger,
    pub generation: ProtectedText<64>,
}
impl core::fmt::Debug for ArtifactBlobSealV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ArtifactBlobSealV1([redacted])")
    }
}

/// Implemented only by a host-selected immutable broker. No path or digest read
/// route is exposed to a worker. Reads below are private staging, not releases.
pub trait ArtifactBlobPort: Send + Sync {
    fn runtime_id(&self) -> &str;
    /// Check actual journal attachment before any confined launch. Descriptive
    /// boundary data cannot create a process or register a capability snapshot.
    fn validate_confined_attachment(
        &self,
        _boundary: &chio_security_types::confinement::IsolationBoundaryV1,
    ) -> Result<(), crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "confined attachment unavailable".into(),
        ))
    }
    fn validate_process(
        &self,
        process: &ProcessId,
        context: &crate::SecurityInvocationContext,
    ) -> Result<(), crate::KernelError>;
    /// Retained journal identity is separate from permission to execute again.
    fn validate_retained_owner(
        &self,
        _process: &ProcessId,
        _context: &crate::SecurityInvocationContext,
    ) -> Result<(), crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "retained storage owner unavailable".into(),
        ))
    }
    /// Private retained reads are used only after fresh native storage authority.
    fn read_retained_private(
        &self,
        _seal: &ArtifactBlobSealV1,
    ) -> Result<Vec<u8>, crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "retained storage read unavailable".into(),
        ))
    }
    fn resolve_retained_private(
        &self,
        _object: &ArtifactObjectId,
        _process: &ProcessId,
        _content: CanonicalPayloadDigest,
        _bytes: SafeInteger,
    ) -> Result<ArtifactBlobSealV1, crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "retained storage identity unavailable".into(),
        ))
    }
    /// Staging retained archives requires independently rechecked fresh Admin.
    fn stage_retained_archive(
        &self,
        _actor: &crate::recovery::AuthenticatedRecoveryActor,
        _context: &crate::SecurityInvocationContext,
        _object: &ArtifactObjectId,
        _bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "retained archive staging unavailable".into(),
        ))
    }
    /// Reserve fixed return capacity before any child-derived value is known.
    fn reserve_confined_return(
        &self,
        _boundary: &chio_security_types::confinement::IsolationBoundaryV1,
    ) -> Result<(), crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "confined return capacity unavailable".into(),
        ))
    }
    /// Fill an already reserved slot after native canonical/projection checks.
    fn stage_confined_return(
        &self,
        _object: &ArtifactObjectId,
        _boundary: &chio_security_types::confinement::IsolationBoundaryV1,
        _bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "confined return staging unavailable".into(),
        ))
    }
    /// The process journal serializes this durable marker with cancellation.
    fn begin_confined_delivery(
        &self,
        _process: &ProcessId,
        _context: &crate::SecurityInvocationContext,
        _intent: &ArtifactReleaseIntentV1,
    ) -> Result<(), crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "confined delivery custody unavailable".into(),
        ))
    }
    /// Finish exact existing custody even if cancellation followed admission.
    fn finish_confined_delivery(
        &self,
        _process: &ProcessId,
        _intent: &ArtifactReleaseIntentV1,
        _delivered: bool,
    ) -> Result<(), crate::KernelError> {
        Err(crate::KernelError::DurableAdmission(
            "confined delivery custody unavailable".into(),
        ))
    }
    fn stage(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, crate::KernelError>;
    fn resolve_private(
        &self,
        object: &ArtifactObjectId,
        process: &ProcessId,
        content: CanonicalPayloadDigest,
        bytes: SafeInteger,
    ) -> Result<ArtifactBlobSealV1, crate::KernelError>;
    fn read_private(&self, seal: &ArtifactBlobSealV1) -> Result<Vec<u8>, crate::KernelError>;
    fn collect_private(&self, seal: &ArtifactBlobSealV1) -> Result<(), crate::KernelError>;
}

/// Delivery identity is independently selected by the trusted host. Provider
/// implementations must use ordinary native effect admission for submission.
pub trait ArtifactReleaseSink: Send + Sync {
    fn recipient(&self) -> &ArtifactRecipientV1;
    fn deliver(
        &self,
        intent: &ArtifactReleaseIntentV1,
        bytes: &[u8],
    ) -> Result<(), crate::KernelError>;
}
