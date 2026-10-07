//! Owner identity is stable data. Native source proofs authorize its mutation.
use super::*;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admission_operation_store) enum ReferenceOwner {
    Publication {
        scope: RecoveryScopeV1,
        artifact: ArtifactId,
        version: ArtifactRevisionId,
    },
    CheckpointRevision {
        scope: RecoveryScopeV1,
        checkpoint: CheckpointId,
        revision: SafeInteger,
    },
    OperatorPin {
        scope: RecoveryScopeV1,
        principal: chio_security_types::PrincipalId,
        evidence: EvidenceRef,
    },
    NativeOperation {
        scope: RecoveryScopeV1,
        operation: OperationId,
    },
    PendingApproval {
        scope: RecoveryScopeV1,
        workflow: WorkflowId,
    },
    ArtifactRelease {
        scope: RecoveryScopeV1,
        release: ReleaseId,
    },
    CheckpointRestore {
        scope: RecoveryScopeV1,
        release: ReleaseId,
    },
    ProductReport {
        scope: RecoveryScopeV1,
        id: EvidenceRef,
        digest: CommandDigest,
    },
    ProductProposal {
        scope: RecoveryScopeV1,
        id: ReviewId,
        digest: CanonicalPayloadDigest,
    },
    ArchivePreparation {
        scope: RecoveryScopeV1,
        principal: chio_security_types::PrincipalId,
        request: RequestId,
    },
    ArchiveDelivery {
        scope: RecoveryScopeV1,
        release: ReleaseId,
    },
    LegacyPinSource {
        scope: RecoveryScopeV1,
        original: SourceAnchor,
    },
}

impl ReferenceOwner {
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        match self {
            Self::Publication { scope, .. }
            | Self::CheckpointRevision { scope, .. }
            | Self::OperatorPin { scope, .. }
            | Self::NativeOperation { scope, .. }
            | Self::PendingApproval { scope, .. }
            | Self::ArtifactRelease { scope, .. }
            | Self::CheckpointRestore { scope, .. }
            | Self::ProductReport { scope, .. }
            | Self::ProductProposal { scope, .. }
            | Self::ArchivePreparation { scope, .. }
            | Self::ArchiveDelivery { scope, .. }
            | Self::LegacyPinSource { scope, .. } => scope,
        }
    }

    pub(in crate::admission_operation_store) fn identity(
        &self,
        reference: CanonicalPayloadDigest,
    ) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
        Ok(CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeReferenceOwner,
                &(self, reference),
            )
            .map_err(refused)?,
        ))
    }
}

/// Product writers describe their own immutable evidence only. Mapping into an
/// index owner cannot supply native pin or retirement authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admission_operation_store) enum ProductEvidenceOwner {
    Report {
        scope: RecoveryScopeV1,
        id: EvidenceRef,
        digest: CommandDigest,
    },
    Proposal {
        scope: RecoveryScopeV1,
        id: ReviewId,
        digest: CanonicalPayloadDigest,
    },
}

impl From<ProductEvidenceOwner> for ReferenceOwner {
    fn from(value: ProductEvidenceOwner) -> Self {
        match value {
            ProductEvidenceOwner::Report { scope, id, digest } => {
                Self::ProductReport { scope, id, digest }
            }
            ProductEvidenceOwner::Proposal { scope, id, digest } => {
                Self::ProductProposal { scope, id, digest }
            }
        }
    }
}

impl std::fmt::Debug for ReferenceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReferenceOwner([redacted])")
    }
}

impl std::fmt::Debug for ProductEvidenceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProductEvidenceOwner([redacted])")
    }
}
