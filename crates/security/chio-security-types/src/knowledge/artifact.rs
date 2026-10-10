use crate::{flow::InformationLabel, recovery::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVersionRefV1 {
    pub scope: RecoveryScopeV1,
    pub artifact: ArtifactId,
    pub version: ArtifactRevisionId,
    pub provenance: ProvenanceDigest,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInfluenceV1 {
    pub commitment: CanonicalPayloadDigest,
    pub externally_influenced: bool,
    pub unknown: bool,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactProducerV1 {
    NativeOperation {
        operation: OperationId,
    },
    Checkpoint {
        checkpoint: CheckpointId,
    },
    Derivation {
        operation: OperationId,
    },
    Adoption {
        evidence: EvidenceRef,
    },
    Import {
        manifest: ProvenanceDigest,
        origin: ArtifactVersionRefV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionV1 {
    Ephemeral,
    Checkpoint,
    Evidence,
}

/// Immutable reference-specific provenance. Equal content is not equal authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVersionV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub artifact: ArtifactId,
    pub version: ArtifactRevisionId,
    pub content: CanonicalPayloadDigest,
    pub size_bytes: SafeInteger,
    pub media_type: ProtectedText<128>,
    pub schema: CanonicalPayloadDigest,
    pub producer: ArtifactProducerV1,
    pub dependencies: BoundedList<ArtifactVersionRefV1, 16>,
    pub label: InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub lineage: IsolationLineageId,
    pub isolation_epoch: ProtectedText<128>,
    pub evidence: BoundedList<EvidenceRef, 8>,
    pub policy: PolicyDigest,
    pub contract: ContractDigest,
    pub creation_sequence: SafeInteger,
    pub retention: ArtifactRetentionV1,
}
impl ArtifactVersionV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.size_bytes.get() > super::MAX_ARTIFACT_BYTES as u64
            || self.creation_sequence.get() == 0
        {
            return Err(ContractError::LimitExceeded);
        }
        for (index, dependency) in self.dependencies.as_slice().iter().enumerate() {
            if dependency.scope.tenant_id != self.scope.tenant_id
                || dependency.scope.authority_domain != self.scope.authority_domain
                || (dependency.artifact == self.artifact && dependency.version == self.version)
                || self.dependencies.as_slice()[..index].contains(dependency)
            {
                return Err(ContractError::BindingMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPublicationStateV1 {
    Reserved,
    Staged,
    MetadataCommitted,
    Available,
    Quarantined,
    Retired,
}

/// This separate certificate family cannot be minted from a one-shot crossing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCertificateKindV1 {
    Classification,
    Projection,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCertificateV1 {
    pub domain_version: VersionV1,
    pub evidence: EvidenceRef,
    pub scope: RecoveryScopeV1,
    pub kind: ArtifactCertificateKindV1,
    pub artifact: ArtifactId,
    pub version: ArtifactRevisionId,
    pub producer: ArtifactProducerV1,
    pub content: CanonicalPayloadDigest,
    pub size_bytes: SafeInteger,
    pub schema: CanonicalPayloadDigest,
    pub dependencies: BoundedList<ArtifactVersionRefV1, 16>,
    pub implementation: CanonicalPayloadDigest,
    pub configuration: CanonicalPayloadDigest,
    pub output_label: InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl ArtifactCertificateV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.size_bytes.get() > super::MAX_ARTIFACT_BYTES as u64
            || self.issued_at_unix_ms.get() == 0
            || self.valid_until_unix_ms <= self.issued_at_unix_ms
            || self.valid_until_unix_ms.get() - self.issued_at_unix_ms.get() > 60_000
            || (self.kind == ArtifactCertificateKindV1::Projection
                && self.dependencies.as_slice().is_empty())
        {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactArchiveManifestV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub root: ArtifactVersionRefV1,
    pub versions: NonEmptyBoundedList<ArtifactVersionV1, 16>,
    pub total_bytes: SafeInteger,
}
impl ArtifactArchiveManifestV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.scope != self.root.scope
            || self.total_bytes.get() > super::MAX_ARTIFACT_BYTES as u64
        {
            return Err(ContractError::BindingMismatch);
        }
        let mut total = 0_u64;
        for (index, version) in self.versions.as_slice().iter().enumerate() {
            version.validate()?;
            if version.scope.authority_domain != self.scope.authority_domain
                || version.scope.tenant_id != self.scope.tenant_id
                || self.versions.as_slice()[..index].iter().any(|old| {
                    old.scope == version.scope
                        && old.artifact == version.artifact
                        && old.version == version.version
                })
            {
                return Err(ContractError::BindingMismatch);
            }
            total = total
                .checked_add(version.size_bytes.get())
                .ok_or(ContractError::LimitExceeded)?;
        }
        if total != self.total_bytes.get() {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

super::protected_debug!(
    ArtifactVersionRefV1,
    ArtifactInfluenceV1,
    ArtifactProducerV1,
    ArtifactVersionV1,
    ArtifactCertificateV1,
    ArtifactArchiveManifestV1
);
