//! Closed descriptions of host-issued isolation and independently admitted returns.
//! Decoding these values never grants launch, observation or disclosure authority.
#![forbid(unsafe_code)]
use crate::{knowledge::*, recovery::*, PrincipalId};
use serde::{Deserialize, Serialize};

pub const MAX_CONFINED_CHILDREN: u64 = 16;
pub const MAX_CONFINED_INPUT_BYTES: u64 = 64 * 1024;
pub const MAX_CONFINED_DIAGNOSTIC_BYTES: usize = 16 * 1024;
pub const CONFINED_BOOLEAN_IMPLEMENTATION: &[u8] = b"chio.confined.json-boolean-field.v1";
pub const CONFINED_BOOLEAN_SCHEMA: &[u8] = b"chio.confined.canonical-boolean.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinedChannelV1 {
    Value,
    Error,
    Stdout,
    Stderr,
    Log,
    Progress,
    File,
    Callback,
    Stream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinedProviderV1 {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationStateV1 {
    Reserved,
    LaunchPrepared,
    EnforcedRunning,
    ReturnStaged,
    ReturnAdmitted,
    Closed,
    Failed,
    Cancelled,
    Quarantined,
}

/// This first profile exposes only an exact boolean field projection. Every
/// diagnostic/status/stream channel is explicitly withheld.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnContractV1 {
    pub domain_version: VersionV1,
    pub contract: ReturnContractDigest,
    pub schema: CanonicalPayloadDigest,
    pub implementation: CanonicalPayloadDigest,
    pub field: ProtectedText<128>,
    pub parent: ArtifactRecipientV1,
    pub source_ceiling: crate::InformationLabel,
    pub target: crate::InformationLabel,
    pub require_integrity: bool,
    pub max_bytes: SafeInteger,
    pub max_values: SafeInteger,
    pub channels: NonEmptyBoundedList<ConfinedChannelV1, 9>,
    pub expires_at_unix_ms: SafeInteger,
    pub policy: PolicyDigest,
}
impl ReturnContractV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.max_bytes.get() != 8
            || self.max_values.get() != 1
            || self.channels.as_slice() != [ConfinedChannelV1::Value]
            || self.expires_at_unix_ms.get() == 0
            || self.field.as_str().is_empty()
            || self.field.as_str().chars().any(char::is_control)
            || self.parent.scope.tenant_id.as_str().is_empty()
        {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinedLimitsV1 {
    pub children: SafeInteger,
    pub depth: SafeInteger,
    pub input_bytes: SafeInteger,
    pub diagnostic_bytes: SafeInteger,
    pub launches: SafeInteger,
    pub tool_calls: SafeInteger,
    pub model_calls: SafeInteger,
    pub wall_clock_ms: SafeInteger,
}
impl ConfinedLimitsV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.children.get() == 0
            || self.children.get() > MAX_CONFINED_CHILDREN
            || self.depth.get() == 0
            || self.depth.get() > 8
            || self.input_bytes.get() == 0
            || self.input_bytes.get() > MAX_CONFINED_INPUT_BYTES
            || self.diagnostic_bytes.get() == 0
            || self.diagnostic_bytes.get() > MAX_CONFINED_DIAGNOSTIC_BYTES as u64
            || self.launches.get() != 1
            || self.tool_calls.get() != 0
            || self.model_calls.get() != 0
            || self.wall_clock_ms.get() == 0
            || self.wall_clock_ms.get() > 30_000
        {
            return Err(ContractError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinedExecutionProfileV1 {
    pub manifest: CageMeasurementDigest,
    pub profile: CageMeasurementDigest,
    pub configuration: CageMeasurementDigest,
    pub helper: CageMeasurementDigest,
    pub image: CageMeasurementDigest,
    pub provider: ConfinedProviderV1,
}

/// Immutable logical boundary. Only the serving authority allocates its child,
/// observation lineage and epoch. A measured launch has separate identity.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationBoundaryV1 {
    pub domain_version: VersionV1,
    pub boundary: EvidenceRef,
    pub request: RequestId,
    pub scope: RecoveryScopeV1,
    pub parent_capability: ConfinedCapabilityDigest,
    pub parent: ArtifactRecipientV1,
    pub child: ProcessId,
    pub child_principal: PrincipalId,
    pub child_capability: ConfinedCapabilityDigest,
    pub ancestry: NonEmptyBoundedList<ProcessId, 8>,
    pub lineage: IsolationLineageId,
    pub isolation_epoch: ProtectedText<128>,
    pub seed_artifacts: BoundedList<ArtifactVersionRefV1, 8>,
    pub observation: ArtifactVersionRefV1,
    pub parent_control: CanonicalPayloadDigest,
    pub seed_label: crate::InformationLabel,
    pub seed_influence: ArtifactInfluenceV1,
    pub execution: ConfinedExecutionProfileV1,
    pub return_contract: ReturnContractDigest,
    pub limits: ConfinedLimitsV1,
    pub deadline_unix_ms: SafeInteger,
    pub policy: PolicyDigest,
}
impl IsolationBoundaryV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.limits.validate()?;
        if self.parent.scope != self.scope
            || self.child == self.scope.process_id
            || self.ancestry.as_slice().last() != Some(&self.scope.process_id)
            || self.ancestry.as_slice().len() as u64 >= self.limits.depth.get()
            || self.deadline_unix_ms.get() == 0
            || self.observation.scope != self.scope
            || self
                .seed_artifacts
                .as_slice()
                .iter()
                .enumerate()
                .any(|(i, s)| {
                    s.scope != self.scope || self.seed_artifacts.as_slice()[..i].contains(s)
                })
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

/// Exact disclosure and endorsement share reviewed data but use distinct
/// signature domains and independently selected authority roots.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinedReturnEvidenceV1 {
    pub domain_version: VersionV1,
    pub evidence: EvidenceRef,
    pub boundary: CanonicalPayloadDigest,
    pub launch: CanonicalPayloadDigest,
    pub artifact: ArtifactVersionRefV1,
    pub content: CanonicalPayloadDigest,
    pub size_bytes: SafeInteger,
    pub source: crate::InformationLabel,
    pub influence: ArtifactInfluenceV1,
    pub parent: ArtifactRecipientV1,
    pub contract: ReturnContractDigest,
    pub implementation: CanonicalPayloadDigest,
    pub observation: ArtifactVersionRefV1,
    pub target: crate::InformationLabel,
    pub policy: PolicyDigest,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
}
impl ConfinedReturnEvidenceV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.artifact.scope != self.parent.scope
            || self.observation.scope != self.parent.scope
            || self.size_bytes.get() > 8
            || self.size_bytes.get() < 4
            || self.issued_at_unix_ms.get() == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms.get() - self.issued_at_unix_ms.get() > 60_000
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnAdmissionV1 {
    pub domain_version: VersionV1,
    pub boundary: EvidenceRef,
    pub child: ProcessId,
    pub launch: CanonicalPayloadDigest,
    pub artifact: ArtifactVersionRefV1,
    pub contract: ReturnContractDigest,
    pub observed_source: crate::InformationLabel,
    pub admitted: ArtifactReleaseIntentV1,
    pub disclosure: Option<EvidenceRef>,
    pub endorsement: Option<EvidenceRef>,
}

crate::knowledge::protected_debug!(
    ReturnContractV1,
    ConfinedLimitsV1,
    ConfinedExecutionProfileV1,
    IsolationBoundaryV1,
    ConfinedReturnEvidenceV1,
    ReturnAdmissionV1
);
