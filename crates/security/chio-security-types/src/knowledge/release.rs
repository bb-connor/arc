use super::ArtifactVersionRefV1;
use crate::{flow::InformationLabel, recovery::*};
use serde::{Deserialize, Serialize};

/// Host-selected model identity includes persistent remote state and tenant/account.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelContextV1 {
    pub context: ModelContextId,
    pub provider: ProviderId,
    pub account: ProviderAccountId,
    pub conversation: ProtectedText<128>,
    pub cache: ProtectedText<128>,
    pub side_files: BoundedList<ArtifactVersionRefV1, 8>,
    pub contract: ContractDigest,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactSinkV1 {
    Agent,
    Model { context: ModelContextV1 },
    Archive,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecipientV1 {
    pub recipient: ArtifactRecipientId,
    pub scope: RecoveryScopeV1,
    pub runtime: ProtectedText<128>,
    pub principal: crate::flow::PrincipalId,
    pub lineage: IsolationLineageId,
    pub isolation_epoch: ProtectedText<128>,
    pub context_generation: SafeInteger,
    pub clearance: InformationLabel,
    pub sink: ArtifactSinkV1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHandleV1 {
    pub handle: ArtifactHandleId,
    pub recipient: ArtifactRecipientId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDeliveryStateV1 {
    Admitted,
    Uncertain,
    Delivered,
}

/// Captured output is original native return custody, never a new artifact read.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactReleaseKindV1 {
    CapturedOutput { operation: OperationId },
    IndependentlyAdmitted { request: RequestId },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReleaseIntentV1 {
    pub domain_version: VersionV1,
    pub release: ReleaseId,
    pub kind: ArtifactReleaseKindV1,
    pub artifact: ArtifactVersionRefV1,
    pub source_label: InformationLabel,
    pub admitted_label: InformationLabel,
    pub influence: super::ArtifactInfluenceV1,
    pub recipient: ArtifactRecipientV1,
    pub policy: PolicyDigest,
    pub authorization: ReleaseAuthorizationDigest,
    pub observation_transition: EvidenceRef,
    pub observation_generation: SafeInteger,
    pub state: ArtifactDeliveryStateV1,
}

super::protected_debug!(
    ModelContextV1,
    ArtifactSinkV1,
    ArtifactRecipientV1,
    ArtifactHandleV1,
    ArtifactReleaseKindV1,
    ArtifactReleaseIntentV1
);
