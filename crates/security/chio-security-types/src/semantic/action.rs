use super::SemanticFieldV1;
use crate::{flow::InformationLabel as InfoLabel, recovery::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticInputVersionV1 {
    pub resource: ProviderResourceId,
    pub version: ArtifactVersionId,
    pub content: CanonicalPayloadDigest,
}

/// The endorsement's original native knowledge basis. Owned input journals may
/// advance it; foreign equal-label generations cannot silently refresh it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticNativeSourceBasisV1 {
    pub key: CanonicalPayloadDigest,
    pub generation: SafeInteger,
    pub principal_label: InfoLabel,
    pub lineage_label: InfoLabel,
    pub session_label: InfoLabel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOutputDispositionV1 {
    ReturnValue,
    Withhold,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticActionV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub registry: SemanticRegistryDigest,
    pub generation: SafeInteger,
    pub operation: SemanticOperationId,
    pub destination: SemanticDestinationId,
    pub request_id: RequestId,
    pub request_namespace: RequestNamespaceDigest,
    pub capability: CapabilityBodyDigest,
    pub request_semantics: CanonicalPayloadDigest,
    pub payload: CanonicalPayloadDigest,
    pub inputs: NonEmptyBoundedList<SemanticInputVersionV1, 16>,
    pub source_label: InfoLabel,
    pub native_source: SemanticNativeSourceBasisV1,
    pub influence: CanonicalPayloadDigest,
    pub externally_influenced: bool,
    pub plan: PlanDigest,
    pub step: StepId,
    pub output: SemanticOutputDispositionV1,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl SemanticActionV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        super::validate_semantic_interval(self.issued_at_unix_ms, self.valid_until_unix_ms)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPayloadV1 {
    pub fields: NonEmptyBoundedList<SemanticFieldV1, 16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SemanticInvocationSchemaV1 {
    #[serde(rename = "chio.semantic.invocation.v1")]
    V1,
}

super::protected_debug!(
    SemanticInputVersionV1,
    SemanticNativeSourceBasisV1,
    SemanticActionV1,
    SemanticPayloadV1
);
