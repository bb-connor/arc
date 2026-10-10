use crate::{flow::InformationLabel as InfoLabel, recovery::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOperationKindV1 {
    SupportRead,
    IssueWrite,
    FieldProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticChannelV1 {
    Input,
    Success,
    Error,
    NoValue,
    Nested,
    Batch,
    Pagination,
    Redirect,
    Stream,
    File,
    Log,
    Shell,
    Model,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticChannelRuleV1 {
    pub channel: SemanticChannelV1,
    pub enabled: bool,
}

/// Flat, typed selectors deliberately have no recursion or executable strings.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticValueV1 {
    Text { value: ProtectedText<4096> },
    Integer { value: SafeInteger },
    Boolean { value: bool },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFieldV1 {
    pub field: SemanticFieldId,
    pub value: SemanticValueV1,
}

/// The signed audience for the constant completion projection of a withheld call.
/// This classifies status data and supplies no disclosure authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticWithheldStatusV1 {
    pub audience: InfoLabel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticSelectorV1 {
    Present {
        field: SemanticFieldId,
    },
    Equals {
        field: SemanticFieldId,
        value: SemanticValueV1,
    },
    TextBytesAtMost {
        field: SemanticFieldId,
        bytes: SafeInteger,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticOperationContractV1 {
    pub operation: SemanticOperationId,
    pub kind: SemanticOperationKindV1,
    pub input_schema: CanonicalPayloadDigest,
    pub output_schema: CanonicalPayloadDigest,
    pub implementation: CanonicalPayloadDigest,
    pub channels: NonEmptyBoundedList<SemanticChannelRuleV1, 13>,
    pub input_fields: BoundedList<SemanticFieldId, 16>,
    pub selectors: BoundedList<SemanticSelectorV1, 16>,
    pub required_assertions: BoundedList<SemanticFactId, 8>,
    pub prerequisites: BoundedList<SemanticPrerequisiteRequirementV1, 8>,
    pub projection_fields: BoundedList<SemanticFieldId, 8>,
    pub source_label: InfoLabel,
    pub external_influence: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_withheld_status"
    )]
    pub withheld_status: Option<SemanticWithheldStatusV1>,
}

fn present_withheld_status<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<SemanticWithheldStatusV1>, D::Error> {
    SemanticWithheldStatusV1::deserialize(decoder).map(Some)
}
use super::SemanticPrerequisiteRequirementV1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPackageV1 {
    pub domain_version: VersionV1,
    pub package: SemanticPackageId,
    pub dependencies: BoundedList<SemanticPackageDigest, 16>,
    pub operations: NonEmptyBoundedList<SemanticOperationContractV1, 16>,
}
impl SemanticPackageV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDestinationV1 {
    pub destination: SemanticDestinationId,
    pub provider: ProviderId,
    pub account: ProviderAccountId,
    pub resource: ProviderResourceId,
    pub endpoint: ProtectedText<2048>,
    pub audience: InfoLabel,
    pub purpose: ProtectedText<256>,
    pub subject_mapping: CanonicalPayloadDigest,
    pub acl_query: CanonicalPayloadDigest,
    pub require_provider_precondition: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnnotatorBindingV1 {
    pub key: RoleKeyDigest,
    pub facts: BoundedList<SemanticFactId, 8>,
    pub may_attest_facts: bool,
}

/// Explicit override can only remove a package selector; it cannot change the
/// separately enforced native capability, information-flow or channel ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticReviewedOverrideV1 {
    pub selector_index: SafeInteger,
    pub reason: ProtectedText<512>,
    pub fixture_digests: NonEmptyBoundedList<CanonicalPayloadDigest, 8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRouteV1 {
    pub server: ProtectedText<128>,
    pub tool: ProtectedText<128>,
    pub package: SemanticPackageDigest,
    pub operation: SemanticOperationId,
    pub implementation: CanonicalPayloadDigest,
    pub input_schema: CanonicalPayloadDigest,
    pub output_schema: CanonicalPayloadDigest,
    pub destinations: NonEmptyBoundedList<SemanticDestinationV1, 16>,
    pub operator_selectors: BoundedList<SemanticSelectorV1, 16>,
    pub reviewed_overrides: BoundedList<SemanticReviewedOverrideV1, 16>,
    pub resolver_key: RoleKeyDigest,
    pub endorsement_key: RoleKeyDigest,
    pub prerequisite_key: RoleKeyDigest,
    pub transformation_key: RoleKeyDigest,
    pub annotators: BoundedList<SemanticAnnotatorBindingV1, 16>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDeploymentV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub generation: SafeInteger,
    pub native_binding: CanonicalPayloadDigest,
    pub context_binding: CanonicalPayloadDigest,
    pub exposure_binding: CanonicalPayloadDigest,
    pub packages: NonEmptyBoundedList<SemanticPackageDigest, 16>,
    pub routes: NonEmptyBoundedList<SemanticRouteV1, 16>,
}
impl SemanticDeploymentV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.generation.get() == 0 {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}

super::protected_debug!(
    SemanticOperationContractV1,
    SemanticPackageV1,
    SemanticDestinationV1,
    SemanticRouteV1,
    SemanticDeploymentV1,
    SemanticValueV1,
    SemanticFieldV1,
    SemanticWithheldStatusV1
);
