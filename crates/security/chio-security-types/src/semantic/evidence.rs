use super::{SemanticInputVersionV1, SemanticOutputDispositionV1};
use crate::{flow::InformationLabel as InfoLabel, recovery::*};
use serde::{Deserialize, Serialize};

/// Exact provider attempt identity, distinct from provider version or content.
/// Its established protected UTF-8 wire representation is retained unchanged.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticProviderAttemptId(ProtectedText<128>);

impl SemanticProviderAttemptId {
    pub fn new(value: &str) -> Result<Self, ContractError> {
        ProtectedText::new(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

super::protected_debug!(SemanticProviderAttemptId);

/// The qualified gateway must apply this identity tuple and provider version
/// before reading or creating an issue. Payload bytes cannot select an account.
/// Provider attempt identity cannot be assigned as provider-version text.
/// ```compile_fail
/// use chio_security_types::recovery::ProtectedText;
/// use chio_security_types::semantic::SemanticProviderRequestV1;
/// fn confuse(request: SemanticProviderRequestV1) -> ProtectedText<128> {
///     request.attempt
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticProviderRequestV1 {
    pub domain_version: VersionV1,
    pub kind: super::SemanticOperationKindV1,
    pub provider: ProviderId,
    pub account: ProviderAccountId,
    pub resource: ProviderResourceId,
    pub provider_version: ProtectedText<128>,
    pub operation: OperationId,
    pub attempt: SemanticProviderAttemptId,
    pub payload: super::SemanticPayloadV1,
}

/// The pinned provider gateway confirms the identity and ACL precondition it
/// actually used. Unknown fields and unbound raw provider bodies are refused.
/// Provider response identity cannot be assigned as provider-version text.
/// ```compile_fail
/// use chio_security_types::recovery::ProtectedText;
/// use chio_security_types::semantic::SemanticProviderResponseV1;
/// fn confuse(response: SemanticProviderResponseV1) -> ProtectedText<128> {
///     response.attempt
/// }
/// ```
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticProviderResponseV1 {
    pub provider: ProviderId,
    pub account: ProviderAccountId,
    pub resource: ProviderResourceId,
    pub checked_provider_version: ProtectedText<128>,
    pub operation: OperationId,
    pub attempt: SemanticProviderAttemptId,
    pub payload: super::SemanticPayloadV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticAudienceCompletenessV1 {
    Complete,
    Partial,
    Ambiguous,
    Outage,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticAclCursorV1 {
    Complete,
    Pending,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAclPaginationV1 {
    pub pages_observed: SafeInteger,
    pub pages_expected: SafeInteger,
    pub cursor: SemanticAclCursorV1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAudienceObservationV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub provider: ProviderId,
    pub account: ProviderAccountId,
    pub resource: ProviderResourceId,
    pub audience: InfoLabel,
    pub subject_mapping: CanonicalPayloadDigest,
    pub query: CanonicalPayloadDigest,
    pub provider_version: ProtectedText<128>,
    pub completeness: SemanticAudienceCompletenessV1,
    pub pagination: SemanticAclPaginationV1,
    pub observed_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl SemanticAudienceObservationV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        super::validate_semantic_interval(self.observed_at_unix_ms, self.valid_until_unix_ms)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticEndorsementTargetV1 {
    ExactAction { action: SemanticActionDigest },
    PersistentArtifact { artifact: ArtifactVersionId },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEndorsementV1 {
    pub domain_version: VersionV1,
    pub evidence: EvidenceRef,
    pub scope: RecoveryScopeV1,
    pub target: SemanticEndorsementTargetV1,
    pub influence: CanonicalPayloadDigest,
    pub assertions: NonEmptyBoundedList<SemanticFactId, 8>,
    pub destination: SemanticDestinationId,
    pub purpose: ProtectedText<256>,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl ScopedEndorsementV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        super::validate_semantic_interval(self.issued_at_unix_ms, self.valid_until_unix_ms)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAnnotationV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub input: SemanticInputVersionV1,
    pub restrictions: InfoLabel,
    pub externally_influenced: bool,
    pub facts: BoundedList<SemanticFactId, 8>,
    pub confidence_basis_points: SafeInteger,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl SemanticAnnotationV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.confidence_basis_points.get() > 10_000 {
            return Err(ContractError::InvalidState);
        }
        super::validate_semantic_interval(self.issued_at_unix_ms, self.valid_until_unix_ms)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTransformationV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub producer: OperationId,
    pub producer_action: SemanticActionDigest,
    pub inputs: NonEmptyBoundedList<SemanticInputVersionV1, 16>,
    pub implementation: CanonicalPayloadDigest,
    pub configuration: CanonicalPayloadDigest,
    pub output_schema: CanonicalPayloadDigest,
    pub output: CanonicalPayloadDigest,
    pub output_label: InfoLabel,
    pub influence: CanonicalPayloadDigest,
    pub destination: SemanticDestinationId,
    pub purpose: ProtectedText<256>,
    pub disposition: SemanticOutputDispositionV1,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl SemanticTransformationV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        super::validate_semantic_interval(self.issued_at_unix_ms, self.valid_until_unix_ms)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticPrerequisiteKindV1 {
    HistoricalFact,
    CurrentPredicate,
    HeldReservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPrerequisiteRequirementV1 {
    pub fact: SemanticFactId,
    pub kind: SemanticPrerequisiteKindV1,
    pub resource: ProviderResourceId,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPrerequisiteV1 {
    pub domain_version: VersionV1,
    pub evidence: EvidenceRef,
    pub scope: RecoveryScopeV1,
    pub action: SemanticActionDigest,
    pub fact: SemanticFactId,
    pub kind: SemanticPrerequisiteKindV1,
    pub resource: ProviderResourceId,
    pub version: ArtifactVersionId,
    pub material: CanonicalPayloadDigest,
    pub producer: OperationId,
    #[serde(deserialize_with = "required_lease")]
    pub lease: Option<SemanticLeaseId>,
    pub purpose: ProtectedText<256>,
    pub issued_at_unix_ms: SafeInteger,
    pub valid_until_unix_ms: SafeInteger,
}
impl SemanticPrerequisiteV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.lease.is_some() != (self.kind == SemanticPrerequisiteKindV1::HeldReservation) {
            return Err(ContractError::InvalidState);
        }
        super::validate_semantic_interval(self.issued_at_unix_ms, self.valid_until_unix_ms)
    }
}

fn required_lease<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<SemanticLeaseId>, D::Error> {
    Option::<SemanticLeaseId>::deserialize(decoder)
}

super::protected_debug!(
    SemanticAudienceObservationV1,
    ScopedEndorsementV1,
    SemanticAnnotationV1,
    SemanticTransformationV1,
    SemanticPrerequisiteV1,
    SemanticProviderRequestV1,
    SemanticProviderResponseV1
);
