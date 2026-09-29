#[cfg(feature = "std")]
use super::PortResult;
use super::{
    BoundedVec, CanonicalBody, ClassifierId, ClassifierVersion, Deserialize, Digest32, RecordId,
    RequestId, Serialize, TenantId,
};

pub type ClassificationFindings = BoundedVec<ClassificationFinding, 256>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRequest {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub payload: CanonicalBody,
    pub payload_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationFinding {
    pub category: RecordId,
    pub confidence_basis_points: u16,
    pub byte_range: Option<ByteRange>,
    pub field_path: Option<RecordId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationResult {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub payload_digest: Digest32,
    pub classifier_id: ClassifierId,
    pub classifier_version: ClassifierVersion,
    pub findings: ClassificationFindings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    CanaryCapability,
    HoneyTool,
    CredentialArtifact,
    FileMarker,
    BrowserCookie,
    InternalHostname,
    SignedWatermark,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireInput {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub kind: TripwireKind,
    /// Bounded presented bytes. The detector verifies `content_digest`
    /// before interpreting this value.
    pub content: CanonicalBody,
    pub content_digest: Digest32,
    pub canonical_context_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum TripwireDecision {
    Clear,
    Match {
        artifact_id_hash: Digest32,
        artifact_version_hash: Digest32,
    },
}

#[cfg(feature = "std")]
pub trait ClassificationPort: Send + Sync {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult>;
}

#[cfg(feature = "std")]
pub trait TripwireDetectorPort: Send + Sync {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision>;
}
