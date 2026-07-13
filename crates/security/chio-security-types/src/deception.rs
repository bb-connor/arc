use crate::ports::{ArtifactId, BoundedVec, Digest32, RecordId, TenantId};
use alloc::vec::Vec;
use core::fmt;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_DECOY_EXPORT_PAGE: u16 = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoySurface {
    CanaryCapability,
    HoneyTool,
    CredentialArtifact,
    CredentialFile,
    FileMarker,
    BrowserCookie,
    InternalHostname,
    SignedWatermark,
}

impl DecoySurface {
    #[must_use]
    pub const fn domain_name(self) -> &'static str {
        match self {
            Self::CanaryCapability => "canary_capability",
            Self::HoneyTool => "honey_tool",
            Self::CredentialArtifact => "credential_artifact",
            Self::CredentialFile => "credential_file",
            Self::FileMarker => "file_marker",
            Self::BrowserCookie => "browser_cookie",
            Self::InternalHostname => "internal_hostname",
            Self::SignedWatermark => "signed_watermark",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DecoyVersion(u64);

impl DecoyVersion {
    pub const fn new(value: u64) -> Result<Self, DecoyRecordError> {
        if value == 0 {
            return Err(DecoyRecordError::ZeroVersion);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, DecoyRecordError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(DecoyRecordError::VersionOverflow),
        }
    }
}

impl<'de> Deserialize<'de> for DecoyVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyLifecycleState {
    Planned,
    Materializing,
    Armed,
    Triggered,
    Rotating,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyOperationKind {
    BeginMaterialization,
    Arm,
    Trigger,
    BeginRotation,
    Retire,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyOperationAttempt {
    pub operation_id: RecordId,
    pub kind: DecoyOperationKind,
    pub expected_generation: u64,
    pub expected_version: DecoyVersion,
    pub successor_artifact_id: Option<ArtifactId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyErrorClass {
    Conflict,
    IntegrityFailure,
    InvalidInput,
    IoFailure,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DecoyLifecycle {
    Planned,
    Materializing,
    Armed,
    Triggered,
    Rotating,
    Retired,
    Error {
        prior: DecoyLifecycleState,
        attempted: DecoyOperationAttempt,
        error_class: DecoyErrorClass,
    },
}

impl DecoyLifecycle {
    #[must_use]
    pub const fn state(&self) -> Option<DecoyLifecycleState> {
        match self {
            Self::Planned => Some(DecoyLifecycleState::Planned),
            Self::Materializing => Some(DecoyLifecycleState::Materializing),
            Self::Armed => Some(DecoyLifecycleState::Armed),
            Self::Triggered => Some(DecoyLifecycleState::Triggered),
            Self::Rotating => Some(DecoyLifecycleState::Rotating),
            Self::Retired => Some(DecoyLifecycleState::Retired),
            Self::Error { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_matchable(&self) -> bool {
        matches!(
            Self::state(self),
            Some(
                DecoyLifecycleState::Armed
                    | DecoyLifecycleState::Triggered
                    | DecoyLifecycleState::Rotating
            )
        )
    }
}

impl From<DecoyLifecycleState> for DecoyLifecycle {
    fn from(value: DecoyLifecycleState) -> Self {
        match value {
            DecoyLifecycleState::Planned => Self::Planned,
            DecoyLifecycleState::Materializing => Self::Materializing,
            DecoyLifecycleState::Armed => Self::Armed,
            DecoyLifecycleState::Triggered => Self::Triggered,
            DecoyLifecycleState::Rotating => Self::Rotating,
            DecoyLifecycleState::Retired => Self::Retired,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyRecord {
    pub tenant_id: TenantId,
    pub artifact_id: ArtifactId,
    pub public_marker_ref: Option<RecordId>,
    pub surface: DecoySurface,
    pub scope_id: RecordId,
    pub marker_digest: Digest32,
    pub creation_policy_id: RecordId,
    pub version: DecoyVersion,
    pub version_hash: Digest32,
    pub lifecycle: DecoyLifecycle,
    pub generation: u64,
    pub expires_at_unix_ms: u64,
    pub predecessor_artifact_id: Option<ArtifactId>,
    pub successor_artifact_id: Option<ArtifactId>,
}

impl DecoyRecord {
    pub fn validate(&self) -> Result<(), DecoyRecordError> {
        if self.expires_at_unix_ms == 0 {
            return Err(DecoyRecordError::ZeroExpiry);
        }
        if self.predecessor_artifact_id.as_ref() == Some(&self.artifact_id)
            || self.successor_artifact_id.as_ref() == Some(&self.artifact_id)
        {
            return Err(DecoyRecordError::SelfReference);
        }
        match (self.surface, self.public_marker_ref.is_some()) {
            (DecoySurface::SignedWatermark, false) => {
                return Err(DecoyRecordError::MissingPublicMarkerRef);
            }
            (DecoySurface::SignedWatermark, true) | (_, false) => {}
            (_, true) => return Err(DecoyRecordError::UnexpectedPublicMarkerRef),
        }
        if let DecoyLifecycle::Error { attempted, .. } = &self.lifecycle {
            if attempted.expected_version != self.version {
                return Err(DecoyRecordError::ErrorVersionMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoyRecordError {
    ZeroVersion,
    VersionOverflow,
    ZeroExpiry,
    SelfReference,
    MissingPublicMarkerRef,
    UnexpectedPublicMarkerRef,
    ErrorVersionMismatch,
    EnvelopeTooLarge,
}

impl fmt::Display for DecoyRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroVersion => "decoy version must be nonzero",
            Self::VersionOverflow => "decoy version overflow",
            Self::ZeroExpiry => "decoy expiry must be nonzero",
            Self::SelfReference => "decoy predecessor and successor must be distinct",
            Self::MissingPublicMarkerRef => "signed watermark requires a public marker reference",
            Self::UnexpectedPublicMarkerRef => {
                "public marker reference is restricted to signed watermarks"
            }
            Self::ErrorVersionMismatch => "decoy error attempt version does not match record",
            Self::EnvelopeTooLarge => "encrypted decoy envelope exceeds the byte limit",
        })
    }
}

impl core::error::Error for DecoyRecordError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyEvidenceRef {
    pub artifact_id_hash: Digest32,
    pub version_hash: Digest32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EncryptedDecoyEnvelope(BoundedVec<u8, MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES>);

impl EncryptedDecoyEnvelope {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DecoyRecordError> {
        BoundedVec::new(bytes)
            .map(Self)
            .map_err(|_| DecoyRecordError::EnvelopeTooLarge)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for EncryptedDecoyEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDecoyEnvelope")
            .field("ciphertext_len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DecoyAeadNonce([u8; 12]);

impl DecoyAeadNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyArtifactLookup {
    pub tenant_id: TenantId,
    pub artifact_token: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedMarkerLookup {
    pub tenant_id: TenantId,
    pub surface: DecoySurface,
    pub marker_token: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedPublicRefLookup {
    pub tenant_id: TenantId,
    pub public_ref_token: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDecoyRecord {
    pub tenant_id: TenantId,
    pub artifact_token: Digest32,
    pub public_ref_token: Option<Digest32>,
    pub surface: DecoySurface,
    pub marker_token: Digest32,
    pub version_hash: Digest32,
    pub generation: u64,
    pub nonce: DecoyAeadNonce,
    pub encrypted_envelope: EncryptedDecoyEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDecoyCasRequest {
    pub record: SealedDecoyRecord,
    pub expected_generation: Option<u64>,
    pub operation_token: Digest32,
    pub transition_token: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyScan {
    pub tenant_id: TenantId,
    pub after_artifact_token: Option<Digest32>,
    pub limit: u16,
}

impl DecoyScan {
    pub const fn validate(&self) -> Result<(), DecoyScanError> {
        if self.limit == 0 || self.limit > MAX_DECOY_EXPORT_PAGE {
            return Err(DecoyScanError::InvalidLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoyScanError {
    InvalidLimit,
}

impl fmt::Display for DecoyScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decoy scan limit is outside the allowed range")
    }
}

impl core::error::Error for DecoyScanError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDecoyPage {
    pub records: BoundedVec<SealedDecoyRecord, { MAX_DECOY_EXPORT_PAGE as usize }>,
    pub next_artifact_token: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkSequenceKey {
    pub tenant_id: TenantId,
    pub application_id: RecordId,
    pub session_id: RecordId,
    pub tool_id: RecordId,
    pub public_ref_token: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkSequenceReservation {
    pub key: WatermarkSequenceKey,
    pub sequence: u64,
    pub operation_id: RecordId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkSequenceReservationResult {
    Reserved,
    ExactRetry,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkObservation {
    pub source_tenant_id: TenantId,
    pub observing_tenant_id: TenantId,
    pub public_ref_token: Digest32,
    pub observation_id: RecordId,
    pub payload_digest: Digest32,
    pub token_digest: Digest32,
    pub evidence_ref: RecordId,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WatermarkObservationResult {
    Recorded,
    Duplicate {
        first_payload_digest: Digest32,
        first_token_digest: Digest32,
        first_evidence_ref: RecordId,
        first_observed_at_unix_ms: u64,
    },
}
