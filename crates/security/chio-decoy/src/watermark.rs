// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::{canonical_json_bytes, PublicKey, Signature, SigningBackend};
use chio_security_types::ports::{
    Digest32, PortError, PortErrorKind, PortResult, RecordId, TenantId, WatermarkObservationStore,
    WatermarkSequenceStore,
};
use chio_security_types::{
    DecoyEvidenceRef, DecoyLifecycle, WatermarkObservation, WatermarkObservationResult,
    WatermarkSequenceKey, WatermarkSequenceReservation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::registry::{PrivateDecoyRegistry, RegistryError, ResolvedDecoy};

const ENVELOPE_SCHEMA: &str = "chio.signed-watermark-envelope.v1";
const SIGNING_DOMAIN: &[u8] = b"chio.signed-watermark.v1\0";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"chio.watermark-payload-digest.v1\0";
const TOKEN_DIGEST_DOMAIN: &[u8] = b"chio.watermark-token-digest.v1\0";
const TOKEN_PREFIX: &str = "[[chio-wm1:";
const TOKEN_SUFFIX: &str = "]]";
const MAX_TOKEN_BYTES: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4 * 1_048_576;
const MAX_CANDIDATES: usize = 32;
pub const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkEncoding {
    Base64UrlCanonicalJson,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatermarkPayload {
    pub tenant_id: TenantId,
    pub application_id: RecordId,
    pub session_id: RecordId,
    pub source_receipt_id: RecordId,
    pub tool_id: RecordId,
    pub sequence: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub marker_ref: RecordId,
    pub key_id: RecordId,
    pub encoding: WatermarkEncoding,
}

impl WatermarkPayload {
    fn validate_shape(&self) -> Result<(), WatermarkCandidateError> {
        if self.sequence == 0
            || self.sequence > MAX_IJSON_INTEGER
            || self.issued_at_unix_ms == 0
            || self.issued_at_unix_ms > MAX_IJSON_INTEGER
            || self.expires_at_unix_ms > MAX_IJSON_INTEGER
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(WatermarkCandidateError::InvalidPayload);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatermarkIssueRequest {
    pub source_receipt_id: RecordId,
    pub marker_ref: RecordId,
    pub sequence: u64,
    pub operation_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWatermarkEnvelope {
    pub schema: String,
    pub payload: WatermarkPayload,
    pub encoded_payload: String,
    pub signature: Signature,
}

impl SignedWatermarkEnvelope {
    pub fn encode_payload(payload: &WatermarkPayload) -> Result<String, WatermarkIssueError> {
        payload
            .validate_shape()
            .map_err(|_| WatermarkIssueError::InvalidContext)?;
        let canonical = canonical_json_bytes(payload).map_err(|_| WatermarkIssueError::Encoding)?;
        Ok(URL_SAFE_NO_PAD.encode(canonical))
    }

    pub fn encode_token(&self) -> Result<String, WatermarkIssueError> {
        let canonical = canonical_json_bytes(self).map_err(|_| WatermarkIssueError::Encoding)?;
        let encoded = URL_SAFE_NO_PAD.encode(canonical);
        if encoded.len() > MAX_TOKEN_BYTES {
            return Err(WatermarkIssueError::EnvelopeTooLarge);
        }
        Ok(format!("{TOKEN_PREFIX}{encoded}{TOKEN_SUFFIX}"))
    }

    pub fn decode_token(token: &str) -> Result<Self, WatermarkCandidateError> {
        if token.len() > MAX_TOKEN_BYTES + TOKEN_PREFIX.len() + TOKEN_SUFFIX.len() {
            return Err(WatermarkCandidateError::EnvelopeTooLarge);
        }
        let encoded = token
            .strip_prefix(TOKEN_PREFIX)
            .and_then(|value| value.strip_suffix(TOKEN_SUFFIX))
            .ok_or(WatermarkCandidateError::MalformedEnvelope)?;
        if encoded.is_empty() || encoded.contains('=') {
            return Err(WatermarkCandidateError::MalformedEnvelope);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| WatermarkCandidateError::MalformedEnvelope)?;
        if bytes.len() > MAX_TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(WatermarkCandidateError::NonCanonicalEnvelope);
        }
        let envelope: Self = serde_json::from_slice(&bytes)
            .map_err(|_| WatermarkCandidateError::MalformedEnvelope)?;
        let canonical = canonical_json_bytes(&envelope)
            .map_err(|_| WatermarkCandidateError::MalformedEnvelope)?;
        if canonical != bytes || envelope.schema != ENVELOPE_SCHEMA {
            return Err(WatermarkCandidateError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, WatermarkCandidateError> {
        self.payload.validate_shape()?;
        if self.encoded_payload.contains('=') {
            return Err(WatermarkCandidateError::EncodedPayloadMismatch);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.encoded_payload)
            .map_err(|_| WatermarkCandidateError::EncodedPayloadMismatch)?;
        let canonical = canonical_json_bytes(&self.payload)
            .map_err(|_| WatermarkCandidateError::InvalidPayload)?;
        if decoded != canonical || URL_SAFE_NO_PAD.encode(&decoded) != self.encoded_payload {
            return Err(WatermarkCandidateError::EncodedPayloadMismatch);
        }
        Ok(canonical)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatermarkSourceContext {
    pub tenant_id: TenantId,
    pub application_id: RecordId,
    pub session_id: RecordId,
    pub source_receipt_id: RecordId,
    pub tool_id: RecordId,
    pub issued_at_unix_ms: u64,
    pub not_after_unix_ms: u64,
}

impl WatermarkSourceContext {
    fn validate(&self) -> Result<(), WatermarkIssueError> {
        if self.issued_at_unix_ms == 0
            || self.issued_at_unix_ms > MAX_IJSON_INTEGER
            || self.not_after_unix_ms > MAX_IJSON_INTEGER
            || self.not_after_unix_ms <= self.issued_at_unix_ms
        {
            return Err(WatermarkIssueError::InvalidContext);
        }
        Ok(())
    }
}

pub trait WatermarkSourceContextResolver: Send + Sync {
    fn resolve(&self, source_receipt_id: &RecordId) -> PortResult<Option<WatermarkSourceContext>>;
}

pub trait WatermarkClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatermarkIssuerPolicy {
    ttl_ms: u64,
    max_context_age_ms: u64,
    max_future_skew_ms: u64,
}

impl WatermarkIssuerPolicy {
    pub const fn new(
        ttl_ms: u64,
        max_context_age_ms: u64,
        max_future_skew_ms: u64,
    ) -> Result<Self, WatermarkIssueError> {
        if ttl_ms == 0
            || ttl_ms > MAX_IJSON_INTEGER
            || max_context_age_ms > MAX_IJSON_INTEGER
            || max_future_skew_ms > MAX_IJSON_INTEGER
        {
            return Err(WatermarkIssueError::InvalidPolicy);
        }
        Ok(Self {
            ttl_ms,
            max_context_age_ms,
            max_future_skew_ms,
        })
    }
}

#[derive(Clone)]
pub struct WatermarkIssuerConfig {
    pub key_id: RecordId,
    pub policy: WatermarkIssuerPolicy,
}

pub struct WatermarkIssuerDependencies {
    pub signer: Arc<dyn SigningBackend>,
    pub keys: Arc<dyn WatermarkKeyResolver>,
    pub registry: PrivateDecoyRegistry,
    pub contexts: Arc<dyn WatermarkSourceContextResolver>,
    pub sequences: Arc<dyn WatermarkSequenceStore>,
    pub clock: Arc<dyn WatermarkClock>,
}

pub struct WatermarkIssuer {
    config: WatermarkIssuerConfig,
    dependencies: WatermarkIssuerDependencies,
}

impl WatermarkIssuer {
    #[must_use]
    pub fn new(config: WatermarkIssuerConfig, dependencies: WatermarkIssuerDependencies) -> Self {
        Self {
            config,
            dependencies,
        }
    }

    pub fn issue(&self, request: WatermarkIssueRequest) -> Result<String, WatermarkIssueError> {
        if request.sequence == 0 || request.sequence > MAX_IJSON_INTEGER {
            return Err(WatermarkIssueError::InvalidSequence);
        }
        let context = self
            .dependencies
            .contexts
            .resolve(&request.source_receipt_id)
            .map_err(map_issue_dependency_error)?
            .ok_or(WatermarkIssueError::UnverifiedContext)?;
        context.validate()?;
        if context.source_receipt_id != request.source_receipt_id {
            return Err(WatermarkIssueError::InvalidContext);
        }
        let now = self.dependencies.clock.now_unix_ms();
        validate_issuance_time(now, &context, self.config.policy)?;
        let trusted = self
            .dependencies
            .keys
            .resolve(&context.tenant_id, &self.config.key_id)
            .map_err(map_issue_dependency_error)?
            .ok_or(WatermarkIssueError::UntrustedKey)?;
        trusted.validate()?;
        if trusted.status != WatermarkKeyStatus::Active
            || trusted.public_key != self.dependencies.signer.public_key()
            || now < trusted.not_before_unix_ms
            || now >= trusted.signing_cutoff_unix_ms
            || context.issued_at_unix_ms < trusted.not_before_unix_ms
            || context.issued_at_unix_ms >= trusted.signing_cutoff_unix_ms
        {
            return Err(WatermarkIssueError::KeyNotActive);
        }
        let resolved = self
            .dependencies
            .registry
            .resolve_public_marker_ref(&context.tenant_id, &request.marker_ref)
            .map_err(map_issue_registry_error)?
            .ok_or(WatermarkIssueError::UnknownRegistryEntry)?;
        if !resolved.record.lifecycle.is_matchable() || now >= resolved.record.expires_at_unix_ms {
            return Err(WatermarkIssueError::InactiveRegistryEntry);
        }
        let ttl_expiry = context
            .issued_at_unix_ms
            .checked_add(self.config.policy.ttl_ms)
            .ok_or(WatermarkIssueError::InvalidPolicy)?;
        let expires_at_unix_ms = ttl_expiry
            .min(context.not_after_unix_ms)
            .min(resolved.record.expires_at_unix_ms)
            .min(trusted.verify_until_unix_ms)
            .min(MAX_IJSON_INTEGER);
        if expires_at_unix_ms <= now {
            return Err(WatermarkIssueError::NoValidLifetime);
        }
        let payload = WatermarkPayload {
            tenant_id: context.tenant_id.clone(),
            application_id: context.application_id.clone(),
            session_id: context.session_id.clone(),
            source_receipt_id: context.source_receipt_id,
            tool_id: context.tool_id.clone(),
            sequence: request.sequence,
            issued_at_unix_ms: context.issued_at_unix_ms,
            expires_at_unix_ms,
            marker_ref: request.marker_ref,
            key_id: self.config.key_id.clone(),
            encoding: WatermarkEncoding::Base64UrlCanonicalJson,
        };
        let canonical =
            canonical_json_bytes(&payload).map_err(|_| WatermarkIssueError::Encoding)?;
        let public_ref_token = resolved
            .public_ref_token
            .ok_or(WatermarkIssueError::DependencyIntegrityFailure)?;
        let reservation = WatermarkSequenceReservation {
            key: WatermarkSequenceKey {
                tenant_id: context.tenant_id,
                application_id: context.application_id,
                session_id: context.session_id,
                tool_id: context.tool_id,
                public_ref_token,
            },
            sequence: payload.sequence,
            operation_id: request.operation_id,
        };
        self.dependencies
            .sequences
            .reserve(&reservation)
            .map_err(map_sequence_error)?;
        let signature = self
            .dependencies
            .signer
            .sign_bytes(&signing_message(&canonical))
            .map_err(|_| WatermarkIssueError::SigningFailed)?;
        SignedWatermarkEnvelope {
            schema: ENVELOPE_SCHEMA.to_string(),
            payload,
            encoded_payload: URL_SAFE_NO_PAD.encode(canonical),
            signature,
        }
        .encode_token()
    }
}

impl fmt::Debug for WatermarkIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WatermarkIssuer")
            .field("key_id", &self.config.key_id)
            .field("signer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkKeyStatus {
    Active,
    Overlap,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedWatermarkKey {
    pub public_key: PublicKey,
    pub status: WatermarkKeyStatus,
    pub not_before_unix_ms: u64,
    pub signing_cutoff_unix_ms: u64,
    pub verify_until_unix_ms: u64,
}

impl TrustedWatermarkKey {
    fn validate(&self) -> Result<(), WatermarkIssueError> {
        if self.not_before_unix_ms > MAX_IJSON_INTEGER
            || self.signing_cutoff_unix_ms > MAX_IJSON_INTEGER
            || self.verify_until_unix_ms > MAX_IJSON_INTEGER
            || self.signing_cutoff_unix_ms <= self.not_before_unix_ms
            || self.verify_until_unix_ms < self.signing_cutoff_unix_ms
        {
            return Err(WatermarkIssueError::InvalidKeyWindow);
        }
        Ok(())
    }
}

pub trait WatermarkKeyResolver: Send + Sync {
    fn resolve(
        &self,
        tenant_id: &TenantId,
        key_id: &RecordId,
    ) -> PortResult<Option<TrustedWatermarkKey>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatermarkObservationContext {
    pub observing_tenant_id: TenantId,
    pub observation_id: RecordId,
    pub evidence_ref: RecordId,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatermarkScanVerdict {
    Clear,
    Advisory,
    ActiveHit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatermarkRegistryState {
    Armed,
    Triggered,
    Rotating,
    Planned,
    Materializing,
    Retired,
    Error,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatermarkObservationPersistence {
    Persisted(WatermarkObservationResult),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWatermark {
    pub payload: WatermarkPayload,
    pub key_status: WatermarkKeyStatus,
    pub evidence: DecoyEvidenceRef,
    pub registry_state: WatermarkRegistryState,
    pub cross_tenant: bool,
    pub observation: WatermarkObservationPersistence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InactiveWatermark {
    pub payload: WatermarkPayload,
    pub key_status: WatermarkKeyStatus,
    pub evidence: DecoyEvidenceRef,
    pub registry_state: WatermarkRegistryState,
    pub cross_tenant: bool,
    pub observation: WatermarkObservationPersistence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatermarkScanReport {
    pub verdict: WatermarkScanVerdict,
    pub active_hits: Vec<VerifiedWatermark>,
    pub inactive_hits: Vec<InactiveWatermark>,
    pub malformed_candidates: u16,
    pub invalid_candidates: u16,
    pub duplicate_candidates: u16,
    pub detector_failures: u16,
}

pub struct WatermarkVerifierDependencies {
    pub keys: Arc<dyn WatermarkKeyResolver>,
    pub contexts: Arc<dyn WatermarkSourceContextResolver>,
    pub registry: PrivateDecoyRegistry,
    pub observations: Arc<dyn WatermarkObservationStore>,
}

pub struct WatermarkVerifier {
    dependencies: WatermarkVerifierDependencies,
}

impl WatermarkVerifier {
    #[must_use]
    pub fn new(dependencies: WatermarkVerifierDependencies) -> Self {
        Self { dependencies }
    }

    pub fn scan_text(
        &self,
        text: &str,
        context: &WatermarkObservationContext,
    ) -> Result<WatermarkScanReport, WatermarkScanError> {
        if context.observed_at_unix_ms == 0 || context.observed_at_unix_ms > MAX_IJSON_INTEGER {
            return Err(WatermarkScanError::InvalidObservationContext);
        }
        let candidates = scan_candidates(text)?;
        let mut report = WatermarkScanReport {
            verdict: WatermarkScanVerdict::Clear,
            active_hits: Vec::new(),
            inactive_hits: Vec::new(),
            malformed_candidates: candidates.malformed,
            invalid_candidates: 0,
            duplicate_candidates: 0,
            detector_failures: 0,
        };
        let mut seen = BTreeSet::new();
        let mut unresolved_infrastructure_failure = false;
        for token in candidates.tokens {
            let token_digest = digest(TOKEN_DIGEST_DOMAIN, token.as_bytes());
            if !seen.insert(token_digest) {
                report.duplicate_candidates = report.duplicate_candidates.saturating_add(1);
                continue;
            }
            match self.verify_candidate(token, token_digest, context) {
                CandidateResult::Active(hit, persistence_failed) => {
                    report.active_hits.push(hit);
                    if persistence_failed {
                        report.detector_failures = report.detector_failures.saturating_add(1);
                    }
                }
                CandidateResult::Inactive(hit, persistence_failed) => {
                    report.inactive_hits.push(hit);
                    if persistence_failed {
                        report.detector_failures = report.detector_failures.saturating_add(1);
                    }
                }
                CandidateResult::Invalid => {
                    report.invalid_candidates = report.invalid_candidates.saturating_add(1);
                }
                CandidateResult::InfrastructureFailure => {
                    unresolved_infrastructure_failure = true;
                    report.detector_failures = report.detector_failures.saturating_add(1);
                }
            }
        }
        if !report.active_hits.is_empty() {
            report.verdict = WatermarkScanVerdict::ActiveHit;
            return Ok(report);
        }
        if unresolved_infrastructure_failure {
            return Err(WatermarkScanError::DetectorUnavailable);
        }
        if !report.inactive_hits.is_empty()
            || report.malformed_candidates > 0
            || report.invalid_candidates > 0
        {
            report.verdict = WatermarkScanVerdict::Advisory;
        }
        Ok(report)
    }

    fn verify_candidate(
        &self,
        token: &str,
        token_digest: Digest32,
        observation_context: &WatermarkObservationContext,
    ) -> CandidateResult {
        let envelope = match SignedWatermarkEnvelope::decode_token(token) {
            Ok(envelope) => envelope,
            Err(_) => return CandidateResult::Invalid,
        };
        let canonical = match envelope.canonical_payload() {
            Ok(canonical) => canonical,
            Err(_) => return CandidateResult::Invalid,
        };
        let trusted = match self
            .dependencies
            .keys
            .resolve(&envelope.payload.tenant_id, &envelope.payload.key_id)
        {
            Ok(Some(trusted)) => trusted,
            Ok(None) => return CandidateResult::Invalid,
            Err(_) => return CandidateResult::InfrastructureFailure,
        };
        if trusted.validate().is_err()
            || trusted.status == WatermarkKeyStatus::Rejected
            || !trusted
                .public_key
                .verify(&signing_message(&canonical), &envelope.signature)
        {
            return CandidateResult::Invalid;
        }
        let source_context = match self
            .dependencies
            .contexts
            .resolve(&envelope.payload.source_receipt_id)
        {
            Ok(Some(context)) => context,
            Ok(None) => return CandidateResult::Invalid,
            Err(_) => return CandidateResult::InfrastructureFailure,
        };
        if !payload_matches_context(&envelope.payload, &source_context)
            || !payload_within_key_window(
                &envelope.payload,
                &trusted,
                observation_context.observed_at_unix_ms,
            )
        {
            return CandidateResult::Invalid;
        }
        let resolved = match self
            .dependencies
            .registry
            .resolve_public_marker_ref(&envelope.payload.tenant_id, &envelope.payload.marker_ref)
        {
            Ok(Some(resolved)) => resolved,
            Ok(None) => return CandidateResult::Invalid,
            Err(RegistryError::KeyUnavailable | RegistryError::Unavailable) => {
                return CandidateResult::InfrastructureFailure;
            }
            Err(_) => return CandidateResult::InfrastructureFailure,
        };
        let registry_state = registry_state(&resolved, observation_context.observed_at_unix_ms);
        let Some(public_ref_token) = resolved.public_ref_token else {
            return CandidateResult::InfrastructureFailure;
        };
        let payload_digest = digest(PAYLOAD_DIGEST_DOMAIN, &canonical);
        let observation = WatermarkObservation {
            source_tenant_id: envelope.payload.tenant_id.clone(),
            observing_tenant_id: observation_context.observing_tenant_id.clone(),
            public_ref_token,
            observation_id: observation_context.observation_id.clone(),
            payload_digest,
            token_digest,
            evidence_ref: observation_context.evidence_ref.clone(),
            observed_at_unix_ms: observation_context.observed_at_unix_ms,
        };
        let (persistence, persistence_failed) =
            match self.dependencies.observations.record_first(&observation) {
                Ok(result) if observation_result_matches(&result, payload_digest, token_digest) => {
                    (WatermarkObservationPersistence::Persisted(result), false)
                }
                Ok(_) | Err(_) => (WatermarkObservationPersistence::Failed, true),
            };
        let cross_tenant = envelope.payload.tenant_id != observation_context.observing_tenant_id;
        if matches!(
            registry_state,
            WatermarkRegistryState::Armed
                | WatermarkRegistryState::Triggered
                | WatermarkRegistryState::Rotating
        ) {
            CandidateResult::Active(
                VerifiedWatermark {
                    payload: envelope.payload,
                    key_status: trusted.status,
                    evidence: resolved.evidence,
                    registry_state,
                    cross_tenant,
                    observation: persistence,
                },
                persistence_failed,
            )
        } else {
            CandidateResult::Inactive(
                InactiveWatermark {
                    payload: envelope.payload,
                    key_status: trusted.status,
                    evidence: resolved.evidence,
                    registry_state,
                    cross_tenant,
                    observation: persistence,
                },
                persistence_failed,
            )
        }
    }
}

impl fmt::Debug for WatermarkVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WatermarkVerifier(<configured>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WatermarkIssueError {
    #[error("watermark issuance policy is invalid")]
    InvalidPolicy,
    #[error("watermark sequence is invalid")]
    InvalidSequence,
    #[error("watermark source context is not verified")]
    UnverifiedContext,
    #[error("watermark source context is invalid")]
    InvalidContext,
    #[error("watermark source context is stale or future-dated")]
    ContextOutsideTimeWindow,
    #[error("watermark signing key is untrusted")]
    UntrustedKey,
    #[error("watermark signing key window is invalid")]
    InvalidKeyWindow,
    #[error("watermark signing key is not active")]
    KeyNotActive,
    #[error("watermark registry entry is unknown")]
    UnknownRegistryEntry,
    #[error("watermark registry entry is inactive")]
    InactiveRegistryEntry,
    #[error("watermark has no valid lifetime")]
    NoValidLifetime,
    #[error("watermark sequence replay was rejected")]
    SequenceReplay,
    #[error("watermark dependency is unavailable")]
    DependencyUnavailable,
    #[error("watermark dependency failed integrity validation")]
    DependencyIntegrityFailure,
    #[error("watermark signing failed")]
    SigningFailed,
    #[error("watermark encoding failed")]
    Encoding,
    #[error("watermark envelope exceeds the byte limit")]
    EnvelopeTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WatermarkScanError {
    #[error("watermark observation context is invalid")]
    InvalidObservationContext,
    #[error("watermark candidate limit exceeded")]
    CandidateLimitExceeded,
    #[error("watermark text exceeds the byte limit")]
    TextTooLarge,
    #[error("watermark detector is unavailable")]
    DetectorUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WatermarkCandidateError {
    #[error("watermark payload is invalid")]
    InvalidPayload,
    #[error("watermark envelope is malformed")]
    MalformedEnvelope,
    #[error("watermark envelope is not canonical")]
    NonCanonicalEnvelope,
    #[error("watermark envelope exceeds the byte limit")]
    EnvelopeTooLarge,
    #[error("watermark encoded payload does not match canonical payload bytes")]
    EncodedPayloadMismatch,
}

enum CandidateResult {
    Active(VerifiedWatermark, bool),
    Inactive(InactiveWatermark, bool),
    Invalid,
    InfrastructureFailure,
}

struct ScannedCandidates<'a> {
    tokens: Vec<&'a str>,
    malformed: u16,
}

fn scan_candidates(text: &str) -> Result<ScannedCandidates<'_>, WatermarkScanError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(WatermarkScanError::TextTooLarge);
    }
    let mut tokens = Vec::new();
    let mut malformed = 0_u16;
    let mut cursor = 0_usize;
    let mut count = 0_usize;
    while let Some(relative_start) = text[cursor..].find(TOKEN_PREFIX) {
        count = count.saturating_add(1);
        if count > MAX_CANDIDATES {
            return Err(WatermarkScanError::CandidateLimitExceeded);
        }
        let start = cursor + relative_start;
        let body_start = start + TOKEN_PREFIX.len();
        let remainder = &text[body_start..];
        let suffix = remainder.find(TOKEN_SUFFIX);
        let nested = remainder.find(TOKEN_PREFIX);
        if suffix.is_none() || nested.zip(suffix).is_some_and(|(next, end)| next < end) {
            malformed = malformed.saturating_add(1);
            cursor = body_start;
            continue;
        }
        let Some(suffix) = suffix else {
            malformed = malformed.saturating_add(1);
            break;
        };
        let end = body_start + suffix + TOKEN_SUFFIX.len();
        if end - start > MAX_TOKEN_BYTES + TOKEN_PREFIX.len() + TOKEN_SUFFIX.len() {
            malformed = malformed.saturating_add(1);
        } else {
            tokens.push(&text[start..end]);
        }
        cursor = end;
    }
    Ok(ScannedCandidates { tokens, malformed })
}

fn validate_issuance_time(
    now: u64,
    context: &WatermarkSourceContext,
    policy: WatermarkIssuerPolicy,
) -> Result<(), WatermarkIssueError> {
    if now == 0 || now > MAX_IJSON_INTEGER {
        return Err(WatermarkIssueError::ContextOutsideTimeWindow);
    }
    if context.issued_at_unix_ms > now {
        if context.issued_at_unix_ms - now > policy.max_future_skew_ms {
            return Err(WatermarkIssueError::ContextOutsideTimeWindow);
        }
    } else if now - context.issued_at_unix_ms > policy.max_context_age_ms {
        return Err(WatermarkIssueError::ContextOutsideTimeWindow);
    }
    Ok(())
}

fn payload_matches_context(payload: &WatermarkPayload, context: &WatermarkSourceContext) -> bool {
    context.validate().is_ok()
        && payload.tenant_id == context.tenant_id
        && payload.application_id == context.application_id
        && payload.session_id == context.session_id
        && payload.source_receipt_id == context.source_receipt_id
        && payload.tool_id == context.tool_id
        && payload.issued_at_unix_ms == context.issued_at_unix_ms
        && payload.expires_at_unix_ms <= context.not_after_unix_ms
}

fn payload_within_key_window(
    payload: &WatermarkPayload,
    key: &TrustedWatermarkKey,
    observed_at_unix_ms: u64,
) -> bool {
    payload.issued_at_unix_ms >= key.not_before_unix_ms
        && payload.issued_at_unix_ms < key.signing_cutoff_unix_ms
        && payload.expires_at_unix_ms <= key.verify_until_unix_ms
        && observed_at_unix_ms >= payload.issued_at_unix_ms
        && observed_at_unix_ms < payload.expires_at_unix_ms
        && observed_at_unix_ms < key.verify_until_unix_ms
}

fn registry_state(resolved: &ResolvedDecoy, observed_at_unix_ms: u64) -> WatermarkRegistryState {
    if observed_at_unix_ms >= resolved.record.expires_at_unix_ms {
        return WatermarkRegistryState::Expired;
    }
    match &resolved.record.lifecycle {
        DecoyLifecycle::Armed => WatermarkRegistryState::Armed,
        DecoyLifecycle::Triggered => WatermarkRegistryState::Triggered,
        DecoyLifecycle::Rotating => WatermarkRegistryState::Rotating,
        DecoyLifecycle::Planned => WatermarkRegistryState::Planned,
        DecoyLifecycle::Materializing => WatermarkRegistryState::Materializing,
        DecoyLifecycle::Retired => WatermarkRegistryState::Retired,
        DecoyLifecycle::Error { .. } => WatermarkRegistryState::Error,
    }
}

fn observation_result_matches(
    result: &WatermarkObservationResult,
    payload_digest: Digest32,
    token_digest: Digest32,
) -> bool {
    match result {
        WatermarkObservationResult::Recorded => true,
        WatermarkObservationResult::Duplicate {
            first_payload_digest,
            first_token_digest,
            ..
        } => *first_payload_digest == payload_digest && *first_token_digest == token_digest,
    }
}

fn signing_message(canonical_payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical_payload.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(canonical_payload);
    message
}

fn digest(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(output.as_slice());
    Digest32::new(digest)
}

fn map_sequence_error(error: PortError) -> WatermarkIssueError {
    match error.kind() {
        PortErrorKind::Conflict => WatermarkIssueError::SequenceReplay,
        PortErrorKind::Unavailable => WatermarkIssueError::DependencyUnavailable,
        PortErrorKind::InvalidData | PortErrorKind::IntegrityFailure => {
            WatermarkIssueError::DependencyIntegrityFailure
        }
    }
}

fn map_issue_dependency_error(error: PortError) -> WatermarkIssueError {
    match error.kind() {
        PortErrorKind::Unavailable => WatermarkIssueError::DependencyUnavailable,
        PortErrorKind::Conflict | PortErrorKind::InvalidData | PortErrorKind::IntegrityFailure => {
            WatermarkIssueError::DependencyIntegrityFailure
        }
    }
}

fn map_issue_registry_error(error: RegistryError) -> WatermarkIssueError {
    match error {
        RegistryError::KeyUnavailable | RegistryError::Unavailable => {
            WatermarkIssueError::DependencyUnavailable
        }
        RegistryError::NotFound => WatermarkIssueError::UnknownRegistryEntry,
        _ => WatermarkIssueError::DependencyIntegrityFailure,
    }
}
