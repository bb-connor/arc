// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chio_core_types::canonical_json_bytes;
use chio_security_types::ports::{
    ArtifactId, Digest32, PortError, PortErrorKind, RecordId, SealedDecoyRegistryStore, TenantId,
};
use chio_security_types::{
    DecoyAeadNonce, DecoyArtifactLookup, DecoyErrorClass, DecoyEvidenceRef, DecoyLifecycle,
    DecoyOperationAttempt, DecoyRecord, DecoyScan, DecoySurface, DecoyVersion,
    EncryptedDecoyEnvelope, SealedDecoyCasRequest, SealedDecoyRecord, SealedMarkerLookup,
    SealedPublicRefLookup, MAX_DECOY_EXPORT_PAGE, MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES,
};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::lifecycle::{
    fail_transition as fail_lifecycle_transition, retry_transition as retry_lifecycle_transition,
    transition as apply_lifecycle_transition, ArmedReplacement, LifecycleError,
};
use crate::materialize::{
    CleanupRequest, FileMaterializer, MaterializationIdentity, MaterializationReceipt,
    MaterializationRequest, MaterializeError,
};

const PRIVATE_ENVELOPE_SCHEMA_V1: &str = "chio.decoy-private-envelope.v1";
const PRIVATE_ENVELOPE_SCHEMA: &str = "chio.decoy-private-envelope.v2";
const ARTIFACT_INDEX_DOMAIN: &[u8] = b"chio-decoy-artifact-index-v1";
const MARKER_INDEX_DOMAIN: &[u8] = b"chio-decoy-marker-index-v1";
const PUBLIC_REF_INDEX_DOMAIN: &[u8] = b"chio-decoy-public-ref-index-v1";
const OPERATION_INDEX_DOMAIN: &[u8] = b"chio-decoy-operation-index-v1";
const TRANSITION_INDEX_DOMAIN: &[u8] = b"chio-decoy-transition-index-v1";
const VERSION_HASH_DOMAIN: &[u8] = b"chio-decoy-version-hash-v1";
const EVIDENCE_ID_DOMAIN: &[u8] = b"chio-decoy-evidence-id-v1";
const ENVELOPE_AAD_DOMAIN: &[u8] = b"chio-decoy-envelope-aad-v1";
const ARM_OPERATION_DOMAIN: &[u8] = b"chio-decoy-arm-operation-v1";
const MAX_EXPORT_CREDENTIAL_BYTES: usize = 4_096;
pub const MAX_REGISTRY_LEGACY_KEYS: usize = 4;

type HmacSha256 = Hmac<Sha256>;

pub struct RegistryKey {
    encryption_key: Zeroizing<[u8; 32]>,
    index_key: Zeroizing<[u8; 32]>,
}

impl RegistryKey {
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 64]) -> Self {
        let mut encryption_key = [0_u8; 32];
        let mut index_key = [0_u8; 32];
        encryption_key.copy_from_slice(&bytes[..32]);
        index_key.copy_from_slice(&bytes[32..]);
        bytes.zeroize();
        Self {
            encryption_key: Zeroizing::new(encryption_key),
            index_key: Zeroizing::new(index_key),
        }
    }

    fn encryption_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }

    fn index_key(&self) -> &[u8; 32] {
        &self.index_key
    }
}

impl fmt::Debug for RegistryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RegistryKeyVersion(u32);

impl RegistryKeyVersion {
    pub fn new(value: u32) -> Result<Self, RegistryError> {
        if value == 0 {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

pub struct VersionedRegistryKey {
    version: RegistryKeyVersion,
    key: RegistryKey,
}

impl VersionedRegistryKey {
    #[must_use]
    pub const fn new(version: RegistryKeyVersion, key: RegistryKey) -> Self {
        Self { version, key }
    }

    #[must_use]
    pub const fn version(&self) -> RegistryKeyVersion {
        self.version
    }

    fn key(&self) -> &RegistryKey {
        &self.key
    }
}

impl fmt::Debug for VersionedRegistryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedRegistryKey")
            .field("version", &self.version)
            .field("key", &"<redacted>")
            .finish()
    }
}

pub struct LegacyRegistryKey {
    key: VersionedRegistryKey,
    overlap_started_at_unix_ms: u64,
    overlap_ends_at_unix_ms: u64,
}

impl LegacyRegistryKey {
    pub fn new(
        key: VersionedRegistryKey,
        overlap_started_at_unix_ms: u64,
        overlap_ends_at_unix_ms: u64,
    ) -> Result<Self, RegistryError> {
        if overlap_started_at_unix_ms == 0 || overlap_ends_at_unix_ms <= overlap_started_at_unix_ms
        {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(Self {
            key,
            overlap_started_at_unix_ms,
            overlap_ends_at_unix_ms,
        })
    }

    #[must_use]
    pub const fn version(&self) -> RegistryKeyVersion {
        self.key.version()
    }

    #[must_use]
    pub const fn overlap_started_at_unix_ms(&self) -> u64 {
        self.overlap_started_at_unix_ms
    }

    #[must_use]
    pub const fn overlap_ends_at_unix_ms(&self) -> u64 {
        self.overlap_ends_at_unix_ms
    }

    const fn is_readable_at(&self, now_unix_ms: u64) -> bool {
        self.overlap_started_at_unix_ms <= now_unix_ms && now_unix_ms < self.overlap_ends_at_unix_ms
    }
}

impl fmt::Debug for LegacyRegistryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyRegistryKey")
            .field("version", &self.key.version)
            .field(
                "overlap_started_at_unix_ms",
                &self.overlap_started_at_unix_ms,
            )
            .field("overlap_ends_at_unix_ms", &self.overlap_ends_at_unix_ms)
            .field("key", &"<redacted>")
            .finish()
    }
}

pub struct RegistryKeyRing {
    active: VersionedRegistryKey,
    legacy: Vec<LegacyRegistryKey>,
    evaluated_at_unix_ms: u64,
}

impl RegistryKeyRing {
    pub fn new(
        active: VersionedRegistryKey,
        legacy: Vec<LegacyRegistryKey>,
        evaluated_at_unix_ms: u64,
    ) -> Result<Self, RegistryError> {
        if evaluated_at_unix_ms == 0 || legacy.len() > MAX_REGISTRY_LEGACY_KEYS {
            return Err(RegistryError::IntegrityFailure);
        }
        for (index, candidate) in legacy.iter().enumerate() {
            if candidate.overlap_started_at_unix_ms > evaluated_at_unix_ms
                || candidate.version() == active.version()
                || same_registry_key(candidate.key.key(), active.key())
            {
                return Err(RegistryError::IntegrityFailure);
            }
            if legacy[..index].iter().any(|existing| {
                existing.version() == candidate.version()
                    || same_registry_key(existing.key.key(), candidate.key.key())
            }) {
                return Err(RegistryError::IntegrityFailure);
            }
        }
        Ok(Self {
            active,
            legacy,
            evaluated_at_unix_ms,
        })
    }

    #[must_use]
    pub const fn active(&self) -> &VersionedRegistryKey {
        &self.active
    }

    #[must_use]
    pub fn legacy(&self) -> &[LegacyRegistryKey] {
        self.legacy.as_slice()
    }

    #[must_use]
    pub const fn evaluated_at_unix_ms(&self) -> u64 {
        self.evaluated_at_unix_ms
    }

    fn has_expired_legacy(&self) -> bool {
        self.legacy
            .iter()
            .any(|key| self.evaluated_at_unix_ms >= key.overlap_ends_at_unix_ms)
    }
}

pub trait RegistryKeyProvider: Send + Sync {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError>;

    fn keyring_for(&self, tenant_id: &TenantId) -> Result<RegistryKeyRing, RegistryError> {
        RegistryKeyRing::new(
            VersionedRegistryKey::new(RegistryKeyVersion(1), self.key_for(tenant_id)?),
            Vec::new(),
            1,
        )
    }
}

pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, RegistryError> {
        if bytes.is_empty() {
            return Err(RegistryError::EmptySecret);
        }
        if bytes.len() > MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES {
            return Err(RegistryError::SecretTooLarge);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PartialEq for SecretMaterial {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for SecretMaterial {}

pub struct PrivilegedExportCredential(Zeroizing<Vec<u8>>);

impl PrivilegedExportCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, RegistryError> {
        if bytes.is_empty() || bytes.len() > MAX_EXPORT_CREDENTIAL_BYTES {
            return Err(RegistryError::InvalidCredential);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for PrivilegedExportCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivilegedExportCredential(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryExportGrant {
    tenant_id: TenantId,
    max_entries: u16,
    expires_at_unix_ms: u64,
}

impl RegistryExportGrant {
    pub fn new(
        tenant_id: TenantId,
        max_entries: u16,
        expires_at_unix_ms: u64,
    ) -> Result<Self, RegistryError> {
        if max_entries == 0 || max_entries > MAX_DECOY_EXPORT_PAGE || expires_at_unix_ms == 0 {
            return Err(RegistryError::InvalidGrant);
        }
        Ok(Self {
            tenant_id,
            max_entries,
            expires_at_unix_ms,
        })
    }
}

pub trait RegistryExportAuthorizer: Send + Sync {
    fn authorize(
        &self,
        credential: &PrivilegedExportCredential,
        now_unix_ms: u64,
    ) -> Result<RegistryExportGrant, RegistryError>;
}

pub struct DecoyCreateRequest {
    pub tenant_id: TenantId,
    pub artifact_id: ArtifactId,
    pub surface: DecoySurface,
    pub scope_id: RecordId,
    pub creation_policy_id: RecordId,
    pub version: DecoyVersion,
    pub expires_at_unix_ms: u64,
    pub predecessor_artifact_id: Option<ArtifactId>,
    pub marker: SecretMaterial,
    pub materialization_payload: Option<SecretMaterial>,
}

impl fmt::Debug for DecoyCreateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecoyCreateRequest")
            .field("tenant_id", &self.tenant_id)
            .field("surface", &self.surface)
            .field("version", &self.version)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("marker", &"<redacted>")
            .field("materialization_payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    #[error("registry key is unavailable")]
    KeyUnavailable,
    #[error("registry export is not authorized")]
    AuthorizationDenied,
    #[error("registry export authorization expired")]
    AuthorizationExpired,
    #[error("registry export limit exceeds authorization")]
    ExportLimitExceeded,
    #[error("registry export credential is invalid")]
    InvalidCredential,
    #[error("registry export grant is invalid")]
    InvalidGrant,
    #[error("secret material must not be empty")]
    EmptySecret,
    #[error("secret material exceeds the byte limit")]
    SecretTooLarge,
    #[error("registry request is invalid")]
    InvalidRequest,
    #[error("registry entry was not found")]
    NotFound,
    #[error("registry operation conflicts with durable state")]
    Conflict,
    #[error("registry persistence is unavailable")]
    Unavailable,
    #[error("registry integrity validation failed")]
    IntegrityFailure,
    #[error("registry envelope authentication failed")]
    AuthenticationFailed,
    #[error("registry envelope serialization failed")]
    Serialization,
    #[error("decoy file materialization failed: {0}")]
    Materialization(MaterializeError),
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
}

struct PrivateEnvelope {
    schema: String,
    key_version: Option<RegistryKeyVersion>,
    record: DecoyRecord,
    marker: Vec<u8>,
    materialization_payload: Option<Vec<u8>>,
    materialization_operation_id: Option<RecordId>,
    materialization_receipt: Option<Vec<u8>>,
    last_operation_id: RecordId,
    last_attempt: Option<DecoyOperationAttempt>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SerializablePrivateEnvelope<'a> {
    schema: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<RegistryKeyVersion>,
    record: &'a DecoyRecord,
    marker: &'a [u8],
    materialization_payload: Option<&'a [u8]>,
    materialization_operation_id: Option<&'a RecordId>,
    materialization_receipt: Option<&'a [u8]>,
    last_operation_id: &'a RecordId,
    last_attempt: Option<&'a DecoyOperationAttempt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeserializablePrivateEnvelope {
    schema: String,
    #[serde(default)]
    key_version: Option<RegistryKeyVersion>,
    record: DecoyRecord,
    marker: Vec<u8>,
    materialization_payload: Option<Vec<u8>>,
    materialization_operation_id: Option<RecordId>,
    materialization_receipt: Option<Vec<u8>>,
    last_operation_id: RecordId,
    last_attempt: Option<DecoyOperationAttempt>,
}

impl Serialize for PrivateEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializablePrivateEnvelope {
            schema: self.schema.as_str(),
            key_version: self.key_version,
            record: &self.record,
            marker: self.marker.as_slice(),
            materialization_payload: self.materialization_payload.as_deref(),
            materialization_operation_id: self.materialization_operation_id.as_ref(),
            materialization_receipt: self.materialization_receipt.as_deref(),
            last_operation_id: &self.last_operation_id,
            last_attempt: self.last_attempt.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PrivateEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = DeserializablePrivateEnvelope::deserialize(deserializer)?;
        Ok(Self {
            schema: value.schema,
            key_version: value.key_version,
            record: value.record,
            marker: value.marker,
            materialization_payload: value.materialization_payload,
            materialization_operation_id: value.materialization_operation_id,
            materialization_receipt: value.materialization_receipt,
            last_operation_id: value.last_operation_id,
            last_attempt: value.last_attempt,
        })
    }
}

impl Drop for PrivateEnvelope {
    fn drop(&mut self) {
        self.marker.zeroize();
        if let Some(payload) = self.materialization_payload.as_mut() {
            payload.zeroize();
        }
        if let Some(receipt) = self.materialization_receipt.as_mut() {
            receipt.zeroize();
        }
    }
}

pub struct PrivilegedDecoyExport {
    record: DecoyRecord,
    marker: SecretMaterial,
    materialization_payload: Option<SecretMaterial>,
}

impl PrivilegedDecoyExport {
    #[must_use]
    pub const fn record(&self) -> &DecoyRecord {
        &self.record
    }

    #[must_use]
    pub const fn marker(&self) -> &SecretMaterial {
        &self.marker
    }

    #[must_use]
    pub const fn materialization_payload(&self) -> Option<&SecretMaterial> {
        self.materialization_payload.as_ref()
    }
}

impl fmt::Debug for PrivilegedDecoyExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivilegedDecoyExport")
            .field("tenant_id", &self.record.tenant_id)
            .field("surface", &self.record.surface)
            .field("version_hash", &self.record.version_hash)
            .field("marker", &"<redacted>")
            .field("materialization_payload", &"<redacted>")
            .finish()
    }
}

impl PartialEq for PrivilegedDecoyExport {
    fn eq(&self, other: &Self) -> bool {
        self.record == other.record
            && self.marker == other.marker
            && self.materialization_payload == other.materialization_payload
    }
}

impl Eq for PrivilegedDecoyExport {}

#[derive(Debug, Eq, PartialEq)]
pub struct PrivilegedExportPage {
    entries: Vec<PrivilegedDecoyExport>,
    next_cursor: Option<Digest32>,
}

impl PrivilegedExportPage {
    #[must_use]
    pub fn entries(&self) -> &[PrivilegedDecoyExport] {
        self.entries.as_slice()
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<Digest32> {
        self.next_cursor
    }
}

pub(crate) struct ResolvedDecoy {
    pub(crate) record: DecoyRecord,
    pub(crate) evidence: DecoyEvidenceRef,
    pub(crate) public_ref_token: Option<Digest32>,
}

struct OpenedEnvelope<'a> {
    key: &'a VersionedRegistryKey,
    sealed: SealedDecoyRecord,
    envelope: PrivateEnvelope,
}

#[derive(Clone)]
pub struct PrivateDecoyRegistry {
    store: Arc<dyn SealedDecoyRegistryStore>,
    keys: Arc<dyn RegistryKeyProvider>,
    export_authorizer: Arc<dyn RegistryExportAuthorizer>,
}

impl PrivateDecoyRegistry {
    #[must_use]
    pub fn new(
        store: Arc<dyn SealedDecoyRegistryStore>,
        keys: Arc<dyn RegistryKeyProvider>,
        export_authorizer: Arc<dyn RegistryExportAuthorizer>,
    ) -> Self {
        Self {
            store,
            keys,
            export_authorizer,
        }
    }

    pub fn create(
        &self,
        request: DecoyCreateRequest,
        operation_id: RecordId,
    ) -> Result<DecoyRecord, RegistryError> {
        if request.expires_at_unix_ms == 0 {
            return Err(RegistryError::InvalidRequest);
        }
        let keys = self.keys.keyring_for(&request.tenant_id)?;
        let key = keys.active();
        let artifact_token = artifact_token(key.key(), &request.tenant_id, &request.artifact_id)?;
        if let Some(existing) =
            self.load_envelope(&keys, &request.tenant_id, &request.artifact_id)?
        {
            let envelope = existing.envelope;
            if envelope.last_operation_id == operation_id
                && create_request_matches(&request, &envelope)
            {
                return Ok(envelope.record.clone());
            }
            return Err(RegistryError::Conflict);
        }
        self.validate_predecessor(&keys, &request)?;

        if self
            .load_marker_envelope(
                &keys,
                &request.tenant_id,
                request.surface,
                request.marker.as_bytes(),
            )?
            .is_some()
        {
            return Err(RegistryError::Conflict);
        }

        let public_marker_ref = (request.surface == DecoySurface::SignedWatermark)
            .then(generate_public_marker_ref)
            .transpose()?;
        let marker_digest = sha256_parts(&[request.marker.as_bytes()]);
        let version_hash = version_hash(&request, public_marker_ref.as_ref(), marker_digest)?;
        let marker_token = marker_token(
            key.key(),
            &request.tenant_id,
            request.surface,
            request.marker.as_bytes(),
        )?;
        let record = DecoyRecord {
            tenant_id: request.tenant_id.clone(),
            artifact_id: request.artifact_id.clone(),
            public_marker_ref,
            surface: request.surface,
            scope_id: request.scope_id.clone(),
            marker_digest,
            creation_policy_id: request.creation_policy_id.clone(),
            version: request.version,
            version_hash,
            lifecycle: DecoyLifecycle::Planned,
            generation: 0,
            expires_at_unix_ms: request.expires_at_unix_ms,
            predecessor_artifact_id: request.predecessor_artifact_id.clone(),
            successor_artifact_id: None,
        };
        record
            .validate()
            .map_err(|_| RegistryError::InvalidRequest)?;
        let envelope = PrivateEnvelope {
            schema: PRIVATE_ENVELOPE_SCHEMA.to_string(),
            key_version: Some(key.version()),
            record: record.clone(),
            marker: request.marker.into_vec(),
            materialization_payload: request
                .materialization_payload
                .map(SecretMaterial::into_vec),
            materialization_operation_id: None,
            materialization_receipt: None,
            last_operation_id: operation_id.clone(),
            last_attempt: None,
        };
        let sealed = seal_envelope(
            key,
            artifact_token,
            marker_token,
            record.surface,
            record.version_hash,
            record.generation,
            &envelope,
        )?;
        let request = SealedDecoyCasRequest {
            record: sealed.clone(),
            expected_generation: None,
            operation_token: operation_token(key.key(), &record.tenant_id, &operation_id)?,
            transition_token: transition_token(
                key.key(),
                &record.tenant_id,
                &operation_id,
                b"create",
                None,
                record.generation,
            )?,
        };
        let stored = self
            .store
            .compare_and_swap(&request)
            .map_err(map_port_error)?;
        if stored != sealed {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(record)
    }

    pub fn load_private(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
    ) -> Result<Option<DecoyRecord>, RegistryError> {
        let keys = self.keys.keyring_for(tenant_id)?;
        let opened = self.load_envelope(&keys, tenant_id, artifact_id)?;
        Ok(opened.map(|opened| opened.envelope.record.clone()))
    }

    pub(crate) fn resolve_public_marker_ref(
        &self,
        tenant_id: &TenantId,
        public_marker_ref: &RecordId,
    ) -> Result<Option<ResolvedDecoy>, RegistryError> {
        let keys = self.keys.keyring_for(tenant_id)?;
        let Some(opened) = self.load_public_ref_envelope(&keys, tenant_id, public_marker_ref)?
        else {
            return Ok(None);
        };
        let sealed = opened.sealed;
        let envelope = opened.envelope;
        if envelope.record.surface != DecoySurface::SignedWatermark
            || envelope.record.public_marker_ref.as_ref() != Some(public_marker_ref)
        {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(Some(ResolvedDecoy {
            public_ref_token: Some(
                sealed
                    .public_ref_token
                    .ok_or(RegistryError::IntegrityFailure)?,
            ),
            evidence: DecoyEvidenceRef {
                artifact_id_hash: evidence_artifact_hash(
                    &envelope.record.tenant_id,
                    &envelope.record.artifact_id,
                ),
                version_hash: envelope.record.version_hash,
            },
            record: envelope.record.clone(),
        }))
    }

    pub fn materialize_file(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        operation_id: &RecordId,
        relative_path: &Path,
        materializer: &FileMaterializer,
        now_unix_ms: u64,
    ) -> Result<MaterializationReceipt, RegistryError> {
        if now_unix_ms == 0 {
            return Err(RegistryError::InvalidRequest);
        }
        let keys = self.keys.keyring_for(tenant_id)?;
        let opened = self
            .load_envelope(&keys, tenant_id, artifact_id)?
            .ok_or(RegistryError::NotFound)?;
        let key = opened.key;
        let mut envelope = opened.envelope;
        if !requires_file_materialization(envelope.record.surface)
            || envelope.record.expires_at_unix_ms <= now_unix_ms
        {
            return Err(RegistryError::InvalidRequest);
        }

        if matches!(envelope.record.lifecycle, DecoyLifecycle::Planned) {
            let begin = DecoyOperationAttempt {
                operation_id: operation_id.clone(),
                kind: chio_security_types::DecoyOperationKind::BeginMaterialization,
                expected_generation: envelope.record.generation,
                expected_version: envelope.record.version,
                successor_artifact_id: None,
            };
            self.apply_transition(tenant_id, artifact_id, &begin)?;
            envelope = self
                .load_envelope(&keys, tenant_id, artifact_id)?
                .map(|opened| opened.envelope)
                .ok_or(RegistryError::NotFound)?;
        }

        if envelope.materialization_operation_id.as_ref() != Some(operation_id) {
            return Err(RegistryError::Conflict);
        }
        if envelope.record.lifecycle.is_matchable() {
            let receipt = decode_materialization_receipt(&envelope)?;
            if receipt.proof.relative_path != relative_path {
                return Err(RegistryError::Conflict);
            }
            return Ok(receipt);
        }
        let can_continue = matches!(envelope.record.lifecycle, DecoyLifecycle::Materializing)
            || matches!(
                envelope.record.lifecycle,
                DecoyLifecycle::Error {
                    prior: chio_security_types::DecoyLifecycleState::Materializing,
                    ..
                }
            );
        if !can_continue {
            return Err(RegistryError::Conflict);
        }
        let payload = envelope
            .materialization_payload
            .as_deref()
            .ok_or(RegistryError::InvalidRequest)?;
        let identity = MaterializationIdentity {
            operation_id: operation_id.as_str().to_string(),
            tenant_id: tenant_id.as_str().to_string(),
            artifact_id: artifact_id.as_str().to_string(),
            version_hash: *envelope.record.version_hash.as_bytes(),
        };
        let receipt = match materializer.materialize(&MaterializationRequest {
            identity: &identity,
            relative_path,
            content: payload,
        }) {
            Ok(receipt) => receipt,
            Err(error) => {
                if matches!(envelope.record.lifecycle, DecoyLifecycle::Materializing) {
                    let arm = arm_attempt(&envelope.record, operation_id)?;
                    if let Err(store_error) = self.fail_transition(
                        tenant_id,
                        artifact_id,
                        &arm,
                        materialization_error_class(error),
                    ) {
                        if !matches!(store_error, RegistryError::Conflict) {
                            return Err(store_error);
                        }
                    }
                }
                return Err(RegistryError::Materialization(error));
            }
        };
        match self.commit_materialization_receipt(
            key,
            tenant_id,
            artifact_id,
            operation_id,
            &receipt,
        ) {
            Ok(()) => Ok(receipt),
            Err(RegistryError::Conflict) => {
                let current = self
                    .load_envelope(&keys, tenant_id, artifact_id)?
                    .map(|opened| opened.envelope)
                    .ok_or(RegistryError::NotFound)?;
                let durable = decode_materialization_receipt(&current)?;
                if durable == receipt {
                    Ok(durable)
                } else {
                    Err(RegistryError::Conflict)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub fn retire_materialized_file(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        attempt: &DecoyOperationAttempt,
        materializer: &FileMaterializer,
    ) -> Result<DecoyRecord, RegistryError> {
        if !matches!(
            attempt.kind,
            chio_security_types::DecoyOperationKind::Retire
        ) {
            return Err(RegistryError::InvalidRequest);
        }
        let keys = self.keys.keyring_for(tenant_id)?;
        let envelope = self
            .load_envelope(&keys, tenant_id, artifact_id)?
            .map(|opened| opened.envelope)
            .ok_or(RegistryError::NotFound)?;
        if matches!(envelope.record.lifecycle, DecoyLifecycle::Retired)
            && envelope.last_attempt.as_ref() == Some(attempt)
        {
            return Ok(envelope.record.clone());
        }
        let error_retry = matches!(
            &envelope.record.lifecycle,
            DecoyLifecycle::Error {
                prior: chio_security_types::DecoyLifecycleState::Rotating,
                attempted,
                ..
            } if attempted == attempt
        );
        if !matches!(envelope.record.lifecycle, DecoyLifecycle::Rotating) && !error_retry {
            return Err(RegistryError::Conflict);
        }
        let receipt = decode_materialization_receipt(&envelope)?;
        if let Err(error) = materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: attempt.operation_id.as_str(),
            receipt: &receipt,
        }) {
            if matches!(envelope.record.lifecycle, DecoyLifecycle::Rotating) {
                if let Err(store_error) = self.fail_transition(
                    tenant_id,
                    artifact_id,
                    attempt,
                    materialization_error_class(error),
                ) {
                    if !matches!(store_error, RegistryError::Conflict) {
                        return Err(store_error);
                    }
                }
            }
            return Err(RegistryError::Materialization(error));
        }
        if error_retry {
            self.retry_transition(tenant_id, artifact_id, attempt)
        } else {
            self.apply_transition(tenant_id, artifact_id, attempt)
        }
    }

    pub fn apply_transition(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        attempt: &DecoyOperationAttempt,
    ) -> Result<DecoyRecord, RegistryError> {
        self.update_lifecycle(tenant_id, artifact_id, attempt, None, UpdateKind::Apply)
    }

    pub fn fail_transition(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        attempt: &DecoyOperationAttempt,
        error_class: DecoyErrorClass,
    ) -> Result<DecoyRecord, RegistryError> {
        self.update_lifecycle(
            tenant_id,
            artifact_id,
            attempt,
            Some(error_class),
            UpdateKind::Fail,
        )
    }

    pub fn retry_transition(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        attempt: &DecoyOperationAttempt,
    ) -> Result<DecoyRecord, RegistryError> {
        self.update_lifecycle(tenant_id, artifact_id, attempt, None, UpdateKind::Retry)
    }

    pub fn export_page(
        &self,
        credential: &PrivilegedExportCredential,
        after_cursor: Option<Digest32>,
        limit: u16,
        now_unix_ms: u64,
    ) -> Result<PrivilegedExportPage, RegistryError> {
        let grant = self.export_authorizer.authorize(credential, now_unix_ms)?;
        if grant.expires_at_unix_ms <= now_unix_ms {
            return Err(RegistryError::AuthorizationExpired);
        }
        if limit == 0 || limit > grant.max_entries || limit > MAX_DECOY_EXPORT_PAGE {
            return Err(RegistryError::ExportLimitExceeded);
        }
        let keys = self.keys.keyring_for(&grant.tenant_id)?;
        let page = self
            .store
            .scan(&DecoyScan {
                tenant_id: grant.tenant_id.clone(),
                after_artifact_token: after_cursor,
                limit,
            })
            .map_err(map_port_error)?;
        let mut entries = Vec::with_capacity(page.records.len());
        for record in page.records.as_slice() {
            let mut envelope = open_scanned_envelope(&keys, record)?;
            let marker = SecretMaterial::new(std::mem::take(&mut envelope.marker))?;
            let materialization_payload = envelope
                .materialization_payload
                .take()
                .map(SecretMaterial::new)
                .transpose()?;
            entries.push(PrivilegedDecoyExport {
                record: envelope.record.clone(),
                marker,
                materialization_payload,
            });
        }
        Ok(PrivilegedExportPage {
            entries,
            next_cursor: page.next_artifact_token,
        })
    }

    pub(crate) fn resolve_marker(
        &self,
        tenant_id: &TenantId,
        surface: DecoySurface,
        presented: &[u8],
    ) -> Result<Option<ResolvedDecoy>, RegistryError> {
        if presented.is_empty() || presented.len() > MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES {
            return Err(RegistryError::InvalidRequest);
        }
        let keys = self.keys.keyring_for(tenant_id)?;
        let Some(opened) = self.load_marker_envelope(&keys, tenant_id, surface, presented)? else {
            return Ok(None);
        };
        let sealed = opened.sealed;
        let envelope = opened.envelope;
        let evidence = DecoyEvidenceRef {
            artifact_id_hash: evidence_artifact_hash(
                &envelope.record.tenant_id,
                &envelope.record.artifact_id,
            ),
            version_hash: envelope.record.version_hash,
        };
        Ok(Some(ResolvedDecoy {
            record: envelope.record.clone(),
            evidence,
            public_ref_token: sealed.public_ref_token,
        }))
    }

    fn validate_predecessor(
        &self,
        keys: &RegistryKeyRing,
        request: &DecoyCreateRequest,
    ) -> Result<(), RegistryError> {
        let Some(predecessor_id) = request.predecessor_artifact_id.as_ref() else {
            if request.version.get() != 1 {
                return Err(RegistryError::InvalidRequest);
            }
            return Ok(());
        };
        let predecessor = self
            .load_envelope(keys, &request.tenant_id, predecessor_id)?
            .map(|opened| opened.envelope)
            .ok_or(RegistryError::NotFound)?;
        let expected_version = predecessor
            .record
            .version
            .checked_next()
            .map_err(|_| RegistryError::InvalidRequest)?;
        if predecessor.record.surface != request.surface
            || predecessor.record.scope_id != request.scope_id
            || predecessor.record.successor_artifact_id.is_some()
            || request.version != expected_version
            || !matches!(predecessor.record.lifecycle, DecoyLifecycle::Triggered)
        {
            return Err(RegistryError::InvalidRequest);
        }
        Ok(())
    }

    fn load_envelope<'a>(
        &self,
        keys: &'a RegistryKeyRing,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
    ) -> Result<Option<OpenedEnvelope<'a>>, RegistryError> {
        self.find_envelope(keys, |key| {
            let lookup = DecoyArtifactLookup {
                tenant_id: tenant_id.clone(),
                artifact_token: artifact_token(key, tenant_id, artifact_id)?,
            };
            self.store.load_by_id(&lookup).map_err(map_port_error)
        })
    }

    fn load_marker_envelope<'a>(
        &self,
        keys: &'a RegistryKeyRing,
        tenant_id: &TenantId,
        surface: DecoySurface,
        marker: &[u8],
    ) -> Result<Option<OpenedEnvelope<'a>>, RegistryError> {
        self.find_envelope(keys, |key| {
            let lookup = SealedMarkerLookup {
                tenant_id: tenant_id.clone(),
                surface,
                marker_token: marker_token(key, tenant_id, surface, marker)?,
            };
            self.store.load_by_marker(&lookup).map_err(map_port_error)
        })
    }

    fn load_public_ref_envelope<'a>(
        &self,
        keys: &'a RegistryKeyRing,
        tenant_id: &TenantId,
        public_marker_ref: &RecordId,
    ) -> Result<Option<OpenedEnvelope<'a>>, RegistryError> {
        self.find_envelope(keys, |key| {
            let lookup = SealedPublicRefLookup {
                tenant_id: tenant_id.clone(),
                public_ref_token: public_ref_token(key, tenant_id, public_marker_ref)?,
            };
            self.store
                .load_by_public_ref(&lookup)
                .map_err(map_port_error)
        })
    }

    fn find_envelope<'a, F>(
        &self,
        keys: &'a RegistryKeyRing,
        mut lookup: F,
    ) -> Result<Option<OpenedEnvelope<'a>>, RegistryError>
    where
        F: FnMut(&RegistryKey) -> Result<Option<SealedDecoyRecord>, RegistryError>,
    {
        let mut authentication_failed = false;
        if let Some(sealed) = lookup(keys.active.key())? {
            match open_envelope(&keys.active, &sealed) {
                Ok(envelope) => {
                    return Ok(Some(OpenedEnvelope {
                        key: &keys.active,
                        sealed,
                        envelope,
                    }));
                }
                Err(RegistryError::AuthenticationFailed) => authentication_failed = true,
                Err(error) => return Err(error),
            }
        }
        for legacy in &keys.legacy {
            if !legacy.is_readable_at(keys.evaluated_at_unix_ms) {
                continue;
            }
            if let Some(sealed) = lookup(legacy.key.key())? {
                match open_envelope(&legacy.key, &sealed) {
                    Ok(envelope) => {
                        return Ok(Some(OpenedEnvelope {
                            key: &legacy.key,
                            sealed,
                            envelope,
                        }));
                    }
                    Err(RegistryError::AuthenticationFailed) => authentication_failed = true,
                    Err(error) => return Err(error),
                }
            }
        }
        if keys.has_expired_legacy() {
            return Err(RegistryError::KeyUnavailable);
        }
        if authentication_failed {
            return Err(RegistryError::AuthenticationFailed);
        }
        Ok(None)
    }

    fn update_lifecycle(
        &self,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        attempt: &DecoyOperationAttempt,
        error_class: Option<DecoyErrorClass>,
        kind: UpdateKind,
    ) -> Result<DecoyRecord, RegistryError> {
        let keys = self.keys.keyring_for(tenant_id)?;
        let opened = self
            .load_envelope(&keys, tenant_id, artifact_id)?
            .ok_or(RegistryError::NotFound)?;
        let key = opened.key;
        let sealed = opened.sealed;
        let mut envelope = opened.envelope;
        if envelope.last_operation_id == attempt.operation_id
            && !(matches!(kind, UpdateKind::Retry)
                && matches!(envelope.record.lifecycle, DecoyLifecycle::Error { .. }))
        {
            if envelope.last_attempt.as_ref() == Some(attempt) {
                return Ok(envelope.record.clone());
            }
            return Err(RegistryError::Conflict);
        }
        if matches!(attempt.kind, chio_security_types::DecoyOperationKind::Arm)
            && requires_file_materialization(envelope.record.surface)
            && !matches!(kind, UpdateKind::Fail)
        {
            return Err(RegistryError::InvalidRequest);
        }

        let successor_record = if let Some(successor) = attempt.successor_artifact_id.as_ref() {
            self.load_envelope(&keys, tenant_id, successor)?
                .map(|successor| successor.envelope.record.clone())
        } else {
            None
        };
        if matches!(
            attempt.kind,
            chio_security_types::DecoyOperationKind::BeginRotation
        ) {
            let successor = successor_record.as_ref().ok_or(RegistryError::NotFound)?;
            validate_rotation_successor(&envelope.record, successor)?;
        }
        let armed_replacement = if matches!(
            attempt.kind,
            chio_security_types::DecoyOperationKind::Retire
        ) {
            successor_record
                .as_ref()
                .map(|replacement| ArmedReplacement::new(&envelope.record, replacement))
                .transpose()?
        } else {
            None
        };
        let next = match kind {
            UpdateKind::Apply => {
                apply_lifecycle_transition(&envelope.record, attempt, armed_replacement.as_ref())?
            }
            UpdateKind::Fail => fail_lifecycle_transition(
                &envelope.record,
                attempt,
                error_class.ok_or(RegistryError::InvalidRequest)?,
            )?,
            UpdateKind::Retry => {
                retry_lifecycle_transition(&envelope.record, attempt, armed_replacement.as_ref())?
            }
        };
        envelope.record = next.clone();
        if matches!(
            attempt.kind,
            chio_security_types::DecoyOperationKind::BeginMaterialization
        ) {
            match envelope.materialization_operation_id.as_ref() {
                None => envelope.materialization_operation_id = Some(attempt.operation_id.clone()),
                Some(existing) if existing == &attempt.operation_id => {}
                Some(_) => return Err(RegistryError::Conflict),
            }
        }
        envelope.last_operation_id = attempt.operation_id.clone();
        envelope.last_attempt = Some(attempt.clone());
        bind_envelope_to_key(&mut envelope, key);
        let updated = seal_envelope(
            key,
            sealed.artifact_token,
            sealed.marker_token,
            sealed.surface,
            sealed.version_hash,
            next.generation,
            &envelope,
        )?;
        let request = SealedDecoyCasRequest {
            record: updated.clone(),
            expected_generation: Some(sealed.generation),
            operation_token: operation_token(key.key(), tenant_id, &attempt.operation_id)?,
            transition_token: transition_token(
                key.key(),
                tenant_id,
                &attempt.operation_id,
                kind.domain(),
                Some(sealed.generation),
                next.generation,
            )?,
        };
        let stored = self
            .store
            .compare_and_swap(&request)
            .map_err(map_port_error)?;
        if stored != updated {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(next)
    }

    fn commit_materialization_receipt(
        &self,
        key: &VersionedRegistryKey,
        tenant_id: &TenantId,
        artifact_id: &ArtifactId,
        materialization_operation_id: &RecordId,
        receipt: &MaterializationReceipt,
    ) -> Result<(), RegistryError> {
        let lookup = DecoyArtifactLookup {
            tenant_id: tenant_id.clone(),
            artifact_token: artifact_token(key.key(), tenant_id, artifact_id)?,
        };
        let sealed = self
            .store
            .load_by_id(&lookup)
            .map_err(map_port_error)?
            .ok_or(RegistryError::NotFound)?;
        let mut envelope = open_envelope(key, &sealed)?;
        if envelope.materialization_operation_id.as_ref() != Some(materialization_operation_id) {
            return Err(RegistryError::Conflict);
        }
        if envelope.record.lifecycle.is_matchable() {
            return if decode_materialization_receipt(&envelope)? == *receipt {
                Ok(())
            } else {
                Err(RegistryError::Conflict)
            };
        }
        let arm = match &envelope.record.lifecycle {
            DecoyLifecycle::Materializing => {
                arm_attempt(&envelope.record, materialization_operation_id)?
            }
            DecoyLifecycle::Error {
                prior: chio_security_types::DecoyLifecycleState::Materializing,
                attempted,
                ..
            } if matches!(attempted.kind, chio_security_types::DecoyOperationKind::Arm) => {
                attempted.clone()
            }
            _ => return Err(RegistryError::Conflict),
        };
        let retrying = matches!(envelope.record.lifecycle, DecoyLifecycle::Error { .. });
        let next = if retrying {
            retry_lifecycle_transition(&envelope.record, &arm, None)?
        } else {
            apply_lifecycle_transition(&envelope.record, &arm, None)?
        };
        let canonical_receipt = Zeroizing::new(
            canonical_json_bytes(receipt).map_err(|_| RegistryError::Serialization)?,
        );
        envelope.record = next.clone();
        envelope.materialization_receipt = Some(canonical_receipt.to_vec());
        envelope.last_operation_id = arm.operation_id.clone();
        envelope.last_attempt = Some(arm.clone());
        bind_envelope_to_key(&mut envelope, key);
        let updated = seal_envelope(
            key,
            sealed.artifact_token,
            sealed.marker_token,
            sealed.surface,
            sealed.version_hash,
            next.generation,
            &envelope,
        )?;
        let request = SealedDecoyCasRequest {
            record: updated.clone(),
            expected_generation: Some(sealed.generation),
            operation_token: operation_token(key.key(), tenant_id, &arm.operation_id)?,
            transition_token: transition_token(
                key.key(),
                tenant_id,
                &arm.operation_id,
                if retrying { b"arm_retry" } else { b"arm" },
                Some(sealed.generation),
                next.generation,
            )?,
        };
        let stored = self
            .store
            .compare_and_swap(&request)
            .map_err(map_port_error)?;
        if stored != updated {
            return Err(RegistryError::IntegrityFailure);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum UpdateKind {
    Apply,
    Fail,
    Retry,
}

impl UpdateKind {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Apply => b"apply",
            Self::Fail => b"failure",
            Self::Retry => b"retry",
        }
    }
}

fn create_request_matches(request: &DecoyCreateRequest, envelope: &PrivateEnvelope) -> bool {
    envelope.record.tenant_id == request.tenant_id
        && envelope.record.artifact_id == request.artifact_id
        && (envelope.record.surface != DecoySurface::SignedWatermark
            || envelope.record.public_marker_ref.is_some())
        && envelope.record.surface == request.surface
        && envelope.record.scope_id == request.scope_id
        && envelope.record.creation_policy_id == request.creation_policy_id
        && envelope.record.version == request.version
        && envelope.record.expires_at_unix_ms == request.expires_at_unix_ms
        && envelope.record.predecessor_artifact_id == request.predecessor_artifact_id
        && envelope.marker.as_slice() == request.marker.as_bytes()
        && match (
            envelope.materialization_payload.as_deref(),
            request
                .materialization_payload
                .as_ref()
                .map(SecretMaterial::as_bytes),
        ) {
            (Some(left), Some(right)) => left == right,
            (None, None) => true,
            _ => false,
        }
}

fn validate_rotation_successor(
    predecessor: &DecoyRecord,
    successor: &DecoyRecord,
) -> Result<(), RegistryError> {
    let expected_version = predecessor
        .version
        .checked_next()
        .map_err(|_| RegistryError::InvalidRequest)?;
    if predecessor.tenant_id != successor.tenant_id
        || predecessor.artifact_id == successor.artifact_id
        || predecessor.surface != successor.surface
        || predecessor.scope_id != successor.scope_id
        || (predecessor.surface == DecoySurface::SignedWatermark
            && predecessor.public_marker_ref == successor.public_marker_ref)
        || successor.predecessor_artifact_id.as_ref() != Some(&predecessor.artifact_id)
        || successor.version != expected_version
    {
        return Err(RegistryError::IntegrityFailure);
    }
    Ok(())
}

fn arm_attempt(
    record: &DecoyRecord,
    materialization_operation_id: &RecordId,
) -> Result<DecoyOperationAttempt, RegistryError> {
    Ok(DecoyOperationAttempt {
        operation_id: derived_operation_id(
            ARM_OPERATION_DOMAIN,
            &record.tenant_id,
            &record.artifact_id,
            materialization_operation_id,
        )?,
        kind: chio_security_types::DecoyOperationKind::Arm,
        expected_generation: record.generation,
        expected_version: record.version,
        successor_artifact_id: None,
    })
}

fn derived_operation_id(
    domain: &[u8],
    tenant_id: &TenantId,
    artifact_id: &ArtifactId,
    source_operation_id: &RecordId,
) -> Result<RecordId, RegistryError> {
    let digest = sha256_framed(&[
        domain,
        tenant_id.as_str().as_bytes(),
        artifact_id.as_str().as_bytes(),
        source_operation_id.as_str().as_bytes(),
    ])?;
    RecordId::new(format!("arm-{}", hex::encode(digest.as_bytes())))
        .map_err(|_| RegistryError::IntegrityFailure)
}

fn decode_materialization_receipt(
    envelope: &PrivateEnvelope,
) -> Result<MaterializationReceipt, RegistryError> {
    let bytes = envelope
        .materialization_receipt
        .as_deref()
        .ok_or(RegistryError::IntegrityFailure)?;
    serde_json::from_slice(bytes).map_err(|_| RegistryError::IntegrityFailure)
}

const fn materialization_error_class(error: MaterializeError) -> DecoyErrorClass {
    match error {
        MaterializeError::Unsupported => DecoyErrorClass::Unsupported,
        MaterializeError::InvalidRoot
        | MaterializeError::InvalidIdentity
        | MaterializeError::InvalidPath(_)
        | MaterializeError::Symlink => DecoyErrorClass::InvalidInput,
        MaterializeError::Io { .. } => DecoyErrorClass::IoFailure,
        MaterializeError::ForeignExisting
        | MaterializeError::OwnershipMismatch
        | MaterializeError::MetadataMismatch
        | MaterializeError::ContentMismatch
        | MaterializeError::Hardlink
        | MaterializeError::QuarantineConflict => DecoyErrorClass::IntegrityFailure,
    }
}

fn open_scanned_envelope(
    keys: &RegistryKeyRing,
    sealed: &SealedDecoyRecord,
) -> Result<PrivateEnvelope, RegistryError> {
    match open_envelope(&keys.active, sealed) {
        Ok(envelope) => return Ok(envelope),
        Err(RegistryError::AuthenticationFailed) => {}
        Err(error) => return Err(error),
    }
    for legacy in &keys.legacy {
        if !legacy.is_readable_at(keys.evaluated_at_unix_ms) {
            continue;
        }
        match open_envelope(&legacy.key, sealed) {
            Ok(envelope) => return Ok(envelope),
            Err(RegistryError::AuthenticationFailed) => {}
            Err(error) => return Err(error),
        }
    }
    if keys.has_expired_legacy() {
        Err(RegistryError::KeyUnavailable)
    } else {
        Err(RegistryError::AuthenticationFailed)
    }
}

fn bind_envelope_to_key(envelope: &mut PrivateEnvelope, key: &VersionedRegistryKey) {
    envelope.schema = PRIVATE_ENVELOPE_SCHEMA.to_string();
    envelope.key_version = Some(key.version());
}

fn validate_envelope_key_binding(
    envelope: &PrivateEnvelope,
    key: &VersionedRegistryKey,
) -> Result<(), RegistryError> {
    match (envelope.schema.as_str(), envelope.key_version) {
        (PRIVATE_ENVELOPE_SCHEMA, Some(version)) if version == key.version() => Ok(()),
        (PRIVATE_ENVELOPE_SCHEMA, Some(_)) => Err(RegistryError::KeyUnavailable),
        (PRIVATE_ENVELOPE_SCHEMA_V1, None) => Ok(()),
        _ => Err(RegistryError::IntegrityFailure),
    }
}

fn seal_envelope(
    key: &VersionedRegistryKey,
    artifact_token: Digest32,
    marker_token: Digest32,
    surface: DecoySurface,
    version_hash: Digest32,
    generation: u64,
    envelope: &PrivateEnvelope,
) -> Result<SealedDecoyRecord, RegistryError> {
    if envelope.schema != PRIVATE_ENVELOPE_SCHEMA || envelope.key_version != Some(key.version()) {
        return Err(RegistryError::IntegrityFailure);
    }
    let public_ref_token = envelope
        .record
        .public_marker_ref
        .as_ref()
        .map(|public_marker_ref| {
            public_ref_token(key.key(), &envelope.record.tenant_id, public_marker_ref)
        })
        .transpose()?;
    let plaintext =
        Zeroizing::new(canonical_json_bytes(envelope).map_err(|_| RegistryError::Serialization)?);
    let aad = envelope_aad(
        &envelope.record.tenant_id,
        artifact_token,
        surface,
        marker_token,
        public_ref_token,
        version_hash,
        generation,
    )?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.key().encryption_key()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| RegistryError::IntegrityFailure)?;
    Ok(SealedDecoyRecord {
        tenant_id: envelope.record.tenant_id.clone(),
        artifact_token,
        public_ref_token,
        surface,
        marker_token,
        version_hash,
        generation,
        nonce: DecoyAeadNonce::new(nonce),
        encrypted_envelope: EncryptedDecoyEnvelope::new(ciphertext)
            .map_err(|_| RegistryError::SecretTooLarge)?,
    })
}

fn open_envelope(
    key: &VersionedRegistryKey,
    sealed: &SealedDecoyRecord,
) -> Result<PrivateEnvelope, RegistryError> {
    let aad = envelope_aad(
        &sealed.tenant_id,
        sealed.artifact_token,
        sealed.surface,
        sealed.marker_token,
        sealed.public_ref_token,
        sealed.version_hash,
        sealed.generation,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.key().encryption_key()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(sealed.nonce.as_bytes()),
                Payload {
                    msg: sealed.encrypted_envelope.as_bytes(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| RegistryError::AuthenticationFailed)?,
    );
    let envelope: PrivateEnvelope = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| RegistryError::IntegrityFailure)?;
    let canonical = Zeroizing::new(
        canonical_json_bytes(&envelope).map_err(|_| RegistryError::IntegrityFailure)?,
    );
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(RegistryError::IntegrityFailure);
    }
    validate_envelope_key_binding(&envelope, key)?;
    validate_opened_envelope(key, sealed, &envelope)?;
    Ok(envelope)
}

fn validate_opened_envelope(
    key: &VersionedRegistryKey,
    sealed: &SealedDecoyRecord,
    envelope: &PrivateEnvelope,
) -> Result<(), RegistryError> {
    envelope
        .record
        .validate()
        .map_err(|_| RegistryError::IntegrityFailure)?;
    if envelope.record.tenant_id != sealed.tenant_id
        || envelope.record.surface != sealed.surface
        || envelope.record.version_hash != sealed.version_hash
        || envelope.record.generation != sealed.generation
        || sha256_parts(&[envelope.marker.as_slice()]) != envelope.record.marker_digest
        || artifact_token(
            key.key(),
            &envelope.record.tenant_id,
            &envelope.record.artifact_id,
        )? != sealed.artifact_token
        || marker_token(
            key.key(),
            &envelope.record.tenant_id,
            envelope.record.surface,
            envelope.marker.as_slice(),
        )? != sealed.marker_token
        || envelope
            .record
            .public_marker_ref
            .as_ref()
            .map(|public_marker_ref| {
                public_ref_token(key.key(), &envelope.record.tenant_id, public_marker_ref)
            })
            .transpose()?
            != sealed.public_ref_token
    {
        return Err(RegistryError::IntegrityFailure);
    }
    validate_materialization_binding(envelope)?;
    Ok(())
}

fn validate_materialization_binding(envelope: &PrivateEnvelope) -> Result<(), RegistryError> {
    let materialization_in_progress = matches!(
        envelope.record.lifecycle,
        DecoyLifecycle::Materializing
            | DecoyLifecycle::Error {
                prior: chio_security_types::DecoyLifecycleState::Materializing,
                ..
            }
    );
    if materialization_in_progress && envelope.materialization_operation_id.is_none() {
        return Err(RegistryError::IntegrityFailure);
    }
    let Some(bytes) = envelope.materialization_receipt.as_deref() else {
        if requires_file_materialization(envelope.record.surface)
            && envelope.record.lifecycle.is_matchable()
        {
            return Err(RegistryError::IntegrityFailure);
        }
        return Ok(());
    };
    let operation_id = envelope
        .materialization_operation_id
        .as_ref()
        .ok_or(RegistryError::IntegrityFailure)?;
    let receipt: MaterializationReceipt =
        serde_json::from_slice(bytes).map_err(|_| RegistryError::IntegrityFailure)?;
    let canonical = Zeroizing::new(
        canonical_json_bytes(&receipt).map_err(|_| RegistryError::IntegrityFailure)?,
    );
    if canonical.as_slice() != bytes
        || receipt.identity.operation_id != operation_id.as_str()
        || receipt.identity.tenant_id != envelope.record.tenant_id.as_str()
        || receipt.identity.artifact_id != envelope.record.artifact_id.as_str()
        || receipt.identity.version_hash != *envelope.record.version_hash.as_bytes()
    {
        return Err(RegistryError::IntegrityFailure);
    }
    Ok(())
}

const fn requires_file_materialization(surface: DecoySurface) -> bool {
    matches!(
        surface,
        DecoySurface::CredentialFile | DecoySurface::FileMarker
    )
}

fn artifact_token(
    key: &RegistryKey,
    tenant_id: &TenantId,
    artifact_id: &ArtifactId,
) -> Result<Digest32, RegistryError> {
    keyed_digest(
        key.index_key(),
        ARTIFACT_INDEX_DOMAIN,
        &[
            tenant_id.as_str().as_bytes(),
            artifact_id.as_str().as_bytes(),
        ],
    )
}

fn marker_token(
    key: &RegistryKey,
    tenant_id: &TenantId,
    surface: DecoySurface,
    marker: &[u8],
) -> Result<Digest32, RegistryError> {
    keyed_digest(
        key.index_key(),
        MARKER_INDEX_DOMAIN,
        &[
            tenant_id.as_str().as_bytes(),
            surface.domain_name().as_bytes(),
            marker,
        ],
    )
}

fn public_ref_token(
    key: &RegistryKey,
    tenant_id: &TenantId,
    public_marker_ref: &RecordId,
) -> Result<Digest32, RegistryError> {
    keyed_digest(
        key.index_key(),
        PUBLIC_REF_INDEX_DOMAIN,
        &[
            tenant_id.as_str().as_bytes(),
            public_marker_ref.as_str().as_bytes(),
        ],
    )
}

fn generate_public_marker_ref() -> Result<RecordId, RegistryError> {
    let mut entropy = [0_u8; 24];
    OsRng.fill_bytes(&mut entropy);
    RecordId::new(format!("wmref_{}", hex::encode(entropy)))
        .map_err(|_| RegistryError::IntegrityFailure)
}

fn operation_token(
    key: &RegistryKey,
    tenant_id: &TenantId,
    operation_id: &RecordId,
) -> Result<Digest32, RegistryError> {
    keyed_digest(
        key.index_key(),
        OPERATION_INDEX_DOMAIN,
        &[
            tenant_id.as_str().as_bytes(),
            operation_id.as_str().as_bytes(),
        ],
    )
}

fn transition_token(
    key: &RegistryKey,
    tenant_id: &TenantId,
    operation_id: &RecordId,
    phase: &[u8],
    expected_generation: Option<u64>,
    result_generation: u64,
) -> Result<Digest32, RegistryError> {
    let expected = expected_generation.unwrap_or(u64::MAX).to_be_bytes();
    let result = result_generation.to_be_bytes();
    keyed_digest(
        key.index_key(),
        TRANSITION_INDEX_DOMAIN,
        &[
            tenant_id.as_str().as_bytes(),
            operation_id.as_str().as_bytes(),
            phase,
            &expected,
            &result,
        ],
    )
}

fn keyed_digest(key: &[u8; 32], domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, RegistryError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| RegistryError::IntegrityFailure)?;
    update_framed(&mut mac, domain)?;
    for part in parts {
        update_framed(&mut mac, part)?;
    }
    let output = mac.finalize().into_bytes();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(output.as_slice());
    Ok(Digest32::new(digest))
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), RegistryError> {
    let len = u64::try_from(value.len()).map_err(|_| RegistryError::InvalidRequest)?;
    mac.update(&len.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn version_hash(
    request: &DecoyCreateRequest,
    public_marker_ref: Option<&RecordId>,
    marker_digest: Digest32,
) -> Result<Digest32, RegistryError> {
    let version = request.version.get().to_be_bytes();
    let predecessor = request
        .predecessor_artifact_id
        .as_ref()
        .map_or(&[][..], |id| id.as_str().as_bytes());
    let public_marker_ref = public_marker_ref.map_or(&[][..], |id| id.as_str().as_bytes());
    sha256_framed(&[
        VERSION_HASH_DOMAIN,
        request.tenant_id.as_str().as_bytes(),
        request.artifact_id.as_str().as_bytes(),
        request.surface.domain_name().as_bytes(),
        request.scope_id.as_str().as_bytes(),
        request.creation_policy_id.as_str().as_bytes(),
        &version,
        marker_digest.as_bytes(),
        public_marker_ref,
        predecessor,
    ])
}

fn evidence_artifact_hash(tenant_id: &TenantId, artifact_id: &ArtifactId) -> Digest32 {
    sha256_parts(&[
        EVIDENCE_ID_DOMAIN,
        tenant_id.as_str().as_bytes(),
        artifact_id.as_str().as_bytes(),
    ])
}

fn envelope_aad(
    tenant_id: &TenantId,
    artifact_token: Digest32,
    surface: DecoySurface,
    marker_token: Digest32,
    public_ref_token: Option<Digest32>,
    version_hash: Digest32,
    generation: u64,
) -> Result<Vec<u8>, RegistryError> {
    let generation = generation.to_be_bytes();
    let mut public_ref = [0_u8; 33];
    if let Some(token) = public_ref_token {
        public_ref[0] = 1;
        public_ref[1..].copy_from_slice(token.as_bytes());
    }
    framed_bytes(&[
        ENVELOPE_AAD_DOMAIN,
        tenant_id.as_str().as_bytes(),
        artifact_token.as_bytes(),
        surface.domain_name().as_bytes(),
        marker_token.as_bytes(),
        &public_ref,
        version_hash.as_bytes(),
        &generation,
    ])
}

fn sha256_framed(parts: &[&[u8]]) -> Result<Digest32, RegistryError> {
    let bytes = framed_bytes(parts)?;
    Ok(sha256_parts(&[bytes.as_slice()]))
}

fn sha256_parts(parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let output = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(output.as_slice());
    Digest32::new(digest)
}

fn framed_bytes(parts: &[&[u8]]) -> Result<Vec<u8>, RegistryError> {
    let mut output = Vec::new();
    for part in parts {
        let len = u64::try_from(part.len()).map_err(|_| RegistryError::InvalidRequest)?;
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(part);
    }
    Ok(output)
}

fn same_registry_key(left: &RegistryKey, right: &RegistryKey) -> bool {
    left.encryption_key() == right.encryption_key() && left.index_key() == right.index_key()
}

fn map_port_error(error: PortError) -> RegistryError {
    match error.kind() {
        PortErrorKind::Unavailable => RegistryError::Unavailable,
        PortErrorKind::Conflict => RegistryError::Conflict,
        PortErrorKind::InvalidData => RegistryError::InvalidRequest,
        PortErrorKind::IntegrityFailure => RegistryError::IntegrityFailure,
    }
}
