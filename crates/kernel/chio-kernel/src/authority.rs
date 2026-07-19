use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence,
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey, Signature, SigningBackend, SigningOutcome};
use chio_core::{CanonicalBytes, CanonicalJsonWitness};
use chio_keyring::{SystemTrustedClock, TrustedClock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::{NoContext, Timestamp, Uuid};

use crate::KernelError;
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;

/// Authoritative tenant and capability-lineage binding for direct issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityIssuanceContext {
    pub tenant_id: TenantId,
    pub lineage_id: LineageId,
    pub session_id: Option<SessionId>,
    pub principal_id: Option<PrincipalId>,
    pub isolation_epoch_id: Option<IsolationEpochId>,
    pub context_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityAuthorityWorkloadBinding {
    pub tenant_id: String,
    pub workload_id: String,
    pub server_id: String,
    pub signer_public_key: PublicKey,
}

impl CapabilityIssuanceContext {
    #[must_use]
    pub fn authoritative_session(
        tenant_id: TenantId,
        lineage_id: LineageId,
        session_id: SessionId,
        principal_id: PrincipalId,
        isolation_epoch_id: IsolationEpochId,
        context_generation: u64,
    ) -> Self {
        Self {
            tenant_id,
            lineage_id,
            session_id: Some(session_id),
            principal_id: Some(principal_id),
            isolation_epoch_id: Some(isolation_epoch_id),
            context_generation: Some(context_generation),
        }
    }

    #[must_use]
    pub const fn tenant_lineage(tenant_id: TenantId, lineage_id: LineageId) -> Self {
        Self {
            tenant_id,
            lineage_id,
            session_id: None,
            principal_id: None,
            isolation_epoch_id: None,
            context_generation: None,
        }
    }
}

pub trait CapabilityAuthority: Send + Sync {
    fn authority_public_key(&self) -> PublicKey;

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.authority_public_key()]
    }

    fn workload_binding(&self) -> Option<CapabilityAuthorityWorkloadBinding> {
        None
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError>;

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        _runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability(subject, scope, ttl_seconds)
    }

    fn issue_capability_with_security_context(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        _security_context: &CapabilityIssuanceContext,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, runtime_attestation)
    }
}

/// Resolves current and historical runtime authority keys using durable
/// key-log state and trusted artifact-time evidence. Once installed, the
/// resolver is authoritative for runtime-key verification. Implementations
/// must verify the exact byte preimage and signature supplied by the caller
/// and return only the claimed issuer when that signature remains valid.
pub trait AuthorityArtifactTrustResolver: Send + Sync {
    fn trusted_issuer_for_artifact(
        &self,
        artifact: &[u8],
        claimed_issuer: &PublicKey,
        signature: &Signature,
    ) -> Result<Option<PublicKey>, String>;
}

pub struct LocalCapabilityAuthority {
    keypair: Keypair,
    clock: Arc<dyn TrustedClock>,
}

impl LocalCapabilityAuthority {
    pub fn new(keypair: Keypair) -> Self {
        Self::new_with_clock(keypair, Arc::new(SystemTrustedClock))
    }

    pub fn new_with_clock(keypair: Keypair, clock: Arc<dyn TrustedClock>) -> Self {
        Self { keypair, clock }
    }
}

pub(crate) fn capability_authority_now_unix_secs(
    clock: &dyn TrustedClock,
) -> Result<u64, KernelError> {
    if let Some(now) = crate::fixed_runtime_unix_secs_for_current_thread() {
        return Ok(now);
    }
    clock
        .now()
        .map(|now_unix_ms| now_unix_ms / 1_000)
        .map_err(|error| {
            KernelError::CapabilityIssuanceFailed(format!(
                "capability authority clock is unavailable: {error}"
            ))
        })
}

fn capability_id_at(now_unix_secs: u64) -> Result<String, KernelError> {
    const MAX_UUID_V7_UNIX_SECS: u64 = ((1_u64 << 48) - 1) / 1_000;
    if now_unix_secs > MAX_UUID_V7_UNIX_SECS {
        return Err(KernelError::CapabilityIssuanceFailed(
            "capability authority clock is outside the UUIDv7 timestamp range".to_string(),
        ));
    }
    let timestamp = Timestamp::from_unix(NoContext, now_unix_secs, 0);
    Ok(format!("cap-{}", Uuid::new_v7(timestamp)))
}

impl CapabilityAuthority for LocalCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = capability_authority_now_unix_secs(self.clock.as_ref())?;
        let body = CapabilityTokenBody {
            id: capability_id_at(now)?,
            issuer: self.keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };

        CapabilityToken::sign(body, &self.keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

pub struct GovernedCapabilityAuthority {
    backend: Arc<dyn SigningBackend>,
    clock: Arc<dyn TrustedClock>,
}

pub(crate) struct TrackedAuthoritySigningBackend {
    inner: Arc<dyn SigningBackend>,
    used: Arc<AtomicBool>,
}

impl TrackedAuthoritySigningBackend {
    pub(crate) fn wrap(
        inner: Arc<dyn SigningBackend>,
    ) -> (Arc<dyn SigningBackend>, Arc<AtomicBool>) {
        let used = Arc::new(AtomicBool::new(false));
        let backend: Arc<dyn SigningBackend> = Arc::new(Self {
            inner,
            used: Arc::clone(&used),
        });
        (backend, used)
    }

    fn mark_used(&self) {
        self.used.store(true, Ordering::Release);
    }
}

impl SigningBackend for TrackedAuthoritySigningBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        self.mark_used();
        self.inner.sign_bytes(message)
    }

    fn sign_bytes_with_identity(&self, message: &[u8]) -> chio_core::error::Result<SigningOutcome> {
        self.mark_used();
        self.inner.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(
        &self,
        expected_key: &PublicKey,
        message: &[u8],
    ) -> chio_core::error::Result<SigningOutcome> {
        self.mark_used();
        self.inner.sign_bytes_for_identity(expected_key, message)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> chio_core::error::Result<Signature> {
        self.mark_used();
        self.inner.sign_canonical_bytes(canonical)
    }
}

impl GovernedCapabilityAuthority {
    pub(crate) fn new(backend: Arc<dyn SigningBackend>, clock: Arc<dyn TrustedClock>) -> Self {
        Self { backend, clock }
    }
}

impl CapabilityAuthority for GovernedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.backend.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = capability_authority_now_unix_secs(self.clock.as_ref())?;
        let body = CapabilityTokenBody {
            id: capability_id_at(now)?,
            issuer: self.backend.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign_with_backend(body, self.backend.as_ref())
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub public_key: PublicKey,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustedKeySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub activated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_keys: Vec<AuthorityTrustedKeySnapshot>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare authority store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid authority seed: {0}")]
    Core(#[from] chio_core::error::Error),

    #[error("authority fence rejected mutation: {0}")]
    Fence(String),

    #[error("{0}")]
    Schema(String),
}
