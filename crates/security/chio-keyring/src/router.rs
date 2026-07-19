use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use chio_core_types::{
    canonical_json_bytes, sha256, Hash, PublicKey, Signature, SigningAlgorithm, SigningBackend,
    SigningOutcome,
};
use serde::{Deserialize, Serialize};

use crate::{
    derive_key_id, AnchorId, EventId, IndependentKeyLogServices, KeyId, KeyringError, Result,
    SignedArtifactTimeAnchor, SqliteKeyLogStore,
};

pub const KEYRING_ARTIFACT_SIGNATURE_SCHEMA: &str = "chio.keyring.artifact-signature.v1";
const ARTIFACT_HASH_DOMAIN: &[u8] = b"chio.keyring.artifact-hash.v1\0";
const ARTIFACT_SIGNATURE_DOMAIN: &[u8] = b"chio.keyring.artifact-signature.v1\0";

pub(crate) fn artifact_hash(artifact: &[u8]) -> Result<Hash> {
    domain_hash(ARTIFACT_HASH_DOMAIN, artifact)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringArtifactSignature {
    pub schema: String,
    pub artifact_hash: Hash,
    pub key_id: KeyId,
    pub signing_epoch: u64,
    pub algorithm: SigningAlgorithm,
    pub artifact_signature: Signature,
    pub fence_signature: Signature,
}

/// Atomic router result for one returned authority artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringSigningResult {
    pub public_key: PublicKey,
    pub algorithm: SigningAlgorithm,
    pub key_id: KeyId,
    pub signing_epoch: u64,
    pub signature: Signature,
    pub evidence: KeyringArtifactSignature,
    pub time_anchor: Option<SignedArtifactTimeAnchor>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactSignatureStatement<'a> {
    schema: &'static str,
    artifact_hash: Hash,
    key_id: KeyId,
    signing_epoch: u64,
    algorithm: SigningAlgorithm,
    artifact_signature: &'a Signature,
}

impl KeyringArtifactSignature {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(self)?)
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        if self.schema != KEYRING_ARTIFACT_SIGNATURE_SCHEMA
            || public_key.algorithm() != self.algorithm
            || self.artifact_signature.algorithm() != self.algorithm
            || self.fence_signature.algorithm() != self.algorithm
            || derive_key_id(public_key.algorithm(), public_key)? != self.key_id
            || !public_key.verify(
                &artifact_signature_bytes(
                    self.artifact_hash,
                    self.key_id,
                    self.signing_epoch,
                    self.algorithm,
                    &self.artifact_signature,
                )?,
                &self.fence_signature,
            )
        {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_artifact_bytes(&self, public_key: &PublicKey, artifact: &[u8]) -> Result<()> {
        self.verify(public_key)?;
        if domain_hash(ARTIFACT_HASH_DOMAIN, artifact)? != self.artifact_hash
            || !public_key.verify(artifact, &self.artifact_signature)
        {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingLease {
    event_id: EventId,
    key_id: KeyId,
    base_epoch: u64,
}

pub struct StagedPendingBackend {
    lease: PendingLease,
    backend: Option<Box<dyn SigningBackend>>,
}

struct RouterState {
    active_key_id: KeyId,
    signing_epoch: u64,
    active: Box<dyn SigningBackend>,
    pending_lease: Option<PendingLease>,
}

pub struct KeyringSigningRouter {
    store: Arc<SqliteKeyLogStore>,
    state: RwLock<RouterState>,
    artifact_time_signer: Option<ArtifactTimeSigner>,
}

struct ArtifactTimeSigner {
    anchor_id: AnchorId,
    backend: Arc<dyn SigningBackend>,
}

impl KeyringSigningRouter {
    /// Returns true only when `store` is the exact durable selector store used
    /// by this router. Runtime composition uses this identity check to prevent
    /// signing through one key log while resolving trust through another.
    #[must_use]
    pub fn uses_store(&self, store: &Arc<SqliteKeyLogStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
    }

    /// Enterprise routers may activate a selector only through the runtime
    /// path that carries the required migration admission guard.
    #[must_use]
    pub(crate) fn requires_enterprise_activation_guard(&self) -> bool {
        self.artifact_time_signer.is_some()
    }

    pub fn configuration_binding(&self) -> Result<Hash> {
        self.store.configuration_binding()
    }

    pub fn open(
        store: Arc<SqliteKeyLogStore>,
        active_backend: Box<dyn SigningBackend>,
    ) -> Result<Self> {
        Self::open_inner(store, active_backend, None)
    }

    pub fn open_enterprise(
        store: Arc<SqliteKeyLogStore>,
        active_backend: Box<dyn SigningBackend>,
        anchor_id: AnchorId,
        artifact_time_signer: Arc<dyn SigningBackend>,
    ) -> Result<Self> {
        store.validate_artifact_time_signer(&anchor_id, &artifact_time_signer.public_key())?;
        for signature in store.load_artifact_signatures()? {
            if store
                .artifact_time_anchor(&signature.artifact_hash)?
                .is_none()
            {
                return Err(KeyringError::StateInvariant(
                    "enterprise artifact signature is missing trusted-time evidence",
                ));
            }
        }
        Self::open_inner(
            store,
            active_backend,
            Some(ArtifactTimeSigner {
                anchor_id,
                backend: artifact_time_signer,
            }),
        )
    }

    fn open_inner(
        store: Arc<SqliteKeyLogStore>,
        active_backend: Box<dyn SigningBackend>,
        artifact_time_signer: Option<ArtifactTimeSigner>,
    ) -> Result<Self> {
        let durable = store
            .load_state()?
            .ok_or(KeyringError::StateInvariant("key log is not initialized"))?;
        let active = durable.active_signing_key()?;
        let active_key_id =
            derive_key_id(active_backend.algorithm(), &active_backend.public_key())?;
        if active_key_id != active.key_id
            || active_backend.public_key() != active.public_key
            || active_backend.algorithm() != active.algorithm
        {
            return Err(KeyringError::StateInvariant(
                "active backend does not match durable key selector",
            ));
        }
        Ok(Self {
            store,
            state: RwLock::new(RouterState {
                active_key_id,
                signing_epoch: durable.signing_epoch(),
                active: active_backend,
                pending_lease: None,
            }),
            artifact_time_signer,
        })
    }

    pub fn stage_pending(
        &self,
        event_id: EventId,
        backend: Box<dyn SigningBackend>,
    ) -> Result<StagedPendingBackend> {
        let mut router = self.write_state()?;
        if router.pending_lease.is_some() {
            return Err(KeyringError::StateInvariant(
                "a pending signing backend is already staged",
            ));
        }
        let durable = self
            .store
            .load_state()?
            .ok_or(KeyringError::StateInvariant("key log is not initialized"))?;
        if durable.active_signing_key()?.key_id != router.active_key_id
            || durable.signing_epoch() != router.signing_epoch
            || durable.pending_event_id() != Some(&event_id)
        {
            return Err(KeyringError::StateInvariant(
                "pending event does not match durable key selector",
            ));
        }
        let pending = durable
            .pending_rotation_key()
            .ok_or(KeyringError::StateInvariant(
                "durable pending key is absent",
            ))?;
        let key_id = derive_key_id(backend.algorithm(), &backend.public_key())?;
        if key_id != pending.key_id
            || backend.public_key() != pending.public_key
            || backend.algorithm() != pending.algorithm
        {
            return Err(KeyringError::StateInvariant(
                "pending backend does not match durable pending key",
            ));
        }
        let lease = PendingLease {
            event_id,
            key_id,
            base_epoch: router.signing_epoch,
        };
        router.pending_lease = Some(lease.clone());
        Ok(StagedPendingBackend {
            lease,
            backend: Some(backend),
        })
    }

    pub fn sign_canonical<T: Serialize>(
        &self,
        expected_epoch: u64,
        artifact: &T,
    ) -> Result<KeyringArtifactSignature> {
        let canonical = canonical_json_bytes(artifact)?;
        if canonical.len() > crate::MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "canonical artifact exceeds 1048576 bytes".to_string(),
            ));
        }
        self.sign_bytes(expected_epoch, &canonical)
    }

    pub fn sign_bytes(
        &self,
        expected_epoch: u64,
        artifact: &[u8],
    ) -> Result<KeyringArtifactSignature> {
        self.sign_bytes_bound(Some(expected_epoch), None, artifact)
            .map(|result| result.evidence)
    }

    pub fn sign_bytes_with_identity(&self, artifact: &[u8]) -> Result<KeyringSigningResult> {
        self.sign_bytes_bound(None, None, artifact)
    }

    pub fn sign_bytes_for_identity(
        &self,
        expected_public_key: &PublicKey,
        artifact: &[u8],
    ) -> Result<KeyringSigningResult> {
        self.sign_bytes_bound(None, Some(expected_public_key), artifact)
    }

    /// Resolve the exact durable evidence produced by a prior router-backed
    /// signature. This never signs. It lets guarded `SigningBackend` wrappers
    /// retain their enforcement boundary while callers recover the evidence
    /// that the trait-level signing outcome cannot represent.
    pub fn persisted_signing_result_for_artifact(
        &self,
        expected_public_key: &PublicKey,
        artifact: &[u8],
        expected_signature: &Signature,
    ) -> Result<KeyringSigningResult> {
        if artifact.len() > crate::MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "artifact exceeds 1048576 bytes".to_string(),
            ));
        }
        let artifact_hash = domain_hash(ARTIFACT_HASH_DOMAIN, artifact)?;
        let evidence = self
            .store
            .artifact_signature(&artifact_hash)?
            .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        if evidence.artifact_signature != *expected_signature {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        evidence.verify_artifact_bytes(expected_public_key, artifact)?;
        let time_anchor = self
            .store
            .artifact_time_anchor(&artifact_hash)?
            .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        if time_anchor.body.artifact_hash != artifact_hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        Ok(KeyringSigningResult {
            public_key: expected_public_key.clone(),
            algorithm: evidence.algorithm,
            key_id: evidence.key_id,
            signing_epoch: evidence.signing_epoch,
            signature: evidence.artifact_signature.clone(),
            evidence,
            time_anchor: Some(time_anchor),
        })
    }

    fn sign_bytes_bound(
        &self,
        expected_epoch: Option<u64>,
        expected_public_key: Option<&PublicKey>,
        artifact: &[u8],
    ) -> Result<KeyringSigningResult> {
        if artifact.len() > crate::MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "artifact exceeds 1048576 bytes".to_string(),
            ));
        }
        let artifact_hash = domain_hash(ARTIFACT_HASH_DOMAIN, artifact)?;
        let router = self.read_state()?;
        if expected_epoch.is_some_and(|expected| router.signing_epoch != expected) {
            return Err(KeyringError::StateInvariant("stale signing epoch"));
        }
        let algorithm = router.active.algorithm();
        let public_key = router.active.public_key();
        if expected_public_key.is_some_and(|expected| expected != &public_key) {
            return Err(KeyringError::StateInvariant(
                "active signing identity does not match the requested key",
            ));
        }
        if derive_key_id(algorithm, &public_key)? != router.active_key_id {
            return Err(KeyringError::StateInvariant(
                "active backend changed signing identity",
            ));
        }
        if let Some(existing) = self.store.artifact_signature(&artifact_hash)? {
            if existing.key_id != router.active_key_id
                || existing.signing_epoch != router.signing_epoch
            {
                return Err(KeyringError::StateInvariant(
                    "artifact signature conflicts with the active signing epoch",
                ));
            }
            existing.verify_artifact_bytes(&public_key, artifact)?;
            let time_anchor = self.artifact_time_anchor_for_existing(&artifact_hash)?;
            return Ok(KeyringSigningResult {
                public_key,
                algorithm,
                key_id: existing.key_id,
                signing_epoch: existing.signing_epoch,
                signature: existing.artifact_signature.clone(),
                evidence: existing,
                time_anchor,
            });
        }
        let artifact_outcome = router
            .active
            .sign_bytes_for_identity(&public_key, artifact)?;
        let artifact_signature = artifact_outcome.signature;
        let fence_outcome = router.active.sign_bytes_for_identity(
            &public_key,
            &artifact_signature_bytes(
                artifact_hash,
                router.active_key_id,
                router.signing_epoch,
                algorithm,
                &artifact_signature,
            )?,
        )?;
        let fence_signature = fence_outcome.signature;
        if artifact_outcome.algorithm != algorithm
            || fence_outcome.algorithm != algorithm
            || artifact_signature.algorithm() != algorithm
            || fence_signature.algorithm() != algorithm
        {
            return Err(KeyringError::AlgorithmMismatch);
        }
        let evidence = KeyringArtifactSignature {
            schema: KEYRING_ARTIFACT_SIGNATURE_SCHEMA.to_string(),
            artifact_hash,
            key_id: router.active_key_id,
            signing_epoch: router.signing_epoch,
            algorithm,
            artifact_signature,
            fence_signature,
        };
        evidence.verify(&public_key)?;
        evidence.verify_artifact_bytes(&public_key, artifact)?;
        let (persisted, time_anchor) = match &self.artifact_time_signer {
            Some(anchor_signer) => {
                let anchor = self.store.build_local_artifact_time_anchor(
                    artifact_hash,
                    &anchor_signer.anchor_id,
                    anchor_signer.backend.as_ref(),
                )?;
                let persisted = self
                    .store
                    .persist_artifact_signature_with_time_anchor(&evidence, &anchor)?;
                (persisted, Some(anchor))
            }
            None => (self.store.persist_artifact_signature(&evidence)?, None),
        };
        persisted.verify_artifact_bytes(&public_key, artifact)?;
        Ok(KeyringSigningResult {
            public_key,
            algorithm,
            key_id: persisted.key_id,
            signing_epoch: persisted.signing_epoch,
            signature: persisted.artifact_signature.clone(),
            evidence: persisted,
            time_anchor,
        })
    }

    fn artifact_time_anchor_for_existing(
        &self,
        artifact_hash: &Hash,
    ) -> Result<Option<SignedArtifactTimeAnchor>> {
        if self.artifact_time_signer.is_none() {
            return Ok(None);
        }
        self.store
            .artifact_time_anchor(artifact_hash)?
            .map(Some)
            .ok_or(KeyringError::StateInvariant(
                "enterprise artifact signature is missing trusted-time evidence",
            ))
    }

    pub fn signing_epoch(&self) -> Result<u64> {
        Ok(self.read_state()?.signing_epoch)
    }

    pub fn active_public_key(&self) -> Result<PublicKey> {
        Ok(self.read_state()?.active.public_key())
    }

    pub fn activate_rotation(
        &self,
        staged: &mut StagedPendingBackend,
        checkpoint_hash: &Hash,
        operator: &dyn SigningBackend,
    ) -> Result<()> {
        if self.requires_enterprise_activation_guard() {
            return Err(KeyringError::StateInvariant(
                "enterprise router activation requires the guarded enterprise runtime",
            ));
        }
        self.activate_rotation_with_fence(staged, checkpoint_hash, operator, || Ok(()))
    }

    pub(crate) fn activate_rotation_guarded(
        &self,
        staged: &mut StagedPendingBackend,
        checkpoint_hash: &Hash,
        operator: &dyn SigningBackend,
        activation_guard: &dyn crate::runtime::KeyLogActivationGuard,
    ) -> Result<()> {
        self.activate_rotation_with_fence(staged, checkpoint_hash, operator, || {
            activation_guard.require_activation()
        })
    }

    fn activate_rotation_with_fence<F>(
        &self,
        staged: &mut StagedPendingBackend,
        checkpoint_hash: &Hash,
        operator: &dyn SigningBackend,
        activation_fence: F,
    ) -> Result<()>
    where
        F: Fn() -> Result<()>,
    {
        let mut router = self.write_state()?;
        let durable = self
            .store
            .load_state()?
            .ok_or(KeyringError::StateInvariant("key log is not initialized"))?;
        if durable.pending_event_id().is_none()
            && durable.active_signing_key()?.key_id == staged.lease.key_id
            && durable.signing_epoch() > staged.lease.base_epoch
            && router.active_key_id == durable.active_signing_key()?.key_id
            && router.signing_epoch == durable.signing_epoch()
        {
            activation_fence()?;
            if router.pending_lease.as_ref() == Some(&staged.lease) {
                router.pending_lease = None;
            }
            staged.backend.take();
            return Ok(());
        }
        let pending = router
            .pending_lease
            .as_ref()
            .ok_or(KeyringError::StateInvariant(
                "pending signing lease is absent",
            ))?;
        if pending != &staged.lease || staged.backend.is_none() {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        if durable.active_signing_key()?.key_id != router.active_key_id
            || durable.signing_epoch() != router.signing_epoch
            || durable.pending_event_id() != Some(&staged.lease.event_id)
            || durable.pending_rotation_key().map(|key| key.key_id) != Some(staged.lease.key_id)
        {
            return Err(KeyringError::StateInvariant(
                "router selector does not match durable pending rotation",
            ));
        }
        let backend = staged.backend.as_ref().ok_or(KeyringError::StateInvariant(
            "staged signing backend is absent",
        ))?;
        if derive_key_id(backend.algorithm(), &backend.public_key())? != staged.lease.key_id {
            return Err(KeyringError::StateInvariant(
                "staged signing backend changed identity",
            ));
        }
        activation_fence()?;
        let activated =
            self.store
                .activate_rotation(&staged.lease.event_id, checkpoint_hash, operator)?;
        let backend = staged.backend.take().ok_or(KeyringError::StateInvariant(
            "staged signing backend disappeared",
        ))?;
        router.active_key_id = staged.lease.key_id;
        router.signing_epoch = activated.signing_epoch();
        router.active = backend;
        router.pending_lease = None;
        Ok(())
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, RouterState>> {
        self.state.read().map_err(|_| KeyringError::Synchronization)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, RouterState>> {
        self.state
            .write()
            .map_err(|_| KeyringError::Synchronization)
    }
}

pub struct KeyringAuthoritySigningBackend {
    router: Arc<KeyringSigningRouter>,
    fallback_public_key: PublicKey,
    _independent_services: Arc<IndependentKeyLogServices>,
}

impl KeyringAuthoritySigningBackend {
    pub fn new(_router: Arc<KeyringSigningRouter>) -> Result<Self> {
        Err(KeyringError::StateInvariant(
            "authority signing requires validated independent key-log services",
        ))
    }

    pub fn new_enterprise(
        router: Arc<KeyringSigningRouter>,
        independent_services: Arc<IndependentKeyLogServices>,
    ) -> Result<Self> {
        if !router.requires_enterprise_activation_guard() {
            return Err(KeyringError::StateInvariant(
                "enterprise authority signing requires an enterprise router",
            ));
        }
        if router.configuration_binding()? != independent_services.configuration_binding() {
            return Err(KeyringError::StateInvariant(
                "authority router and independent services use different policy bindings",
            ));
        }
        let fallback_public_key = router.active_public_key()?;
        Ok(Self {
            router,
            fallback_public_key,
            _independent_services: independent_services,
        })
    }
}

impl SigningBackend for KeyringAuthoritySigningBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.router
            .active_public_key()
            .map(|key| key.algorithm())
            .unwrap_or_else(|_| self.fallback_public_key.algorithm())
    }

    fn public_key(&self) -> PublicKey {
        self.router
            .active_public_key()
            .unwrap_or_else(|_| self.fallback_public_key.clone())
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        self.router
            .sign_bytes_with_identity(message)
            .map(|result| result.signature)
            .map_err(|error| chio_core_types::Error::InvalidSignature(error.to_string()))
    }

    fn sign_bytes_with_identity(&self, message: &[u8]) -> chio_core_types::Result<SigningOutcome> {
        self.router
            .sign_bytes_with_identity(message)
            .map(|result| SigningOutcome {
                public_key: result.public_key,
                algorithm: result.algorithm,
                signature: result.signature,
            })
            .map_err(|error| chio_core_types::Error::InvalidSignature(error.to_string()))
    }

    fn sign_bytes_for_identity(
        &self,
        expected_key: &PublicKey,
        message: &[u8],
    ) -> chio_core_types::Result<SigningOutcome> {
        self.router
            .sign_bytes_for_identity(expected_key, message)
            .map(|result| SigningOutcome {
                public_key: result.public_key,
                algorithm: result.algorithm,
                signature: result.signature,
            })
            .map_err(|error| chio_core_types::Error::InvalidSignature(error.to_string()))
    }
}

fn artifact_signature_bytes(
    artifact_hash: Hash,
    key_id: KeyId,
    signing_epoch: u64,
    algorithm: SigningAlgorithm,
    artifact_signature: &Signature,
) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(&ArtifactSignatureStatement {
        schema: KEYRING_ARTIFACT_SIGNATURE_SCHEMA,
        artifact_hash,
        key_id,
        signing_epoch,
        algorithm,
        artifact_signature,
    })?;
    let capacity = ARTIFACT_SIGNATURE_DOMAIN
        .len()
        .checked_add(canonical.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(ARTIFACT_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Result<Hash> {
    let capacity = domain
        .len()
        .checked_add(bytes.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    Ok(sha256(&input))
}
