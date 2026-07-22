use chio_core::crypto::{Ed25519Backend, SigningBackend};
use uuid::Uuid;

struct FixedArtifactTrustResolver {
    key: PublicKey,
}

struct ToggleCurrentArtifactTrustResolver {
    key: PublicKey,
    allowed: Arc<std::sync::atomic::AtomicBool>,
}

struct ExactArtifactTrustResolver {
    key: PublicKey,
    artifact: Vec<u8>,
}

impl AuthorityArtifactTrustResolver for FixedArtifactTrustResolver {
    fn trusted_issuer_for_artifact(
        &self,
        _artifact: &[u8],
        claimed_issuer: &PublicKey,
        _signature: &chio_core::Signature,
    ) -> Result<Option<PublicKey>, String> {
        if *claimed_issuer == self.key {
            Ok(Some(self.key.clone()))
        } else {
            Ok(None)
        }
    }
}

impl AuthorityArtifactTrustResolver for ToggleCurrentArtifactTrustResolver {
    fn trusted_issuer_for_artifact(
        &self,
        _artifact: &[u8],
        claimed_issuer: &PublicKey,
        _signature: &chio_core::Signature,
    ) -> Result<Option<PublicKey>, String> {
        if claimed_issuer != &self.key {
            return Ok(None);
        }
        if self.allowed.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(Some(self.key.clone()))
        } else {
            Err("current runtime key verification is disabled".to_string())
        }
    }
}

impl AuthorityArtifactTrustResolver for ExactArtifactTrustResolver {
    fn trusted_issuer_for_artifact(
        &self,
        artifact: &[u8],
        claimed_issuer: &PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<Option<PublicKey>, String> {
        if claimed_issuer != &self.key {
            return Ok(None);
        }
        if artifact != self.artifact.as_slice() || !claimed_issuer.verify(artifact, signature) {
            return Err("resolver received the wrong signed artifact preimage".to_string());
        }
        Ok(Some(self.key.clone()))
    }
}

struct SubvertingCapabilityAuthority {
    signer: Keypair,
    injected_trust: PublicKey,
}

impl CapabilityAuthority for SubvertingCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.signer.public_key(), self.injected_trust.clone()]
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        _scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = current_unix_timestamp();
        CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: "subverted-capability".to_string(),
                issuer: self.signer.public_key(),
                subject: subject.clone(),
                scope: ChioScope::default(),
                issued_at: now,
                expires_at: now.saturating_add(ttl_seconds),
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &self.signer,
        )
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

struct SplitAuthoritySigningBackend {
    advertised_public_key: PublicKey,
    signer: Ed25519Backend,
}

struct ArtifactSigningDeniedBackend {
    public_key: PublicKey,
}

impl SigningBackend for ArtifactSigningDeniedBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.public_key.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign_bytes(&self, _message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        Err(chio_core::error::Error::InvalidSignature(
            "artifact signing is denied".to_string(),
        ))
    }
}

#[derive(Clone, Copy)]
enum IssuancePostconditionMutation {
    Issuer,
    Subject,
    Scope,
    Lifetime,
    Schema,
    Signature,
    Attenuation,
}

struct MutatingCapabilityAuthority {
    signer: Keypair,
    mutation: IssuancePostconditionMutation,
}

impl CapabilityAuthority for MutatingCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = current_unix_timestamp();
        let mut capability = CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: "mutated-capability".to_string(),
                issuer: self.signer.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: now,
                expires_at: now.saturating_add(ttl_seconds),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &self.signer,
        )
        .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        match self.mutation {
            IssuancePostconditionMutation::Issuer => {
                capability.issuer = Keypair::generate().public_key();
            }
            IssuancePostconditionMutation::Subject => {
                capability.subject = Keypair::generate().public_key();
            }
            IssuancePostconditionMutation::Scope => {
                capability.scope = ChioScope::default();
            }
            IssuancePostconditionMutation::Lifetime => {
                capability.expires_at = capability
                    .issued_at
                    .saturating_add(ttl_seconds)
                    .saturating_add(1);
            }
            IssuancePostconditionMutation::Schema => {
                capability.schema = "chio.capability.unknown".to_string();
            }
            IssuancePostconditionMutation::Signature => {
                capability.id.push_str("-tampered");
            }
            IssuancePostconditionMutation::Attenuation => {
                capability.budget_share_bps = Some(1);
            }
        }
        Ok(capability)
    }
}

impl SigningBackend for SplitAuthoritySigningBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.signer.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.advertised_public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        self.signer.sign_bytes(message)
    }
}

struct AtomicIdentitySigningBackend {
    signer: Ed25519Backend,
    advertised_public_key: PublicKey,
    identity_calls: std::sync::atomic::AtomicUsize,
    expected_identity_calls: std::sync::atomic::AtomicUsize,
    canonical_calls: std::sync::atomic::AtomicUsize,
}

struct CountingSettlementHook {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl chio_settle::SettlementHook for CountingSettlementHook {
    fn supports_receipt_id_idempotency(&self) -> bool {
        true
    }

    fn observe(
        &self,
        observation: &chio_settle::SettlementObservation,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(chio_settle::SettlementOutcome::accepted(format!(
            "settlement-{}",
            observation.receipt_id
        )))
    }
}

impl SigningBackend for AtomicIdentitySigningBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.signer.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.advertised_public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        self.signer.sign_bytes(message)
    }

    fn sign_bytes_with_identity(
        &self,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.identity_calls.fetch_add(1, Ordering::SeqCst);
        self.signer.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(
        &self,
        expected_key: &PublicKey,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.expected_identity_calls
            .fetch_add(1, Ordering::SeqCst);
        self.signer.sign_bytes_for_identity(expected_key, message)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &chio_core::CanonicalBytes<chio_core::CanonicalJsonWitness>,
    ) -> chio_core::error::Result<chio_core::Signature> {
        self.canonical_calls.fetch_add(1, Ordering::SeqCst);
        self.signer.sign_canonical_bytes(canonical)
    }
}

#[derive(Default)]
struct AuthorityCompositionReceiptStore {
    checkpoint_backend: Mutex<Option<Arc<dyn SigningBackend>>>,
    latest_checkpoint: Mutex<Option<KernelCheckpoint>>,
    session_anchors: Mutex<Vec<serde_json::Value>>,
}

struct FailingAuthorityCompositionClock {
    calls: std::sync::atomic::AtomicUsize,
}

impl crate::authority::CapabilityAuthorityClock for FailingAuthorityCompositionClock {
    fn now_unix_millis(
        &self,
    ) -> Result<u64, crate::authority::CapabilityAuthorityClockError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(crate::authority::CapabilityAuthorityClockError::Unavailable)
    }
}

struct SequencedAuthorityCompositionClock {
    readings: Mutex<std::collections::VecDeque<u64>>,
    calls: std::sync::atomic::AtomicUsize,
}

impl SequencedAuthorityCompositionClock {
    fn new(readings: impl IntoIterator<Item = u64>) -> Self {
        Self {
            readings: Mutex::new(readings.into_iter().collect()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl crate::authority::CapabilityAuthorityClock for SequencedAuthorityCompositionClock {
    fn now_unix_millis(
        &self,
    ) -> Result<u64, crate::authority::CapabilityAuthorityClockError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.readings
            .lock()
            .map_err(|_| crate::authority::CapabilityAuthorityClockError::Unavailable)?
            .pop_front()
            .ok_or(crate::authority::CapabilityAuthorityClockError::Unavailable)
    }
}

fn authority_composition_receipt(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    label: &str,
) -> ChioReceipt {
    let content = label.as_bytes().to_vec();
    kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: Some(label),
            capability_id: &capability.id,
            tool_name: "read_file",
            server_id: "srv-a",
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(serde_json::json!({"label": label})).unwrap(),
            content_hash: chio_core::crypto::sha256_hex(&content),
            canonical_content: content,
            metadata: None,
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .unwrap()
}

fn authority_composition_economic_receipt(kernel: &ChioKernel, label: &str) -> ChioReceipt {
    let content = label.as_bytes().to_vec();
    kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: Some(label),
            capability_id: "cap-settlement-authority",
            tool_name: "priced_tool",
            server_id: "srv-settlement",
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(serde_json::json!({"label": label})).unwrap(),
            content_hash: chio_core::crypto::sha256_hex(&content),
            canonical_content: content,
            metadata: Some(serde_json::json!({
                "financial": {
                    "cost_charged": 100,
                    "currency": "USD"
                }
            })),
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .unwrap()
}

impl ReceiptStore for AuthorityCompositionReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Ok(self
            .latest_checkpoint
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("checkpoint lock poisoned".to_string()))?
            .clone())
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn enable_background_checkpoints(
        &self,
        backend: Arc<dyn SigningBackend>,
        _max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        *self.checkpoint_backend.lock().map_err(|_| {
            ReceiptStoreError::Conflict("checkpoint backend lock poisoned".to_string())
        })? = Some(backend);
        Ok(true)
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.session_anchors
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("session anchor lock poisoned".to_string()))?
            .push(anchor_json.clone());
        Ok(())
    }
}

#[test]
fn authority_replacement_updates_every_signer_and_then_latches_closed() {
    let mut config = make_config();
    config.allow_ephemeral_receipt_log = true;
    config.checkpoint_batch_size = 1;
    let old_public_key = config.keypair.public_key();
    let mut kernel = ChioKernel::new(config);
    let replacement = make_keypair();
    let replacement_public_key = replacement.public_key();
    kernel
        .replace_authority_signing_backend_before_use(Arc::new(Ed25519Backend::new(
            replacement.clone(),
        )))
        .unwrap();
    assert_eq!(kernel.public_key(), replacement_public_key);
    kernel
        .set_capability_authority(Box::new(LocalCapabilityAuthority::new(replacement.clone())))
        .unwrap();

    let store = Arc::new(AuthorityCompositionReceiptStore::default());
    kernel.try_set_receipt_store_handle(store.clone()).unwrap();

    let subject = make_keypair();
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            make_scope(vec![make_grant("srv-a", "read_file")]),
            300,
        )
        .unwrap();
    assert_eq!(capability.issuer, replacement_public_key);
    assert!(capability.verify_signature().unwrap());
    assert!(kernel
        .set_capability_authority(Box::new(LocalCapabilityAuthority::new(replacement.clone())))
        .is_err());

    let receipt = authority_composition_receipt(&kernel, &capability, "req-one-authority");
    assert_eq!(receipt.kernel_key, replacement_public_key);
    assert!(receipt.verify_signature().unwrap());

    let nonce_config = ExecutionNonceConfig::default();
    kernel
        .set_execution_nonce_store(
            nonce_config.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
        )
        .unwrap();
    let request = make_request("req-one-authority", &capability, "read_file", "srv-a");
    let nonce = kernel
        .mint_execution_nonce_for_allow(&request, &capability, &receipt)
        .unwrap()
        .unwrap();
    assert!(replacement_public_key
        .verify_canonical(&nonce.nonce, &nonce.signature)
        .unwrap());

    kernel
        .open_session(subject.public_key().to_hex(), vec![capability])
        .unwrap();
    let anchors = store.session_anchors.lock().unwrap();
    let anchor: chio_core::session::SessionAnchor =
        serde_json::from_value(anchors.last().unwrap().clone()).unwrap();
    assert_eq!(anchor.kernel_key, replacement_public_key);
    assert!(anchor.verify_signature().unwrap());
    drop(anchors);

    let checkpoint_backend = store
        .checkpoint_backend
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .unwrap();
    assert_eq!(checkpoint_backend.public_key(), replacement_public_key);
    let checkpoint = build_checkpoint_with_backend(
        1,
        1,
        1,
        &[b"receipt".to_vec()],
        checkpoint_backend.as_ref(),
        None,
    )
    .unwrap();
    assert_eq!(checkpoint.body.kernel_key, replacement_public_key);
    assert!(verify_checkpoint_signature(&checkpoint).unwrap());

    assert!(kernel
        .replace_authority_signing_backend_before_use(Arc::new(
            Ed25519Backend::new(make_keypair(),)
        ))
        .is_err());
    assert_ne!(old_public_key, kernel.public_key());
}

#[test]
fn tracked_authority_backend_preserves_atomic_identity_signing_methods() {
    let signer = Ed25519Backend::new(make_keypair());
    let signing_key = signer.public_key();
    let inner = Arc::new(AtomicIdentitySigningBackend {
        signer,
        advertised_public_key: make_keypair().public_key(),
        identity_calls: std::sync::atomic::AtomicUsize::new(0),
        expected_identity_calls: std::sync::atomic::AtomicUsize::new(0),
        canonical_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let (tracked, used) =
        crate::authority::TrackedAuthoritySigningBackend::wrap(inner.clone());
    let message = b"atomic tracked authority signature";

    let signature = tracked.sign_bytes(message).unwrap();
    assert!(used.load(Ordering::Acquire));
    assert!(signing_key.verify(message, &signature));

    used.store(false, Ordering::Release);
    let outcome = tracked.sign_bytes_with_identity(message).unwrap();
    assert!(used.load(Ordering::Acquire));
    assert_eq!(outcome.public_key, signing_key);
    assert_eq!(inner.identity_calls.load(Ordering::SeqCst), 1);

    used.store(false, Ordering::Release);
    let outcome = tracked
        .sign_bytes_for_identity(&signing_key, message)
        .unwrap();
    assert!(used.load(Ordering::Acquire));
    assert_eq!(outcome.public_key, signing_key);
    assert_eq!(inner.expected_identity_calls.load(Ordering::SeqCst), 1);

    used.store(false, Ordering::Release);
    let canonical = chio_core::CanonicalBytes::from_serializable(
        &serde_json::json!({"authority": "atomic"}),
    )
    .unwrap();
    let signature = tracked.sign_canonical_bytes(&canonical).unwrap();
    assert!(used.load(Ordering::Acquire));
    assert!(signing_key.verify(canonical.as_bytes(), &signature));
    assert_eq!(inner.canonical_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn governed_capability_clock_failure_happens_before_signing() {
    let config = make_config();
    let signer = Ed25519Backend::new(config.keypair.clone());
    let public_key = signer.public_key();
    let backend = Arc::new(AtomicIdentitySigningBackend {
        signer,
        advertised_public_key: public_key.clone(),
        identity_calls: std::sync::atomic::AtomicUsize::new(0),
        expected_identity_calls: std::sync::atomic::AtomicUsize::new(0),
        canonical_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let clock = Arc::new(FailingAuthorityCompositionClock {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let kernel = ChioKernel::new_with_authority_signing_runtime_and_clock(
        config,
        backend.clone(),
        Arc::new(FixedArtifactTrustResolver { key: public_key }),
        clock.clone(),
    )
    .unwrap();
    let subject = make_keypair();

    let error = kernel
        .issue_capability(&subject.public_key(), ChioScope::default(), 300)
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::CapabilityIssuanceFailed(reason)
            if reason.contains("capability authority clock is unavailable")
    ));
    assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.identity_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.expected_identity_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.canonical_calls.load(Ordering::SeqCst), 0);
    assert!(!kernel.authority_signing_used.load(Ordering::Acquire));
}

#[test]
fn external_authority_runtime_forwards_supplied_clock_and_fails_before_signing() {
    let config = make_config();
    let signer = Ed25519Backend::new(make_keypair());
    let public_key = signer.public_key();
    assert_ne!(public_key, config.keypair.public_key());
    let backend = Arc::new(AtomicIdentitySigningBackend {
        signer,
        advertised_public_key: public_key.clone(),
        identity_calls: std::sync::atomic::AtomicUsize::new(0),
        expected_identity_calls: std::sync::atomic::AtomicUsize::new(0),
        canonical_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let clock = Arc::new(FailingAuthorityCompositionClock {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let kernel = ChioKernel::new_with_external_authority_signing_runtime_and_clock(
        config,
        backend.clone(),
        Arc::new(FixedArtifactTrustResolver { key: public_key }),
        clock.clone(),
    )
    .unwrap();
    let subject = make_keypair();

    let error = kernel
        .issue_capability(&subject.public_key(), ChioScope::default(), 300)
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::CapabilityIssuanceFailed(reason)
            if reason.contains("capability authority clock is unavailable")
    ));
    assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.identity_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.expected_identity_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.canonical_calls.load(Ordering::SeqCst), 0);
    assert!(!kernel.authority_signing_used.load(Ordering::Acquire));
}

#[test]
fn governed_capability_issuance_respects_the_fixed_runtime_clock() {
    let config = make_config();
    let backend: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(config.keypair.clone()));
    let public_key = backend.public_key();
    let clock = Arc::new(FailingAuthorityCompositionClock {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let kernel = ChioKernel::new_with_authority_signing_runtime_and_clock(
        config,
        backend,
        Arc::new(FixedArtifactTrustResolver { key: public_key }),
        clock.clone(),
    )
    .unwrap();
    let subject = make_keypair();
    let _runtime = crate::scope_fixed_runtime_for_current_thread(420, Vec::new());

    let capability = kernel
        .issue_capability(&subject.public_key(), ChioScope::default(), 300)
        .unwrap();

    assert_eq!(capability.issued_at, 420);
    assert_eq!(capability.expires_at, 720);
    let id = capability.id.strip_prefix("cap-").unwrap();
    let timestamp = Uuid::parse_str(id).unwrap().get_timestamp().unwrap();
    assert_eq!(timestamp.to_unix(), (420, 0));
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn governed_capability_issuance_uses_one_clock_snapshot_across_clock_jumps() {
    for later_reading in [0, u64::MAX] {
        let config = make_config();
        let backend: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(config.keypair.clone()));
        let public_key = backend.public_key();
        let clock = Arc::new(SequencedAuthorityCompositionClock::new([
            120_000,
            later_reading,
        ]));
        let kernel = ChioKernel::new_with_authority_signing_runtime_and_clock(
            config,
            backend,
            Arc::new(FixedArtifactTrustResolver { key: public_key }),
            clock.clone(),
        )
        .unwrap();
        let subject = make_keypair();

        let capability = kernel
            .issue_capability(&subject.public_key(), ChioScope::default(), 300)
            .unwrap();

        assert_eq!(capability.issued_at, 120);
        assert_eq!(capability.expires_at, 420);
        assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
        assert_eq!(clock.readings.lock().unwrap().len(), 1);
    }
}

#[test]
fn authority_topology_latches_close_before_first_signature() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.lock_authority_signing_backend_topology();
    assert!(kernel
        .replace_authority_signing_backend_before_use(Arc::new(
            Ed25519Backend::new(make_keypair(),)
        ))
        .is_err());

    let governed = kernel.governed_capability_authority();
    kernel.set_capability_authority(governed).unwrap();
    kernel.seal_authority_composition();
    let governed = kernel.governed_capability_authority();
    assert!(kernel.set_capability_authority(governed).is_err());
}

#[test]
fn bound_authority_runtime_blocks_untrusted_settlement_observation_then_recovers() {
    let config = make_config();
    let signer = config.keypair.clone();
    let current_key = signer.public_key();
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolver = Arc::new(ToggleCurrentArtifactTrustResolver {
        key: current_key,
        allowed: Arc::clone(&allowed),
    });
    let backend: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(signer));
    let mut kernel =
        ChioKernel::new_with_authority_signing_runtime(config, backend, resolver).unwrap();
    assert!(kernel
        .replace_authority_signing_backend_before_use(Arc::new(Ed25519Backend::new(
            make_keypair(),
        )))
        .is_err());

    install_empty_durable_settlement_stores(&mut kernel, 0x41);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel.set_settlement_observer(Arc::new(CountingSettlementHook {
        calls: Arc::clone(&calls),
    }))
    .expect("install settlement observer");
    let receipt = authority_composition_economic_receipt(&kernel, "resolver-settlement");

    assert!(matches!(
        kernel.run_settlement_observer(&receipt),
        settlement_observer::SettlementObserverStatus::TrustFailed { error }
            if error.contains("authority trust resolution failed")
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    allowed.store(true, Ordering::SeqCst);
    assert!(matches!(
        kernel.run_settlement_observer(&receipt),
        settlement_observer::SettlementObserverStatus::Observed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn artifact_trust_resolver_admits_only_the_exact_historical_issuer() {
    let historical = make_keypair();
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_authority_artifact_trust_resolver(Arc::new(FixedArtifactTrustResolver {
        key: historical.public_key(),
    }))
    .unwrap();
    let subject = make_keypair();
    let token = CapabilityToken::sign(
        chio_core::capability::token::CapabilityTokenBody {
            id: "historical-capability".to_string(),
            issuer: historical.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &historical,
    )
    .unwrap();
    kernel
        .verify_capability_full_pre_admit(&token, None, 150)
        .unwrap();

    let untrusted = make_keypair();
    let untrusted_token = CapabilityToken::sign(
        chio_core::capability::token::CapabilityTokenBody {
            issuer: untrusted.public_key(),
            id: "untrusted-capability".to_string(),
            ..token.body()
        },
        &untrusted,
    )
    .unwrap();
    assert!(kernel
        .verify_capability_full_pre_admit(&untrusted_token, None, 150)
        .is_err());
}

#[test]
fn artifact_resolver_receives_exact_current_and_historical_legacy_capability_preimages() {
    let current_config = make_config();
    let current_signer = current_config.keypair.clone();
    let current_body = chio_core::capability::token::CapabilityTokenBody {
        id: "current-legacy-capability".to_string(),
        issuer: current_signer.public_key(),
        subject: make_keypair().public_key(),
        scope: ChioScope::default(),
        issued_at: 100,
        expires_at: 300,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let mut current_token = CapabilityToken::sign(current_body.clone(), &current_signer).unwrap();
    let (current_signature, current_artifact) =
        current_signer.sign_canonical(&current_body).unwrap();
    current_token.signature = current_signature;
    assert!(current_token.verify_signature().unwrap());
    let mut current_kernel = ChioKernel::new(current_config);
    current_kernel
        .set_authority_artifact_trust_resolver(Arc::new(ExactArtifactTrustResolver {
            key: current_signer.public_key(),
            artifact: current_artifact,
        }))
        .unwrap();
    current_kernel
        .verify_stored_capability_for_reuse(&current_token, 150)
        .unwrap();

    let historical_signer = make_keypair();
    let historical_body = chio_core::capability::token::CapabilityTokenBody {
        id: "historical-legacy-capability".to_string(),
        issuer: historical_signer.public_key(),
        subject: make_keypair().public_key(),
        scope: ChioScope::default(),
        issued_at: 100,
        expires_at: 300,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let mut historical_token =
        CapabilityToken::sign(historical_body.clone(), &historical_signer).unwrap();
    let (historical_signature, historical_artifact) = historical_signer
        .sign_canonical(&historical_body)
        .unwrap();
    historical_token.signature = historical_signature;
    assert!(historical_token.verify_signature().unwrap());
    let mut historical_kernel = ChioKernel::new(make_config());
    historical_kernel
        .set_authority_artifact_trust_resolver(Arc::new(ExactArtifactTrustResolver {
            key: historical_signer.public_key(),
            artifact: historical_artifact,
        }))
        .unwrap();
    historical_kernel
        .verify_stored_capability_for_reuse(&historical_token, 150)
        .unwrap();
}

#[test]
fn installed_artifact_resolver_guards_current_key_artifacts_and_capabilities() {
    let static_ca = make_keypair().public_key();
    let historical_runtime_key = make_keypair().public_key();
    let mut config = make_config();
    config.ca_public_keys.push(static_ca.clone());
    let signer = config.keypair.clone();
    let current_key = signer.public_key();
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut kernel = ChioKernel::new(config);
    kernel.set_authority_artifact_trust_resolver(Arc::new(
        ToggleCurrentArtifactTrustResolver {
            key: current_key.clone(),
            allowed: Arc::clone(&allowed),
        },
    ))
    .unwrap();
    assert!(kernel
        .set_authority_artifact_trust_resolver(Arc::new(FixedArtifactTrustResolver {
            key: current_key.clone(),
        }))
        .is_err());
    assert!(kernel.capability_issuer_is_trusted(&static_ca));
    assert!(!kernel.capability_issuer_is_trusted(&current_key));
    assert!(!kernel.capability_issuer_is_trusted(&historical_runtime_key));
    kernel.lock_authority_signing_backend_topology();
    let governed = kernel.governed_capability_authority();
    kernel.set_capability_authority(governed).unwrap();
    kernel.seal_authority_composition();

    let artifact = b"current-runtime-artifact";
    let signature = Ed25519Backend::new(signer.clone())
        .sign_bytes(artifact)
        .unwrap();
    assert!(kernel
        .verify_trusted_authority_artifact_signature(artifact, &current_key, &signature)
        .is_err());
    allowed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(kernel
        .verify_trusted_authority_artifact_signature(artifact, &current_key, &signature)
        .unwrap());

    let subject = make_keypair();
    let token = CapabilityToken::sign(
        chio_core::capability::token::CapabilityTokenBody {
            id: "current-runtime-capability".to_string(),
            issuer: current_key,
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &signer,
    )
    .unwrap();
    allowed.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(kernel
        .verify_stored_capability_for_reuse(&token, 150)
        .is_err());
    assert!(!kernel.capability_issuer_is_trusted(&token.issuer));
    allowed.store(true, std::sync::atomic::Ordering::SeqCst);
    kernel
        .verify_stored_capability_for_reuse(&token, 150)
        .unwrap();
}

#[test]
fn receipt_checkpoint_hydration_requires_resolver_trust_and_accepts_anchored_history() {
    let current_config = make_config();
    let current_signer = current_config.keypair.clone();
    let current_key = current_signer.public_key();
    let current_checkpoint = build_checkpoint_with_backend(
        1,
        1,
        1,
        &[b"current-checkpoint".to_vec()],
        &Ed25519Backend::new(current_signer),
        None,
    )
    .unwrap();
    let current_store = Arc::new(AuthorityCompositionReceiptStore::default());
    *current_store.latest_checkpoint.lock().unwrap() = Some(current_checkpoint);
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut current_kernel = ChioKernel::new(current_config);
    current_kernel
        .set_authority_artifact_trust_resolver(Arc::new(
            ToggleCurrentArtifactTrustResolver {
                key: current_key,
                allowed: Arc::clone(&allowed),
            },
        ))
        .unwrap();
    assert!(current_kernel
        .try_set_receipt_store_handle(current_store.clone())
        .is_err());
    assert_eq!(
        current_kernel
            .checkpoint_seq_counter
            .load(Ordering::SeqCst),
        0
    );
    allowed.store(true, Ordering::SeqCst);
    current_kernel
        .try_set_receipt_store_handle(current_store)
        .unwrap();
    assert_eq!(
        current_kernel
            .checkpoint_seq_counter
            .load(Ordering::SeqCst),
        1
    );

    let historical_signer = make_keypair();
    let historical_checkpoint = build_checkpoint_with_backend(
        2,
        2,
        2,
        &[b"historical-checkpoint".to_vec()],
        &Ed25519Backend::new(historical_signer.clone()),
        None,
    )
    .unwrap();
    let historical_artifact =
        chio_core::canonical_json_bytes(&historical_checkpoint.body).unwrap();
    let historical_store = Arc::new(AuthorityCompositionReceiptStore::default());
    *historical_store.latest_checkpoint.lock().unwrap() = Some(historical_checkpoint);
    let mut historical_kernel = ChioKernel::new(make_config());
    historical_kernel
        .set_authority_artifact_trust_resolver(Arc::new(ExactArtifactTrustResolver {
            key: historical_signer.public_key(),
            artifact: historical_artifact,
        }))
        .unwrap();
    historical_kernel
        .try_set_receipt_store_handle(historical_store)
        .unwrap();
    assert_eq!(
        historical_kernel
            .checkpoint_seq_counter
            .load(Ordering::SeqCst),
        2
    );
    assert_eq!(
        historical_kernel.last_checkpoint_seq.load(Ordering::SeqCst),
        2
    );
}

#[test]
fn governed_approval_and_continuation_runtime_signers_require_resolver_trust() {
    let config = make_config();
    let signer = config.keypair.clone();
    let signer_key = signer.public_key();
    let subject = make_keypair().public_key();
    let denied_artifact = Arc::new(Mutex::new(None));
    let mut kernel = ChioKernel::new(config);
    kernel
        .set_authority_artifact_trust_resolver(Arc::new(
            SelectiveAuthorityArtifactTrustResolver {
                key: signer_key.clone(),
                denied_artifact: Arc::clone(&denied_artifact),
            },
        ))
        .unwrap();

    let approval = chio_core::capability::governance::GovernedApprovalToken::sign(
        chio_core::capability::governance::GovernedApprovalTokenBody {
            id: "resolver-governed-approval".to_string(),
            approver: signer_key.clone(),
            subject: subject.clone(),
            governed_intent_hash: "resolver-governed-intent".to_string(),
            threshold_proposal_hash: None,
            request_id: "resolver-governed-request".to_string(),
            issued_at: 100,
            expires_at: 300,
            decision: chio_core::capability::governance::GovernedApprovalDecision::Approved,
        },
        &signer,
    )
    .unwrap();
    *denied_artifact.lock().unwrap() =
        Some(chio_core::canonical_json_bytes(&approval.body()).unwrap());
    assert!(kernel.verify_governed_approval_signature(&approval).is_err());
    *denied_artifact.lock().unwrap() = None;
    kernel
        .verify_governed_approval_signature(&approval)
        .unwrap();

    let continuation =
        chio_core::capability::governance::CallChainContinuationToken::sign(
            chio_core::capability::governance::CallChainContinuationTokenBody {
                schema: chio_core::capability::governance::CHIO_CALL_CHAIN_CONTINUATION_SCHEMA
                    .to_string(),
                token_id: "resolver-continuation".to_string(),
                signer: signer_key,
                subject: subject.clone(),
                chain_id: "resolver-chain".to_string(),
                parent_request_id: "resolver-parent-request".to_string(),
                parent_receipt_id: Some("resolver-parent-receipt".to_string()),
                parent_receipt_hash: Some("resolver-parent-receipt-hash".to_string()),
                parent_session_anchor: None,
                current_subject: subject.to_hex(),
                delegator_subject: subject.to_hex(),
                origin_subject: subject.to_hex(),
                parent_capability_id: None,
                delegation_link_hash: None,
                governed_intent_hash: None,
                audience: None,
                nonce: Some("resolver-continuation-nonce".to_string()),
                issued_at: 100,
                expires_at: 300,
            },
            &signer,
        )
        .unwrap();
    *denied_artifact.lock().unwrap() =
        Some(chio_core::canonical_json_bytes(&continuation.body()).unwrap());
    assert!(kernel
        .verify_trusted_governed_continuation_signer(&continuation)
        .is_err());
    *denied_artifact.lock().unwrap() = None;
    assert!(kernel
        .verify_trusted_governed_continuation_signer(&continuation)
        .unwrap());
}

#[test]
fn replacement_authority_cannot_expand_trust_or_mutate_the_final_artifact() {
    let config = make_config();
    let signer = config.keypair.clone();
    let injected = make_keypair();
    let mut kernel = ChioKernel::new(config);
    kernel
        .set_capability_authority(Box::new(SubvertingCapabilityAuthority {
            signer,
            injected_trust: injected.public_key(),
        }))
        .unwrap();
    assert!(!kernel.capability_issuer_is_trusted(&injected.public_key()));
    let subject = make_keypair();
    assert!(kernel
        .issue_capability(
            &subject.public_key(),
            make_scope(vec![make_grant("srv-a", "read_file")]),
            300,
        )
        .is_err());
}

#[test]
fn external_authority_constructor_keeps_local_equality_invariant_and_never_resigns_capability() {
    let bootstrap = make_keypair();
    let authority = make_keypair();
    let mut local_config = make_config();
    local_config.keypair = bootstrap.clone();
    let local_backend: Arc<dyn SigningBackend> = Arc::new(ArtifactSigningDeniedBackend {
        public_key: authority.public_key(),
    });
    assert!(ChioKernel::new_with_authority_signing_runtime(
        local_config,
        Arc::clone(&local_backend),
        Arc::new(FixedArtifactTrustResolver {
            key: authority.public_key(),
        }),
    )
    .is_err());

    let mut external_config = make_config();
    external_config.keypair = bootstrap;
    let mut kernel = ChioKernel::new_with_external_authority_signing_runtime(
        external_config,
        local_backend,
        Arc::new(FixedArtifactTrustResolver {
            key: authority.public_key(),
        }),
    )
    .unwrap();
    kernel
        .set_capability_authority(Box::new(LocalCapabilityAuthority::new(authority.clone())))
        .unwrap();
    kernel.seal_authority_composition();

    let subject = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let capability = kernel
        .issue_capability(&subject.public_key(), scope.clone(), 300)
        .unwrap();
    assert_eq!(capability.issuer, authority.public_key());
    assert_eq!(
        chio_core::canonical_json_bytes(&capability.scope).unwrap(),
        chio_core::canonical_json_bytes(&scope).unwrap()
    );
    assert!(capability.verify_signature().unwrap());
}

#[test]
fn issued_capability_postconditions_reject_every_mutated_authority_result() {
    let mutations = [
        IssuancePostconditionMutation::Issuer,
        IssuancePostconditionMutation::Subject,
        IssuancePostconditionMutation::Scope,
        IssuancePostconditionMutation::Lifetime,
        IssuancePostconditionMutation::Schema,
        IssuancePostconditionMutation::Signature,
        IssuancePostconditionMutation::Attenuation,
    ];
    for mutation in mutations {
        let config = make_config();
        let signer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel
            .set_capability_authority(Box::new(MutatingCapabilityAuthority {
                signer,
                mutation,
            }))
            .unwrap();
        let subject = make_keypair();
        assert!(kernel
            .issue_capability(
                &subject.public_key(),
                make_scope(vec![make_grant("srv-a", "read_file")]),
                300,
            )
            .is_err());
    }
}

#[test]
fn split_backend_fails_closed_for_every_governed_artifact() {
    let advertised = make_keypair();
    let actual_signer = make_keypair();
    let mut config = make_config();
    config.keypair = advertised.clone();
    config.allow_ephemeral_receipt_log = true;
    config.checkpoint_batch_size = 0;
    let mut kernel = ChioKernel::new_with_authority_signing_runtime(
        config,
        Arc::new(SplitAuthoritySigningBackend {
            advertised_public_key: advertised.public_key(),
            signer: Ed25519Backend::new(actual_signer),
        }),
        Arc::new(FixedArtifactTrustResolver {
            key: advertised.public_key(),
        }),
    )
    .unwrap();
    let subject = make_keypair();

    assert!(kernel
        .issue_capability(&subject.public_key(), ChioScope::default(), 300)
        .is_err());

    let content = b"split-backend-receipt".to_vec();
    assert!(kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: Some("req-split-backend"),
            capability_id: "cap-split-backend",
            tool_name: "read_file",
            server_id: "srv-a",
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(serde_json::json!({"path": "/safe"})).unwrap(),
            content_hash: chio_core::crypto::sha256_hex(&content),
            canonical_content: content,
            metadata: None,
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .is_err());

    assert!(crate::execution_nonce::mint_execution_nonce_with_backend(
        kernel.authority_signing_backend.as_ref(),
        NonceBinding {
            subject_id: subject.public_key().to_hex(),
            capability_id: "cap-split-backend".to_string(),
            tool_server: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            parameter_hash: "parameter-hash".to_string(),
        },
        &ExecutionNonceConfig::default(),
        1_000,
    )
    .is_err());

    let store = Arc::new(AuthorityCompositionReceiptStore::default());
    kernel.try_set_receipt_store_handle(store).unwrap();
    assert!(kernel
        .open_session(subject.public_key().to_hex(), Vec::new())
        .is_err());

    assert!(build_checkpoint_with_backend(
        1,
        1,
        1,
        &[b"receipt".to_vec()],
        kernel.authority_signing_backend.as_ref(),
        None,
    )
    .is_err());
}
