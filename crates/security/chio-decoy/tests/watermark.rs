mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_core_types::{
    Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_decoy::{
    DecoyCreateRequest, PrivateDecoyRegistry, SecretMaterial, SignedWatermarkEnvelope,
    TrustedWatermarkKey, WatermarkClock, WatermarkIssueError, WatermarkIssueRequest,
    WatermarkIssuer, WatermarkIssuerConfig, WatermarkIssuerDependencies, WatermarkIssuerPolicy,
    WatermarkKeyResolver, WatermarkKeyStatus, WatermarkObservationContext,
    WatermarkObservationPersistence, WatermarkScanError, WatermarkScanVerdict,
    WatermarkSequenceStore, WatermarkSourceContext, WatermarkSourceContextResolver,
    WatermarkVerifier, WatermarkVerifierDependencies, MAX_IJSON_INTEGER,
};
use chio_security_types::ports::{
    ArtifactId, Digest32, PortError, PortResult, RecordId, TenantId, WatermarkObservationStore,
};
use chio_security_types::{
    DecoyOperationAttempt, DecoyOperationKind, DecoySurface, DecoyVersion, WatermarkObservation,
    WatermarkObservationResult, WatermarkSequenceKey, WatermarkSequenceReservation,
    WatermarkSequenceReservationResult,
};
use chio_test_support::prelude::*;
use support::{registry, MemoryStore};

const ISSUED_AT: u64 = 1_000;
const OBSERVED_AT: u64 = 1_001;

#[derive(Default)]
struct Sequences {
    keys: Mutex<BTreeMap<WatermarkSequenceKey, (u64, RecordId)>>,
    operations: Mutex<BTreeMap<(TenantId, RecordId), WatermarkSequenceReservation>>,
}

impl WatermarkSequenceStore for Sequences {
    fn reserve(
        &self,
        request: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let mut keys = self.keys.lock().map_err(|_| PortError::unavailable())?;
        let operation_key = (request.key.tenant_id.clone(), request.operation_id.clone());
        if let Some(existing) = operations.get(&operation_key) {
            return if existing == request {
                Ok(WatermarkSequenceReservationResult::ExactRetry)
            } else {
                Err(PortError::conflict())
            };
        }
        if request.sequence == 0
            || keys
                .get(&request.key)
                .is_some_and(|(sequence, _)| request.sequence <= *sequence)
        {
            return Err(PortError::conflict());
        }
        keys.insert(
            request.key.clone(),
            (request.sequence, request.operation_id.clone()),
        );
        operations.insert(operation_key, request.clone());
        Ok(WatermarkSequenceReservationResult::Reserved)
    }
}

#[derive(Default)]
struct Observations {
    rows: Mutex<BTreeMap<(TenantId, Digest32, RecordId), WatermarkObservation>>,
    fail: AtomicBool,
}

impl WatermarkObservationStore for Observations {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        let mut rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let key = (
            observation.source_tenant_id.clone(),
            observation.public_ref_token,
            observation.observation_id.clone(),
        );
        if let Some(first) = rows.get(&key) {
            if first != observation {
                return Err(PortError::conflict());
            }
            return Ok(WatermarkObservationResult::Duplicate {
                first_payload_digest: first.payload_digest,
                first_token_digest: first.token_digest,
                first_evidence_ref: first.evidence_ref.clone(),
                first_observed_at_unix_ms: first.observed_at_unix_ms,
            });
        }
        rows.insert(key, observation.clone());
        Ok(WatermarkObservationResult::Recorded)
    }
}

#[derive(Default)]
struct Contexts {
    values: Mutex<BTreeMap<RecordId, WatermarkSourceContext>>,
    fail: AtomicBool,
}

impl WatermarkSourceContextResolver for Contexts {
    fn resolve(&self, source_receipt_id: &RecordId) -> PortResult<Option<WatermarkSourceContext>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        Ok(self
            .values
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(source_receipt_id)
            .cloned())
    }
}

#[derive(Default)]
struct Keys {
    values: Mutex<BTreeMap<(TenantId, RecordId), TrustedWatermarkKey>>,
    fail: AtomicBool,
}

impl Keys {
    fn set_status(&self, tenant_id: &TenantId, key_id: &RecordId, status: WatermarkKeyStatus) {
        self.values
            .lock()
            .test_expect("keys lock")
            .get_mut(&(tenant_id.clone(), key_id.clone()))
            .test_expect("trusted key")
            .status = status;
    }
}

impl WatermarkKeyResolver for Keys {
    fn resolve(
        &self,
        tenant_id: &TenantId,
        key_id: &RecordId,
    ) -> PortResult<Option<TrustedWatermarkKey>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        Ok(self
            .values
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(&(tenant_id.clone(), key_id.clone()))
            .cloned())
    }
}

struct Clock(AtomicU64);

impl WatermarkClock for Clock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct CountingSigner {
    backend: Ed25519Backend,
    calls: AtomicUsize,
}

impl CountingSigner {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            backend: Ed25519Backend::new(Keypair::from_seed(&seed)),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SigningBackend for CountingSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.backend.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.backend.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.backend.sign_bytes(message)
    }
}

struct Fixture {
    registry: PrivateDecoyRegistry,
    issuer: WatermarkIssuer,
    signer: Arc<CountingSigner>,
    keys: Arc<Keys>,
    contexts: Arc<Contexts>,
    observations: Arc<Observations>,
    tenant_id: TenantId,
    key_id: RecordId,
    marker_ref: RecordId,
    source_receipt_id: RecordId,
}

impl Fixture {
    fn new(arm_record: bool, registry_expiry: u64) -> Self {
        let registry = registry(Arc::new(MemoryStore::default()));
        let tenant_id = TenantId::new("tenant-a").test_expect("valid tenant");
        let key_id = RecordId::new("watermark-key-1").test_expect("valid key id");
        let source_receipt_id = RecordId::new("receipt-a").test_expect("valid receipt");
        let record = create_watermark(
            &registry,
            "watermark-a-v1",
            b"private-marker-v1",
            registry_expiry,
            1,
            None,
        );
        let marker_ref = record
            .public_marker_ref
            .clone()
            .test_expect("generated public marker reference");
        if arm_record {
            arm(&registry, "watermark-a-v1", "v1");
        }

        let signer = Arc::new(CountingSigner::new([17_u8; 32]));
        let keys = Arc::new(Keys::default());
        keys.values.lock().test_expect("keys lock").insert(
            (tenant_id.clone(), key_id.clone()),
            TrustedWatermarkKey {
                public_key: signer.public_key(),
                status: WatermarkKeyStatus::Active,
                not_before_unix_ms: 900,
                signing_cutoff_unix_ms: 2_000,
                verify_until_unix_ms: 10_000,
            },
        );
        let contexts = Arc::new(Contexts::default());
        contexts.values.lock().test_expect("contexts lock").insert(
            source_receipt_id.clone(),
            WatermarkSourceContext {
                tenant_id: tenant_id.clone(),
                application_id: RecordId::new("application-a").test_expect("valid application"),
                session_id: RecordId::new("session-a").test_expect("valid session"),
                source_receipt_id: source_receipt_id.clone(),
                tool_id: RecordId::new("tool-a").test_expect("valid tool"),
                issued_at_unix_ms: ISSUED_AT,
                not_after_unix_ms: 9_000,
            },
        );
        let observations = Arc::new(Observations::default());
        let clock = Arc::new(Clock(AtomicU64::new(OBSERVED_AT)));
        let issuer = WatermarkIssuer::new(
            WatermarkIssuerConfig {
                key_id: key_id.clone(),
                policy: WatermarkIssuerPolicy::new(4_000, 100, 10).test_expect("valid policy"),
            },
            WatermarkIssuerDependencies {
                signer: Arc::clone(&signer) as Arc<dyn SigningBackend>,
                keys: Arc::clone(&keys) as Arc<dyn WatermarkKeyResolver>,
                registry: registry.clone(),
                contexts: Arc::clone(&contexts) as Arc<dyn WatermarkSourceContextResolver>,
                sequences: Arc::new(Sequences::default()),
                clock: Arc::clone(&clock) as Arc<dyn WatermarkClock>,
            },
        );
        Self {
            registry,
            issuer,
            signer,
            keys,
            contexts,
            observations,
            tenant_id,
            key_id,
            marker_ref,
            source_receipt_id,
        }
    }

    fn issue_request(&self, sequence: u64, operation: &str) -> WatermarkIssueRequest {
        WatermarkIssueRequest {
            source_receipt_id: self.source_receipt_id.clone(),
            marker_ref: self.marker_ref.clone(),
            sequence,
            operation_id: RecordId::new(operation).test_expect("valid operation"),
        }
    }

    fn issue(&self) -> String {
        self.issuer
            .issue(self.issue_request(1, "issue-1"))
            .test_expect("issue watermark")
    }

    fn verifier(&self) -> WatermarkVerifier {
        WatermarkVerifier::new(WatermarkVerifierDependencies {
            keys: Arc::clone(&self.keys) as Arc<dyn WatermarkKeyResolver>,
            contexts: Arc::clone(&self.contexts) as Arc<dyn WatermarkSourceContextResolver>,
            registry: self.registry.clone(),
            observations: Arc::clone(&self.observations) as Arc<dyn WatermarkObservationStore>,
        })
    }

    fn observation(
        &self,
        id: &str,
        evidence: &str,
        observed_at: u64,
    ) -> WatermarkObservationContext {
        WatermarkObservationContext {
            observing_tenant_id: self.tenant_id.clone(),
            observation_id: RecordId::new(id).test_expect("valid observation"),
            evidence_ref: RecordId::new(evidence).test_expect("valid evidence"),
            observed_at_unix_ms: observed_at,
        }
    }
}

fn create_watermark(
    registry: &PrivateDecoyRegistry,
    artifact: &str,
    marker: &[u8],
    expires_at_unix_ms: u64,
    version: u64,
    predecessor: Option<&str>,
) -> chio_security_types::DecoyRecord {
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: TenantId::new("tenant-a").test_expect("valid tenant"),
                artifact_id: ArtifactId::new(artifact).test_expect("valid artifact"),
                surface: DecoySurface::SignedWatermark,
                scope_id: RecordId::new("scope-a").test_expect("valid scope"),
                creation_policy_id: RecordId::new("policy-a").test_expect("valid policy"),
                version: DecoyVersion::new(version).test_expect("valid version"),
                expires_at_unix_ms,
                predecessor_artifact_id: predecessor
                    .map(|value| ArtifactId::new(value).test_expect("valid predecessor")),
                marker: SecretMaterial::new(marker.to_vec()).test_expect("valid marker"),
                materialization_payload: None,
            },
            RecordId::new(format!("create-{artifact}")).test_expect("valid operation"),
        )
        .test_expect("create watermark decoy")
}

fn apply(
    registry: &PrivateDecoyRegistry,
    artifact: &str,
    operation: &str,
    kind: DecoyOperationKind,
    successor: Option<&str>,
) {
    let tenant_id = TenantId::new("tenant-a").test_expect("valid tenant");
    let artifact_id = ArtifactId::new(artifact).test_expect("valid artifact");
    let current = registry
        .load_private(&tenant_id, &artifact_id)
        .test_expect("load record")
        .test_expect("record exists");
    registry
        .apply_transition(
            &tenant_id,
            &artifact_id,
            &DecoyOperationAttempt {
                operation_id: RecordId::new(operation).test_expect("valid operation"),
                kind,
                expected_generation: current.generation,
                expected_version: current.version,
                successor_artifact_id: successor
                    .map(|value| ArtifactId::new(value).test_expect("valid successor")),
            },
        )
        .test_expect("apply transition");
}

fn arm(registry: &PrivateDecoyRegistry, artifact: &str, suffix: &str) {
    apply(
        registry,
        artifact,
        &format!("begin-{suffix}"),
        DecoyOperationKind::BeginMaterialization,
        None,
    );
    apply(
        registry,
        artifact,
        &format!("arm-{suffix}"),
        DecoyOperationKind::Arm,
        None,
    );
}

#[test]
fn clean_output_is_clear_and_malformed_or_duplicate_candidates_cannot_mask_a_valid_hit() {
    let fixture = Fixture::new(true, 10_000);
    let verifier = fixture.verifier();
    let context = fixture.observation("observation-a", "evidence-a", OBSERVED_AT);
    assert_eq!(
        verifier
            .scan_text("ordinary tool output", &context)
            .test_expect("clean scan")
            .verdict,
        WatermarkScanVerdict::Clear
    );

    let token = fixture.issue();
    let report = verifier
        .scan_text(
            &format!("[[chio-wm1:broken {token} middle {token} trailing"),
            &context,
        )
        .test_expect("bounded scan");
    assert_eq!(report.verdict, WatermarkScanVerdict::ActiveHit);
    assert_eq!(report.active_hits.len(), 1);
    assert_eq!(report.malformed_candidates, 1);
    assert_eq!(report.duplicate_candidates, 1);
}

#[test]
fn issuer_requires_verified_recent_context_an_active_key_and_an_armed_registry_entry() {
    let planned = Fixture::new(false, 10_000);
    assert_eq!(
        planned
            .issuer
            .issue(planned.issue_request(1, "issue-planned")),
        Err(WatermarkIssueError::InactiveRegistryEntry)
    );
    assert_eq!(planned.signer.calls(), 0);

    let fixture = Fixture::new(true, 10_000);
    fixture
        .contexts
        .values
        .lock()
        .test_expect("contexts lock")
        .clear();
    assert_eq!(
        fixture
            .issuer
            .issue(fixture.issue_request(1, "issue-missing")),
        Err(WatermarkIssueError::UnverifiedContext)
    );
    fixture
        .contexts
        .values
        .lock()
        .test_expect("contexts lock")
        .insert(
            fixture.source_receipt_id.clone(),
            WatermarkSourceContext {
                tenant_id: fixture.tenant_id.clone(),
                application_id: RecordId::new("application-a").test_expect("valid application"),
                session_id: RecordId::new("session-a").test_expect("valid session"),
                source_receipt_id: fixture.source_receipt_id.clone(),
                tool_id: RecordId::new("tool-a").test_expect("valid tool"),
                issued_at_unix_ms: 1,
                not_after_unix_ms: 9_000,
            },
        );
    assert_eq!(
        fixture
            .issuer
            .issue(fixture.issue_request(1, "issue-stale")),
        Err(WatermarkIssueError::ContextOutsideTimeWindow)
    );
    assert_eq!(fixture.signer.calls(), 0);
}

#[test]
fn replay_is_reserved_before_signing_and_exact_operation_retry_is_idempotent() {
    let fixture = Fixture::new(true, 10_000);
    let first = fixture
        .issuer
        .issue(fixture.issue_request(7, "issue-seven"))
        .test_expect("first issue");
    assert_eq!(fixture.signer.calls(), 1);
    let retry = fixture
        .issuer
        .issue(fixture.issue_request(7, "issue-seven"))
        .test_expect("exact retry");
    assert_eq!(retry, first);
    assert_eq!(fixture.signer.calls(), 2);

    assert_eq!(
        fixture
            .issuer
            .issue(fixture.issue_request(7, "issue-seven-other")),
        Err(WatermarkIssueError::SequenceReplay)
    );
    assert_eq!(
        fixture.issuer.issue(fixture.issue_request(6, "issue-six")),
        Err(WatermarkIssueError::SequenceReplay)
    );
    assert_eq!(fixture.signer.calls(), 2);
}

#[test]
fn active_and_overlap_keys_verify_only_inside_receipt_anchored_windows() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    fixture.keys.set_status(
        &fixture.tenant_id,
        &fixture.key_id,
        WatermarkKeyStatus::Overlap,
    );
    let report = fixture
        .verifier()
        .scan_text(
            &token,
            &fixture.observation("observation-overlap", "evidence-overlap", 2_100),
        )
        .test_expect("overlap verification");
    assert_eq!(report.verdict, WatermarkScanVerdict::ActiveHit);
    assert_eq!(
        report.active_hits[0].key_status,
        WatermarkKeyStatus::Overlap
    );

    fixture
        .contexts
        .values
        .lock()
        .test_expect("contexts lock")
        .get_mut(&fixture.source_receipt_id)
        .test_expect("source context")
        .issued_at_unix_ms = 2_100;
    let invalid = fixture
        .verifier()
        .scan_text(
            &token,
            &fixture.observation("observation-backdate", "evidence-backdate", 2_101),
        )
        .test_expect("invalid anchored context is advisory");
    assert_eq!(invalid.verdict, WatermarkScanVerdict::Advisory);
    assert_eq!(invalid.active_hits.len(), 0);
    assert_eq!(invalid.invalid_candidates, 1);
}

#[test]
fn future_issued_watermarks_are_invalid_until_their_issuance_time() {
    let fixture = Fixture::new(true, 10_000);
    fixture
        .contexts
        .values
        .lock()
        .test_expect("contexts lock")
        .get_mut(&fixture.source_receipt_id)
        .test_expect("source context")
        .issued_at_unix_ms = OBSERVED_AT + 5;
    let token = fixture.issue();

    let early = fixture
        .verifier()
        .scan_text(
            &token,
            &fixture.observation("observation-early", "evidence-early", OBSERVED_AT),
        )
        .test_expect("early observation is advisory");
    assert_eq!(early.verdict, WatermarkScanVerdict::Advisory);
    assert_eq!(early.active_hits.len(), 0);
    assert_eq!(early.invalid_candidates, 1);
    assert!(fixture
        .observations
        .rows
        .lock()
        .test_expect("observations lock")
        .is_empty());

    let current = fixture
        .verifier()
        .scan_text(
            &token,
            &fixture.observation("observation-current", "evidence-current", OBSERVED_AT + 5),
        )
        .test_expect("current observation verifies");
    assert_eq!(current.verdict, WatermarkScanVerdict::ActiveHit);
}

#[test]
fn retired_and_expired_entries_are_verified_inactive_advisories() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    apply(
        &fixture.registry,
        "watermark-a-v1",
        "trigger-v1",
        DecoyOperationKind::Trigger,
        None,
    );
    create_watermark(
        &fixture.registry,
        "watermark-a-v2",
        b"private-marker-v2",
        10_000,
        2,
        Some("watermark-a-v1"),
    );
    arm(&fixture.registry, "watermark-a-v2", "v2");
    apply(
        &fixture.registry,
        "watermark-a-v1",
        "rotate-v1",
        DecoyOperationKind::BeginRotation,
        Some("watermark-a-v2"),
    );
    apply(
        &fixture.registry,
        "watermark-a-v1",
        "retire-v1",
        DecoyOperationKind::Retire,
        Some("watermark-a-v2"),
    );
    let report = fixture
        .verifier()
        .scan_text(
            &token,
            &fixture.observation("observation-retired", "evidence-retired", OBSERVED_AT),
        )
        .test_expect("retired scan");
    assert_eq!(report.verdict, WatermarkScanVerdict::Advisory);
    assert_eq!(report.inactive_hits.len(), 1);
    assert_eq!(
        report.inactive_hits[0].registry_state,
        chio_decoy::WatermarkRegistryState::Retired
    );
}

#[test]
fn a_verified_active_hit_survives_observation_store_failure_and_cross_tenant_replay() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    fixture.observations.fail.store(true, Ordering::SeqCst);
    let mut context = fixture.observation("observation-cross", "evidence-cross", OBSERVED_AT);
    context.observing_tenant_id = TenantId::new("tenant-b").test_expect("valid tenant");
    let report = fixture
        .verifier()
        .scan_text(&token, &context)
        .test_expect("verified hit remains visible");
    assert_eq!(report.verdict, WatermarkScanVerdict::ActiveHit);
    assert_eq!(report.detector_failures, 1);
    assert!(report.active_hits[0].cross_tenant);
    assert_eq!(
        report.active_hits[0].observation,
        WatermarkObservationPersistence::Failed
    );
}

#[test]
fn canonical_payload_signature_and_safe_integer_tampering_are_advisory_not_clear() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    let mut envelope = SignedWatermarkEnvelope::decode_token(&token).test_expect("decode token");
    envelope.payload.sequence = MAX_IJSON_INTEGER + 1;
    let unsafe_token = envelope.encode_token().test_expect("encode outer envelope");
    let unsafe_report = fixture
        .verifier()
        .scan_text(
            &unsafe_token,
            &fixture.observation("observation-unsafe", "evidence-unsafe", OBSERVED_AT),
        )
        .test_expect("unsafe integer is advisory");
    assert_eq!(unsafe_report.verdict, WatermarkScanVerdict::Advisory);
    assert_eq!(unsafe_report.invalid_candidates, 1);

    let mut signature = SignedWatermarkEnvelope::decode_token(&token).test_expect("decode token");
    signature.signature = Keypair::from_seed(&[99_u8; 32]).sign(b"wrong message");
    let signature = signature
        .encode_token()
        .test_expect("encode signature mutation");
    let signature_report = fixture
        .verifier()
        .scan_text(
            &signature,
            &fixture.observation("observation-signature", "evidence-signature", OBSERVED_AT),
        )
        .test_expect("invalid signature is advisory");
    assert_eq!(signature_report.verdict, WatermarkScanVerdict::Advisory);
    assert_eq!(signature_report.invalid_candidates, 1);
}

#[test]
fn observation_deduplication_binds_token_and_first_complete_attribution() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    let context = fixture.observation("observation-dedupe", "evidence-first", OBSERVED_AT);
    let first = fixture
        .verifier()
        .scan_text(&token, &context)
        .test_expect("first scan");
    assert_eq!(
        first.active_hits[0].observation,
        WatermarkObservationPersistence::Persisted(WatermarkObservationResult::Recorded)
    );
    let duplicate = fixture
        .verifier()
        .scan_text(&token, &context)
        .test_expect("duplicate scan");
    assert!(matches!(
        duplicate.active_hits[0].observation,
        WatermarkObservationPersistence::Persisted(WatermarkObservationResult::Duplicate { .. })
    ));

    let changed = fixture.observation("observation-dedupe", "evidence-changed", OBSERVED_AT);
    let conflict = fixture
        .verifier()
        .scan_text(&token, &changed)
        .test_expect("active conflict remains a hit");
    assert_eq!(conflict.verdict, WatermarkScanVerdict::ActiveHit);
    assert_eq!(conflict.detector_failures, 1);
    assert_eq!(
        conflict.active_hits[0].observation,
        WatermarkObservationPersistence::Failed
    );
}

#[test]
fn detector_dependency_failure_is_never_reported_as_clear() {
    let fixture = Fixture::new(true, 10_000);
    let token = fixture.issue();
    fixture.keys.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.verifier().scan_text(
            &token,
            &fixture.observation("observation-failure", "evidence-failure", OBSERVED_AT),
        ),
        Err(WatermarkScanError::DetectorUnavailable)
    );
}
