use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, SigningBackend};
use chio_decoy::registry::{
    LegacyRegistryKey, RegistryKeyRing, RegistryKeyVersion, VersionedRegistryKey,
};
use chio_decoy::{
    DecoyCreateRequest, DecoyDetection, DecoyDetector, ObservationClass, PrivateDecoyRegistry,
    PrivilegedExportCredential, RegistryError, RegistryExportAuthorizer, RegistryExportGrant,
    RegistryKey, RegistryKeyProvider, SecretMaterial, TripwireObservation, TrustedWatermarkKey,
    WatermarkClock, WatermarkIssueRequest, WatermarkIssuer, WatermarkIssuerConfig,
    WatermarkIssuerDependencies, WatermarkIssuerPolicy, WatermarkKeyResolver, WatermarkKeyStatus,
    WatermarkSequenceStore, WatermarkSourceContext, WatermarkSourceContextResolver,
};
use chio_security_types::ports::{
    ArtifactId, BoundedVec, Digest32, PortError, PortResult, RecordId, SealedDecoyRegistryStore,
    TenantId,
};
use chio_security_types::{
    DecoyArtifactLookup, DecoyOperationAttempt, DecoyOperationKind, DecoyScan, DecoySurface,
    DecoyVersion, EncryptedDecoyEnvelope, SealedDecoyCasRequest, SealedDecoyPage,
    SealedDecoyRecord, SealedMarkerLookup, SealedPublicRefLookup, WatermarkSequenceReservation,
    WatermarkSequenceReservationResult,
};
use chio_test_support::prelude::*;

const OLD: u8 = 0;
const OVERLAP: u8 = 1;
const EXPIRED: u8 = 2;
const NEW_ONLY: u8 = 3;
const MISLABELED_LEGACY: u8 = 4;
const ENCRYPTION_ONLY_OVERLAP: u8 = 5;
const OVERLAP_START: u64 = 100;
const OVERLAP_END: u64 = 200;

#[derive(Default)]
struct MemoryStore {
    rows: Mutex<BTreeMap<(TenantId, Digest32), SealedDecoyRecord>>,
}

impl MemoryStore {
    fn rewrite_only_row_as_unversioned_v1(&self, encryption_fill: u8) {
        let mut rows = self.rows.lock().test_expect("rows lock");
        assert_eq!(rows.len(), 1);
        let row = rows.values_mut().next().test_expect("sealed row");
        let aad = envelope_aad(row);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&[encryption_fill; 32]));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(row.nonce.as_bytes()),
                Payload {
                    msg: row.encrypted_envelope.as_bytes(),
                    aad: aad.as_slice(),
                },
            )
            .test_expect("decrypt versioned fixture");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&plaintext).test_expect("decode private envelope");
        let object = envelope
            .as_object_mut()
            .test_expect("private envelope object");
        assert!(object.remove("key_version").is_some());
        object.insert(
            "schema".to_string(),
            serde_json::Value::String("chio.decoy-private-envelope.v1".to_string()),
        );
        let canonical = canonical_json_bytes(&envelope).test_expect("canonical v1 envelope");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(row.nonce.as_bytes()),
                Payload {
                    msg: canonical.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .test_expect("seal unversioned v1 fixture");
        row.encrypted_envelope =
            EncryptedDecoyEnvelope::new(ciphertext).test_expect("valid encrypted envelope");
    }
}

fn envelope_aad(row: &SealedDecoyRecord) -> Vec<u8> {
    let mut public_ref = [0_u8; 33];
    if let Some(token) = row.public_ref_token {
        public_ref[0] = 1;
        public_ref[1..].copy_from_slice(token.as_bytes());
    }
    let generation = row.generation.to_be_bytes();
    framed(&[
        b"chio-decoy-envelope-aad-v1",
        row.tenant_id.as_str().as_bytes(),
        row.artifact_token.as_bytes(),
        row.surface.domain_name().as_bytes(),
        row.marker_token.as_bytes(),
        &public_ref,
        row.version_hash.as_bytes(),
        &generation,
    ])
}

fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(
            &u64::try_from(part.len())
                .test_expect("framed length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(part);
    }
    bytes
}

impl SealedDecoyRegistryStore for MemoryStore {
    fn load_by_id(&self, lookup: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(&(lookup.tenant_id.clone(), lookup.artifact_token))
            .cloned())
    }

    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .values()
            .find(|row| {
                row.tenant_id == lookup.tenant_id
                    && row.surface == lookup.surface
                    && row.marker_token == lookup.marker_token
            })
            .cloned())
    }

    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .values()
            .find(|row| {
                row.tenant_id == lookup.tenant_id
                    && row.public_ref_token == Some(lookup.public_ref_token)
            })
            .cloned())
    }

    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord> {
        let mut rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let key = (
            request.record.tenant_id.clone(),
            request.record.artifact_token,
        );
        match (rows.get(&key), request.expected_generation) {
            (None, None) if request.record.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.record.generation == expected.saturating_add(1)
                    && current.tenant_id == request.record.tenant_id
                    && current.artifact_token == request.record.artifact_token
                    && current.public_ref_token == request.record.public_ref_token
                    && current.surface == request.record.surface
                    && current.marker_token == request.record.marker_token
                    && current.version_hash == request.record.version_hash => {}
            _ => return Err(PortError::conflict()),
        }
        rows.insert(key, request.record.clone());
        Ok(request.record.clone())
    }

    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage> {
        let mut records: Vec<_> = self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .values()
            .filter(|row| row.tenant_id == scan.tenant_id)
            .cloned()
            .collect();
        records.sort_by_key(|row| row.artifact_token);
        records.truncate(usize::from(scan.limit));
        Ok(SealedDecoyPage {
            records: BoundedVec::new(records).map_err(|_| PortError::integrity_failure())?,
            next_artifact_token: None,
        })
    }
}

struct RotatingKeys {
    phase: AtomicU8,
}

impl RotatingKeys {
    fn new() -> Self {
        Self {
            phase: AtomicU8::new(OLD),
        }
    }

    fn set_phase(&self, phase: u8) {
        self.phase.store(phase, Ordering::SeqCst);
    }

    fn fill(tenant_id: &TenantId, new: bool) -> Result<u8, RegistryError> {
        match (tenant_id.as_str(), new) {
            ("tenant-a", false) => Ok(0xA1),
            ("tenant-a", true) => Ok(0xA2),
            ("tenant-b", false) => Ok(0xB1),
            ("tenant-b", true) => Ok(0xB2),
            _ => Err(RegistryError::KeyUnavailable),
        }
    }

    fn versioned(
        tenant_id: &TenantId,
        new: bool,
        version: u32,
    ) -> Result<VersionedRegistryKey, RegistryError> {
        Ok(VersionedRegistryKey::new(
            RegistryKeyVersion::new(version)?,
            RegistryKey::from_bytes([Self::fill(tenant_id, new)?; 64]),
        ))
    }

    fn encryption_only_active(tenant_id: &TenantId) -> Result<VersionedRegistryKey, RegistryError> {
        let mut bytes = [0_u8; 64];
        bytes[..32].fill(Self::fill(tenant_id, true)?);
        bytes[32..].fill(Self::fill(tenant_id, false)?);
        Ok(VersionedRegistryKey::new(
            RegistryKeyVersion::new(2)?,
            RegistryKey::from_bytes(bytes),
        ))
    }
}

impl RegistryKeyProvider for RotatingKeys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        if self.phase.load(Ordering::SeqCst) == ENCRYPTION_ONLY_OVERLAP {
            let mut bytes = [0_u8; 64];
            bytes[..32].fill(Self::fill(tenant_id, true)?);
            bytes[32..].fill(Self::fill(tenant_id, false)?);
            return Ok(RegistryKey::from_bytes(bytes));
        }
        let new = self.phase.load(Ordering::SeqCst) != OLD;
        Ok(RegistryKey::from_bytes([Self::fill(tenant_id, new)?; 64]))
    }

    fn keyring_for(&self, tenant_id: &TenantId) -> Result<RegistryKeyRing, RegistryError> {
        match self.phase.load(Ordering::SeqCst) {
            OLD => RegistryKeyRing::new(Self::versioned(tenant_id, false, 1)?, Vec::new(), 50),
            OVERLAP => RegistryKeyRing::new(
                Self::versioned(tenant_id, true, 2)?,
                vec![LegacyRegistryKey::new(
                    Self::versioned(tenant_id, false, 1)?,
                    OVERLAP_START,
                    OVERLAP_END,
                )?],
                150,
            ),
            EXPIRED => RegistryKeyRing::new(
                Self::versioned(tenant_id, true, 2)?,
                vec![LegacyRegistryKey::new(
                    Self::versioned(tenant_id, false, 1)?,
                    OVERLAP_START,
                    OVERLAP_END,
                )?],
                OVERLAP_END,
            ),
            NEW_ONLY => RegistryKeyRing::new(Self::versioned(tenant_id, true, 2)?, Vec::new(), 250),
            MISLABELED_LEGACY => RegistryKeyRing::new(
                Self::versioned(tenant_id, true, 2)?,
                vec![LegacyRegistryKey::new(
                    Self::versioned(tenant_id, false, 3)?,
                    OVERLAP_START,
                    OVERLAP_END,
                )?],
                150,
            ),
            ENCRYPTION_ONLY_OVERLAP => RegistryKeyRing::new(
                Self::encryption_only_active(tenant_id)?,
                vec![LegacyRegistryKey::new(
                    Self::versioned(tenant_id, false, 1)?,
                    OVERLAP_START,
                    OVERLAP_END,
                )?],
                150,
            ),
            _ => Err(RegistryError::KeyUnavailable),
        }
    }
}

struct Exports;

impl RegistryExportAuthorizer for Exports {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        _: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        Err(RegistryError::AuthorizationDenied)
    }
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).test_expect("valid tenant")
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).test_expect("valid artifact")
}

fn create(
    registry: &PrivateDecoyRegistry,
    tenant_id: &str,
    artifact_id: &str,
    marker: &[u8],
    surface: DecoySurface,
) -> chio_security_types::DecoyRecord {
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: tenant(tenant_id),
                artifact_id: artifact(artifact_id),
                surface,
                scope_id: RecordId::new("scope-a").test_expect("valid scope"),
                creation_policy_id: RecordId::new("policy-a").test_expect("valid policy"),
                version: DecoyVersion::new(1).test_expect("valid version"),
                expires_at_unix_ms: 10_000,
                predecessor_artifact_id: None,
                marker: SecretMaterial::new(marker.to_vec()).test_expect("valid marker"),
                materialization_payload: None,
            },
            RecordId::new(format!("create-{tenant_id}-{artifact_id}"))
                .test_expect("valid operation"),
        )
        .test_expect("create decoy")
}

fn arm(registry: &PrivateDecoyRegistry, tenant_id: &TenantId, artifact_id: &ArtifactId) {
    for (operation, kind) in [
        ("begin-watermark", DecoyOperationKind::BeginMaterialization),
        ("arm-watermark", DecoyOperationKind::Arm),
    ] {
        let current = registry
            .load_private(tenant_id, artifact_id)
            .test_expect("load watermark")
            .test_expect("watermark exists");
        registry
            .apply_transition(
                tenant_id,
                artifact_id,
                &DecoyOperationAttempt {
                    operation_id: RecordId::new(operation).test_expect("valid operation"),
                    kind,
                    expected_generation: current.generation,
                    expected_version: current.version,
                    successor_artifact_id: None,
                },
            )
            .test_expect("advance watermark lifecycle");
    }
}

struct SourceContext(WatermarkSourceContext);

impl WatermarkSourceContextResolver for SourceContext {
    fn resolve(&self, source_receipt_id: &RecordId) -> PortResult<Option<WatermarkSourceContext>> {
        Ok((self.0.source_receipt_id == *source_receipt_id).then(|| self.0.clone()))
    }
}

struct WatermarkKeys {
    tenant_id: TenantId,
    key_id: RecordId,
    key: TrustedWatermarkKey,
}

impl WatermarkKeyResolver for WatermarkKeys {
    fn resolve(
        &self,
        tenant_id: &TenantId,
        key_id: &RecordId,
    ) -> PortResult<Option<TrustedWatermarkKey>> {
        Ok((self.tenant_id == *tenant_id && self.key_id == *key_id).then(|| self.key.clone()))
    }
}

struct Clock;

impl WatermarkClock for Clock {
    fn now_unix_ms(&self) -> u64 {
        150
    }
}

struct Sequences;

impl WatermarkSequenceStore for Sequences {
    fn reserve(
        &self,
        _: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult> {
        Ok(WatermarkSequenceReservationResult::Reserved)
    }
}

fn issue_watermark(registry: PrivateDecoyRegistry, marker_ref: RecordId, tenant_id: TenantId) {
    let source_receipt_id = RecordId::new("receipt-a").test_expect("valid receipt");
    let key_id = RecordId::new("watermark-signing-key").test_expect("valid key id");
    let signer = Arc::new(Ed25519Backend::new(Keypair::from_seed(&[0x33; 32])));
    let issuer = WatermarkIssuer::new(
        WatermarkIssuerConfig {
            key_id: key_id.clone(),
            policy: WatermarkIssuerPolicy::new(100, 100, 10).test_expect("valid issuer policy"),
        },
        WatermarkIssuerDependencies {
            signer: Arc::clone(&signer) as Arc<dyn SigningBackend>,
            keys: Arc::new(WatermarkKeys {
                tenant_id: tenant_id.clone(),
                key_id,
                key: TrustedWatermarkKey {
                    public_key: signer.public_key(),
                    status: WatermarkKeyStatus::Active,
                    not_before_unix_ms: 1,
                    signing_cutoff_unix_ms: 1_000,
                    verify_until_unix_ms: 2_000,
                },
            }),
            registry,
            contexts: Arc::new(SourceContext(WatermarkSourceContext {
                tenant_id,
                application_id: RecordId::new("application-a").test_expect("valid application"),
                session_id: RecordId::new("session-a").test_expect("valid session"),
                source_receipt_id: source_receipt_id.clone(),
                tool_id: RecordId::new("tool-a").test_expect("valid tool"),
                issued_at_unix_ms: 140,
                not_after_unix_ms: 1_000,
            })),
            sequences: Arc::new(Sequences),
            clock: Arc::new(Clock),
        },
    );
    issuer
        .issue(WatermarkIssueRequest {
            source_receipt_id,
            marker_ref,
            sequence: 1,
            operation_id: RecordId::new("issue-a").test_expect("valid operation"),
        })
        .test_expect("legacy public reference resolves during overlap");
}

#[test]
fn overlap_opens_legacy_private_public_and_marker_lookups_and_writes_active() {
    let store = Arc::new(MemoryStore::default());
    let keys = Arc::new(RotatingKeys::new());
    let registry = PrivateDecoyRegistry::new(
        Arc::clone(&store) as Arc<dyn SealedDecoyRegistryStore>,
        Arc::clone(&keys) as Arc<dyn RegistryKeyProvider>,
        Arc::new(Exports),
    );
    let tenant_a = tenant("tenant-a");

    create(
        &registry,
        "tenant-a",
        "old-private",
        b"old-marker",
        DecoySurface::BrowserCookie,
    );
    store.rewrite_only_row_as_unversioned_v1(0xA1);
    let watermark = create(
        &registry,
        "tenant-a",
        "old-watermark",
        b"old-watermark-marker",
        DecoySurface::SignedWatermark,
    );
    arm(&registry, &tenant_a, &artifact("old-watermark"));
    keys.set_phase(OVERLAP);

    assert!(registry
        .load_private(&tenant_a, &artifact("old-private"))
        .test_expect("load legacy private record")
        .is_some());
    let detection = DecoyDetector::new(Arc::new(registry.clone()))
        .detect(&TripwireObservation {
            tenant_id: &tenant_a,
            surface: DecoySurface::BrowserCookie,
            presented: b"old-marker",
            class: ObservationClass::InventoryScanner,
            observed_at_unix_ms: 150,
        })
        .test_expect("resolve legacy marker");
    assert!(matches!(
        detection,
        DecoyDetection::InactiveObservation { .. }
    ));
    issue_watermark(
        registry.clone(),
        watermark
            .public_marker_ref
            .test_expect("watermark public reference"),
        tenant_a.clone(),
    );

    create(
        &registry,
        "tenant-a",
        "new-private",
        b"new-marker",
        DecoySurface::BrowserCookie,
    );
    assert!(registry
        .load_private(&tenant_a, &artifact("new-private"))
        .test_expect("load active private record during overlap")
        .is_some());

    keys.set_phase(NEW_ONLY);
    assert!(registry
        .load_private(&tenant_a, &artifact("new-private"))
        .test_expect("new write uses active key")
        .is_some());
    assert!(registry
        .load_private(&tenant_a, &artifact("old-private"))
        .test_expect("retired key is absent after migration window")
        .is_none());
}

#[test]
fn unknown_version_overlap_expiry_and_tenant_boundaries_fail_closed() {
    let store = Arc::new(MemoryStore::default());
    let keys = Arc::new(RotatingKeys::new());
    let registry = PrivateDecoyRegistry::new(
        Arc::clone(&store) as Arc<dyn SealedDecoyRegistryStore>,
        Arc::clone(&keys) as Arc<dyn RegistryKeyProvider>,
        Arc::new(Exports),
    );
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");

    let record_a = create(
        &registry,
        "tenant-a",
        "shared-artifact",
        b"tenant-a-marker",
        DecoySurface::BrowserCookie,
    );
    let record_b = create(
        &registry,
        "tenant-b",
        "shared-artifact",
        b"tenant-b-marker",
        DecoySurface::BrowserCookie,
    );
    assert_ne!(record_a.marker_digest, record_b.marker_digest);
    keys.set_phase(OVERLAP);

    assert_eq!(
        registry
            .load_private(&tenant_a, &artifact("shared-artifact"))
            .test_expect("load tenant a")
            .test_expect("tenant a record")
            .marker_digest,
        record_a.marker_digest
    );
    assert_eq!(
        registry
            .load_private(&tenant_b, &artifact("shared-artifact"))
            .test_expect("load tenant b")
            .test_expect("tenant b record")
            .marker_digest,
        record_b.marker_digest
    );
    assert_eq!(
        DecoyDetector::new(Arc::new(registry.clone()))
            .detect(&TripwireObservation {
                tenant_id: &tenant_b,
                surface: DecoySurface::BrowserCookie,
                presented: b"tenant-a-marker",
                class: ObservationClass::InventoryScanner,
                observed_at_unix_ms: 150,
            })
            .test_expect("cross-tenant marker lookup"),
        DecoyDetection::Clear
    );

    keys.set_phase(MISLABELED_LEGACY);
    assert_eq!(
        registry.load_private(&tenant_a, &artifact("shared-artifact")),
        Err(RegistryError::KeyUnavailable)
    );

    keys.set_phase(EXPIRED);
    assert_eq!(
        registry.load_private(&tenant_a, &artifact("shared-artifact")),
        Err(RegistryError::KeyUnavailable)
    );

    assert_eq!(
        RegistryKeyVersion::new(0),
        Err(RegistryError::IntegrityFailure)
    );
    let duplicate_version = RegistryKeyRing::new(
        RotatingKeys::versioned(&tenant_a, true, 2).test_expect("active key"),
        vec![LegacyRegistryKey::new(
            RotatingKeys::versioned(&tenant_a, false, 2).test_expect("duplicate version"),
            OVERLAP_START,
            OVERLAP_END,
        )
        .test_expect("valid overlap")],
        150,
    );
    assert!(matches!(
        duplicate_version,
        Err(RegistryError::IntegrityFailure)
    ));
}

#[test]
fn shared_index_key_continues_to_the_matching_legacy_encryption_version() {
    let store = Arc::new(MemoryStore::default());
    let keys = Arc::new(RotatingKeys::new());
    let registry = PrivateDecoyRegistry::new(
        store as Arc<dyn SealedDecoyRegistryStore>,
        Arc::clone(&keys) as Arc<dyn RegistryKeyProvider>,
        Arc::new(Exports),
    );
    let tenant_a = tenant("tenant-a");
    create(
        &registry,
        "tenant-a",
        "encryption-only-old",
        b"encryption-only-marker",
        DecoySurface::BrowserCookie,
    );
    keys.set_phase(ENCRYPTION_ONLY_OVERLAP);

    assert!(registry
        .load_private(&tenant_a, &artifact("encryption-only-old"))
        .test_expect("legacy encryption version resolves after active authentication failure")
        .is_some());
}
