use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chio_decoy::{
    DecoyCreateRequest, PrivateDecoyRegistry, PrivilegedExportCredential, RegistryError,
    RegistryExportAuthorizer, RegistryExportGrant, RegistryKey, RegistryKeyProvider,
    SecretMaterial,
};
use chio_security_types::ports::{
    ArtifactId, BoundedVec, Digest32, PortError, PortResult, RecordId, SealedDecoyRegistryStore,
    TenantId,
};
use chio_security_types::{
    DecoyArtifactLookup, DecoyLifecycle, DecoyOperationAttempt, DecoyOperationKind, DecoyScan,
    DecoySurface, DecoyVersion, SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord,
    SealedMarkerLookup, SealedPublicRefLookup,
};
use chio_test_support::prelude::*;

#[derive(Default)]
struct MemoryStore {
    rows: Mutex<BTreeMap<(TenantId, Digest32), SealedDecoyRecord>>,
    operations: Mutex<BTreeMap<(TenantId, Digest32), Digest32>>,
    transitions: Mutex<BTreeMap<(TenantId, Digest32), (Digest32, SealedDecoyRecord)>>,
}

impl MemoryStore {
    fn rows(&self) -> Vec<SealedDecoyRecord> {
        self.rows
            .lock()
            .test_expect("rows lock")
            .values()
            .cloned()
            .collect()
    }

    fn transplant_ciphertext(&self, source: &(TenantId, Digest32), target: &(TenantId, Digest32)) {
        let mut rows = self.rows.lock().test_expect("rows lock");
        let source = rows.get(source).test_expect("source row").clone();
        let target = rows.get_mut(target).test_expect("target row");
        target.nonce = source.nonce;
        target.encrypted_envelope = source.encrypted_envelope;
    }
}

impl SealedDecoyRegistryStore for MemoryStore {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(&(id.tenant_id.clone(), id.artifact_token))
            .cloned())
    }

    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>> {
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        Ok(rows
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
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        Ok(rows
            .values()
            .find(|row| {
                row.tenant_id == lookup.tenant_id
                    && row.public_ref_token == Some(lookup.public_ref_token)
            })
            .cloned())
    }

    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let mut transitions = self
            .transitions
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let mut rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let operation_key = (request.record.tenant_id.clone(), request.operation_token);
        if let Some(artifact_token) = operations.get(&operation_key) {
            if *artifact_token != request.record.artifact_token {
                return Err(PortError::conflict());
            }
        }
        let transition_key = (request.record.tenant_id.clone(), request.transition_token);
        if let Some((artifact_token, result)) = transitions.get(&transition_key) {
            if *artifact_token == request.record.artifact_token && *result == request.record {
                return Ok(result.clone());
            }
            return Err(PortError::conflict());
        }
        let key = (
            request.record.tenant_id.clone(),
            request.record.artifact_token,
        );
        match (rows.get(&key), request.expected_generation) {
            (None, None) if request.record.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.record.generation
                        == expected
                            .checked_add(1)
                            .ok_or_else(PortError::integrity_failure)?
                    && current.tenant_id == request.record.tenant_id
                    && current.artifact_token == request.record.artifact_token
                    && current.public_ref_token == request.record.public_ref_token
                    && current.surface == request.record.surface
                    && current.marker_token == request.record.marker_token
                    && current.version_hash == request.record.version_hash => {}
            _ => return Err(PortError::conflict()),
        }
        if rows.values().any(|current| {
            current.tenant_id == request.record.tenant_id
                && current.surface == request.record.surface
                && current.marker_token == request.record.marker_token
                && current.artifact_token != request.record.artifact_token
        }) {
            return Err(PortError::conflict());
        }
        if request.record.public_ref_token.is_some()
            && rows.values().any(|current| {
                current.tenant_id == request.record.tenant_id
                    && current.public_ref_token == request.record.public_ref_token
                    && current.artifact_token != request.record.artifact_token
            })
        {
            return Err(PortError::conflict());
        }
        rows.insert(key, request.record.clone());
        operations.insert(operation_key, request.record.artifact_token);
        transitions.insert(
            transition_key,
            (request.record.artifact_token, request.record.clone()),
        );
        Ok(request.record.clone())
    }

    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage> {
        scan.validate().map_err(|_| PortError::invalid_data())?;
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let mut matching: Vec<_> = rows
            .values()
            .filter(|row| {
                row.tenant_id == scan.tenant_id
                    && scan
                        .after_artifact_token
                        .is_none_or(|cursor| row.artifact_token > cursor)
            })
            .cloned()
            .collect();
        matching.sort_by_key(|row| row.artifact_token);
        let has_more = matching.len() > usize::from(scan.limit);
        matching.truncate(usize::from(scan.limit));
        let next_artifact_token = has_more
            .then(|| matching.last().map(|row| row.artifact_token))
            .flatten();
        Ok(SealedDecoyPage {
            records: BoundedVec::new(matching).map_err(|_| PortError::integrity_failure())?,
            next_artifact_token,
        })
    }
}

struct Keys;

impl RegistryKeyProvider for Keys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        let fill = match tenant_id.as_str() {
            "tenant-a" => 0xA1,
            "tenant-b" => 0xB2,
            _ => return Err(RegistryError::KeyUnavailable),
        };
        Ok(RegistryKey::from_bytes([fill; 64]))
    }
}

struct Exports;

impl RegistryExportAuthorizer for Exports {
    fn authorize(
        &self,
        credential: &PrivilegedExportCredential,
        now_unix_ms: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        let tenant = match credential.as_bytes() {
            b"operator-a" => "tenant-a",
            b"operator-b" => "tenant-b",
            _ => return Err(RegistryError::AuthorizationDenied),
        };
        RegistryExportGrant::new(
            TenantId::new(tenant).test_expect("valid tenant"),
            16,
            now_unix_ms + 1_000,
        )
    }
}

fn registry(store: Arc<MemoryStore>) -> PrivateDecoyRegistry {
    PrivateDecoyRegistry::new(store, Arc::new(Keys), Arc::new(Exports))
}

fn create_request(tenant: &str, artifact: &str, marker: &[u8]) -> DecoyCreateRequest {
    DecoyCreateRequest {
        tenant_id: TenantId::new(tenant).test_expect("valid tenant"),
        artifact_id: ArtifactId::new(artifact).test_expect("valid artifact"),
        surface: DecoySurface::BrowserCookie,
        scope_id: RecordId::new("scope-a").test_expect("valid scope"),
        creation_policy_id: RecordId::new("policy-a").test_expect("valid policy"),
        version: DecoyVersion::new(1).test_expect("valid version"),
        expires_at_unix_ms: 9_000_000,
        predecessor_artifact_id: None,
        marker: SecretMaterial::new(marker.to_vec()).test_expect("valid marker"),
        materialization_payload: Some(
            SecretMaterial::new(b"honey credential payload".to_vec()).test_expect("valid payload"),
        ),
    }
}

fn apply(
    registry: &PrivateDecoyRegistry,
    artifact_id: &str,
    operation_id: &str,
    kind: DecoyOperationKind,
    successor_artifact_id: Option<&str>,
) -> (DecoyOperationAttempt, chio_security_types::DecoyRecord) {
    let tenant_id = TenantId::new("tenant-a").test_expect("valid tenant");
    let artifact_id = ArtifactId::new(artifact_id).test_expect("valid artifact");
    let current = registry
        .load_private(&tenant_id, &artifact_id)
        .test_expect("load decoy")
        .test_expect("decoy exists");
    let attempt = DecoyOperationAttempt {
        operation_id: RecordId::new(operation_id).test_expect("valid operation"),
        kind,
        expected_generation: current.generation,
        expected_version: current.version,
        successor_artifact_id: successor_artifact_id
            .map(|value| ArtifactId::new(value).test_expect("valid successor")),
    };
    let next = registry
        .apply_transition(&tenant_id, &artifact_id, &attempt)
        .test_expect("apply lifecycle transition");
    (attempt, next)
}

fn arm(registry: &PrivateDecoyRegistry, artifact_id: &str) {
    apply(
        registry,
        artifact_id,
        &format!("begin-{artifact_id}"),
        DecoyOperationKind::BeginMaterialization,
        None,
    );
    apply(
        registry,
        artifact_id,
        &format!("arm-{artifact_id}"),
        DecoyOperationKind::Arm,
        None,
    );
}

#[test]
fn rows_contain_only_keyed_tokens_and_authenticated_ciphertext() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(Arc::clone(&store));
    registry
        .create(
            create_request("tenant-a", "private-artifact-a", b"private-marker-a"),
            RecordId::new("create-a").test_expect("valid transition"),
        )
        .test_expect("create decoy");

    let rows = store.rows();
    assert_eq!(rows.len(), 1);
    let encoded = serde_json::to_vec(&rows[0]).test_expect("serialize sealed row");
    for forbidden in [
        b"private-artifact-a".as_slice(),
        b"private-marker-a".as_slice(),
        b"honey credential payload".as_slice(),
        b"planned".as_slice(),
        b"scope-a".as_slice(),
        b"policy-a".as_slice(),
    ] {
        assert!(!encoded
            .windows(forbidden.len())
            .any(|window| window == forbidden));
    }
}

#[test]
fn tenant_tokens_are_domain_separated_and_ciphertext_transplant_fails() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(Arc::clone(&store));
    for (tenant, transition) in [("tenant-a", "create-a"), ("tenant-b", "create-b")] {
        registry
            .create(
                create_request(tenant, "same-private-id", b"same-private-marker"),
                RecordId::new(transition).test_expect("valid transition"),
            )
            .test_expect("create tenant decoy");
    }
    let rows = store.rows();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].artifact_token, rows[1].artifact_token);
    assert_ne!(rows[0].marker_token, rows[1].marker_token);

    let source = (rows[0].tenant_id.clone(), rows[0].artifact_token);
    let target = (rows[1].tenant_id.clone(), rows[1].artifact_token);
    store.transplant_ciphertext(&source, &target);
    let target_record = registry.load_private(
        &target.0,
        &ArtifactId::new("same-private-id").test_expect("valid artifact"),
    );
    assert_eq!(target_record, Err(RegistryError::AuthenticationFailed));
}

#[test]
fn signed_watermark_public_reference_is_generated_and_never_stored_raw() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(Arc::clone(&store));
    let mut request = create_request("tenant-a", "watermark-a", b"private-watermark-marker");
    request.surface = DecoySurface::SignedWatermark;
    let created = registry
        .create(
            request,
            RecordId::new("create-watermark-a").test_expect("valid operation"),
        )
        .test_expect("create watermark decoy");
    let public_ref = created
        .public_marker_ref
        .clone()
        .test_expect("generated public reference");
    let encoded_ref = public_ref.as_str();
    assert!(encoded_ref.starts_with("wmref_"));
    assert_eq!(encoded_ref.len(), "wmref_".len() + 48);
    assert!(encoded_ref["wmref_".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));

    for row in store.rows() {
        let encoded = serde_json::to_vec(&row).test_expect("serialize sealed row");
        assert!(!encoded
            .windows(public_ref.as_str().len())
            .any(|window| window == public_ref.as_str().as_bytes()));
    }
}

#[test]
fn privileged_export_derives_tenant_from_the_configured_authorizer() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(Arc::clone(&store));
    for (tenant, artifact, transition) in [
        ("tenant-a", "artifact-a", "create-a"),
        ("tenant-b", "artifact-b", "create-b"),
    ] {
        registry
            .create(
                create_request(tenant, artifact, format!("marker-{tenant}").as_bytes()),
                RecordId::new(transition).test_expect("valid transition"),
            )
            .test_expect("create decoy");
    }

    let credential =
        PrivilegedExportCredential::new(b"operator-a".to_vec()).test_expect("valid credential");
    let page = registry
        .export_page(&credential, None, 8, 1_000)
        .test_expect("authorized export");
    assert_eq!(page.entries().len(), 1);
    assert_eq!(page.entries()[0].record().tenant_id.as_str(), "tenant-a");
    assert_eq!(page.entries()[0].marker().as_bytes(), b"marker-tenant-a");
    assert_eq!(
        page.entries()[0]
            .materialization_payload()
            .test_expect("payload")
            .as_bytes(),
        b"honey credential payload"
    );

    let denied =
        PrivilegedExportCredential::new(b"not-authorized".to_vec()).test_expect("valid credential");
    assert_eq!(
        registry.export_page(&denied, None, 8, 1_000),
        Err(RegistryError::AuthorizationDenied)
    );
    assert_eq!(
        registry.export_page(&credential, None, 17, 1_000),
        Err(RegistryError::ExportLimitExceeded)
    );
}

#[test]
fn duplicate_marker_in_the_same_tenant_and_surface_is_rejected() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(store);
    registry
        .create(
            create_request("tenant-a", "artifact-a", b"duplicate-marker"),
            RecordId::new("create-a").test_expect("valid transition"),
        )
        .test_expect("first marker");
    assert_eq!(
        registry.create(
            create_request("tenant-a", "artifact-b", b"duplicate-marker"),
            RecordId::new("create-b").test_expect("valid transition"),
        ),
        Err(RegistryError::Conflict)
    );
}

#[test]
fn operation_id_is_globally_unique_within_a_tenant() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(store);
    let operation_id = RecordId::new("global-operation").test_expect("valid operation");
    registry
        .create(
            create_request("tenant-a", "artifact-a", b"marker-a"),
            operation_id.clone(),
        )
        .test_expect("first operation");
    assert_eq!(
        registry.create(
            create_request("tenant-a", "artifact-b", b"marker-b"),
            operation_id,
        ),
        Err(RegistryError::Conflict)
    );
}

#[test]
fn concurrent_transition_has_one_winner_and_exact_retry_is_stable() {
    let store = Arc::new(MemoryStore::default());
    let registry = Arc::new(registry(store));
    registry
        .create(
            create_request("tenant-a", "artifact-a", b"marker-a"),
            RecordId::new("create-a").test_expect("valid operation"),
        )
        .test_expect("create decoy");
    arm(&registry, "artifact-a");
    let current = registry
        .load_private(
            &TenantId::new("tenant-a").test_expect("valid tenant"),
            &ArtifactId::new("artifact-a").test_expect("valid artifact"),
        )
        .test_expect("load armed")
        .test_expect("armed record");
    let attempts: Vec<_> = ["trigger-left", "trigger-right"]
        .into_iter()
        .map(|operation_id| DecoyOperationAttempt {
            operation_id: RecordId::new(operation_id).test_expect("valid operation"),
            kind: DecoyOperationKind::Trigger,
            expected_generation: current.generation,
            expected_version: current.version,
            successor_artifact_id: None,
        })
        .collect();
    let handles: Vec<_> = attempts
        .into_iter()
        .map(|attempt| {
            let registry = Arc::clone(&registry);
            std::thread::spawn(move || {
                let result = registry.apply_transition(
                    &TenantId::new("tenant-a").test_expect("valid tenant"),
                    &ArtifactId::new("artifact-a").test_expect("valid artifact"),
                    &attempt,
                );
                (attempt, result)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().test_expect("transition thread"))
        .collect();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    let (winning_attempt, winning_record) = results
        .iter()
        .find_map(|(attempt, result)| result.as_ref().ok().map(|record| (attempt, record)))
        .test_expect("one winning transition");
    assert_eq!(winning_record.lifecycle, DecoyLifecycle::Triggered);
    assert_eq!(
        registry
            .apply_transition(
                &TenantId::new("tenant-a").test_expect("valid tenant"),
                &ArtifactId::new("artifact-a").test_expect("valid artifact"),
                winning_attempt,
            )
            .test_expect("exact retry"),
        *winning_record
    );
}

#[test]
fn rotation_arms_the_distinct_successor_before_retiring_the_old_version() {
    let store = Arc::new(MemoryStore::default());
    let registry = registry(store);
    registry
        .create(
            create_request("tenant-a", "artifact-a-v1", b"marker-v1"),
            RecordId::new("create-v1").test_expect("valid operation"),
        )
        .test_expect("create old decoy");
    arm(&registry, "artifact-a-v1");
    apply(
        &registry,
        "artifact-a-v1",
        "trigger-v1",
        DecoyOperationKind::Trigger,
        None,
    );

    let mut replacement = create_request("tenant-a", "artifact-a-v2", b"marker-v2");
    replacement.version = DecoyVersion::new(2).test_expect("valid version");
    replacement.predecessor_artifact_id =
        Some(ArtifactId::new("artifact-a-v1").test_expect("valid predecessor"));
    registry
        .create(
            replacement,
            RecordId::new("create-v2").test_expect("valid operation"),
        )
        .test_expect("create replacement");
    arm(&registry, "artifact-a-v2");

    let (_, rotating) = apply(
        &registry,
        "artifact-a-v1",
        "rotate-v1",
        DecoyOperationKind::BeginRotation,
        Some("artifact-a-v2"),
    );
    let replacement = registry
        .load_private(
            &TenantId::new("tenant-a").test_expect("valid tenant"),
            &ArtifactId::new("artifact-a-v2").test_expect("valid artifact"),
        )
        .test_expect("load replacement")
        .test_expect("replacement exists");
    assert!(rotating.lifecycle.is_matchable());
    assert!(replacement.lifecycle.is_matchable());

    let (_, retired) = apply(
        &registry,
        "artifact-a-v1",
        "retire-v1",
        DecoyOperationKind::Retire,
        Some("artifact-a-v2"),
    );
    assert_eq!(retired.lifecycle, DecoyLifecycle::Retired);
    assert!(registry
        .load_private(
            &TenantId::new("tenant-a").test_expect("valid tenant"),
            &ArtifactId::new("artifact-a-v2").test_expect("valid artifact"),
        )
        .test_expect("load replacement")
        .test_expect("replacement exists")
        .lifecycle
        .is_matchable());
}
