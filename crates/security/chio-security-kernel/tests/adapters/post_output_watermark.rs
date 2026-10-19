use super::*;
use chio_decoy::{
    DecoyCreateRequest, PrivateDecoyRegistry, PrivilegedExportCredential, RegistryError,
    RegistryExportAuthorizer, RegistryExportGrant, RegistryKey, RegistryKeyProvider,
    SecretMaterial, TrustedWatermarkKey, WatermarkIssueRequest, WatermarkIssuer,
    WatermarkIssuerConfig, WatermarkIssuerDependencies, WatermarkIssuerPolicy,
    WatermarkKeyResolver, WatermarkKeyStatus, WatermarkSourceContext,
    WatermarkSourceContextResolver, WatermarkVerifier, WatermarkVerifierDependencies,
};
use chio_security_kernel::DecoyTripwireDetectorPort;
use chio_security_types::ports::{ArtifactId, WatermarkObservationStore};
use chio_security_types::{
    DecoyOperationAttempt, DecoyOperationKind, DecoySurface, DecoyVersion, WatermarkObservation,
    WatermarkObservationResult,
};
use chio_store_sqlite::SqliteSealedDecoyRegistryStore;

const TENANT: &str = "tenant-a";
const ISSUED_AT: u64 = 1_000;
const OBSERVED_AT: u64 = 1_001;

struct RegistryKeys;

impl RegistryKeyProvider for RegistryKeys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        if tenant_id.as_str() == TENANT {
            Ok(RegistryKey::from_bytes([61; 64]))
        } else {
            Err(RegistryError::KeyUnavailable)
        }
    }
}

struct NoExports;

impl RegistryExportAuthorizer for NoExports {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        _: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        Err(RegistryError::AuthorizationDenied)
    }
}

struct SigningKeys(TrustedWatermarkKey);

impl WatermarkKeyResolver for SigningKeys {
    fn resolve(&self, _: &TenantId, _: &RecordId) -> PortResult<Option<TrustedWatermarkKey>> {
        Ok(Some(self.0.clone()))
    }
}

struct SourceContexts(WatermarkSourceContext);

impl WatermarkSourceContextResolver for SourceContexts {
    fn resolve(&self, source_receipt_id: &RecordId) -> PortResult<Option<WatermarkSourceContext>> {
        Ok((*source_receipt_id == self.0.source_receipt_id).then(|| self.0.clone()))
    }
}

/// Forwards to the durable store and keeps every result it returns.
struct RecordingObservations {
    store: Arc<SqliteSealedDecoyRegistryStore>,
    results: Mutex<Vec<WatermarkObservationResult>>,
}

impl WatermarkObservationStore for RecordingObservations {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult> {
        let result = self.store.record_first(observation)?;
        self.results
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(result.clone());
        Ok(result)
    }
}

struct WatermarkFixture {
    registry: PrivateDecoyRegistry,
    issuer: WatermarkIssuer,
    keys: Arc<SigningKeys>,
    contexts: Arc<SourceContexts>,
    observations: Arc<RecordingObservations>,
    marker_ref: RecordId,
    _directory: tempfile::TempDir,
}

impl WatermarkFixture {
    fn new() -> Self {
        let directory = chio_test_support::private_tempdir().test_unwrap();
        let store = Arc::new(
            SqliteSealedDecoyRegistryStore::open(directory.path().join("decoys.sqlite3"))
                .test_unwrap(),
        );
        let registry = PrivateDecoyRegistry::new(
            Arc::clone(&store) as Arc<dyn chio_security_types::ports::SealedDecoyRegistryStore>,
            Arc::new(RegistryKeys),
            Arc::new(NoExports),
        );
        let record = create_marker(&registry, "watermark-a-v1", 1, None);
        arm_marker(&registry, "watermark-a-v1");
        let signer = Ed25519Backend::new(Keypair::from_seed(&[62_u8; 32]));
        let keys = Arc::new(SigningKeys(TrustedWatermarkKey {
            public_key: signer.public_key(),
            status: WatermarkKeyStatus::Active,
            not_before_unix_ms: 900,
            signing_cutoff_unix_ms: 2_000,
            verify_until_unix_ms: 10_000,
        }));
        let contexts = Arc::new(SourceContexts(WatermarkSourceContext {
            tenant_id: TenantId::new(TENANT).test_unwrap(),
            application_id: RecordId::new("application-a").test_unwrap(),
            session_id: RecordId::new("session-a").test_unwrap(),
            source_receipt_id: RecordId::new("receipt-a").test_unwrap(),
            tool_id: RecordId::new("tool-a").test_unwrap(),
            issued_at_unix_ms: ISSUED_AT,
            not_after_unix_ms: 9_000,
        }));
        let issuer = WatermarkIssuer::new(
            WatermarkIssuerConfig {
                key_id: RecordId::new("watermark-key-1").test_unwrap(),
                policy: WatermarkIssuerPolicy::new(4_000, 100, 10).test_unwrap(),
            },
            WatermarkIssuerDependencies {
                signer: Arc::new(signer),
                keys: Arc::clone(&keys) as Arc<dyn WatermarkKeyResolver>,
                registry: registry.clone(),
                contexts: Arc::clone(&contexts) as Arc<dyn WatermarkSourceContextResolver>,
                sequences: Arc::clone(&store)
                    as Arc<dyn chio_security_types::ports::WatermarkSequenceStore>,
                clock: Arc::new(chio_security_types::clock::FixedClock::from_millis(
                    ISSUED_AT,
                )),
            },
        );
        let observations = Arc::new(RecordingObservations {
            store,
            results: Mutex::new(Vec::new()),
        });
        Self {
            registry,
            issuer,
            keys,
            contexts,
            observations,
            marker_ref: record.public_marker_ref.test_unwrap(),
            _directory: directory,
        }
    }

    fn issue(&self, sequence: u64) -> String {
        self.issuer
            .issue(WatermarkIssueRequest {
                source_receipt_id: RecordId::new("receipt-a").test_unwrap(),
                marker_ref: self.marker_ref.clone(),
                sequence,
                operation_id: RecordId::new(format!("issue-{sequence}")).test_unwrap(),
            })
            .test_unwrap()
    }

    fn retire_marker(&self) {
        transition(
            &self.registry,
            "watermark-a-v1",
            "trigger-v1",
            DecoyOperationKind::Trigger,
            None,
        );
        create_marker(&self.registry, "watermark-a-v2", 2, Some("watermark-a-v1"));
        arm_marker(&self.registry, "watermark-a-v2");
        transition(
            &self.registry,
            "watermark-a-v1",
            "rotate-v1",
            DecoyOperationKind::BeginRotation,
            Some("watermark-a-v2"),
        );
        transition(
            &self.registry,
            "watermark-a-v1",
            "retire-v1",
            DecoyOperationKind::Retire,
            Some("watermark-a-v2"),
        );
    }

    fn inspect(
        &self,
        request: &ToolCallRequest,
        observed_at: u64,
        response: &serde_json::Value,
    ) -> PostInvocationVerdict {
        let verifier = WatermarkVerifier::new(WatermarkVerifierDependencies {
            keys: Arc::clone(&self.keys) as Arc<dyn WatermarkKeyResolver>,
            contexts: Arc::clone(&self.contexts) as Arc<dyn WatermarkSourceContextResolver>,
            registry: self.registry.clone(),
            observations: Arc::clone(&self.observations) as Arc<dyn WatermarkObservationStore>,
        });
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(RawOutputTripwireHook::new(
            Arc::new(DecoyTripwireDetectorPort::watermark_only(
                Arc::new(verifier),
                Arc::new(chio_security_types::clock::FixedClock::from_millis(
                    observed_at,
                )),
            )),
            tripwire_publisher(Arc::new(FakeEvents::new(false))),
            MissingContextPolicy::Deny,
        )));
        let security = security_context(request);
        let context = PostInvocationContext::from_request_with_security_context(
            request,
            Some(0),
            Some(&security),
        );
        pipeline
            .evaluate_with_context_and_evidence(&context, response)
            .verdict
    }

    fn results(&self) -> Vec<WatermarkObservationResult> {
        self.observations.results.lock().test_unwrap().clone()
    }
}

fn create_marker(
    registry: &PrivateDecoyRegistry,
    artifact: &str,
    version: u64,
    predecessor: Option<&str>,
) -> chio_security_types::DecoyRecord {
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: TenantId::new(TENANT).test_unwrap(),
                artifact_id: ArtifactId::new(artifact).test_unwrap(),
                surface: DecoySurface::SignedWatermark,
                scope_id: RecordId::new("scope-a").test_unwrap(),
                creation_policy_id: RecordId::new("policy-a").test_unwrap(),
                version: DecoyVersion::new(version).test_unwrap(),
                expires_at_unix_ms: 10_000,
                predecessor_artifact_id: predecessor
                    .map(|value| ArtifactId::new(value).test_unwrap()),
                marker: SecretMaterial::new(format!("private-{artifact}").into_bytes())
                    .test_unwrap(),
                materialization_payload: None,
            },
            RecordId::new(format!("create-{artifact}")).test_unwrap(),
        )
        .test_unwrap()
}

fn arm_marker(registry: &PrivateDecoyRegistry, artifact: &str) {
    transition(
        registry,
        artifact,
        &format!("begin-{artifact}"),
        DecoyOperationKind::BeginMaterialization,
        None,
    );
    transition(
        registry,
        artifact,
        &format!("arm-{artifact}"),
        DecoyOperationKind::Arm,
        None,
    );
}

fn transition(
    registry: &PrivateDecoyRegistry,
    artifact: &str,
    operation: &str,
    kind: DecoyOperationKind,
    successor: Option<&str>,
) {
    let tenant_id = TenantId::new(TENANT).test_unwrap();
    let artifact_id = ArtifactId::new(artifact).test_unwrap();
    let current = registry
        .load_private(&tenant_id, &artifact_id)
        .test_unwrap()
        .test_unwrap();
    registry
        .apply_transition(
            &tenant_id,
            &artifact_id,
            &DecoyOperationAttempt {
                operation_id: RecordId::new(operation).test_unwrap(),
                kind,
                expected_generation: current.generation,
                expected_version: current.version,
                successor_artifact_id: successor.map(|value| ArtifactId::new(value).test_unwrap()),
            },
        )
        .test_unwrap();
}

fn two_retired_tokens(fixture: &WatermarkFixture) -> serde_json::Value {
    let first = fixture.issue(1);
    let second = fixture.issue(2);
    assert_ne!(first, second);
    fixture.retire_marker();
    serde_json::json!({ "text": format!("{first} and {second}") })
}

#[test]
fn two_inactive_tokens_under_one_public_ref_are_two_observations_and_do_not_block() {
    let fixture = WatermarkFixture::new();
    let response = two_retired_tokens(&fixture);
    let request = request();
    assert!(matches!(
        fixture.inspect(&request, OBSERVED_AT, &response),
        PostInvocationVerdict::Allow
    ));
    assert_eq!(
        fixture.results(),
        [
            WatermarkObservationResult::Recorded,
            WatermarkObservationResult::Recorded
        ]
    );
}

#[test]
fn a_retried_request_with_two_inactive_tokens_keeps_both_first_observations() {
    let fixture = WatermarkFixture::new();
    let response = two_retired_tokens(&fixture);
    let request = request();
    assert!(matches!(
        fixture.inspect(&request, OBSERVED_AT, &response),
        PostInvocationVerdict::Allow
    ));
    assert!(matches!(
        fixture.inspect(&request, OBSERVED_AT + 1, &response),
        PostInvocationVerdict::Allow
    ));
    let results = fixture.results();
    assert_eq!(results.len(), 4);
    for retry in &results[2..] {
        assert!(
            matches!(
                retry,
                WatermarkObservationResult::Duplicate {
                    first_observed_at_unix_ms: OBSERVED_AT,
                    ..
                }
            ),
            "retry must return the first observation: {retry:?}"
        );
    }
    let WatermarkObservationResult::Duplicate {
        first_token_digest: first,
        ..
    } = &results[2]
    else {
        panic!("first retry must be a duplicate");
    };
    let WatermarkObservationResult::Duplicate {
        first_token_digest: second,
        ..
    } = &results[3]
    else {
        panic!("second retry must be a duplicate");
    };
    assert_ne!(first, second);
}

fn other_principal(request: &ToolCallRequest) -> ToolCallRequest {
    ToolCallRequest {
        agent_id: Keypair::from_seed(&[63_u8; 32]).public_key().to_hex(),
        ..request.clone()
    }
}

#[test]
fn two_principals_reusing_one_request_id_each_record_their_own_observations() {
    let fixture = WatermarkFixture::new();
    let response = two_retired_tokens(&fixture);
    let first_principal = request();
    let second_principal = other_principal(&first_principal);
    assert_eq!(second_principal.request_id, first_principal.request_id);
    assert_ne!(second_principal.agent_id, first_principal.agent_id);
    assert!(matches!(
        fixture.inspect(&first_principal, OBSERVED_AT, &response),
        PostInvocationVerdict::Allow
    ));
    assert!(matches!(
        fixture.inspect(&second_principal, OBSERVED_AT + 1, &response),
        PostInvocationVerdict::Allow
    ));
    assert_eq!(
        fixture.results(),
        [
            WatermarkObservationResult::Recorded,
            WatermarkObservationResult::Recorded,
            WatermarkObservationResult::Recorded,
            WatermarkObservationResult::Recorded
        ]
    );
}

#[test]
fn a_retry_by_the_second_principal_is_a_duplicate_of_its_own_first_observations() {
    let fixture = WatermarkFixture::new();
    let response = two_retired_tokens(&fixture);
    let first_principal = request();
    let second_principal = other_principal(&first_principal);
    for (principal, observed_at) in [
        (&first_principal, OBSERVED_AT),
        (&second_principal, OBSERVED_AT + 1),
        (&second_principal, OBSERVED_AT + 2),
    ] {
        assert!(matches!(
            fixture.inspect(principal, observed_at, &response),
            PostInvocationVerdict::Allow
        ));
    }
    let results = fixture.results();
    assert_eq!(results.len(), 6);
    for retry in &results[4..] {
        assert!(
            matches!(
                retry,
                WatermarkObservationResult::Duplicate {
                    first_observed_at_unix_ms,
                    ..
                } if *first_observed_at_unix_ms == OBSERVED_AT + 1
            ),
            "retry must return the same principal's first observation: {retry:?}"
        );
    }
}

#[test]
fn an_inactive_token_whose_attribution_changes_for_the_same_principal_still_blocks() {
    let fixture = WatermarkFixture::new();
    let response = two_retired_tokens(&fixture);
    let first_call = request();
    assert!(matches!(
        fixture.inspect(&first_call, OBSERVED_AT, &response),
        PostInvocationVerdict::Allow
    ));
    let changed_attribution = ToolCallRequest {
        tool_name: "tool-b".to_string(),
        ..first_call.clone()
    };
    assert_eq!(changed_attribution.request_id, first_call.request_id);
    assert_eq!(changed_attribution.agent_id, first_call.agent_id);
    assert!(matches!(
        fixture.inspect(&changed_attribution, OBSERVED_AT + 1, &response),
        PostInvocationVerdict::Block(_)
    ));
}
