    #[test]
    fn production_factory_rejects_invalid_watermark_authorities() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create production runtime directory: {error}"));

        let mut empty_keys = factory_config(directory.path());
        empty_keys.runtime.trusted_watermark_keys.clear();
        assert!(open_factory(empty_keys, [31_u8; 32]).is_err());

        let mut rejected_only = factory_config(directory.path());
        rejected_only.runtime.trusted_watermark_keys[0].status = WatermarkKeyStatus::Rejected;
        assert!(open_factory(rejected_only, [32_u8; 32]).is_err());

        let mut duplicate_key = factory_config(directory.path());
        duplicate_key
            .runtime
            .trusted_watermark_keys
            .push(duplicate_key.runtime.trusted_watermark_keys[0].clone());
        assert!(open_factory(duplicate_key, [33_u8; 32]).is_err());

        let mut invalid_key_window = factory_config(directory.path());
        invalid_key_window.runtime.trusted_watermark_keys[0].signing_cutoff_unix_ms = 1;
        assert!(open_factory(invalid_key_window, [34_u8; 32]).is_err());

        let mut empty_contexts = factory_config(directory.path());
        empty_contexts
            .runtime
            .trusted_watermark_source_contexts
            .clear();
        assert!(open_factory(empty_contexts, [35_u8; 32]).is_err());

        let mut duplicate_context = factory_config(directory.path());
        duplicate_context
            .runtime
            .trusted_watermark_source_contexts
            .push(duplicate_context.runtime.trusted_watermark_source_contexts[0].clone());
        assert!(open_factory(duplicate_context, [36_u8; 32]).is_err());

        let mut invalid_context_window = factory_config(directory.path());
        invalid_context_window
            .runtime
            .trusted_watermark_source_contexts[0]
            .not_after_unix_ms = 1;
        assert!(open_factory(invalid_context_window, [37_u8; 32]).is_err());
    }

    #[test]
    fn governed_response_policy_rejects_unconfigured_effects() {
        let policy = GovernedProductionResponsePolicy {
            runtime_policy_hash: "runtime-policy".to_string(),
            policy_version: RecordId::new("broker-production-response-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            approval_policy_id: RecordId::new("broker-production-approval-v1")
                .unwrap_or_else(|error| panic!("approval policy: {error}")),
            allowed_effects: BTreeSet::from([ResponseEffectKind::RestrictEgress]),
            automatic_ttl_ceiling_ms: 30_000,
            max_finding_age_ms: 60_000,
        };

        assert!(policy
            .validate_effects([ResponseEffectKind::RestrictEgress])
            .is_ok());
        assert!(policy
            .validate_effects([ResponseEffectKind::FreezeIssuance])
            .is_err());
    }

    #[test]
    fn correlation_and_governed_kernel_share_the_decoded_runtime_policy_digest() {
        let runtime_policy_hash = "4a".repeat(32);
        let startup_digest = decode_runtime_policy_digest(&runtime_policy_hash)
            .unwrap_or_else(|error| panic!("decode startup policy digest: {error}"));
        let policy = GovernedProductionResponsePolicy {
            runtime_policy_hash: runtime_policy_hash.clone(),
            policy_version: RecordId::new("broker-production-response-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            approval_policy_id: RecordId::new("broker-production-approval-v1")
                .unwrap_or_else(|error| panic!("approval policy: {error}")),
            allowed_effects: BTreeSet::from([ResponseEffectKind::RestrictEgress]),
            automatic_ttl_ceiling_ms: 30_000,
            max_finding_age_ms: 60_000,
        };
        let requirement = policy
            .classify_declared_requirement(
                &ResponseApprovalRequirement::Governed {
                    policy_id: policy.approval_policy_id.clone(),
                },
                30_000,
                &[ResponseEffectKind::RestrictEgress],
            )
            .unwrap_or_else(|error| panic!("classify governed response: {error}"));
        let kernel_digest = decode_runtime_policy_digest(requirement.policy_hash())
            .unwrap_or_else(|error| panic!("decode governed kernel policy digest: {error}"));

        assert_eq!(requirement.policy_hash(), runtime_policy_hash);
        assert_eq!(startup_digest, kernel_digest);
        assert_ne!(
            startup_digest,
            Digest32::new(*chio_core::sha256(runtime_policy_hash.as_bytes()).as_bytes())
        );
    }

    #[test]
    fn production_policy_allows_bounded_automatic_reversible_effects() {
        let policy = GovernedProductionResponsePolicy {
            runtime_policy_hash: "runtime-policy".to_string(),
            policy_version: RecordId::new("broker-production-response-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            approval_policy_id: RecordId::new("broker-production-approval-v1")
                .unwrap_or_else(|error| panic!("approval policy: {error}")),
            allowed_effects: BTreeSet::from([
                ResponseEffectKind::ThrottleSession,
                ResponseEffectKind::RestrictEgress,
                ResponseEffectKind::FreezeIssuance,
            ]),
            automatic_ttl_ceiling_ms: 30_000,
            max_finding_age_ms: 60_000,
        };

        let requirement = policy
            .classify_declared_requirement(
                &ResponseApprovalRequirement::Automatic,
                30_000,
                &[
                    ResponseEffectKind::ThrottleSession,
                    ResponseEffectKind::RestrictEgress,
                ],
            )
            .unwrap_or_else(|error| panic!("classify reversible automatic response: {error}"));
        assert_eq!(
            requirement.approval_requirement(),
            &ResponseApprovalRequirement::Automatic
        );
        assert_eq!(requirement.automatic_ttl_ceiling_ms(), Some(30_000));
        assert!(policy
            .classify_declared_requirement(
                &ResponseApprovalRequirement::Automatic,
                30_001,
                &[ResponseEffectKind::RestrictEgress],
            )
            .is_err());
        assert!(policy
            .classify_declared_requirement(
                &ResponseApprovalRequirement::Governed {
                    policy_id: policy.approval_policy_id.clone(),
                },
                60_001,
                &[ResponseEffectKind::RestrictEgress],
            )
            .is_ok());
        assert!(policy
            .classify_declared_requirement(
                &ResponseApprovalRequirement::Automatic,
                30_000,
                &[ResponseEffectKind::FreezeIssuance],
            )
            .is_err());
    }

    struct FixedWatermarkClock(u64);

    impl WatermarkClock for FixedWatermarkClock {
        fn now_unix_ms(&self) -> u64 {
            self.0
        }
    }

    struct FixedSecurityClock(u64);

    impl SecurityClock for FixedSecurityClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0)
        }
    }

    struct ProductionWatermarkFixture {
        _directory: tempfile::TempDir,
        factory: ProductionSecurityRuntimeFactory,
        token: String,
        now_unix_ms: u64,
        registry: PrivateDecoyRegistry,
        store: Arc<SqliteSealedDecoyRegistryStore>,
        contexts: Arc<ProductionWatermarkSourceContextResolver>,
    }

    impl ProductionWatermarkFixture {
        fn input(&self, content: &str, request_suffix: &str) -> TripwireInput {
            TripwireInput {
                tenant_id: TenantId::new("tenant-production")
                    .unwrap_or_else(|error| panic!("tenant id: {error}")),
                request_id: RequestId::new(format!("production-watermark-{request_suffix}"))
                    .unwrap_or_else(|error| panic!("request id: {error}")),
                kind: TripwireKind::SignedWatermark,
                content: CanonicalBody::new(content.as_bytes().to_vec())
                    .unwrap_or_else(|error| panic!("watermark content: {error}")),
                content_digest: Digest32::new(*sha256(content.as_bytes()).as_bytes()),
                canonical_context_digest: Digest32::new([17_u8; 32]),
            }
        }
    }

    fn now_unix_ms() -> u64 {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock before unix epoch: {error}"));
        u64::try_from(elapsed.as_millis())
            .unwrap_or_else(|error| panic!("unix millisecond timestamp overflow: {error}"))
    }

    fn active_decoy(registry: &PrivateDecoyRegistry, now_unix_ms: u64) -> RecordId {
        let tenant_id =
            TenantId::new("tenant-production").unwrap_or_else(|error| panic!("tenant id: {error}"));
        let artifact_id = ArtifactId::new("production-watermark-artifact-v1")
            .unwrap_or_else(|error| panic!("artifact id: {error}"));
        let record = registry
            .create(
                DecoyCreateRequest {
                    tenant_id: tenant_id.clone(),
                    artifact_id: artifact_id.clone(),
                    surface: DecoySurface::SignedWatermark,
                    scope_id: RecordId::new("production-watermark-scope")
                        .unwrap_or_else(|error| panic!("scope id: {error}")),
                    creation_policy_id: RecordId::new("production-watermark-policy")
                        .unwrap_or_else(|error| panic!("creation policy id: {error}")),
                    version: DecoyVersion::new(1)
                        .unwrap_or_else(|error| panic!("decoy version: {error}")),
                    expires_at_unix_ms: now_unix_ms.saturating_add(240_000),
                    predecessor_artifact_id: None,
                    marker: SecretMaterial::new(b"production-private-marker-v1".to_vec())
                        .unwrap_or_else(|error| panic!("private marker: {error}")),
                    materialization_payload: None,
                },
                RecordId::new("production-watermark-create")
                    .unwrap_or_else(|error| panic!("create operation id: {error}")),
            )
            .unwrap_or_else(|error| panic!("create signed watermark decoy: {error}"));
        for (operation_id, kind) in [
            (
                "production-watermark-materialize",
                DecoyOperationKind::BeginMaterialization,
            ),
            ("production-watermark-arm", DecoyOperationKind::Arm),
        ] {
            let current = registry
                .load_private(&tenant_id, &artifact_id)
                .unwrap_or_else(|error| panic!("load signed watermark decoy: {error}"))
                .unwrap_or_else(|| panic!("signed watermark decoy is missing"));
            registry
                .apply_transition(
                    &tenant_id,
                    &artifact_id,
                    &DecoyOperationAttempt {
                        operation_id: RecordId::new(operation_id)
                            .unwrap_or_else(|error| panic!("transition operation id: {error}")),
                        kind,
                        expected_generation: current.generation,
                        expected_version: current.version,
                        successor_artifact_id: None,
                    },
                )
                .unwrap_or_else(|error| panic!("arm signed watermark decoy: {error}"));
        }
        record
            .public_marker_ref
            .unwrap_or_else(|| panic!("signed watermark public marker reference is missing"))
    }

    fn production_watermark_fixture(
        detector_status: WatermarkKeyStatus,
        detector_public_key: Option<PublicKey>,
        token_age_ms: u64,
    ) -> ProductionWatermarkFixture {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create production runtime directory: {error}"));
        let master_key = [11_u8; 32];
        let token_signer = Arc::new(Ed25519Backend::new(Keypair::from_seed(&[21_u8; 32])));
        let token_public_key = token_signer.public_key();
        let now_unix_ms = now_unix_ms();
        let issued_at_unix_ms = now_unix_ms.saturating_sub(token_age_ms).max(2_000);
        let key_id = "production-watermark-key-v1";
        let source_receipt_id = "production-source-receipt-v1";
        let source_context = ProductionWatermarkSourceContextConfig {
            tenant_id: "tenant-production".to_string(),
            application_id: "production-application".to_string(),
            session_id: "production-session".to_string(),
            source_receipt_id: source_receipt_id.to_string(),
            tool_id: "production-tool".to_string(),
            issued_at_unix_ms,
            not_after_unix_ms: now_unix_ms.saturating_add(120_000),
        };
        let detector_key = ProductionTrustedWatermarkKeyConfig {
            tenant_id: "tenant-production".to_string(),
            key_id: key_id.to_string(),
            public_key: detector_public_key.unwrap_or_else(|| token_public_key.clone()),
            status: detector_status,
            not_before_unix_ms: issued_at_unix_ms.saturating_sub(1_000).max(1),
            signing_cutoff_unix_ms: now_unix_ms.saturating_add(120_000),
            verify_until_unix_ms: now_unix_ms.saturating_add(240_000),
        };
        let issuer_key = ProductionTrustedWatermarkKeyConfig {
            public_key: token_public_key,
            status: WatermarkKeyStatus::Active,
            ..detector_key.clone()
        };
        let mut config = factory_config(directory.path());
        config.runtime.trusted_watermark_keys = vec![detector_key];
        if detector_status == WatermarkKeyStatus::Rejected {
            config
                .runtime
                .trusted_watermark_keys
                .push(ProductionTrustedWatermarkKeyConfig {
                    tenant_id: "tenant-production".to_string(),
                    key_id: "production-watermark-current-key".to_string(),
                    public_key: Keypair::from_seed(&[22_u8; 32]).public_key(),
                    status: WatermarkKeyStatus::Active,
                    not_before_unix_ms: 1,
                    signing_cutoff_unix_ms: now_unix_ms.saturating_add(120_000),
                    verify_until_unix_ms: now_unix_ms.saturating_add(240_000),
                });
        }
        config.runtime.trusted_watermark_source_contexts = vec![source_context.clone()];
        let registry_path = config.runtime.decoy_registry_database_path.clone();
        let factory = open_factory(config, master_key)
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let store = Arc::new(
            SqliteSealedDecoyRegistryStore::open(&registry_path)
                .unwrap_or_else(|error| panic!("open sealed decoy registry store: {error}")),
        );
        let registry = PrivateDecoyRegistry::new(
            store.clone(),
            Arc::new(DerivedRegistryKeyProvider::new(master_key)),
            Arc::new(DenyRegistryExport),
        );
        let marker_ref = active_decoy(&registry, now_unix_ms);
        let issuer_keys = Arc::new(
            ProductionWatermarkKeyResolver::new(&[issuer_key])
                .unwrap_or_else(|error| panic!("issuer key resolver: {error}")),
        );
        let contexts = Arc::new(
            ProductionWatermarkSourceContextResolver::new(&[source_context])
                .unwrap_or_else(|error| panic!("source context resolver: {error}")),
        );
        let issuer = WatermarkIssuer::new(
            WatermarkIssuerConfig {
                key_id: RecordId::new(key_id)
                    .unwrap_or_else(|error| panic!("watermark key id: {error}")),
                policy: WatermarkIssuerPolicy::new(30_000, 10_000, 1_000)
                    .unwrap_or_else(|error| panic!("watermark issuer policy: {error}")),
            },
            WatermarkIssuerDependencies {
                signer: token_signer as Arc<dyn SigningBackend>,
                keys: issuer_keys as Arc<dyn WatermarkKeyResolver>,
                registry: registry.clone(),
                contexts: contexts.clone() as Arc<dyn WatermarkSourceContextResolver>,
                sequences: store.clone() as Arc<dyn WatermarkSequenceStore>,
                clock: Arc::new(FixedWatermarkClock(issued_at_unix_ms.saturating_add(1))),
            },
        );
        let token = issuer
            .issue(WatermarkIssueRequest {
                source_receipt_id: RecordId::new(source_receipt_id)
                    .unwrap_or_else(|error| panic!("source receipt id: {error}")),
                marker_ref,
                sequence: 1,
                operation_id: RecordId::new("production-watermark-issue")
                    .unwrap_or_else(|error| panic!("issue operation id: {error}")),
            })
            .unwrap_or_else(|error| panic!("issue signed watermark: {error}"));

        ProductionWatermarkFixture {
            _directory: directory,
            factory,
            token,
            now_unix_ms,
            registry,
            store,
            contexts,
        }
    }

    #[test]
    fn production_watermark_detector_matches_a_valid_active_token() {
        let fixture = production_watermark_fixture(WatermarkKeyStatus::Active, None, 1_000);

        assert!(matches!(
            fixture
                .factory
                .tripwire_detector
                .detect(&fixture.input(&fixture.token, "valid")),
            Ok(TripwireDecision::Match { .. })
        ));
    }

    #[test]
    fn production_watermark_detector_clears_payload_and_signature_tampering() {
        let fixture = production_watermark_fixture(WatermarkKeyStatus::Active, None, 1_000);
        let mut payload_tamper = SignedWatermarkEnvelope::decode_token(&fixture.token)
            .unwrap_or_else(|error| panic!("decode signed watermark: {error}"));
        payload_tamper.payload.sequence = payload_tamper.payload.sequence.saturating_add(1);
        let payload_tamper = payload_tamper
            .encode_token()
            .unwrap_or_else(|error| panic!("encode payload tamper: {error}"));
        let mut signature_tamper = SignedWatermarkEnvelope::decode_token(&fixture.token)
            .unwrap_or_else(|error| panic!("decode signed watermark: {error}"));
        signature_tamper.signature =
            Keypair::from_seed(&[99_u8; 32]).sign(b"tampered watermark signature");
        let signature_tamper = signature_tamper
            .encode_token()
            .unwrap_or_else(|error| panic!("encode signature tamper: {error}"));

        for (case, token) in [
            ("payload-tamper", payload_tamper),
            ("signature-tamper", signature_tamper),
        ] {
            assert_eq!(
                fixture
                    .factory
                    .tripwire_detector
                    .detect(&fixture.input(&token, case)),
                Ok(TripwireDecision::Clear),
                "{case} must not become a production watermark match"
            );
        }
    }

    #[test]
    fn production_watermark_detector_clears_an_expired_token() {
        let fixture = production_watermark_fixture(WatermarkKeyStatus::Active, None, 120_000);

        assert_eq!(
            fixture
                .factory
                .tripwire_detector
                .detect(&fixture.input(&fixture.token, "expired")),
            Ok(TripwireDecision::Clear)
        );
    }

    #[test]
    fn production_watermark_detector_clears_rejected_and_untrusted_keys() {
        let rejected = production_watermark_fixture(WatermarkKeyStatus::Rejected, None, 1_000);
        assert_eq!(
            rejected
                .factory
                .tripwire_detector
                .detect(&rejected.input(&rejected.token, "rejected-key")),
            Ok(TripwireDecision::Clear)
        );

        let untrusted = production_watermark_fixture(
            WatermarkKeyStatus::Active,
            Some(Keypair::from_seed(&[23_u8; 32]).public_key()),
            1_000,
        );
        assert_eq!(
            untrusted
                .factory
                .tripwire_detector
                .detect(&untrusted.input(&untrusted.token, "untrusted-key")),
            Ok(TripwireDecision::Clear)
        );
    }

    struct UnavailableWatermarkKeys;

    impl WatermarkKeyResolver for UnavailableWatermarkKeys {
        fn resolve(&self, _: &TenantId, _: &RecordId) -> PortResult<Option<TrustedWatermarkKey>> {
            Err(PortError::unavailable())
        }
    }

    #[test]
    fn production_watermark_dependency_outage_fails_closed_instead_of_clearing() {
        let fixture = production_watermark_fixture(WatermarkKeyStatus::Active, None, 1_000);
        let verifier = Arc::new(WatermarkVerifier::new(WatermarkVerifierDependencies {
            keys: Arc::new(UnavailableWatermarkKeys),
            contexts: fixture.contexts.clone() as Arc<dyn WatermarkSourceContextResolver>,
            registry: fixture.registry.clone(),
            observations: fixture.store.clone() as Arc<dyn WatermarkObservationStore>,
        }));
        let detector = DecoyTripwireDetectorPort::new(
            Arc::new(DecoyDetector::new(Arc::new(fixture.registry.clone()))),
            verifier,
            Arc::new(FixedSecurityClock(fixture.now_unix_ms)),
        );
        let error = detector
            .detect(&fixture.input(&fixture.token, "dependency-outage"))
            .err()
            .unwrap_or_else(|| panic!("watermark dependency outage was reported as clear"));

        assert_eq!(error.kind(), PortErrorKind::Unavailable);
    }
