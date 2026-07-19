#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::Cell;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_guards::PostInvocationPipeline;

    struct IdentityReceiptStore {
        identity: chio_core::Hash,
    }

    impl chio_kernel::ReceiptStore for IdentityReceiptStore {
        fn append_chio_receipt(
            &self,
            _receipt: &chio_core::receipt::body::ChioReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            Ok(())
        }

        fn durable_storage_identity(
            &self,
        ) -> Result<Option<chio_core::Hash>, chio_kernel::ReceiptStoreError> {
            Ok(Some(self.identity))
        }

        fn append_child_receipt(
            &self,
            _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            Ok(())
        }
    }

    fn identity_receipt_store(seed: &[u8]) -> Arc<dyn chio_kernel::ReceiptStore> {
        Arc::new(IdentityReceiptStore {
            identity: chio_core::sha256(seed),
        })
    }

    #[test]
    fn keyring_receipt_attachment_rejects_a_then_different_durable_store_b() {
        let attachment = Mutex::new(None);
        let store_a = identity_receipt_store(b"receipt-store-a");
        let store_b = identity_receipt_store(b"receipt-store-b");
        assert_eq!(
            attach_receipt_store_transactionally(&attachment, store_a, |_| Ok(3)).unwrap(),
            3
        );

        let backfill_called = Cell::new(false);
        let error = attach_receipt_store_transactionally(&attachment, store_b, |_| {
            backfill_called.set(true);
            Ok(0)
        })
        .expect_err("different receipt commit domain must fail closed");
        assert!(!backfill_called.get());
        assert!(error
            .to_string()
            .contains("already bound to a different durable commit domain"));
        assert_eq!(
            attachment.lock().unwrap().as_ref().unwrap().identity,
            chio_core::sha256(b"receipt-store-a")
        );
    }

    #[test]
    fn keyring_receipt_attachment_rolls_back_publication_when_backfill_fails() {
        let attachment = Mutex::new(None);
        let store = identity_receipt_store(b"receipt-store-a");
        let error = attach_receipt_store_transactionally(&attachment, Arc::clone(&store), |_| {
            Err(CliError::cli_other_error(
                "injected key-enterprise receipt backfill failure".to_string(),
            ))
        })
        .expect_err("failed backfill must not publish attachment");
        assert!(error.to_string().contains("injected"));
        assert!(attachment.lock().unwrap().is_none());

        assert_eq!(
            attach_receipt_store_transactionally(&attachment, store, |_| Ok(2)).unwrap(),
            2
        );
        assert!(attachment.lock().unwrap().is_some());
    }

    fn make_kernel(require_web3_evidence: bool) -> ChioKernel {
        make_kernel_with_checkpoint_batch(
            require_web3_evidence,
            chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        )
    }

    fn make_kernel_with_checkpoint_batch(
        require_web3_evidence: bool,
        checkpoint_batch_size: u64,
    ) -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "control-plane-test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence,
            checkpoint_batch_size,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            allow_ephemeral_receipt_log: true,
        })
    }

    fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn expect_receipt_configuration_error(
        result: Result<Option<Arc<dyn chio_kernel::ReceiptStore>>, CliError>,
    ) -> CliError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("receipt-store configuration unexpectedly succeeded"),
        }
    }

    fn assert_registry_error(
        err: &CliError,
        expected: &'static ErrorCodeSpec,
        expected_domain: &str,
    ) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected.urn);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    #[test]
    fn migrated_cli_error_helpers_emit_registry_codes_and_domains() {
        let cases = [
            (
                CliError::manifest_signature_error("bad manifest signature"),
                &MANIFEST_SIGNATURE_INVALID,
                "manifest",
            ),
            (
                CliError::manifest_schema_error("bad manifest schema"),
                &MANIFEST_SCHEMA_INVALID,
                "manifest",
            ),
            (
                CliError::guard_error("guard denied request"),
                &GUARD_DENIED,
                "guard",
            ),
            (
                CliError::replay_mismatch_error("replay diverged"),
                &REPLAY_DETERMINISTIC_MISMATCH,
                "replay",
            ),
            (
                CliError::provider_error("provider adapter failed"),
                &PROVIDER_TOOL_SERVER_ERROR,
                "provider",
            ),
            (
                CliError::cli_io_error("could not read input"),
                &CLI_IO,
                "cli",
            ),
            (
                CliError::cli_yaml_error("could not parse yaml"),
                &CLI_YAML,
                "cli",
            ),
        ];

        for (err, expected, expected_domain) in cases {
            assert_registry_error(&err, expected, expected_domain);
        }
    }

    #[test]
    fn cli_error_report_rejects_mismatched_registry_metadata() {
        let spec = &chio_errors::_generated::error_codes::CAPABILITY_EXPIRED;
        let error = CliError::Chio(
            chio_errors::diagnostic(
                spec.urn,
                chio_errors::Domain::Manifest,
                spec.severity,
                "registered code with mismatched diagnostic domain",
            )
            .into_error(),
        );

        let report = error.report();

        assert_eq!(report.code, spec.urn);
        assert_eq!(report.context["domain"], "manifest");
        assert_eq!(report.context["severity"], spec.severity.as_str());
        assert_eq!(report.context["string_code"], serde_json::Value::Null);
        assert_eq!(report.context["stability"], serde_json::Value::Null);
        assert_eq!(
            report.suggested_fix,
            "Inspect the Chio diagnostic and retry after correcting the request."
        );
    }

    #[test]
    fn web3_evidence_requires_local_receipt_store() {
        let mut kernel = make_kernel(true);

        let error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            None,
            None,
            None,
            None,
            &[],
        ));
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
    }

    #[test]
    fn web3_evidence_accepts_checkpoint_capable_sqlite_receipt_store() {
        let path = unique_receipt_db_path("chio-control-plane-web3-evidence");
        let mut kernel = make_kernel(true);

        configure_receipt_store(&mut kernel, Some(&path), None, None, None, &[]).unwrap();
        kernel.validate_web3_evidence_prerequisites().unwrap();

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web3_evidence_preflight_rejects_before_receipt_store_mutation() {
        let path = unique_receipt_db_path("chio-control-plane-web3-preflight");
        let mut kernel = make_kernel_with_checkpoint_batch(true, 0);

        let error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            Some(&path),
            None,
            None,
            None,
            &[],
        ));

        assert!(error.to_string().contains("checkpoint_batch_size > 0"));
        assert!(kernel.aggregate_family_root_resolver().is_none());
        let unchanged = kernel
            .validate_web3_evidence_prerequisites()
            .expect_err("failed preflight must leave the receipt store uninstalled");
        assert!(unchanged.to_string().contains("durable receipt store"));
        assert!(!path.exists());
    }

    #[test]
    fn aggregate_family_root_resolver_is_explicit_for_local_and_remote_stores() {
        let path = unique_receipt_db_path("chio-control-plane-family-resolver");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let root = chio_core::capability::token::CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: "configured-local-root".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: chio_core::capability::scope::ChioScope {
                    grants: vec![chio_core::capability::scope::ToolGrant {
                        server_id: "configured-server".to_string(),
                        tool_name: "configured-tool".to_string(),
                        operations: vec![
                            chio_core::capability::scope::Operation::Invoke,
                            chio_core::capability::scope::Operation::Delegate,
                        ],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .expect("configured root");
        let seed_store = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("seed store");
        seed_store
            .record_aggregate_family_root(&root, &[issuer.public_key()], 1_100)
            .expect("seed root");
        drop(seed_store);
        let mut kernel = make_kernel(false);
        assert!(kernel.aggregate_family_root_resolver().is_none());

        configure_receipt_store(&mut kernel, Some(&path), None, None, None, &[]).unwrap();
        let resolver = kernel
            .aggregate_family_root_resolver()
            .expect("local SQLite composition must install a root resolver");
        assert!(matches!(
            resolver.resolve_aggregate_family_root(&root.id),
            Ok(
                chio_core::capability::aggregate_budget::AggregateFamilyRootResolution::LegacyUnbound(
                    resolved
                )
            ) if resolved.root_subject() == &root.subject
        ));

        let error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            None,
            Some("http://control.example"),
            Some("test-token"),
            Some(&issuer.public_key()),
            &[],
        ));
        assert!(error.to_string().contains("requires HTTPS"));
        assert!(matches!(
            kernel
                .aggregate_family_root_resolver()
                .expect("failed reconfiguration must preserve the local resolver")
                .resolve_aggregate_family_root(&root.id),
            Ok(
                chio_core::capability::aggregate_budget::AggregateFamilyRootResolution::LegacyUnbound(
                    _
                )
            )
        ));

        let remote_error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            None,
            Some("http://127.0.0.1:8080"),
            Some("test-token"),
            Some(&issuer.public_key()),
            &[],
        ));
        assert!(remote_error.to_string().contains("requires HTTPS"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web3_evidence_rejects_remote_append_only_receipt_store() {
        let path = unique_receipt_db_path("chio-control-plane-web3-atomic-reconfiguration");
        let mut kernel = make_kernel(true);
        configure_receipt_store(&mut kernel, Some(&path), None, None, None, &[]).unwrap();

        let error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            None,
            Some("http://127.0.0.1:8080"),
            Some("test-token"),
            Some(&Keypair::generate().public_key()),
            &[],
        ));
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
        assert!(error
            .to_string()
            .contains("append-only remote receipt mirrors are unsupported"));
        kernel
            .validate_web3_evidence_prerequisites()
            .expect("failed remote reconfiguration must preserve the local receipt store");
        assert!(kernel.aggregate_family_root_resolver().is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn remote_receipt_configuration_requires_a_pin_before_mutation() {
        let path = unique_receipt_db_path("chio-control-plane-family-pin");
        let mut kernel = make_kernel(false);
        configure_receipt_store(&mut kernel, Some(&path), None, None, None, &[]).unwrap();

        let error = expect_receipt_configuration_error(configure_receipt_store(
            &mut kernel,
            None,
            Some("https://control.example"),
            Some("test-token"),
            None,
            &[],
        ));

        assert!(error.to_string().contains("independently pinned"));
        assert!(kernel.aggregate_family_root_resolver().is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_error_report_passes_through_kernel_metadata() {
        let report = CliError::Kernel(chio_kernel::KernelError::OutOfScope {
            tool: "read_file".to_string(),
            server: "fs".to_string(),
        })
        .report();

        assert_eq!(report.code, "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
        assert_eq!(report.context["tool"], "read_file");
        assert_eq!(report.context["server"], "fs");
        assert!(report
            .suggested_fix
            .contains("Issue a capability that grants this tool"));
    }

    #[test]
    fn cli_error_report_captures_io_context() {
        let report = CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing file",
        ))
        .report();

        assert_eq!(report.code, "CHIO-CLI-IO");
        assert!(report.message.contains("i/o error"));
        assert!(report.context["source"]
            .as_str()
            .expect("io source string")
            .contains("missing file"));
        assert!(report.suggested_fix.contains("Check file paths"));
    }

    #[test]
    fn build_kernel_registers_post_invocation_pipeline() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: {
                let mut pipeline = PostInvocationPipeline::new();
                pipeline.add(Box::new(chio_guards::SanitizerHook::new()));
                pipeline
            },
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval_resolver: None,
            threshold_approval_policy_authority: None,
            active_defense: policy::ActiveDefensePolicyConfig::default(),
            active_defense_rules: Vec::new(),
        };

        let kernel = build_kernel(loaded_policy, &keypair).expect("build disabled kernel");
        assert_eq!(kernel.post_invocation_hook_count(), 2);
    }

    #[test]
    fn keyring_checkpoint_future_skew_is_converted_from_seconds_to_milliseconds() {
        assert_eq!(checkpoint_future_skew_millis(100).unwrap(), 100_000);
        assert!(checkpoint_future_skew_millis(u64::MAX).is_err());
    }

    fn key_log_migration_test_key() -> EnterpriseMigrationKey {
        let deployment_id = RecordId::new("deployment.keyring.test").unwrap();
        EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Deployment,
            scope_id: deployment_id,
            control: EnterpriseMigrationControl::KeyLogVerification,
        }
    }

    const fn migration_test_digest(byte: u8) -> Digest32 {
        Digest32::new([byte; 32])
    }

    fn key_log_migration_test_policy() -> chio_keyring::KeyLogPolicy {
        chio_keyring::KeyLogPolicy::new(chio_keyring::KeyLogPolicyConfig {
            log_id: chio_keyring::LogId::new("log.keyring.migration.test").unwrap(),
            authority_id: chio_keyring::AuthorityId::new("authority.keyring.migration.test")
                .unwrap(),
            bootstrap_key: Keypair::from_seed(&[0x51; 32]).public_key(),
            operator_key: Keypair::from_seed(&[0x52; 32]).public_key(),
            witness_roster_id: chio_keyring::WitnessRosterId::new(
                "roster.keyring.migration.test",
            )
            .unwrap(),
            witness_keys: BTreeMap::from([(
                chio_keyring::WitnessId::new("witness.keyring.migration.test").unwrap(),
                Keypair::from_seed(&[0x53; 32]).public_key(),
            )]),
            recovery_policy_id: chio_keyring::RecoveryPolicyId::new(
                "recovery.keyring.migration.test",
            )
            .unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100_000,
        })
        .unwrap()
    }

    #[test]
    fn keyring_migration_config_requires_one_enforced_deployment_anchor() {
        let signer_a = Keypair::from_seed(&[0x31; 32]).public_key();
        let signer_b = Keypair::from_seed(&[0x32; 32]).public_key();
        let mut signers = vec![signer_a, signer_b];
        signers.sort_by_key(|key| key.to_hex());
        let key = key_log_migration_test_key();
        let head = EnterpriseMigrationMinimumHead {
            key: key.clone(),
            minimum_generation: EnterpriseMigrationStage::Enforced.generation(),
            transition_digest: migration_test_digest(1),
        };
        let config = KeyLogVerificationMigrationConfig {
            state_database_path: PathBuf::from("/var/lib/chio/key-log-migration.sqlite3"),
            deployment_id: key.deployment_id.clone(),
            stage: EnterpriseMigrationStage::Enforced,
            trusted_transition_signers: signers.clone(),
            minimum_heads: vec![head.clone()],
        };
        assert_eq!(config.validated_key().unwrap(), key);

        let shadow = KeyLogVerificationMigrationConfig {
            stage: EnterpriseMigrationStage::Shadow,
            minimum_heads: vec![EnterpriseMigrationMinimumHead {
                minimum_generation: EnterpriseMigrationStage::Shadow.generation(),
                ..head.clone()
            }],
            ..config
        };
        assert!(shadow.validated_key().is_err());

        let wrong_scope = KeyLogVerificationMigrationConfig {
            stage: EnterpriseMigrationStage::Enforced,
            trusted_transition_signers: signers.clone(),
            minimum_heads: vec![EnterpriseMigrationMinimumHead {
                key: EnterpriseMigrationKey {
                    scope_kind: EnterpriseMigrationScopeKind::Provider,
                    ..head.key.clone()
                },
                ..head.clone()
            }],
            ..shadow
        };
        assert!(wrong_scope.validated_key().is_err());

        let duplicate_signers = KeyLogVerificationMigrationConfig {
            trusted_transition_signers: vec![signers[0].clone(), signers[0].clone()],
            minimum_heads: vec![head],
            ..wrong_scope
        };
        assert!(duplicate_signers.validated_key().is_err());
    }

    #[test]
    fn keyring_runtime_config_deserializes_required_migration_ledger_inputs() {
        let deployment_id = "deployment.keyring.config.test";
        let transition_signer = Keypair::from_seed(&[0x33; 32]).public_key();
        let bootstrap = Keypair::from_seed(&[0x34; 32]).public_key();
        let operator = Keypair::from_seed(&[0x35; 32]).public_key();
        let artifact_time = Keypair::from_seed(&[0x36; 32]).public_key();
        let witness_a = Keypair::from_seed(&[0x37; 32]).public_key();
        let witness_b = Keypair::from_seed(&[0x38; 32]).public_key();
        let witness_c = Keypair::from_seed(&[0x39; 32]).public_key();
        let audit_a = Keypair::from_seed(&[0x3a; 32]).public_key();
        let audit_b = Keypair::from_seed(&[0x3b; 32]).public_key();
        let value = serde_json::json!({
            "schema": "chio.keyring.runtime-config.v1",
            "database_path": "/var/lib/chio/key-log.sqlite3",
            "enterprise_migration": {
                "state_database_path": "/var/lib/chio/key-log-migration.sqlite3",
                "deployment_id": deployment_id,
                "stage": "enforced",
                "trusted_transition_signers": [transition_signer.to_hex()],
                "minimum_heads": [{
                    "key": {
                        "deployment_id": deployment_id,
                        "scope_kind": "deployment",
                        "scope_id": deployment_id,
                        "control": "key_log_verification"
                    },
                    "minimum_generation": 2,
                    "transition_digest": vec![1_u8; 32]
                }]
            },
            "log_id": "production.authority.log",
            "authority_id": "production.authority",
            "bootstrap_public_key": bootstrap.to_hex(),
            "operator_public_key": operator.to_hex(),
            "operator_seed_file_path": "/run/chio/operator.seed",
            "witness_roster_id": "production.witnesses.v1",
            "witness_public_keys": {
                "witness.a": witness_a.to_hex(),
                "witness.b": witness_b.to_hex(),
                "witness.c": witness_c.to_hex()
            },
            "witness_service_endpoints": {
                "witness.a": "/run/chio/witness-a.sock",
                "witness.b": "/run/chio/witness-b.sock",
                "witness.c": "/run/chio/witness-c.sock"
            },
            "audit_service_endpoints": {
                "audit.a": "/run/chio/audit-a.sock",
                "audit.b": "/run/chio/audit-b.sock"
            },
            "audit_public_keys": {
                "audit.a": audit_a.to_hex(),
                "audit.b": audit_b.to_hex()
            },
            "recovery_policy_id": "production.recovery.v1",
            "recovery_public_keys": {},
            "recovery_threshold": 0,
            "artifact_time_public_keys": {
                "timestamp.primary": artifact_time.to_hex()
            },
            "artifact_time_seed_file_path": "/run/chio/artifact-time.seed",
            "max_checkpoint_future_skew_seconds": 30
        });
        let config: KeyringRuntimeConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            config.enterprise_migration.validated_key().unwrap(),
            key_log_migration_test_key_for(deployment_id)
        );
        assert_eq!(config.witness_public_keys.len(), 3);
        assert_eq!(config.audit_public_keys.len(), 2);
    }

    fn key_log_migration_test_key_for(deployment: &str) -> EnterpriseMigrationKey {
        let deployment_id = RecordId::new(deployment).unwrap();
        EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Deployment,
            scope_id: deployment_id,
            control: EnterpriseMigrationControl::KeyLogVerification,
        }
    }

    fn promote_key_log_migration_test_state(
        store: &chio_store_sqlite::SqliteEnterpriseMigrationStateStore,
        signer: &Keypair,
        prior: &chio_security_types::EnterpriseMigrationState,
        posture: Digest32,
        seed: u8,
        trusted_at_unix_ms: u64,
    ) -> chio_security_types::EnterpriseMigrationState {
        use chio_security_types::EnterpriseMigrationStateStore as _;

        let body = chio_security_types::EnterpriseMigrationTransitionBody::promotion(
            prior,
            posture,
            migration_test_digest(seed),
            migration_test_digest(seed.wrapping_add(1)),
            migration_test_digest(seed.wrapping_add(2)),
            trusted_at_unix_ms,
            signer.public_key().to_hex(),
        )
        .unwrap();
        let transition = chio_store_sqlite::sign_enterprise_migration_transition(body, signer)
            .unwrap();
        match store.compare_and_promote(&transition).unwrap() {
            chio_security_types::EnterpriseMigrationCasOutcome::Promoted(state) => state,
            chio_security_types::EnterpriseMigrationCasOutcome::Conflict(state) => {
                panic!("unexpected migration promotion conflict: {state:?}")
            }
        }
    }

    #[test]
    fn keyring_signing_guard_denies_changed_head_and_recovers_after_rebinding() {
        use chio_security_types::EnterpriseMigrationStateStore as _;

        let directory = tempfile::tempdir().unwrap();
        let directory_path = fs::canonicalize(directory.path()).unwrap();
        let key_log_database_path = directory_path.join("key-log.sqlite3");
        std::fs::File::create(&key_log_database_path).unwrap();
        let migration_database_path = directory_path.join("migration.sqlite3");
        let transition_signer = Keypair::from_seed(&[0x41; 32]);
        let policy = SqliteEnterpriseMigrationOpenPolicy::new(
            vec![transition_signer.public_key()],
            Vec::new(),
        )
        .unwrap();
        let concrete = Arc::new(
            SqliteEnterpriseMigrationStateStore::open(&migration_database_path, policy).unwrap(),
        );
        let key = key_log_migration_test_key();
        let key_log_policy = key_log_migration_test_policy();
        let key_log_configuration_binding = key_log_policy.configuration_binding().unwrap();
        let mut enforced_config = KeyLogVerificationMigrationConfig {
            state_database_path: migration_database_path.clone(),
            deployment_id: key.deployment_id.clone(),
            stage: EnterpriseMigrationStage::Enforced,
            trusted_transition_signers: vec![transition_signer.public_key()],
            minimum_heads: vec![EnterpriseMigrationMinimumHead {
                key: key.clone(),
                minimum_generation: EnterpriseMigrationStage::Enforced.generation(),
                transition_digest: migration_test_digest(250),
            }],
        };
        let enforced_posture = key_log_verification_migration_posture_digest(
            &enforced_config,
            key_log_configuration_binding,
        )
        .unwrap();
        let genesis = chio_security_types::EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            migration_test_digest(1),
            migration_test_digest(2),
            migration_test_digest(3),
            migration_test_digest(4),
            100,
            transition_signer.public_key().to_hex(),
        )
        .unwrap();
        let genesis =
            chio_store_sqlite::sign_enterprise_migration_transition(genesis, &transition_signer)
                .unwrap();
        let disabled = match concrete.register(&genesis).unwrap() {
            chio_security_types::EnterpriseMigrationRegisterOutcome::Registered(state) => state,
            outcome => panic!("unexpected migration registration: {outcome:?}"),
        };
        let shadow = promote_key_log_migration_test_state(
            concrete.as_ref(),
            &transition_signer,
            &disabled,
            migration_test_digest(5),
            10,
            200,
        );
        let enforced = promote_key_log_migration_test_state(
            concrete.as_ref(),
            &transition_signer,
            &shadow,
            enforced_posture,
            20,
            300,
        );
        assert!(load_key_log_verification_migration_binding(
            &enforced_config,
            &key_log_policy,
            &key_log_database_path,
        )
        .is_err());
        enforced_config.minimum_heads[0].transition_digest = enforced.transition_digest;
        let binding = load_key_log_verification_migration_binding(
            &enforced_config,
            &key_log_policy,
            &key_log_database_path,
        )
        .unwrap();
        let signing_key = Keypair::from_seed(&[0x42; 32]);
        let inner: Arc<dyn SigningBackend> =
            Arc::new(chio_core::crypto::Ed25519Backend::new(signing_key.clone()));
        let guarded = MigrationGuardedSigningBackend {
            inner: Arc::clone(&inner),
            migration_binding: binding,
        };
        let first = guarded.sign_bytes_with_identity(b"before-head-change").unwrap();
        assert_eq!(first.public_key, signing_key.public_key());

        let mut legacy_removed_config = KeyLogVerificationMigrationConfig {
            stage: EnterpriseMigrationStage::LegacyRemoved,
            minimum_heads: vec![EnterpriseMigrationMinimumHead {
                key: key.clone(),
                minimum_generation: EnterpriseMigrationStage::LegacyRemoved.generation(),
                transition_digest: enforced.transition_digest,
            }],
            ..enforced_config
        };
        let legacy_removed_posture = key_log_verification_migration_posture_digest(
            &legacy_removed_config,
            key_log_configuration_binding,
        )
        .unwrap();
        let legacy_removed = promote_key_log_migration_test_state(
            concrete.as_ref(),
            &transition_signer,
            &enforced,
            legacy_removed_posture,
            30,
            400,
        );
        assert!(guarded.sign_bytes(b"after-head-change").is_err());

        legacy_removed_config.minimum_heads[0].transition_digest =
            legacy_removed.transition_digest;
        let rebound = load_key_log_verification_migration_binding(
            &legacy_removed_config,
            &key_log_policy,
            &key_log_database_path,
        )
        .unwrap();
        assert_eq!(rebound.state(), &legacy_removed);
        let recovered = MigrationGuardedSigningBackend {
            inner,
            migration_binding: rebound,
        };
        let final_signature = recovered.sign_bytes(b"after-runtime-rebuild").unwrap();
        assert!(signing_key
            .public_key()
            .verify(b"after-runtime-rebuild", &final_signature));
    }

    #[test]
    fn keyring_config_selects_durable_signing_and_rejects_missing_roots_or_memory() {
        use chio_core::crypto::Ed25519Backend;
        use chio_keyring::{
            derive_key_id, AuthorityId, BootstrapAuthorization, EventId, EventReason,
            KeyLogAuthorizations, KeyLogEventBody, KeyLogOperation, KeyLogPolicy,
            KeyLogPolicyConfig, LogId, RecoveryPolicyId, SignedKeyLogEvent, SqliteKeyLogStore,
            WitnessId, WitnessRosterId, KEY_LOG_EVENT_SCHEMA,
        };

        let kernel_key = Keypair::generate();
        let bootstrap = Keypair::generate();
        let operator = Keypair::generate();
        let witness = Keypair::generate();
        let artifact_time = Keypair::generate();
        let database_path = unique_receipt_db_path("chio-control-plane-keyring");
        let config_path = database_path.with_extension("yaml");
        let missing_roots_path = database_path.with_extension("missing-roots.yaml");
        let wrong_root_path = database_path.with_extension("wrong-root.yaml");
        let memory_path = database_path.with_extension("memory.yaml");
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.control-plane.keyring").unwrap(),
            authority_id: AuthorityId::new("authority.control-plane.keyring").unwrap(),
            bootstrap_key: bootstrap.public_key(),
            operator_key: operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.control-plane.keyring").unwrap(),
            witness_keys: BTreeMap::from([(
                WitnessId::new("witness.control-plane").unwrap(),
                witness.public_key(),
            )]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.control-plane.keyring").unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100_000,
        })
        .unwrap()
        .with_artifact_time_roots(BTreeMap::from([(
            chio_keyring::AnchorId::new("timestamp.control-plane").unwrap(),
            artifact_time.public_key(),
        )]))
        .unwrap();
        let store = SqliteKeyLogStore::open(&database_path, policy.clone()).unwrap();
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: policy.log_id().clone(),
            sequence: 0,
            event_id: EventId::new("event.control-plane.genesis").unwrap(),
            previous_event_hash: None,
            authority_id: policy.authority_id().clone(),
            key_id: derive_key_id(
                kernel_key.public_key().algorithm(),
                &kernel_key.public_key(),
            )
            .unwrap(),
            algorithm: kernel_key.public_key().algorithm(),
            public_key: kernel_key.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(EventReason::new("configured authority").unwrap()),
            issued_at: 1_000,
        };
        let genesis = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(
                BootstrapAuthorization::sign(&body, &Ed25519Backend::new(bootstrap.clone()))
                    .unwrap(),
            ),
            body,
        };
        store
            .append_event(&genesis, &Ed25519Backend::new(operator.clone()))
            .unwrap();
        let enterprise_receipt = store.load_enterprise_receipts().unwrap().remove(0);
        let forwarded = key_enterprise_receipt_to_chio_receipt(
            &enterprise_receipt,
            &Ed25519Backend::new(operator.clone()),
            policy.configuration_binding().unwrap(),
        )
        .unwrap();
        assert!(forwarded.verify_signature().unwrap());
        assert_eq!(
            forwarded.receipt_kind,
            chio_core::receipt::kinds::ReceiptKind::TraceObservation
        );
        assert_eq!(
            forwarded.metadata.as_ref().unwrap()["keyEnterpriseReceipt"]["body"]["receipt_id"],
            enterprise_receipt.body.receipt_id
        );
        drop(store);

        let config_json = serde_json::json!({
            "schema": "chio.keyring.runtime-config.v1",
            "database_path": database_path.to_string_lossy(),
            "log_id": "log.control-plane.keyring",
            "authority_id": "authority.control-plane.keyring",
            "bootstrap_public_key": bootstrap.public_key().to_hex(),
            "operator_public_key": operator.public_key().to_hex(),
            "witness_roster_id": "roster.control-plane.keyring",
            "witness_public_keys": {
                "witness.control-plane": witness.public_key().to_hex(),
            },
            "recovery_policy_id": "recovery.control-plane.keyring",
            "recovery_public_keys": {},
            "recovery_threshold": 0,
            "artifact_time_public_keys": {
                "timestamp.control-plane": artifact_time.public_key().to_hex(),
            },
            "max_checkpoint_future_skew_seconds": 100,
        });
        fs::write(&config_path, serde_json::to_vec(&config_json).unwrap()).unwrap();
        assert!(load_keyring_runtime_composition(&kernel_key, &config_path).is_err());

        let mut missing_roots = config_json.clone();
        missing_roots["artifact_time_public_keys"] = serde_json::json!({});
        fs::write(
            &missing_roots_path,
            serde_json::to_vec(&missing_roots).unwrap(),
        )
        .unwrap();
        assert!(build_kernel_with_keyring_config(
            test_loaded_policy(),
            &kernel_key,
            &missing_roots_path,
        )
        .is_err());

        let mut wrong_root = config_json.clone();
        wrong_root["bootstrap_public_key"] =
            serde_json::json!(Keypair::generate().public_key().to_hex());
        fs::write(&wrong_root_path, serde_json::to_vec(&wrong_root).unwrap()).unwrap();
        assert!(build_kernel_with_keyring_config(
            test_loaded_policy(),
            &kernel_key,
            &wrong_root_path,
        )
        .is_err());

        let mut memory = config_json;
        memory["database_path"] = serde_json::json!(":memory:");
        fs::write(&memory_path, serde_json::to_vec(&memory).unwrap()).unwrap();
        assert!(
            build_kernel_with_keyring_config(test_loaded_policy(), &kernel_key, &memory_path,)
                .is_err()
        );

        let _ = fs::remove_file(format!("{}-wal", database_path.display()));
        let _ = fs::remove_file(format!("{}-shm", database_path.display()));
        for path in [
            database_path,
            config_path,
            missing_roots_path,
            wrong_root_path,
            memory_path,
        ] {
            let _ = fs::remove_file(path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_seed_loader_rejects_symlinks_hardlinks_and_unsafe_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let keypair = Keypair::generate();
        let seed_path = directory.path().join("authority.seed");
        write_authority_seed_file(&seed_path, &keypair).unwrap();

        let symlink_path = directory.path().join("authority-link.seed");
        symlink(&seed_path, &symlink_path).unwrap();
        assert!(load_existing_authority_keypair(&symlink_path).is_err());

        let hardlink_path = directory.path().join("authority-hardlink.seed");
        fs::hard_link(&seed_path, &hardlink_path).unwrap();
        assert!(load_existing_authority_keypair(&seed_path).is_err());
        assert!(load_existing_authority_keypair(&hardlink_path).is_err());
        fs::remove_file(&hardlink_path).unwrap();

        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_existing_authority_keypair(&seed_path).is_err());
    }

    #[test]
    fn authority_seed_replacement_requires_the_original_file_identity() {
        let directory = tempfile::tempdir().unwrap();
        let seed_path = directory.path().join("authority.seed");
        let original = Keypair::generate();
        let replacement = Keypair::generate();
        let attempted = Keypair::generate();
        write_authority_seed_file(&seed_path, &original).unwrap();
        let original_identity = private_file_identity(&seed_path).unwrap();

        fs::remove_file(&seed_path).unwrap();
        write_authority_seed_file(&seed_path, &replacement).unwrap();
        assert!(
            write_authority_seed_file_bound(&seed_path, &attempted, Some(&original_identity),)
                .is_err()
        );
        assert_eq!(
            load_existing_authority_keypair(&seed_path)
                .unwrap()
                .public_key(),
            replacement.public_key()
        );
    }

    #[test]
    fn pending_authority_seed_is_key_and_epoch_bound_and_cleanup_detects_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let pending_path = directory.path().join("authority.seed.chio-keyring-pending");
        let next = Keypair::generate();
        let handoff = AuthoritySeedHandoff::new(&next, 7, 8).unwrap();
        assert_eq!(
            classify_quiescent_authority_seed_handoff(&handoff, 7, "active-key").unwrap(),
            QuiescentAuthoritySeedHandoff::Resumable { target_epoch: 8 }
        );
        assert_eq!(
            classify_quiescent_authority_seed_handoff(&handoff, 8, &handoff.key_id).unwrap(),
            QuiescentAuthoritySeedHandoff::Completed
        );
        assert!(classify_quiescent_authority_seed_handoff(&handoff, 6, "active-key").is_err());
        let identity = persist_authority_seed_handoff(&pending_path, &handoff).unwrap();
        let (loaded, loaded_keypair, loaded_identity) =
            load_authority_seed_handoff(&pending_path).unwrap();
        assert_eq!(loaded, handoff);
        assert_eq!(loaded_keypair.public_key(), next.public_key());
        assert_eq!(loaded_identity, identity);
        assert!(persist_authority_seed_handoff(&pending_path, &handoff).is_err());

        let replacement = AuthoritySeedHandoff::new(&Keypair::generate(), 7, 8).unwrap();
        let replacement_bytes = chio_core::canonical::canonical_json_bytes(&replacement).unwrap();
        atomic_write_private_file(&pending_path, &replacement_bytes, Some(&identity)).unwrap();
        assert!(remove_authority_seed_handoff(&pending_path, &handoff, &identity).is_err());
        assert!(pending_path.exists());

        let (replacement, _, replacement_identity) =
            load_authority_seed_handoff(&pending_path).unwrap();
        remove_authority_seed_handoff(&pending_path, &replacement, &replacement_identity).unwrap();
        assert!(!pending_path.exists());
    }

    fn test_loaded_policy() -> policy::LoadedPolicy {
        policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: PostInvocationPipeline::new(),
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval_resolver: None,
            threshold_approval_policy_authority: None,
            active_defense: policy::ActiveDefensePolicyConfig::default(),
            active_defense_rules: Vec::new(),
        }
    }

    #[test]
    fn build_kernel_registers_default_guard_profile() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: PostInvocationPipeline::new(),
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval_resolver: None,
            threshold_approval_policy_authority: None,
            active_defense: policy::ActiveDefensePolicyConfig::default(),
            active_defense_rules: Vec::new(),
        };

        let kernel = build_kernel(loaded_policy, &keypair).expect("build disabled kernel");

        assert!(kernel.guard_count() >= 2);
        assert!(kernel.post_invocation_hook_count() >= 1);
    }

    #[test]
    fn build_kernel_rejects_enabled_security_without_runtime_authorities() {
        let keypair = Keypair::generate();
        for mode in [
            crate::security::ActiveDefenseMode::Shadow,
            crate::security::ActiveDefenseMode::Enforce,
        ] {
            let mut loaded_policy = test_loaded_policy();
            loaded_policy.active_defense.mode = mode;
            assert!(build_kernel(loaded_policy, &keypair).is_err());
        }
    }

    #[test]
    fn build_kernel_installs_configured_threshold_resolver_and_proposal_authority() {
        use chio_core::capability::threshold_approval::{
            ThresholdApprovalRequest, ThresholdApprovalRequirementResolver,
        };

        let policy_path = unique_receipt_db_path("chio-threshold-composition");
        let directory_path = unique_receipt_db_path("chio-threshold-approver-directory");
        let approver = Keypair::generate();
        let proposal_authority = Keypair::generate();
        std::fs::write(
            &policy_path,
            format!(
                "hushspec: \"0.1.0\"\nextensions:\n  chio:\n    human_in_loop:\n      approvers:\n        n: 1\n        of:\n          - \"{}\"\n",
                approver.public_key().to_hex()
            ),
        )
        .expect("write threshold policy");
        std::fs::write(
            &directory_path,
            format!(
                "version: 7\napprover_ids:\n  - \"{}\"\n",
                approver.public_key().to_hex()
            ),
        )
        .expect("write authenticated approver directory");
        let loaded = policy::load_policy_for_runtime(
            &policy_path,
            Some(&directory_path),
            Some(&proposal_authority.public_key()),
        )
        .expect("load threshold policy with explicit authorities");
        let runtime_hash = loaded.identity.runtime_hash.clone();
        let request = ThresholdApprovalRequest::new("request-1", "server-1", "tool-1")
            .expect("threshold request");
        let requirement = loaded
            .threshold_approval_resolver
            .as_ref()
            .expect("compiled resolver")
            .resolve_threshold_approval_requirement(&request, &runtime_hash)
            .expect("threshold requirement");

        let kernel_keypair = Keypair::generate();
        let kernel = build_kernel(loaded, &kernel_keypair).expect("build threshold kernel");
        assert_eq!(
            kernel.threshold_approval_policy_authorities(),
            std::slice::from_ref(&proposal_authority.public_key())
        );
        assert_ne!(proposal_authority.public_key(), kernel_keypair.public_key());

        let subject = Keypair::generate();
        let intent_hash = "11".repeat(32);
        let capability_hash = "22".repeat(32);
        let proposal_body =
            chio_core::capability::threshold_approval::ThresholdApprovalProposalBody::new(
                "proposal-1",
                "request-1",
                intent_hash.clone(),
                subject.public_key(),
                capability_hash.clone(),
                runtime_hash.clone(),
                requirement.required(),
                requirement.eligible_set_digest(),
                1_000,
                requirement.proposal_timeout_seconds(),
                1_900,
                1_900,
            )
            .expect("proposal body");
        let proposal = chio_core::capability::threshold_approval::ThresholdApprovalProposal::sign(
            proposal_body,
            &proposal_authority,
        )
        .expect("signed proposal");
        let approval = chio_core::capability::governance::GovernedApprovalToken::sign(
            chio_core::capability::governance::GovernedApprovalTokenBody {
                id: "approval-1".to_string(),
                approver: approver.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: intent_hash.clone(),
                threshold_proposal_hash: Some(proposal.proposal_hash().expect("proposal hash")),
                request_id: "request-1".to_string(),
                issued_at: 1_100,
                expires_at: 1_800,
                decision: chio_core::capability::governance::GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .expect("signed approval");
        let verified = chio_kernel::threshold_approval::verify_threshold_approval_set(
            &chio_kernel::threshold_approval::ThresholdApprovalVerificationInput {
                request_id: "request-1",
                server_id: "server-1",
                tool_name: "tool-1",
                governed_intent_hash: &intent_hash,
                subject: &subject.public_key(),
                authorization_capability_hash: &capability_hash,
                authorizing_capability_expires_at: 1_900,
                governed_operation_expires_at: 1_900,
                policy_hash: &runtime_hash,
                proposal: &proposal,
                approval_tokens: std::slice::from_ref(&approval),
                trusted_policy_authorities: kernel.threshold_approval_policy_authorities(),
                allowed_token_algorithms: &[chio_core::crypto::SigningAlgorithm::Ed25519],
                now: 1_200,
            },
            kernel
                .threshold_approval_requirement_resolver()
                .expect("installed resolver"),
        )
        .expect("verified approval set");
        assert_eq!(verified.required(), 1);

        let _ = std::fs::remove_file(policy_path);
        let _ = std::fs::remove_file(directory_path);
    }

    #[test]
    fn ordinary_admission_composition_rejects_local_remote_authority_mixing() {
        let operation_path = unique_receipt_db_path("chio-ordinary-operation-mixed-authority");
        let budget_path = unique_receipt_db_path("chio-ordinary-budget-mixed-authority");
        let kernel = make_kernel(false);

        let error = match compose_ordinary_admission_runtime(
            kernel,
            OrdinaryAdmissionRuntimeConfig {
                enable_aggregate_invocation_admission: true,
                admission_operation_db_path: Some(&operation_path),
                approval_db_path: None,
                budget_db_path: Some(&budget_path),
                control_url: Some("https://control.example.test"),
                control_token: Some("control-token"),
            },
        ) {
            Ok(_) => panic!("aggregate admission must not mix local and remote authorities"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("aggregate admission requires one local durable authority composition"));
        assert!(!operation_path.exists());
        assert!(!budget_path.exists());
    }

    #[test]
    fn threshold_admission_composition_rejects_local_remote_authority_mixing() {
        let operation_path = unique_receipt_db_path("chio-threshold-operation-mixed-authority");
        let approval_path = unique_receipt_db_path("chio-threshold-approval-mixed-authority");
        let budget_path = unique_receipt_db_path("chio-threshold-budget-mixed-authority");
        let mut kernel = make_kernel(false);
        let requirement = chio_kernel::threshold_approval::ThresholdApprovalRequirement::new(
            1,
            BTreeMap::from([("approver".to_string(), Keypair::generate().public_key())]),
            900,
            "11".repeat(32),
            1,
        )
        .expect("threshold requirement");
        kernel
            .set_threshold_approval_requirement_resolver(Arc::new(
                move |_: &chio_kernel::threshold_approval::ThresholdApprovalRequest, _: &str| {
                    Ok(requirement.clone())
                },
            ))
            .expect("threshold resolver");
        kernel
            .set_threshold_approval_policy_authority(Keypair::generate().public_key())
            .expect("threshold proposal authority");

        let error = match compose_ordinary_admission_runtime(
            kernel,
            OrdinaryAdmissionRuntimeConfig {
                enable_aggregate_invocation_admission: false,
                admission_operation_db_path: Some(&operation_path),
                approval_db_path: Some(&approval_path),
                budget_db_path: Some(&budget_path),
                control_url: Some("https://control.example.test"),
                control_token: Some("control-token"),
            },
        ) {
            Ok(_) => panic!("threshold admission must not mix local and remote authorities"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("threshold approvals require one local durable authority composition"));
        assert!(!operation_path.exists());
        assert!(!approval_path.exists());
        assert!(!budget_path.exists());
    }
}
