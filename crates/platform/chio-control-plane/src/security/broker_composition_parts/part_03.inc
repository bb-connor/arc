#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core::capability::scope::{ChioScope, ToolGrant};
    use chio_secret_broker::ipc_client::BrokerPeerIdentity;
    use chio_secret_broker::protocol::{
        AttemptConsumption, BrokerDestination, CredentialRef, ProofBinding, ProofMode,
        RedirectPolicy, RequestConstraints, BROKER_CAPABILITY_SCHEMA,
    };
    use chio_secret_broker::provision::{AdminClock, GovernedAdminAuthorizationEnvelope};
    use chio_secret_broker::revocation::LiveParentCapability;
    use chio_security_types::{
        EnterpriseMigrationTransitionBody, InformationLabel, ResponseEffectKind,
    };
    use chio_store_sqlite::sign_enterprise_migration_transition;

    use super::*;

    trait TestRequire<T> {
        fn require(self, context: &str) -> T;
    }

    impl<T, E: std::fmt::Debug> TestRequire<T> for Result<T, E> {
        fn require(self, context: &str) -> T {
            self.unwrap_or_else(|error| panic!("{context}: {error:?}"))
        }
    }

    fn test_migration_enforcer() -> Arc<dyn BrokerMigrationEnforcer> {
        TestBrokerMigrationEnforcer::new(["generic-https".to_string()])
    }

    impl<T> TestRequire<T> for Option<T> {
        fn require(self, context: &str) -> T {
            self.unwrap_or_else(|| panic!("{context}"))
        }
    }

    trait TestRequireError<E> {
        fn require_error(self, context: &str) -> E;
    }

    impl<T, E> TestRequireError<E> for Result<T, E> {
        fn require_error(self, context: &str) -> E {
            match self {
                Ok(_) => panic!("{context}: expected an error"),
                Err(error) => error,
            }
        }
    }

    fn raw_descriptor_is_closed(raw_fd: i32) -> bool {
        // SAFETY: F_GETFD accepts an integer descriptor and reports EBADF when
        // the number does not designate an open descriptor.
        let result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    const INDEPENDENT_LIFECYCLE_OWNER_PATH_ENV: &str =
        "CHIO_INDEPENDENT_SECURITY_LIFECYCLE_OWNER_PATH";
    const INDEPENDENT_LIFECYCLE_OWNER_CHILD_TEST: &str =
        "security::broker_composition::tests::independent_security_state_lifecycle_owner_child_is_denied";

    #[test]
    fn independent_security_state_lifecycle_owner_child_is_denied() {
        let Some(path) = std::env::var_os(INDEPENDENT_LIFECYCLE_OWNER_PATH_ENV) else {
            return;
        };

        let error = RetainedSecurityStateLifecycleLease::acquire(Path::new(&path))
            .require_error("independently opened process must not acquire a live owner lease");
        assert!(matches!(error, BrokerIntegrationError::Conflict(_)));
    }

    #[test]
    fn security_state_lifecycle_lease_denies_an_independently_opened_live_owner() {
        let directory = tempfile::tempdir().require("security lifecycle lease directory");
        let database_path = directory.path().join("security-state.sqlite3");
        let lease = RetainedSecurityStateLifecycleLease::acquire(&database_path)
            .require("acquire parent security lifecycle lease");
        let status = Command::new(std::env::current_exe().require("current test executable"))
            .arg("--exact")
            .arg(INDEPENDENT_LIFECYCLE_OWNER_CHILD_TEST)
            .arg("--nocapture")
            .env(INDEPENDENT_LIFECYCLE_OWNER_PATH_ENV, &database_path)
            .status()
            .require("run independent security lifecycle owner child");

        assert!(status.success());
        lease
            .ensure_owned()
            .require("parent retains security lifecycle ownership");
    }

    #[test]
    fn security_state_lifecycle_lease_denies_a_fork_inherited_authority() {
        let directory = tempfile::tempdir().require("fork lifecycle lease directory");
        let database_path = directory.path().join("security-state.sqlite3");
        let lease = Arc::new(
            RetainedSecurityStateLifecycleLease::acquire(&database_path)
                .require("acquire pre-fork security lifecycle lease"),
        );
        let inherited = Arc::clone(&lease);
        let mut command = Command::new("/usr/bin/true");
        // SAFETY: the expected child path calls only getpid through rustix and
        // compares the result before exec. It performs no allocation, locking,
        // descriptor mutation, or explicit unlock after fork.
        unsafe {
            command.pre_exec(move || {
                if inherited.acquired_by_current_process() {
                    Err(std::io::Error::from_raw_os_error(1))
                } else {
                    Ok(())
                }
            });
        }
        let status = command
            .status()
            .require("run fork-inherited security lifecycle authority child");

        assert!(status.success());
        let duplicate = RetainedSecurityStateLifecycleLease::acquire(&database_path)
            .require_error("forked child must not unlock the parent's lifecycle descriptor");
        assert!(matches!(duplicate, BrokerIntegrationError::Conflict(_)));
        lease
            .ensure_owned()
            .require("parent retains security lifecycle ownership after child exec");
    }

    #[test]
    fn broker_signer_binding_rejects_distinct_custody_with_the_same_public_key() {
        let active: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[170_u8; 32])));
        let same_key_distinct_custody: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[170_u8; 32])));

        assert_eq!(active.public_key(), same_key_distinct_custody.public_key());
        assert!(!Arc::ptr_eq(&active, &same_key_distinct_custody));
        assert!(exact_active_defense_signer_matches(Some(&active), &active));
        assert!(!exact_active_defense_signer_matches(
            Some(&active),
            &same_key_distinct_custody
        ));
    }

    #[test]
    fn dedicated_active_defense_executor_custody_is_retained_across_a_clean_restart() {
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[171_u8; 32])));
        let same_key_distinct_custody: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[171_u8; 32])));
        let mut canonical = None;

        let first_start = retain_exact_active_defense_signer(&mut canonical, &signer)
            .unwrap_or_else(|error| panic!("retain first signer: {error}"));
        assert!(Arc::ptr_eq(&first_start, &signer));
        drop(first_start);

        let restarted = retain_exact_active_defense_signer(&mut canonical, &signer)
            .unwrap_or_else(|error| panic!("retain restart signer: {error}"));
        assert!(Arc::ptr_eq(&restarted, &signer));
        assert!(
            retain_exact_active_defense_signer(&mut canonical, &same_key_distinct_custody).is_err()
        );
        assert!(exact_active_defense_signer_matches(
            canonical.as_ref(),
            &signer
        ));
        ensure_active_defense_executor_signer_matches_configured_key(
            &signer,
            &signer.public_key(),
        )
        .require("executor signer matches configured custody key");
        assert!(ensure_active_defense_executor_signer_matches_configured_key(
            &signer,
            &Keypair::from_seed(&[172_u8; 32]).public_key(),
        )
        .is_err());
    }

    struct FixedAdminClock(u64);

    impl AdminClock for FixedAdminClock {
        fn now_unix_seconds(&self) -> BrokerResult<u64> {
            Ok(self.0)
        }
    }

    struct FixedControlClock(u64);

    impl BrokerControlClock for FixedControlClock {
        fn now_unix_seconds(&self) -> BrokerResult<u64> {
            Ok(self.0)
        }
    }

    struct FixedParentLiveness {
        parent_capability_id: String,
        subject: PublicKey,
        audience: String,
        expires_at_unix_seconds: u64,
    }

    impl CapabilityLiveness for FixedParentLiveness {
        fn verify_live_parent(
            &self,
            request: &CapabilityLivenessRequest,
        ) -> BrokerResult<LiveParentCapability> {
            if request.parent_capability_id != self.parent_capability_id
                || request.expected_subject != self.subject
                || request.expected_audience != self.audience
                || request.now_unix_seconds >= self.expires_at_unix_seconds
            {
                return Err(BrokerError::AuthorizationDenied(
                    "fixed parent liveness binding failed".to_string(),
                ));
            }
            Ok(LiveParentCapability {
                capability_id: self.parent_capability_id.clone(),
                subject: self.subject.clone(),
                audience: self.audience.clone(),
                delegation_ancestor_ids: Vec::new(),
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                verified_at_unix_seconds: request.now_unix_seconds,
                authority_snapshot_digest: "aa".repeat(32),
            })
        }
    }

    fn admin_policy(approver: &Keypair, subject: &PublicKey) -> GovernedAdminPolicy {
        GovernedAdminPolicy {
            trusted_approvers: vec![approver.public_key()],
            subject: subject.clone(),
            threshold: 1,
            maximum_token_lifetime_seconds: 60,
        }
    }

    fn production_keys() -> ProductionBrokerKeys {
        ProductionBrokerKeys {
            authority_signer: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[141; 32]))),
            capability_issuer_signer: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[142; 32]))),
            release_receipt_signer: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[143; 32]))),
        }
    }

    fn active_response_authority_test_kernel() -> ChioKernel {
        ChioKernel::new(chio_kernel::KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 4,
            policy_hash: "active-response-authority-test".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: 64,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        })
    }

    #[test]
    fn production_response_authority_is_installed_once_before_publication_and_validated_at_bind() {
        let expected = Keypair::from_seed(&[172_u8; 32]).public_key();
        let wrong = Keypair::from_seed(&[173_u8; 32]).public_key();

        let mut missing = active_response_authority_test_kernel();
        assert!(ensure_active_response_submission_authority_is_pinned(&missing, &expected).is_err());
        missing
            .set_active_response_submission_authority(wrong.clone())
            .require("install wrong preexisting response authority");
        assert!(install_active_response_submission_authority_before_publication(
            &mut missing,
            &expected,
        )
        .is_err());

        let mut exact = active_response_authority_test_kernel();
        install_active_response_submission_authority_before_publication(&mut exact, &expected)
            .require("install exact response authority before publication");
        install_active_response_submission_authority_before_publication(&mut exact, &expected)
            .require("repeat exact response authority installation");
        ensure_active_response_submission_authority_is_pinned(&exact, &expected)
            .require("validate exact response authority at bind");
        assert!(ensure_active_response_submission_authority_is_pinned(&exact, &wrong).is_err());
    }

    #[test]
    fn configured_active_defense_signer_cannot_alias_any_retained_security_role() {
        let response_authority = Keypair::from_seed(&[174_u8; 32]).public_key();
        let admin_approver = Keypair::from_seed(&[175_u8; 32]).public_key();
        let manifest_signer = Keypair::from_seed(&[176_u8; 32]).public_key();
        let disallowed = [
            response_authority.clone(),
            admin_approver.clone(),
            manifest_signer.clone(),
        ]
        .into_iter()
        .map(|key| key.to_hex())
        .collect::<BTreeSet<_>>();

        for aliased in [&response_authority, &admin_approver, &manifest_signer] {
            assert!(ensure_active_defense_signer_role_separation(aliased, &disallowed).is_err());
        }
        let independent = Keypair::from_seed(&[177_u8; 32]).public_key();
        ensure_active_defense_signer_role_separation(&independent, &disallowed)
            .require("independent active-defense signer");
    }

    #[test]
    fn production_database_identity_rejects_hard_link_aliases() {
        let directory = tempfile::tempdir().require("database directory");
        let primary = directory.path().join("primary.sqlite3");
        let alias = directory.path().join("alias.sqlite3");
        File::create(&primary).require("create primary database");
        fs::hard_link(&primary, &alias).require("create database hard link");

        let error = validate_distinct_database_files(&[
            (&primary, "primary database"),
            (&alias, "alias database"),
        ])
        .require_error("hard-linked production databases must fail closed");
        assert!(error.to_string().contains("singly linked regular file"));
    }

    #[test]
    fn production_host_path_binding_rejects_direct_commit_domain_mismatch() {
        let directory = tempfile::tempdir().require("database directory");
        let authoritative = directory.path().join("authoritative.sqlite3");
        let foreign = directory.path().join("foreign.sqlite3");
        prepare_private_database(&authoritative, "normal receipt database")
            .require("create authoritative database");
        prepare_private_database(&foreign, "foreign receipt database")
            .require("create foreign database");
        let authoritative_identity =
            RetainedDatabaseFileIdentity::open(&authoritative, "normal receipt database")
                .require("retain authoritative database identity");

        let error = require_matching_runtime_path(
            Some(&foreign),
            &authoritative,
            &authoritative_identity,
            "normal receipt database",
        )
        .require_error("foreign host commit domain must fail closed");
        assert!(error
            .to_string()
            .contains("conflicts with the broker product commit domain"));
    }

    #[test]
    fn production_host_path_binding_rejects_hard_link_alias_substitution() {
        let directory = tempfile::tempdir().require("database directory");
        let authoritative = directory.path().join("authoritative.sqlite3");
        let alias = directory.path().join("alias.sqlite3");
        prepare_private_database(&authoritative, "normal receipt database")
            .require("create authoritative database");
        let authoritative_identity =
            RetainedDatabaseFileIdentity::open(&authoritative, "normal receipt database")
                .require("retain authoritative database identity");
        fs::hard_link(&authoritative, &alias).require("create hard-link alias");

        let error = require_matching_runtime_path(
            Some(&alias),
            &authoritative,
            &authoritative_identity,
            "normal receipt database",
        )
        .require_error("hard-link host alias must not replace the configured path identity");
        assert!(error.to_string().contains("singly linked regular file"));
    }

    #[test]
    fn production_host_path_binding_rejects_same_name_inode_replacement() {
        let directory = tempfile::tempdir().require("database directory");
        let authoritative = directory.path().join("authoritative.sqlite3");
        let displaced = directory.path().join("authoritative-original.sqlite3");
        prepare_private_database(&authoritative, "normal receipt database")
            .require("create authoritative database");
        let authoritative_identity =
            RetainedDatabaseFileIdentity::open(&authoritative, "normal receipt database")
                .require("retain authoritative database identity");
        fs::rename(&authoritative, &displaced).require("displace authoritative database name");
        prepare_private_database(&authoritative, "replacement receipt database")
            .require("create same-name replacement database");

        let error = require_matching_runtime_path(
            Some(&authoritative),
            &authoritative,
            &authoritative_identity,
            "normal receipt database",
        )
        .require_error("same-name replacement must fail descriptor binding");
        assert!(error
            .to_string()
            .contains("descriptor identity changed after it was retained"));
    }

    fn production_migration_config(directory: &Path) -> ProductionBrokerMigrationConfig {
        let trusted_directory = directory
            .canonicalize()
            .require("canonicalize migration fixture directory");
        let state_database_path = trusted_directory.join("enterprise-migration.sqlite3");
        let signer = Keypair::from_seed(&[159; 32]);
        let store = SqliteEnterpriseMigrationStateStore::open(
            &state_database_path,
            SqliteEnterpriseMigrationOpenPolicy::new(
                vec![signer.public_key()],
                Vec::new(),
            )
            .require("construct migration fixture open policy"),
        )
        .require("open migration fixture ledger");
        let deployment_id = RecordId::new("broker-production")
            .require("construct migration fixture deployment id");
        let credential_provider = RecordId::new("generic-https")
            .require("construct migration fixture credential provider");
        let mut minimum_heads = Vec::new();
        for (control, digest_seed) in [
            (
                EnterpriseMigrationControl::BrokerCredentialCustody,
                0x41_u8,
            ),
            (
                EnterpriseMigrationControl::BrokerQuotaEnforcement,
                0x51_u8,
            ),
        ] {
            let key = EnterpriseMigrationKey {
                deployment_id: deployment_id.clone(),
                scope_kind: EnterpriseMigrationScopeKind::Provider,
                scope_id: credential_provider.clone(),
                control,
            };
            let mut state = store
                .load(&key)
                .require("load migration fixture state");
            if state.is_none() {
                let body = EnterpriseMigrationTransitionBody::genesis(
                    key.clone(),
                    production_broker_migration_posture_digest(
                        &deployment_id,
                        &credential_provider,
                        control,
                        EnterpriseMigrationStage::Disabled,
                    )
                    .require("digest migration fixture genesis posture"),
                    Digest32::new([digest_seed; 32]),
                    Digest32::new([digest_seed.saturating_add(1); 32]),
                    Digest32::new([digest_seed.saturating_add(2); 32]),
                    1,
                    signer.public_key().to_hex(),
                )
                .require("construct migration fixture genesis");
                let transition = sign_enterprise_migration_transition(body, &signer)
                    .require("sign migration fixture genesis");
                let _ = store
                    .register(&transition)
                    .require("register migration fixture genesis");
                state = store
                    .load(&key)
                    .require("load registered migration fixture genesis");
            }
            let mut state = state.require("migration fixture state exists");
            while state.stage < EnterpriseMigrationStage::Enforced {
                let next_stage = state
                    .stage
                    .next()
                    .require("migration fixture has a next stage");
                let generation = next_stage.generation();
                let body = EnterpriseMigrationTransitionBody::promotion(
                    &state,
                    production_broker_migration_posture_digest(
                        &deployment_id,
                        &credential_provider,
                        control,
                        next_stage,
                    )
                    .require("digest migration fixture promotion posture"),
                    Digest32::new([digest_seed.saturating_add(generation as u8 * 3); 32]),
                    Digest32::new([
                        digest_seed.saturating_add(generation as u8 * 3 + 1);
                        32
                    ]),
                    Digest32::new([
                        digest_seed.saturating_add(generation as u8 * 3 + 2);
                        32
                    ]),
                    generation + 1,
                    signer.public_key().to_hex(),
                )
                .require("construct migration fixture promotion");
                let transition = sign_enterprise_migration_transition(body, &signer)
                    .require("sign migration fixture promotion");
                let _ = store
                    .compare_and_promote(&transition)
                    .require("promote migration fixture state");
                state = store
                    .load(&key)
                    .require("load promoted migration fixture state")
                    .require("promoted migration fixture state exists");
            }
            minimum_heads.push(state.minimum_head());
        }
        minimum_heads.sort_unstable();
        fs::set_permissions(
            &state_database_path,
            fs::Permissions::from_mode(0o600),
        )
        .require("harden migration fixture ledger permissions");
        ProductionBrokerMigrationConfig {
            state_database_path,
            deployment_id,
            trusted_transition_signers: vec![signer.public_key()],
            minimum_heads,
            providers: vec![ProductionBrokerProviderMigrationPosture {
                credential_provider,
                credential_custody_stage: EnterpriseMigrationStage::Enforced,
                quota_enforcement_stage: EnterpriseMigrationStage::Enforced,
            }],
        }
    }

    fn production_config(
        directory: &Path,
        keys: &ProductionBrokerKeys,
    ) -> ProductionBrokerCompositionConfig {
        let migration = production_migration_config(directory);
        let native_receipt_database_path = directory.join("native-receipts.sqlite3");
        drop(
            SqliteReceiptStore::open(&native_receipt_database_path)
                .require("create native receipt store"),
        );
        fs::set_permissions(
            &native_receipt_database_path,
            fs::Permissions::from_mode(0o600),
        )
        .require("harden native receipt store permissions");
        let approver = Keypair::from_seed(&[144; 32]);
        let broker_identity = Keypair::from_seed(&[145; 32]).public_key();
        ProductionBrokerCompositionConfig {
            authority_socket_path: directory.join("authority.sock"),
            authority_maximum_clock_skew_seconds: 10,
            broker_client: BrokerIpcClientConfig {
                socket_path: directory.join("broker.sock"),
                tenant_scope: "tenant-production".to_string(),
                timeout_ms: 100,
                expected_peer: BrokerPeerIdentity {
                    process_id: std::process::id(),
                    user_id: 0,
                    group_id: 0,
                },
                trusted_receipt_signer: broker_identity.clone(),
            },
            response_authority_socket_path: directory.join("active-response-authority.sock"),
            response_authority_expected_peer: BrokerPeerIdentity {
                process_id: std::process::id().saturating_add(1),
                user_id: 0,
                group_id: 0,
            },
            authority_public_key: keys.authority_signer.public_key(),
            trusted_broker: broker_identity,
            trusted_capability_issuer: keys.capability_issuer_signer.public_key(),
            trusted_release_receipt_signer: keys.release_receipt_signer.public_key(),
            trusted_response_authority: Keypair::from_seed(&[150; 32]).public_key(),
            broker_server_id: "secret-broker".to_string(),
            broker_tool_name: "execute".to_string(),
            selected_provider_adapter_ids: BTreeSet::from(["generic-bearer".to_string()]),
            broker_audience: "broker-service-production".to_string(),
            parent_audience: "kernel-production".to_string(),
            supplemental_verifier_id: "broker-capability-verifier-v1".to_string(),
            revocation_authority_domain: "combined-sqlite-production".to_string(),
            maximum_pending_admissions: 16,
            enterprise_migration_state_database_path: migration.state_database_path,
            execution_authority_database_path: directory.join("execution.sqlite3"),
            kernel_admission_operation_database_path: directory.join("kernel-operations.sqlite3"),
            governed_admin_database_path: directory.join("admin.sqlite3"),
            broker_receipt_database_path: directory.join("broker-receipts.sqlite3"),
            issuance_database_path: directory.join("issuance.sqlite3"),
            native_receipt_database_path,
            receipt_tenant_id: "tenant-production".to_string(),
            admin_policy: admin_policy(&approver, &Keypair::from_seed(&[147; 32]).public_key()),
        }
    }

    fn product_file_config(
        directory: &Path,
        keys: &ProductionBrokerKeys,
    ) -> ProductionBrokerProductConfig {
        let composition = production_config(directory, keys);
        let enterprise_migration = production_migration_config(directory);
        ProductionBrokerProductConfig {
            schema: PRODUCTION_BROKER_PRODUCT_CONFIG_SCHEMA.to_string(),
            authority_socket_path: composition.authority_socket_path,
            authority_maximum_clock_skew_seconds: composition.authority_maximum_clock_skew_seconds,
            broker_client: ProductionBrokerClientFileConfig {
                socket_path: composition.broker_client.socket_path,
                tenant_scope: composition.broker_client.tenant_scope,
                timeout_ms: composition.broker_client.timeout_ms,
                expected_peer: composition.broker_client.expected_peer,
                trusted_receipt_signer: composition.broker_client.trusted_receipt_signer,
            },
            authority_public_key: composition.authority_public_key,
            trusted_broker: composition.trusted_broker,
            trusted_capability_issuer: composition.trusted_capability_issuer,
            trusted_release_receipt_signer: composition.trusted_release_receipt_signer,
            active_defense_executor_public_key: Keypair::from_seed(&[151; 32]).public_key(),
            broker_server_id: composition.broker_server_id,
            broker_tool_name: composition.broker_tool_name,
            selected_provider_adapter_ids: composition.selected_provider_adapter_ids,
            broker_audience: composition.broker_audience,
            parent_audience: composition.parent_audience,
            supplemental_verifier_id: composition.supplemental_verifier_id,
            revocation_authority_domain: composition.revocation_authority_domain,
            maximum_pending_admissions: composition.maximum_pending_admissions,
            execution_authority_database_path: composition.execution_authority_database_path,
            kernel_admission_operation_database_path: composition
                .kernel_admission_operation_database_path,
            governed_admin_database_path: composition.governed_admin_database_path,
            broker_receipt_database_path: composition.broker_receipt_database_path,
            issuance_database_path: composition.issuance_database_path,
            native_receipt_database_path: composition.native_receipt_database_path,
            enterprise_migration,
            active_defense: ProductionBrokerActiveDefenseFileConfig {
                response_authority: ProductionActiveResponseAuthorityFileConfig {
                    socket_path: composition.response_authority_socket_path,
                    expected_peer: composition.response_authority_expected_peer,
                    trusted_authority: composition.trusted_response_authority,
                    timeout_ms: 1_000,
                    maximum_clock_skew_seconds: 5,
                },
                correlation_bounded_lateness_ms: 1_000,
                correlation_max_scan_events: 128,
                correlation_cas_retries: 2,
                correlation_allow_verified_receipts: false,
                scheduler_lease_owner_id: "broker-production-response-worker".to_string(),
                scheduler_lease_duration_ms: 30_000,
                scheduler_base_backoff_ms: 10,
                scheduler_max_backoff_ms: 100,
                scheduler_operator_page_threshold_ms: 1_000,
                scheduler_max_claims: 8,
                scheduler_renewal_margin_ms: 1_000,
                worker_tick_interval_ms: 100,
                recovery_max_records_per_pass: 128,
                recovery_max_startup_records: 4_096,
                recovery_max_startup_wall_clock_ms: 30_000,
            },
            security_runtime: ProductionSecurityRuntimeFileConfig {
                security_state_database_path: directory.join("security-state.sqlite3"),
                decoy_registry_database_path: directory.join("decoy-registry.sqlite3"),
                approval_database_path: directory.join("security-approvals.sqlite3"),
                alert_outbox_database_path: directory.join("security-alert-outbox.sqlite3"),
                alert_archive_path: directory.join("security-alerts.jsonl"),
                classifier_id: "broker-production-classifier".to_string(),
                classifier_version: "1".to_string(),
                classification_rules: vec![ProductionClassificationRuleConfig {
                    category: "credential".to_string(),
                    expression: "(?i)bearer[ ]+[a-z0-9._-]+".to_string(),
                    confidence_basis_points: 10_000,
                    label: InformationLabel::bottom(),
                }],
                operator_input_floor: InformationLabel::bottom(),
                trusted_declassification_authorities: Default::default(),
                trusted_watermark_keys: vec![ProductionTrustedWatermarkKeyConfig {
                    tenant_id: "tenant-production".to_string(),
                    key_id: "broker-production-watermark-key-v1".to_string(),
                    public_key: Keypair::from_seed(&[149; 32]).public_key(),
                    status: chio_decoy::WatermarkKeyStatus::Active,
                    not_before_unix_ms: 1,
                    signing_cutoff_unix_ms: chio_decoy::MAX_IJSON_INTEGER - 1,
                    verify_until_unix_ms: chio_decoy::MAX_IJSON_INTEGER,
                }],
                trusted_watermark_source_contexts: vec![ProductionWatermarkSourceContextConfig {
                    tenant_id: "tenant-production".to_string(),
                    application_id: "broker-production".to_string(),
                    session_id: "broker-production-bootstrap".to_string(),
                    source_receipt_id: "broker-production-bootstrap-receipt".to_string(),
                    tool_id: "broker-production-secret-execute".to_string(),
                    issued_at_unix_ms: 1,
                    not_after_unix_ms: chio_decoy::MAX_IJSON_INTEGER,
                }],
                flow_fence_ttl_ms: 30_000,
                tripwire_producer_id: "broker-production-tripwire".to_string(),
                tripwire_producer_key_id: "broker-production-tripwire-key-v1".to_string(),
                tripwire_policy_version: "broker-production-tripwire-policy-v1".to_string(),
                tripwire_max_event_age_ms: 60_000,
                tripwire_max_future_skew_ms: 1_000,
                active_response_executor_generation: 1,
                active_response_executor_lease_owner_id:
                    "broker-production-active-response-executor-node-1".to_string(),
                active_response_execution_lease_ms: 30_000,
                active_response_policy_version: "broker-production-response-v1".to_string(),
                active_response_approval_policy_id: "broker-production-approval-v1".to_string(),
                active_response_allowed_effects: BTreeSet::from([
                    ResponseEffectKind::EscalateAlert,
                    ResponseEffectKind::ThrottleSession,
                    ResponseEffectKind::RestrictEgress,
                    ResponseEffectKind::SuspendSession,
                    ResponseEffectKind::SuspendCapabilitySet,
                    ResponseEffectKind::FreezeIssuance,
                ]),
                active_response_automatic_ttl_ceiling_ms: 30_000,
                active_response_max_finding_age_ms: 60_000,
            },
            receipt_tenant_id: composition.receipt_tenant_id,
            broker_manifest_path: directory.join("broker-manifest.json"),
            broker_manifest_public_key: Keypair::from_seed(&[148; 32]).public_key(),
            admin: ProductionBrokerAdminFileConfig {
                trusted_approvers: composition.admin_policy.trusted_approvers,
                subject: composition.admin_policy.subject,
                threshold: composition.admin_policy.threshold,
                maximum_token_lifetime_seconds: composition
                    .admin_policy
                    .maximum_token_lifetime_seconds,
            },
            key_custody: ProductionBrokerKeyCustodyConfig {
                expected_owner_uid: fs::metadata(directory)
                    .require("product config directory metadata")
                    .uid(),
                capability_issuer_signing_key_fd: 11,
                release_receipt_signing_key_fd: 12,
                active_defense_executor_signing_key_fd: 13,
                decoy_registry_master_key_fd: 14,
            },
        }
    }

    fn issue_body(issuer: &Keypair, subject: &Keypair) -> BrokerCapabilityBody {
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: issuer.public_key(),
            capability_id: "broker-capability-production-1".to_string(),
            parent_capability_id: "parent-capability-production-1".to_string(),
            subject: subject.public_key(),
            audience: "broker-service-production".to_string(),
            issued_at_unix_seconds: 100,
            not_before_unix_seconds: 100,
            expires_at_unix_seconds: 150,
            credential: CredentialRef {
                provider: "generic-https".to_string(),
                credential_id: "credential-production-1".to_string(),
                version: 1,
            },
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            destination: BrokerDestination::parse("https://example.com/v1", "post", false)
                .require("production destination"),
            constraints: RequestConstraints {
                allowed_caller_headers: Vec::new(),
                provider_owned_headers: vec!["authorization".to_string()],
                maximum_body_bytes: 4_096,
                required_body_sha256: "11".repeat(32),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 4_096,
                streaming_allowed: false,
                maximum_timeout_ms: 1_000,
            },
            broker_quota_key_id: "broker-quota-production-1".to_string(),
            maximum_executions: 1,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "broker-revocation-production-1".to_string(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: subject.public_key(),
                nonce_ttl_seconds: 30,
            },
        }
    }

    fn governed_authorization(
        operation: IpcOperation,
        payload: &[u8],
        approver: &Keypair,
        subject: &PublicKey,
        suffix: &str,
    ) -> Vec<u8> {
        let intent = daemon_admin_intent_digest(operation, "tenant-production", payload)
            .require("admin intent");
        let approval = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("broker-control-approval-{suffix}"),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent,
                threshold_proposal_hash: Some("cc".repeat(32)),
                request_id: format!("broker-control-request-{suffix}"),
                issued_at: 90,
                expires_at: 110,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .require("sign governed approval");
        GovernedAdminAuthorizationEnvelope::new(vec![approval])
            .require("governed envelope")
            .canonical_bytes()
            .require("canonical governed envelope")
    }

    fn control_authority(
        directory: &Path,
        issuer: &Keypair,
        subject: &Keypair,
        approver: &Keypair,
        admin_subject: &PublicKey,
    ) -> DurableBrokerControlAuthority {
        control_authority_with_admin_clock(
            directory,
            issuer,
            subject,
            approver,
            admin_subject,
            Arc::new(FixedAdminClock(100)),
        )
    }

    fn control_authority_with_admin_clock(
        directory: &Path,
        issuer: &Keypair,
        subject: &Keypair,
        approver: &Keypair,
        admin_subject: &PublicKey,
        admin_clock: Arc<dyn AdminClock>,
    ) -> DurableBrokerControlAuthority {
        let admin = Arc::new(
            GovernedAdminAuthorizer::open(
                directory.join("control-admin.sqlite3"),
                admin_policy(approver, admin_subject),
                Keypair::from_seed(&[96; 32]).public_key(),
                admin_clock,
            )
            .require("open governed admin"),
        );
        let combined = Arc::new(
            SqliteAdmissionCaptureAuthority::open(directory.join("combined.sqlite3"))
                .require("open combined authority"),
        );
        DurableBrokerControlAuthority::open_with_clock(
            directory.join("control-issuance.sqlite3"),
            DurableBrokerControlConfig {
                tenant_scope: "tenant-production".to_string(),
                broker_audience: "broker-service-production".to_string(),
                parent_audience: "kernel-production".to_string(),
                maximum_clock_skew_seconds: 10,
                selected_provider_adapter_ids: BTreeSet::from(["generic-bearer".to_string()]),
            },
            DurableBrokerControlAuthorities {
                issuer: Arc::new(Ed25519Backend::new(issuer.clone())),
                admin,
                liveness: Arc::new(FixedParentLiveness {
                    parent_capability_id: "parent-capability-production-1".to_string(),
                    subject: subject.public_key(),
                    audience: "kernel-production".to_string(),
                    expires_at_unix_seconds: 200,
                }),
                combined,
                migration: test_migration_enforcer(),
            },
            Arc::new(FixedControlClock(100)),
        )
        .require("open durable broker control authority")
    }

    #[test]
    fn production_composition_rejects_missing_or_ephemeral_components() {
        let directory = tempfile::tempdir().require("production config directory");
        let keys = production_keys();
        let mut config = production_config(directory.path(), &keys);
        config.selected_provider_adapter_ids.clear();
        assert!(matches!(
            config.validate(&keys),
            Err(BrokerIntegrationError::InvalidConfiguration(_))
        ));

        let mut config = production_config(directory.path(), &keys);
        config.issuance_database_path = PathBuf::new();
        assert!(matches!(
            config.validate(&keys),
            Err(BrokerIntegrationError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn production_signing_topology_accepts_one_broker_identity_and_rejects_role_collapse() {
        let directory = tempfile::tempdir().require("production topology directory");
        let keys = production_keys();
        let baseline = production_config(directory.path(), &keys);
        baseline
            .validate(&keys)
            .require("broker IPC and receipt signatures share the daemon identity");

        let mut mismatched_receipt = baseline.clone();
        mismatched_receipt.broker_client.trusted_receipt_signer =
            Keypair::from_seed(&[149; 32]).public_key();
        assert!(mismatched_receipt.validate(&keys).is_err());

        let mut authority_broker = baseline.clone();
        authority_broker.trusted_broker = authority_broker.authority_public_key.clone();
        authority_broker.broker_client.trusted_receipt_signer =
            authority_broker.authority_public_key.clone();
        assert!(authority_broker.validate(&keys).is_err());

        let mut authority_issuer = baseline.clone();
        authority_issuer.trusted_capability_issuer = authority_issuer.authority_public_key.clone();
        let mut authority_issuer_keys = keys.clone();
        authority_issuer_keys.capability_issuer_signer =
            authority_issuer_keys.authority_signer.clone();
        assert!(authority_issuer.validate(&authority_issuer_keys).is_err());

        let mut authority_release = baseline.clone();
        authority_release.trusted_release_receipt_signer =
            authority_release.authority_public_key.clone();
        let mut authority_release_keys = keys.clone();
        authority_release_keys.release_receipt_signer =
            authority_release_keys.authority_signer.clone();
        assert!(authority_release.validate(&authority_release_keys).is_err());

        let mut broker_issuer = baseline.clone();
        broker_issuer.trusted_broker = broker_issuer.trusted_capability_issuer.clone();
        broker_issuer.broker_client.trusted_receipt_signer =
            broker_issuer.trusted_capability_issuer.clone();
        assert!(broker_issuer.validate(&keys).is_err());

        let mut broker_release = baseline.clone();
        broker_release.trusted_broker = broker_release.trusted_release_receipt_signer.clone();
        broker_release.broker_client.trusted_receipt_signer =
            broker_release.trusted_release_receipt_signer.clone();
        assert!(broker_release.validate(&keys).is_err());

        let mut issuer_release = baseline;
        issuer_release.trusted_release_receipt_signer =
            issuer_release.trusted_capability_issuer.clone();
        let mut issuer_release_keys = keys;
        issuer_release_keys.release_receipt_signer =
            issuer_release_keys.capability_issuer_signer.clone();
        assert!(issuer_release.validate(&issuer_release_keys).is_err());
    }

    #[test]
    fn response_authority_requires_separate_process_path_and_signing_roles() {
        let directory = tempfile::tempdir().require("response authority topology directory");
        let keys = production_keys();
        let baseline = production_config(directory.path(), &keys);
        baseline
            .validate(&keys)
            .require("separated response authority topology");

        let mut shared_process = baseline.clone();
        shared_process.response_authority_expected_peer.process_id =
            shared_process.broker_client.expected_peer.process_id;
        assert!(shared_process.validate(&keys).is_err());

        let mut aliased_socket = baseline.clone();
        aliased_socket.response_authority_socket_path = directory.path().join(".").join("broker.sock");
        assert!(aliased_socket.validate(&keys).is_err());

        let mut database_socket = baseline.clone();
        database_socket.response_authority_socket_path =
            database_socket.issuance_database_path.clone();
        assert!(database_socket.validate(&keys).is_err());

        let mut authority_key = baseline.clone();
        authority_key.trusted_response_authority = authority_key.authority_public_key.clone();
        assert!(authority_key.validate(&keys).is_err());

        let mut admin_subject = baseline.clone();
        admin_subject.trusted_response_authority = admin_subject.admin_policy.subject.clone();
        assert!(admin_subject.validate(&keys).is_err());

        let mut admin_approver = baseline;
        admin_approver.trusted_response_authority = admin_approver.admin_policy.trusted_approvers[0].clone();
        assert!(admin_approver.validate(&keys).is_err());
    }

    #[test]
    fn product_response_authority_socket_cannot_alias_security_runtime_files() {
        let directory = tempfile::tempdir().require("response authority product directory");
        let keys = production_keys();
        let mut config = product_file_config(directory.path(), &keys);
        config.active_defense.response_authority.socket_path =
            config.security_runtime.security_state_database_path.clone();
        assert!(config.validate_wire_contract().is_err());
    }

    #[test]
    fn product_active_defense_executor_requires_distinct_key_and_custody() {
        let directory = tempfile::tempdir().require("active-defense executor product directory");
        let keys = production_keys();
        let baseline = product_file_config(directory.path(), &keys);
        baseline
            .validate_wire_contract()
            .require("separated active-defense executor role");

        let mut response_alias = baseline.clone();
        response_alias.active_defense_executor_public_key = response_alias
            .active_defense
            .response_authority
            .trusted_authority
            .clone();
        assert!(response_alias.validate_wire_contract().is_err());

        let mut authority_alias = baseline.clone();
        authority_alias.active_defense_executor_public_key =
            authority_alias.authority_public_key.clone();
        assert!(authority_alias.validate_wire_contract().is_err());

        let mut broker_alias = baseline.clone();
        broker_alias.active_defense_executor_public_key = broker_alias.trusted_broker.clone();
        assert!(broker_alias.validate_wire_contract().is_err());

        let mut issuer_alias = baseline.clone();
        issuer_alias.active_defense_executor_public_key =
            issuer_alias.trusted_capability_issuer.clone();
        assert!(issuer_alias.validate_wire_contract().is_err());

        let mut release_alias = baseline.clone();
        release_alias.active_defense_executor_public_key =
            release_alias.trusted_release_receipt_signer.clone();
        assert!(release_alias.validate_wire_contract().is_err());

        let mut admin_alias = baseline.clone();
        admin_alias.active_defense_executor_public_key = admin_alias.admin.subject.clone();
        assert!(admin_alias.validate_wire_contract().is_err());

        let mut approver_alias = baseline.clone();
        approver_alias.active_defense_executor_public_key =
            approver_alias.admin.trusted_approvers[0].clone();
        assert!(approver_alias.validate_wire_contract().is_err());

        let mut manifest_alias = baseline.clone();
        manifest_alias.active_defense_executor_public_key =
            manifest_alias.broker_manifest_public_key.clone();
        assert!(manifest_alias.validate_wire_contract().is_err());

        let mut descriptor_alias = baseline;
        descriptor_alias
            .key_custody
            .active_defense_executor_signing_key_fd = descriptor_alias
            .key_custody
            .capability_issuer_signing_key_fd;
        assert!(descriptor_alias.validate_wire_contract().is_err());
    }

    #[test]
    fn production_key_custody_rejects_a_closed_inherited_descriptor() {
        let raw_fd = tempfile::tempfile()
            .require("create closed production descriptor")
            .into_raw_fd();
        // SAFETY: into_raw_fd transferred ownership to this test, which closes
        // the descriptor exactly once before exercising the rejection path.
        assert_eq!(unsafe { libc::close(raw_fd) }, 0);

        let error = take_production_inherited_key_file(
            u32::try_from(raw_fd).require("production descriptor is nonnegative"),
            "test production key",
        )
        .require_error("closed production descriptor must be rejected");

        assert!(matches!(
            error,
            BrokerIntegrationError::Broker(BrokerError::Custody(message))
                if message.contains("inherited descriptor duplication failed")
        ));
        assert!(raw_descriptor_is_closed(raw_fd));
    }

    #[test]
    fn production_key_custody_retires_only_the_transferred_descriptor() {
        let mut source = tempfile::tempfile().require("create production descriptor fixture");
        source
            .write_all(b"production-key")
            .require("write production descriptor fixture");
        source
            .seek(SeekFrom::Start(0))
            .require("rewind production descriptor fixture");
        let mut independent_alias = source
            .try_clone()
            .require("duplicate production descriptor fixture");
        let raw_fd = source.into_raw_fd();

        let mut adopted = take_production_inherited_key_file(
            u32::try_from(raw_fd).require("production descriptor is nonnegative"),
            "test production key",
        )
        .require("adopt production descriptor");

        assert_ne!(adopted.as_raw_fd(), raw_fd);
        assert!(raw_descriptor_is_closed(raw_fd));
        // SAFETY: adopted owns a live descriptor for the duration of this call.
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        let mut bytes = Vec::new();
        adopted
            .read_to_end(&mut bytes)
            .require("read adopted production descriptor");
        assert_eq!(bytes, b"production-key");
        drop(adopted);

        independent_alias
            .seek(SeekFrom::Start(0))
            .require("rewind independent production alias");
        bytes.clear();
        independent_alias
            .read_to_end(&mut bytes)
            .require("read independent production alias");
        assert_eq!(bytes, b"production-key");
    }

    #[test]
    fn product_active_defense_receipt_ingress_flag_matches_configured_trust() {
        let directory = tempfile::tempdir().require("receipt ingress product directory");
        let keys = production_keys();
        let mut config = product_file_config(directory.path(), &keys);
        assert!(config.validate_wire_contract().is_ok());

        config.active_defense.correlation_allow_verified_receipts = true;
        assert!(config.validate_wire_contract().is_err());
    }

    #[test]
    fn product_broker_migration_requires_complete_enforced_external_anchors() {
        let directory = tempfile::tempdir().require("broker migration product directory");
        let keys = production_keys();
        let baseline = product_file_config(directory.path(), &keys);
        baseline
            .validate_wire_contract()
            .require("validate anchored broker migration contract");

        let mut missing_anchor = baseline.clone();
        let _ = missing_anchor.enterprise_migration.minimum_heads.pop();
        assert!(missing_anchor.validate_wire_contract().is_err());

        let mut shadow_fallback = baseline.clone();
        shadow_fallback.enterprise_migration.providers[0].credential_custody_stage =
            EnterpriseMigrationStage::Shadow;
        assert!(shadow_fallback.validate_wire_contract().is_err());

        let mut unknown_control = baseline.clone();
        unknown_control.enterprise_migration.minimum_heads[0]
            .key
            .control = EnterpriseMigrationControl::CageEnforcement;
        assert!(unknown_control.validate_wire_contract().is_err());

        let mut duplicate_signer = baseline;
        let signer = duplicate_signer.enterprise_migration.trusted_transition_signers[0]
            .clone();
        duplicate_signer
            .enterprise_migration
            .trusted_transition_signers
            .push(signer);
        assert!(duplicate_signer.validate_wire_contract().is_err());
    }

    #[test]
    fn production_active_defense_v5_fixture_is_canonical_and_validated() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docs/security/fixtures/production-broker-active-defense-v5.json"
        ));
        let canonical_fixture = bytes
            .strip_suffix(b"\n")
            .unwrap_or(bytes.as_slice());
        let value: serde_json::Value =
            serde_json::from_slice(canonical_fixture).require("decode v5 active-defense fixture");
        assert_eq!(
            value.get("schema").and_then(serde_json::Value::as_str),
            Some(PRODUCTION_BROKER_PRODUCT_CONFIG_SCHEMA)
        );
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(4));
        assert_eq!(
            canonical_json_bytes(&value).require("canonicalize v5 active-defense fixture"),
            canonical_fixture
        );
        let active_defense: ProductionBrokerActiveDefenseFileConfig = serde_json::from_value(
            value
                .get("activeDefense")
                .cloned()
                .require("v5 active-defense fixture body"),
        )
        .require("decode v5 active-defense config");
        active_defense
            .validate()
            .require("validate v5 active-defense fixture");
        let executor_key: PublicKey = serde_json::from_value(
            value
                .get("activeDefenseExecutorPublicKey")
                .cloned()
                .require("v5 active-defense executor public key"),
        )
        .require("decode v5 active-defense executor public key");
        assert_ne!(
            executor_key,
            active_defense.response_authority.trusted_authority
        );
        let custody: ProductionBrokerKeyCustodyConfig = serde_json::from_value(
            value
                .get("keyCustody")
                .cloned()
                .require("v5 active-defense key custody"),
        )
        .require("decode v5 active-defense key custody");
        let custody_fds = [
            custody.capability_issuer_signing_key_fd,
            custody.release_receipt_signing_key_fd,
            custody.active_defense_executor_signing_key_fd,
            custody.decoy_registry_master_key_fd,
        ];
        assert_eq!(custody_fds.into_iter().collect::<BTreeSet<_>>().len(), 4);
    }

    #[test]
    fn product_active_defense_recovery_limits_are_bounded() {
        let directory = tempfile::tempdir().require("recovery limits product directory");
        let keys = production_keys();
        let mut config = product_file_config(directory.path(), &keys);

        config.active_defense.recovery_max_startup_records = 127;
        assert!(config.validate_wire_contract().is_err());
        config.active_defense.recovery_max_startup_records = 4_096;
        config.active_defense.recovery_max_startup_wall_clock_ms = 3_600_001;
        assert!(config.validate_wire_contract().is_err());
    }

    #[test]
    fn runtime_policy_digest_is_decoded_once_and_rejects_noncanonical_hex() {
        let runtime_hash = "4a".repeat(32);
        let decoded = decode_runtime_policy_digest(&runtime_hash)
            .require("canonical runtime policy digest");
        assert_eq!(decoded, Digest32::new([0x4a; 32]));
        assert_ne!(
            decoded,
            Digest32::new(*chio_core::sha256(runtime_hash.as_bytes()).as_bytes())
        );
        assert!(decode_runtime_policy_digest(&runtime_hash.to_uppercase()).is_err());
        assert!(decode_runtime_policy_digest("4a").is_err());
    }

    #[test]
    fn product_config_loader_rejects_unknown_and_noncanonical_json() {
        let directory = tempfile::tempdir().require("product config directory");
        let keys = production_keys();
        let config = product_file_config(directory.path(), &keys);
        let config_path = directory.path().join("broker-product.json");

        let canonical = canonical_json_bytes(&config).require("canonical product config");
        fs::write(&config_path, &canonical).require("write canonical product config");
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .require("harden product config");
        assert_eq!(
            ProductionBrokerProductConfig::load(&config_path)
                .require("load canonical product config"),
            config
        );

        let mut unknown = serde_json::to_value(&config).require("encode product config");
        unknown
            .as_object_mut()
            .require("product config object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        fs::write(
            &config_path,
            canonical_json_bytes(&unknown).require("canonical unknown-field config"),
        )
        .require("write unknown-field config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());

        let mut nested_unknown = serde_json::to_value(&config).require("encode product config");
        nested_unknown
            .get_mut("brokerClient")
            .and_then(serde_json::Value::as_object_mut)
            .require("broker client config object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        fs::write(
            &config_path,
            canonical_json_bytes(&nested_unknown).require("canonical nested-unknown config"),
        )
        .require("write nested-unknown config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());

        let mut legacy_authority_descriptor =
            serde_json::to_value(&config).require("encode product config");
        legacy_authority_descriptor
            .get_mut("keyCustody")
            .and_then(serde_json::Value::as_object_mut)
            .require("key custody config object")
            .insert("authoritySigningKeyFd".to_string(), serde_json::json!(10));
        fs::write(
            &config_path,
            canonical_json_bytes(&legacy_authority_descriptor)
                .require("canonical legacy-authority-descriptor config"),
        )
        .require("write legacy-authority-descriptor config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());

        let mut missing_custody = serde_json::to_value(&config).require("encode product config");
        missing_custody
            .as_object_mut()
            .require("product config object")
            .remove("keyCustody");
        fs::write(
            &config_path,
            canonical_json_bytes(&missing_custody).require("canonical missing-custody config"),
        )
        .require("write missing-custody config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());

        let mut duplicate_descriptors = config.clone();
        duplicate_descriptors
            .key_custody
            .release_receipt_signing_key_fd = duplicate_descriptors
            .key_custody
            .capability_issuer_signing_key_fd;
        fs::write(
            &config_path,
            canonical_json_bytes(&duplicate_descriptors)
                .require("canonical duplicate-descriptor config"),
        )
        .require("write duplicate-descriptor config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());

        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).require("pretty product config"),
        )
        .require("write noncanonical config");
        assert!(ProductionBrokerProductConfig::load(&config_path).is_err());
    }

    #[test]
    fn product_config_rejects_reused_active_response_worker_identity() {
        let directory = tempfile::tempdir().require("product config directory");
        let keys = production_keys();
        let mut config = product_file_config(directory.path(), &keys);
        config
            .security_runtime
            .active_response_executor_lease_owner_id =
            config.active_defense.scheduler_lease_owner_id.clone();

        assert!(config.validate_wire_contract().is_err());
    }

    #[test]
    fn production_product_owns_live_correlator_and_ttl_worker_health_gate() {
        fn assert_active_defense_host_accessor(
            accessor: fn(&ProductionBrokerProductRuntime) -> Option<&ProductionActiveDefenseHost>,
        ) {
            let _ = accessor;
        }

        fn assert_fail_closed_health_gate<E>(
            gate: fn(&ProductionBrokerProductRuntime) -> Result<(), E>,
        ) {
            let _ = gate;
        }

        let _host_offset =
            std::mem::offset_of!(ProductionBrokerProductRuntime, active_defense_host);
        let _start = ProductionBrokerProductRuntime::start_active_defense;
        assert_active_defense_host_accessor(ProductionBrokerProductRuntime::active_defense_host);
        assert_fail_closed_health_gate(ProductionBrokerProductRuntime::ensure_active_defense_ready);
    }

    #[test]
    fn broker_route_requires_an_invocable_default_capability() {
        let capability = |server_id: &str, tool_name: &str, operations: Vec<Operation>| {
            crate::policy::DefaultCapability {
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations,
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                ttl: 60,
            }
        };

        assert!(require_broker_route_default_capability(
            &[capability(
                "secret-broker",
                "execute",
                vec![Operation::Invoke],
            )],
            "secret-broker",
            "execute",
        )
        .is_ok());
        assert!(require_broker_route_default_capability(
            &[capability("*", "*", vec![Operation::Invoke])],
            "secret-broker",
            "execute",
        )
        .is_ok());
        assert!(require_broker_route_default_capability(
            &[capability(
                "secret-broker",
                "execute",
                vec![Operation::ReadResult],
            )],
            "secret-broker",
            "execute",
        )
        .is_err());
        assert!(require_broker_route_default_capability(
            &[capability(
                "direct-provider",
                "execute",
                vec![Operation::Invoke],
            )],
            "secret-broker",
            "execute",
        )
        .is_err());
    }

    #[test]
    fn production_composition_binds_authority_before_broker_is_available() {
        let directory = tempfile::tempdir().require("cold-start directory");
        let keys = production_keys();
        let config = production_config(directory.path(), &keys);
        let authority_socket = config.authority_socket_path.clone();
        let broker_socket = config.broker_client.socket_path.clone();
        let execution_path = config.execution_authority_database_path.clone();
        let composition = ProductionBrokerComposition::open(
            config,
            keys,
            test_migration_enforcer(),
        )
        .require("open cold-start authority");

        assert!(authority_socket.exists());
        assert!(!broker_socket.exists());
        assert!(execution_path.exists());

        let authority = composition.start_authority().require("start authority");
        authority.shutdown().require("stop authority");
    }

    #[test]
    fn durable_control_is_idempotent_and_rejects_conflicting_issue_replay() {
        let directory = tempfile::tempdir().require("control directory");
        let issuer = Keypair::from_seed(&[151; 32]);
        let subject = Keypair::from_seed(&[152; 32]);
        let approver = Keypair::from_seed(&[153; 32]);
        let admin_subject = Keypair::from_seed(&[154; 32]).public_key();
        let authority = control_authority(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
        );
        let command = IssueCapabilityCommand {
            schema: ISSUE_CAPABILITY_SCHEMA.to_string(),
            body: issue_body(&issuer, &subject),
        };
        let payload = canonical_json_bytes(&command).require("issue payload");
        let request = AuthorityControlRequest {
            operation: IpcOperation::Issue,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Issue,
                &payload,
                &approver,
                &admin_subject,
                "first",
            ),
            payload,
        };
        let first = authority.control(&request).require("first issue");
        assert_eq!(
            authority.control(&request).require("idempotent replay"),
            first
        );
        let governed_retry = AuthorityControlRequest {
            operation: IpcOperation::Issue,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Issue,
                &request.payload,
                &approver,
                &admin_subject,
                "governed-retry",
            ),
            payload: request.payload.clone(),
        };
        assert_eq!(
            authority
                .control(&governed_retry)
                .require("governed idempotent retry"),
            first
        );

        let mut conflicting = command;
        conflicting.body.maximum_executions = 2;
        let conflicting_payload =
            canonical_json_bytes(&conflicting).require("conflicting issue payload");
        let conflicting_request = AuthorityControlRequest {
            operation: IpcOperation::Issue,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Issue,
                &conflicting_payload,
                &approver,
                &admin_subject,
                "conflict",
            ),
            payload: conflicting_payload,
        };
        assert!(matches!(
            authority.control(&conflicting_request),
            Err(BrokerError::Conflict(_))
        ));
    }

    #[test]
    fn durable_control_recovers_begun_governance_after_expiry_and_rejects_rebinding() {
        let directory = tempfile::tempdir().require("control recovery directory");
        let issuer = Keypair::from_seed(&[165; 32]);
        let subject = Keypair::from_seed(&[166; 32]);
        let approver = Keypair::from_seed(&[167; 32]);
        let admin_subject = Keypair::from_seed(&[168; 32]).public_key();
        let authority = control_authority(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
        );
        let body = issue_body(&issuer, &subject);
        let issue_payload = canonical_json_bytes(&IssueCapabilityCommand {
            schema: ISSUE_CAPABILITY_SCHEMA.to_string(),
            body: body.clone(),
        })
        .require("issue payload");
        authority
            .control(&AuthorityControlRequest {
                operation: IpcOperation::Issue,
                tenant_scope: "tenant-production".to_string(),
                authorization: governed_authorization(
                    IpcOperation::Issue,
                    &issue_payload,
                    &approver,
                    &admin_subject,
                    "recovery-issue",
                ),
                payload: issue_payload,
            })
            .require("issue before recovery");

        let control_payload = canonical_json_bytes(&CapabilityControlCommand {
            schema: CAPABILITY_CONTROL_SCHEMA.to_string(),
            capability_id: body.capability_id,
            revocation_id: body.revocation_id,
            credential: body.credential,
        })
        .require("status payload");
        let status_request = AuthorityControlRequest {
            operation: IpcOperation::Status,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Status,
                &control_payload,
                &approver,
                &admin_subject,
                "recovery-status",
            ),
            payload: control_payload,
        };
        authority
            .govern(&status_request)
            .require("durably begin status governance");
        drop(authority);

        let reopened = control_authority_with_admin_clock(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
            Arc::new(FixedAdminClock(1_000)),
        );
        let status: CapabilityStatusResponse = decode_canonical(
            &reopened
                .control(&status_request)
                .require("recover status after approval expiry"),
            "recovered status",
        )
        .require("decode recovered status");
        assert!(!status.revoked);

        let mut rebound = status_request;
        rebound.operation = IpcOperation::Revoke;
        assert!(matches!(
            reopened.control(&rebound),
            Err(BrokerError::Conflict(_))
        ));
    }

    #[test]
    fn durable_control_governs_status_and_commits_combined_revocation() {
        let directory = tempfile::tempdir().require("control revocation directory");
        let issuer = Keypair::from_seed(&[155; 32]);
        let subject = Keypair::from_seed(&[156; 32]);
        let approver = Keypair::from_seed(&[157; 32]);
        let admin_subject = Keypair::from_seed(&[158; 32]).public_key();
        let authority = control_authority(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
        );
        let body = issue_body(&issuer, &subject);
        let issue_payload = canonical_json_bytes(&IssueCapabilityCommand {
            schema: ISSUE_CAPABILITY_SCHEMA.to_string(),
            body: body.clone(),
        })
        .require("issue payload");
        let issue_request = AuthorityControlRequest {
            operation: IpcOperation::Issue,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Issue,
                &issue_payload,
                &approver,
                &admin_subject,
                "revocation-issue",
            ),
            payload: issue_payload,
        };
        let issued = authority
            .control(&issue_request)
            .require("issue before revocation");
        assert_eq!(
            authority.control(&issue_request).require("retry issue"),
            issued
        );

        let control_payload = canonical_json_bytes(&CapabilityControlCommand {
            schema: CAPABILITY_CONTROL_SCHEMA.to_string(),
            capability_id: body.capability_id.clone(),
            revocation_id: body.revocation_id.clone(),
            credential: body.credential,
        })
        .require("control payload");
        let status_request = AuthorityControlRequest {
            operation: IpcOperation::Status,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Status,
                &control_payload,
                &approver,
                &admin_subject,
                "status-before-revoke",
            ),
            payload: control_payload.clone(),
        };
        let status_bytes = authority
            .control(&status_request)
            .require("status before revoke");
        assert_eq!(
            authority.control(&status_request).require("retry status"),
            status_bytes
        );
        let status: CapabilityStatusResponse =
            decode_canonical(&status_bytes, "status before revoke")
                .require("decode status before revoke");
        assert!(!status.revoked);

        let revoke_request = AuthorityControlRequest {
            operation: IpcOperation::Revoke,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Revoke,
                &control_payload,
                &approver,
                &admin_subject,
                "revoke",
            ),
            payload: control_payload.clone(),
        };
        let revoked_bytes = authority
            .control(&revoke_request)
            .require("commit combined revocation");
        assert_eq!(
            authority
                .control(&revoke_request)
                .require("retry revocation"),
            revoked_bytes
        );
        let revoked: CapabilityStatusResponse =
            decode_canonical(&revoked_bytes, "revocation status")
                .require("decode revocation status");
        assert!(revoked.revoked);
        assert!(revoked.authority_commit_index > status.authority_commit_index);

        let status_after_revoke_request = AuthorityControlRequest {
            operation: IpcOperation::Status,
            tenant_scope: "tenant-production".to_string(),
            authorization: governed_authorization(
                IpcOperation::Status,
                &control_payload,
                &approver,
                &admin_subject,
                "status-after-revoke",
            ),
            payload: control_payload,
        };
        let status_after_revoke = authority
            .control(&status_after_revoke_request)
            .require("status after revoke");
        assert_eq!(
            authority
                .control(&status_after_revoke_request)
                .require("retry status after revoke"),
            status_after_revoke
        );

        let mut rebound = revoke_request.clone();
        rebound.operation = IpcOperation::Status;
        assert!(matches!(
            authority.control(&rebound),
            Err(BrokerError::Conflict(_))
        ));

        drop(authority);
        let reopened = control_authority_with_admin_clock(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
            Arc::new(FixedAdminClock(1_000)),
        );
        assert_eq!(
            reopened
                .control(&issue_request)
                .require("retry issue after admin expiry"),
            issued
        );
        assert_eq!(
            reopened
                .control(&revoke_request)
                .require("retry revocation after admin expiry"),
            revoked_bytes
        );
        assert_eq!(
            reopened
                .control(&status_after_revoke_request)
                .require("retry status after admin expiry"),
            status_after_revoke
        );
    }

    #[test]
    fn issuance_restart_fails_closed_on_malformed_durable_state() {
        let directory = tempfile::tempdir().require("restart directory");
        let issuer = Keypair::from_seed(&[161; 32]);
        let subject = Keypair::from_seed(&[162; 32]);
        let approver = Keypair::from_seed(&[163; 32]);
        let admin_subject = Keypair::from_seed(&[164; 32]).public_key();
        drop(control_authority(
            directory.path(),
            &issuer,
            &subject,
            &approver,
            &admin_subject,
        ));

        let connection = Connection::open(directory.path().join("control-issuance.sqlite3"))
            .require("open issuance state for corruption fixture");
        connection
            .execute(
                r#"
                INSERT INTO broker_capability_issuance (
                    capability_id, revocation_id, parent_capability_id,
                    subject_key, expires_at, command_digest,
                    request_authorization_digest, admin_authorization_digest,
                    canonical_capability
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    "malformed-capability",
                    "malformed-revocation",
                    "parent-capability-production-1",
                    subject.public_key().to_hex(),
                    150_i64,
                    "11".repeat(32),
                    "22".repeat(32),
                    "33".repeat(32),
                    vec![0_u8],
                ],
            )
            .require("insert malformed durable issuance row");
        drop(connection);

        let admin = Arc::new(
            GovernedAdminAuthorizer::open(
                directory.path().join("control-admin.sqlite3"),
                admin_policy(&approver, &admin_subject),
                Keypair::from_seed(&[96; 32]).public_key(),
                Arc::new(FixedAdminClock(100)),
            )
            .require("reopen governed admin"),
        );
        let combined = Arc::new(
            SqliteAdmissionCaptureAuthority::open(directory.path().join("combined.sqlite3"))
                .require("reopen combined authority"),
        );
        let reopened = DurableBrokerControlAuthority::open_with_clock(
            directory.path().join("control-issuance.sqlite3"),
            DurableBrokerControlConfig {
                tenant_scope: "tenant-production".to_string(),
                broker_audience: "broker-service-production".to_string(),
                parent_audience: "kernel-production".to_string(),
                maximum_clock_skew_seconds: 10,
                selected_provider_adapter_ids: BTreeSet::from(["generic-bearer".to_string()]),
            },
            DurableBrokerControlAuthorities {
                issuer: Arc::new(Ed25519Backend::new(issuer)),
                admin,
                liveness: Arc::new(FixedParentLiveness {
                    parent_capability_id: "parent-capability-production-1".to_string(),
                    subject: subject.public_key(),
                    audience: "kernel-production".to_string(),
                    expires_at_unix_seconds: 200,
                }),
                combined,
                migration: test_migration_enforcer(),
            },
            Arc::new(FixedControlClock(100)),
        );
        assert!(matches!(
            reopened,
            Err(BrokerIntegrationError::InvalidConfiguration(_))
        ));
    }
}
