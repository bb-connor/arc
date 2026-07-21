    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::scope::ChioScope;
    use chio_core::capability::token::CapabilityTokenBody;
    use chio_core::crypto::{Ed25519Backend, Keypair, SigningBackend};
    use chio_core::session::{
        OperationContext, RequestId as KernelRequestId, SessionId as KernelSessionId,
        ToolCallOperation,
    };
    use chio_core::sha256;
    use chio_decoy::{
        DecoyCreateRequest, SecretMaterial, SignedWatermarkEnvelope, WatermarkClock,
        WatermarkIssueRequest, WatermarkIssuer, WatermarkIssuerConfig, WatermarkIssuerDependencies,
        WatermarkIssuerPolicy, WatermarkSequenceStore,
    };
    use chio_kernel::ToolCallRequest;
    use chio_security_types::ports::{
        ArtifactId, CanonicalBody, Digest32, PortError, PortErrorKind, RecordId, RequestId,
        TripwireDecision, TripwireInput, TripwireKind, WatermarkObservationStore,
    };
    use chio_security_types::{
        DecoyOperationAttempt, DecoyOperationKind, DecoySurface, DecoyVersion, InformationLabel,
        ResponseEffectKind,
    };
    use chio_store_sqlite::{
        SqliteBudgetStore, SqliteReceiptStore, SqliteSealedDecoyRegistryStore,
    };

    use super::*;
    use crate::security::scheduler_worker::{
        ProductionResponseWorker, ResponseWorkerPort, ResponseWorkerTick, ResponseWorkerTickError,
    };

    fn rejected<T: std::fmt::Debug, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(value) => panic!("{message}: {value:?}"),
            Err(error) => error,
        }
    }

    struct ReadyLifecycleWorkerPort;

    impl ResponseWorkerPort for ReadyLifecycleWorkerPort {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            Ok(())
        }

        fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
            Err(ResponseWorkerTickError::WorkerStopped)
        }

        fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
            Ok(())
        }
    }

    struct ToggleReadyLifecycleWorkerPort {
        ready: Arc<AtomicBool>,
    }

    impl ResponseWorkerPort for ToggleReadyLifecycleWorkerPort {
        fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
            if self.ready.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(ResponseWorkerTickError::Port(PortError::unavailable()))
            }
        }

        fn tick(&self, _: u64, _: bool) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
            Err(ResponseWorkerTickError::WorkerStopped)
        }

        fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
            Ok(())
        }
    }

    struct MutatingWorkerFailurePostHook {
        ready: Arc<AtomicBool>,
        mutations: Arc<AtomicUsize>,
    }

    impl PostInvocationHook for MutatingWorkerFailurePostHook {
        fn name(&self) -> &str {
            "mutating-worker-failure-post-hook"
        }

        fn inspect(
            &self,
            _: &PostInvocationContext<'_>,
            _: &serde_json::Value,
        ) -> PostInvocationVerdict {
            self.mutations.fetch_add(1, Ordering::AcqRel);
            self.ready.store(false, Ordering::Release);
            PostInvocationVerdict::Allow
        }
    }

    fn bind_ready_lifecycle_worker(
        lifecycle: &ProductionDeclassificationReceiptLifecycle,
    ) -> Arc<ProductionResponseWorker> {
        let port: Arc<dyn ResponseWorkerPort> = Arc::new(ReadyLifecycleWorkerPort);
        let worker = Arc::new(
            ProductionResponseWorker::new(port)
                .unwrap_or_else(|error| panic!("create lifecycle worker: {error}")),
        );
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("bind lifecycle worker: {error}"));
        worker
            .mark_publication_released_for_test()
            .unwrap_or_else(|error| panic!("release lifecycle worker: {error}"));
        worker
    }

    struct SuccessfulFlowDispatchOutcomeRecorder;

    impl FlowDispatchOutcomeRecorder for SuccessfulFlowDispatchOutcomeRecorder {
        fn record(&mut self, _: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
            Ok(())
        }
    }

    struct FailingFlowDispatchOutcomeRecorder;

    impl FlowDispatchOutcomeRecorder for FailingFlowDispatchOutcomeRecorder {
        fn record(&mut self, _: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
            Err(FlowDenial::DeclassificationStoreFailure)
        }
    }

    struct DropTrackedFlowDispatchOutcomeRecorder {
        drops: Arc<AtomicUsize>,
        dispatch_failures: Arc<AtomicUsize>,
    }

    impl Drop for DropTrackedFlowDispatchOutcomeRecorder {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl FlowDispatchOutcomeRecorder for DropTrackedFlowDispatchOutcomeRecorder {
        fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
            if matches!(outcome, DeclassificationDispatchOutcome::DispatchFailed) {
                self.dispatch_failures.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }
    }

    struct WorkerFailingFlowPreDispatchPort {
        ready: Arc<AtomicBool>,
        commits: Arc<AtomicUsize>,
        recorder_drops: Arc<AtomicUsize>,
        dispatch_failures: Arc<AtomicUsize>,
    }

    impl FlowPreDispatchPort for WorkerFailingFlowPreDispatchPort {
        fn commit(
            &self,
            _: &FlowPreDispatchInput<'_>,
        ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
            self.commits.fetch_add(1, Ordering::AcqRel);
            self.ready.store(false, Ordering::Release);
            Ok(Some(Box::new(DropTrackedFlowDispatchOutcomeRecorder {
                drops: Arc::clone(&self.recorder_drops),
                dispatch_failures: Arc::clone(&self.dispatch_failures),
            })))
        }
    }

    struct EmptyFlowPreDispatchPort;

    impl FlowPreDispatchPort for EmptyFlowPreDispatchPort {
        fn commit(
            &self,
            _: &FlowPreDispatchInput<'_>,
        ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
            Ok(None)
        }
    }

    struct CountingActiveResponseExecutorAuthority {
        identity: ActiveResponseExecutorAuthorityIdentity,
        readiness_checks: Arc<AtomicUsize>,
        executions: Arc<AtomicUsize>,
    }

    impl ActiveResponseExecutorAuthority for CountingActiveResponseExecutorAuthority {
        fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
            self.identity.clone()
        }

        fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
            self.readiness_checks.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn execute_active_response(
            &self,
            _: &ActiveResponseExecutionRequest,
        ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
            self.executions.fetch_add(1, Ordering::AcqRel);
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "test executor has no response fixture".to_string(),
            ))
        }
    }

    fn flow_pre_dispatch_test_request() -> ToolCallRequest {
        let keypair = Keypair::from_seed(&[87_u8; 32]);
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "pre-dispatch-lifecycle-capability".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope: ChioScope::default(),
                issued_at: 1,
                expires_at: 1_000_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &keypair,
        )
        .unwrap_or_else(|error| panic!("sign pre-dispatch lifecycle capability: {error}"));
        ToolCallRequest {
            request_id: "pre-dispatch-lifecycle-request".to_string(),
            capability,
            tool_name: "pre-dispatch-lifecycle-tool".to_string(),
            server_id: "pre-dispatch-lifecycle-server".to_string(),
            agent_id: keypair.public_key().to_hex(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        }
    }

    fn flow_pre_dispatch_test_security_context() -> SecurityInvocationContextV1 {
        SecurityInvocationContextV1::new(
            TenantId::new("tenant-pre-dispatch-lifecycle")
                .unwrap_or_else(|error| panic!("pre-dispatch tenant: {error}")),
            SessionId::new("session-pre-dispatch-lifecycle")
                .unwrap_or_else(|error| panic!("pre-dispatch session: {error}")),
            PrincipalId::new("principal-pre-dispatch-lifecycle")
                .unwrap_or_else(|error| panic!("pre-dispatch principal: {error}")),
            IsolationEpochId::new("epoch-pre-dispatch-lifecycle")
                .unwrap_or_else(|error| panic!("pre-dispatch epoch: {error}")),
            LineageId::new("lineage-pre-dispatch-lifecycle")
                .unwrap_or_else(|error| panic!("pre-dispatch lineage: {error}")),
            1,
        )
    }

    fn factory_config(directory: &std::path::Path) -> ProductionSecurityRuntimeFactoryConfig {
        let native_receipt_database_path = directory.join("native-receipts.sqlite3");
        drop(
            SqliteReceiptStore::open(&native_receipt_database_path)
                .unwrap_or_else(|error| panic!("create native receipt store: {error}")),
        );
        ProductionSecurityRuntimeFactoryConfig {
            runtime: ProductionSecurityRuntimeFileConfig {
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
                trusted_declassification_authorities: BTreeMap::new(),
                trusted_watermark_keys: vec![ProductionTrustedWatermarkKeyConfig {
                    tenant_id: "tenant-production".to_string(),
                    key_id: "broker-production-watermark-key-v1".to_string(),
                    public_key: Keypair::from_seed(&[12_u8; 32]).public_key(),
                    status: WatermarkKeyStatus::Active,
                    not_before_unix_ms: 1,
                    signing_cutoff_unix_ms: MAX_IJSON_INTEGER - 1,
                    verify_until_unix_ms: MAX_IJSON_INTEGER,
                }],
                trusted_watermark_source_contexts: vec![ProductionWatermarkSourceContextConfig {
                    tenant_id: "tenant-production".to_string(),
                    application_id: "broker-production".to_string(),
                    session_id: "broker-production-bootstrap".to_string(),
                    source_receipt_id: "broker-production-bootstrap-receipt".to_string(),
                    tool_id: "broker-production-secret-execute".to_string(),
                    issued_at_unix_ms: 1,
                    not_after_unix_ms: MAX_IJSON_INTEGER,
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
            admission_operation_database_path: directory.join("admission-operations.sqlite3"),
            budget_database_path: directory.join("budgets.sqlite3"),
            native_receipt_database_path,
            tripwire_tenant_id: TenantId::new("tenant-production")
                .unwrap_or_else(|error| panic!("tripwire tenant: {error}")),
        }
    }

    fn receipt_authority_tempdir() -> tempfile::TempDir {
        chio_test_support::private_fs::private_tempdir("control-plane-production-runtime-")
            .unwrap_or_else(|error| panic!("create production runtime directory: {error}"))
    }

    fn open_factory(
        config: ProductionSecurityRuntimeFactoryConfig,
        decoy_registry_master_key: [u8; 32],
    ) -> Result<ProductionSecurityRuntimeFactory, BrokerIntegrationError> {
        let budget_store = Arc::new(
            SqliteBudgetStore::open(&config.budget_database_path)
                .unwrap_or_else(|error| panic!("open shared budget store: {error}")),
        ) as Arc<dyn BudgetStore>;
        ProductionSecurityRuntimeFactory::open(config, decoy_registry_master_key, budget_store)
    }

    fn set_security_lifecycle_reconciliation_active(path: &Path) {
        let connection = rusqlite::Connection::open(path)
            .unwrap_or_else(|error| panic!("open lifecycle flags database: {error}"));
        connection
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET reconciliation_active = 1, live_dispatch_sealed = 0,
                    compaction_active = 0
                WHERE singleton = 1
                "#,
                [],
            )
            .unwrap_or_else(|error| panic!("set lifecycle flags: {error}"));
    }

    fn security_lifecycle_flags(path: &Path) -> (i64, i64, i64) {
        let connection = rusqlite::Connection::open(path)
            .unwrap_or_else(|error| panic!("open lifecycle flags database: {error}"));
        connection
            .query_row(
                r#"
                SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_declassification_lifecycle
                WHERE singleton = 1
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap_or_else(|error| panic!("read lifecycle flags: {error}"))
    }

    #[test]
    fn production_factory_denies_concurrent_security_state_owners_and_reopens_after_drop() {
        let directory = receipt_authority_tempdir();
        let first = open_factory(factory_config(directory.path()), [81_u8; 32])
            .unwrap_or_else(|error| panic!("open first factory: {error}"));

        let concurrent = open_factory(factory_config(directory.path()), [81_u8; 32])
            .err()
            .unwrap_or_else(|| panic!("concurrent factory acquired the security state lease"));
        assert!(matches!(concurrent, BrokerIntegrationError::Conflict(_)));

        drop(first);
        let restarted = open_factory(factory_config(directory.path()), [81_u8; 32])
            .unwrap_or_else(|error| panic!("reopen factory after clean drop: {error}"));
        drop(restarted);
    }

    #[test]
    fn production_factory_has_only_the_kernel_approval_ledger() {
        let directory = receipt_authority_tempdir();
        let config = factory_config(directory.path());
        let security_state_database_path = config.runtime.security_state_database_path.clone();
        let approval_database_path = config.runtime.approval_database_path.clone();

        let factory = open_factory(config, [82_u8; 32])
            .unwrap_or_else(|error| panic!("open production factory: {error}"));
        drop(factory);

        let read_table_names = |path: &std::path::Path| -> BTreeSet<String> {
            let connection = rusqlite::Connection::open(path)
                .unwrap_or_else(|error| panic!("open schema database {}: {error}", path.display()));
            let mut statement = connection
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                .unwrap_or_else(|error| {
                    panic!("prepare schema query for {}: {error}", path.display())
                });
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap_or_else(|error| panic!("query schema for {}: {error}", path.display()))
                .map(|row| {
                    row.unwrap_or_else(|error| {
                        panic!("read schema row for {}: {error}", path.display())
                    })
                })
                .collect()
        };

        let security_state_tables = read_table_names(&security_state_database_path);
        let approval_tables = read_table_names(&approval_database_path);
        let legacy_approval_table = concat!("security_response_", "approvals");
        let kernel_approval_table = "chio_hitl_operation_reservations";

        assert!(!security_state_tables.contains(legacy_approval_table));
        assert!(!security_state_tables.contains(kernel_approval_table));
        assert!(approval_tables.contains(kernel_approval_table));
        assert!(!approval_tables.contains(legacy_approval_table));
    }

    #[test]
    fn security_state_lifecycle_lease_rejects_hardlink_and_symlink_aliases() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let database_path = directory.path().join("security-state.sqlite3");
        let hardlink_path = directory.path().join("security-state-hardlink.sqlite3");
        let symlink_path = directory.path().join("security-state-symlink.sqlite3");
        let lease = RetainedSecurityStateLifecycleLease::acquire(&database_path)
            .unwrap_or_else(|error| panic!("acquire original lifecycle lease: {error}"));
        fs::hard_link(&database_path, &hardlink_path)
            .unwrap_or_else(|error| panic!("create hardlink alias: {error}"));
        std::os::unix::fs::symlink(&database_path, &symlink_path)
            .unwrap_or_else(|error| panic!("create symlink alias: {error}"));

        assert!(RetainedSecurityStateLifecycleLease::acquire(&hardlink_path).is_err());
        assert!(RetainedSecurityStateLifecycleLease::acquire(&symlink_path).is_err());
        drop(lease);
    }

    #[test]
    fn pre_open_path_swap_is_rejected_without_resetting_the_substituted_database() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let authoritative = directory.path().join("security-state.sqlite3");
        let retained = directory.path().join("security-state-retained.sqlite3");
        let substitute = directory.path().join("security-state-substitute.sqlite3");
        drop(
            SqliteSecurityStateStore::open(&authoritative)
                .unwrap_or_else(|error| panic!("create authoritative store: {error}")),
        );
        drop(
            SqliteSecurityStateStore::open(&substitute)
                .unwrap_or_else(|error| panic!("create substitute store: {error}")),
        );
        set_security_lifecycle_reconciliation_active(&substitute);

        let error =
            open_security_state_store_with_lifecycle_lease_after_acquire(&authoritative, || {
                fs::rename(&authoritative, &retained).map_err(|error| {
                    invalid(format!("retain locked database during path swap: {error}"))
                })?;
                fs::rename(&substitute, &authoritative).map_err(|error| {
                    invalid(format!(
                        "install substituted database during path swap: {error}"
                    ))
                })?;
                Ok(())
            })
            .err()
            .unwrap_or_else(|| panic!("path-swapped database passed lifecycle custody"));

        assert!(matches!(
            error,
            BrokerIntegrationError::InvalidConfiguration(_)
        ));
        assert_eq!(security_lifecycle_flags(&authoritative), (1, 0, 0));
    }

    const CRASH_LEASE_DIRECTORY_ENV: &str = "CHIO_SECURITY_LIFECYCLE_CRASH_DIRECTORY";
    const CRASH_LEASE_MARKER_ENV: &str = "CHIO_SECURITY_LIFECYCLE_CRASH_MARKER";

    #[test]
    fn security_state_lifecycle_lease_child_aborts() {
        let Some(directory) = std::env::var_os(CRASH_LEASE_DIRECTORY_ENV) else {
            return;
        };
        let marker = std::env::var_os(CRASH_LEASE_MARKER_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("crash lifecycle marker path is missing"));
        let factory = open_factory(factory_config(Path::new(&directory)), [82_u8; 32])
            .unwrap_or_else(|error| panic!("open crash-owner factory: {error}"));
        fs::write(&marker, b"locked")
            .unwrap_or_else(|error| panic!("write crash-owner marker: {error}"));
        std::hint::black_box(&factory);
        std::process::abort();
    }

    #[test]
    fn security_state_lifecycle_lease_is_recoverable_after_process_abort() {
        let directory = receipt_authority_tempdir();
        let marker = directory.path().join("lease-acquired.marker");
        let status = Command::new(
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("locate current test executable: {error}")),
        )
        .arg("--exact")
        .arg("security::production_runtime::tests::security_state_lifecycle_lease_child_aborts")
        .arg("--nocapture")
        .env(CRASH_LEASE_DIRECTORY_ENV, directory.path())
        .env(CRASH_LEASE_MARKER_ENV, &marker)
        .status()
        .unwrap_or_else(|error| panic!("run crash-owner child: {error}"));

        assert!(!status.success());
        assert!(marker.is_file());
        let recovered = open_factory(factory_config(directory.path()), [82_u8; 32])
            .unwrap_or_else(|error| panic!("take over lease after process abort: {error}"));
        drop(recovered);
    }

    fn test_runtime_policy_hash() -> String {
        hex::encode([0x4a_u8; 32])
    }

    fn test_kernel() -> chio_kernel::ChioKernel {
        chio_kernel::ChioKernel::new(chio_kernel::KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: test_runtime_policy_hash(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        })
    }

    fn unavailable_threshold_resolver(
    ) -> Arc<dyn chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver> {
        Arc::new(
            |_: &chio_core::capability::threshold_approval::ThresholdApprovalRequest,
             _: &str|
             -> Result<
                chio_core::capability::threshold_approval::ThresholdApprovalRequirement,
                chio_core::capability::threshold_approval::ThresholdApprovalResolutionError,
            > {
                Err(
                    chio_core::capability::threshold_approval::ThresholdApprovalResolutionError::Missing,
                )
            },
        )
    }

    fn security_context_capability(
        agent: &Keypair,
        id: &str,
        session_id: &str,
        principal_id: &str,
        lineage_id: &str,
        isolation_epoch_id: &str,
        context_generation: u64,
    ) -> CapabilityToken {
        let issuer = Keypair::from_seed(&[71_u8; 32]);
        CapabilityToken::sign_with_security_binding(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: agent.public_key(),
                scope: ChioScope::default(),
                issued_at: 1,
                expires_at: 1_000_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            chio_core::capability::caveat::CapabilitySecurityBinding {
                schema: chio_core::capability::caveat::CAPABILITY_SECURITY_BINDING_SCHEMA
                    .to_string(),
                tenant_id: "tenant-production".to_string(),
                lineage_id: lineage_id.to_string(),
                session_id: session_id.to_string(),
                principal_id: principal_id.to_string(),
                isolation_epoch_id: isolation_epoch_id.to_string(),
                context_generation,
                workload_id: "production-context-workload".to_string(),
                server_id: "server-production-context".to_string(),
                workload_signer_public_key: issuer.public_key().to_hex(),
            },
            &issuer,
        )
        .unwrap_or_else(|error| panic!("sign security context capability: {error}"))
    }

    fn security_context_operation(capability: CapabilityToken) -> ToolCallOperation {
        ToolCallOperation {
            capability,
            server_id: "server-production-context".to_string(),
            tool_name: "tool-production-context".to_string(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            execution_nonce: None,
            model_metadata: None,
            extra_metadata: None,
            declassification_grant: None,
        }
    }

    #[test]
    fn production_factory_retains_the_exact_live_manifest_registry_arc() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [7_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let manifests = Arc::new(chio_manifest::VerifiedManifestRegistry::default());
        let signing_key = Keypair::from_seed(&[8_u8; 32]);
        let signer =
            Arc::new(Ed25519Backend::new(signing_key)) as Arc<dyn chio_core::SigningBackend>;
        let lifecycle = factory
            .declassification_lifecycle(Arc::clone(&signer))
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .prepare_startup()
            .unwrap_or_else(|error| panic!("prepare lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let _worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let runtime = factory
            .build(
                Arc::clone(&manifests),
                signer,
                &test_runtime_policy_hash(),
            )
            .unwrap_or_else(|error| panic!("build production security runtime: {error}"));

        assert!(Arc::ptr_eq(runtime.manifests(), &manifests));
        assert!(runtime.durability().is_persistent());
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        assert!(matches!(
            lifecycle.prepare_startup(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        assert!(matches!(
            lifecycle.reconcile_and_drain_startup(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        drop(runtime);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiescent shutdown: {error}"));
    }

    #[test]
    fn post_release_worker_failure_closes_existing_and_new_lifecycle_admission() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [19_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[20_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let retained_kernel_lease = lifecycle
            .acquire_runtime_lease()
            .unwrap_or_else(|error| panic!("kernel runtime lease: {error}"));
        assert!(retained_kernel_lease.admission_is_open());

        worker.mark_failed_for_test();

        assert!(!retained_kernel_lease.admission_is_open());
        assert!(matches!(
            lifecycle.acquire_dispatch_recorder_lease(),
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        ));
        assert!(matches!(
            lifecycle.acquire_consumer_lease(),
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        ));
        drop(retained_kernel_lease);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close failed lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("restart reconciliation: {error}"));
        let restarted_worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("restart publication: {error}"));
        assert!(matches!(
            lifecycle.acquire_consumer_lease_for(&worker),
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        ));
        let current_consumer = lifecycle
            .acquire_consumer_lease_for(&restarted_worker)
            .unwrap_or_else(|error| panic!("current consumer lease: {error}"));
        drop(current_consumer);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close restarted lifecycle: {error}"));
    }

    #[test]
    fn pre_dispatch_commit_rechecks_lifecycle_after_inner_commit() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [88_u8; 32])
            .unwrap_or_else(|error| panic!("open pre-dispatch lifecycle factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[89_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("pre-dispatch lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile pre-dispatch lifecycle: {error}"));
        let ready = Arc::new(AtomicBool::new(true));
        let worker_port: Arc<dyn ResponseWorkerPort> = Arc::new(ToggleReadyLifecycleWorkerPort {
            ready: Arc::clone(&ready),
        });
        let worker = Arc::new(
            ProductionResponseWorker::new(worker_port)
                .unwrap_or_else(|error| panic!("create pre-dispatch lifecycle worker: {error}")),
        );
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("bind pre-dispatch lifecycle worker: {error}"));
        worker
            .mark_publication_released_for_test()
            .unwrap_or_else(|error| panic!("release pre-dispatch lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish pre-dispatch lifecycle: {error}"));

        let commits = Arc::new(AtomicUsize::new(0));
        let recorder_drops = Arc::new(AtomicUsize::new(0));
        let dispatch_failures = Arc::new(AtomicUsize::new(0));
        let port: Arc<dyn FlowPreDispatchPort> = Arc::new(WorkerFailingFlowPreDispatchPort {
            ready: Arc::clone(&ready),
            commits: Arc::clone(&commits),
            recorder_drops: Arc::clone(&recorder_drops),
            dispatch_failures: Arc::clone(&dispatch_failures),
        });
        let leased = LeasedProductionFlowPreDispatchPort::new(port, lifecycle.clone());
        let security_context = flow_pre_dispatch_test_security_context();
        let request = flow_pre_dispatch_test_request();
        let canonical_request = canonical_json_bytes(&request)
            .unwrap_or_else(|error| panic!("canonical pre-dispatch request: {error}"));
        let dispatch_commitment_id = RecordId::new("pre-dispatch-lifecycle-commitment")
            .unwrap_or_else(|error| panic!("pre-dispatch commitment: {error}"));

        let result = leased.commit(&FlowPreDispatchInput {
            security_context: &security_context,
            request: &request,
            canonical_request: &canonical_request,
            dispatch_commitment_id: &dispatch_commitment_id,
        });

        assert!(matches!(
            result,
            Err(FlowDenial::DeclassificationStoreFailure)
        ));
        assert_eq!(commits.load(Ordering::Acquire), 1);
        assert!(!ready.load(Ordering::Acquire));
        assert_eq!(dispatch_failures.load(Ordering::Acquire), 1);
        assert_eq!(recorder_drops.load(Ordering::Acquire), 1);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close pre-dispatch lifecycle: {error}"));
    }

    #[test]
    fn dispatch_outcome_store_failure_closes_runtime_admission_until_reconciliation() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [96_u8; 32])
            .unwrap_or_else(|error| panic!("open outcome failure factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[97_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("outcome failure lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile outcome failure lifecycle: {error}"));
        let worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish outcome failure lifecycle: {error}"));
        let lease = lifecycle
            .acquire_dispatch_recorder_lease()
            .unwrap_or_else(|error| panic!("outcome failure lease: {error}"));
        let mut recorder = LeasedProductionFlowDispatchOutcomeRecorder {
            inner: Box::new(FailingFlowDispatchOutcomeRecorder),
            lease: Some(lease),
            lifecycle: lifecycle.clone(),
        };

        assert!(matches!(
            recorder.record(DeclassificationDispatchOutcome::Released),
            Err(FlowDenial::DeclassificationStoreFailure)
        ));
        assert!(matches!(
            lifecycle.ensure_runtime_admission_open(),
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
        ));
        drop(recorder);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiesce outcome failure lifecycle: {error}"));
        drop(worker);
    }

    #[test]
    fn request_lifecycle_permit_gates_final_release_and_quiesces_on_drop() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [93_u8; 32])
            .unwrap_or_else(|error| panic!("open request lifecycle factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[94_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("request lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile request lifecycle: {error}"));
        let ready = Arc::new(AtomicBool::new(true));
        let worker_port: Arc<dyn ResponseWorkerPort> = Arc::new(ToggleReadyLifecycleWorkerPort {
            ready: Arc::clone(&ready),
        });
        let worker = Arc::new(
            ProductionResponseWorker::new(worker_port)
                .unwrap_or_else(|error| panic!("create request lifecycle worker: {error}")),
        );
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("bind request lifecycle worker: {error}"));
        worker
            .mark_publication_released_for_test()
            .unwrap_or_else(|error| panic!("release request lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish request lifecycle: {error}"));

        let port: Arc<dyn FlowPreDispatchPort> = Arc::new(EmptyFlowPreDispatchPort);
        let leased = LeasedProductionFlowPreDispatchPort::new(port, lifecycle.clone());
        let security_context = flow_pre_dispatch_test_security_context();
        let request = flow_pre_dispatch_test_request();
        let canonical_request = canonical_json_bytes(&request)
            .unwrap_or_else(|error| panic!("canonical request lifecycle request: {error}"));
        let dispatch_commitment_id = RecordId::new("request-lifecycle-commitment")
            .unwrap_or_else(|error| panic!("request lifecycle commitment: {error}"));
        let input = FlowPreDispatchInput {
            security_context: &security_context,
            request: &request,
            canonical_request: &canonical_request,
            dispatch_commitment_id: &dispatch_commitment_id,
        };

        let retained_sibling_permit = leased
            .acquire_request_lifecycle(&input)
            .unwrap_or_else(|error| panic!("acquire retained sibling request permit: {error:?}"))
            .unwrap_or_else(|| panic!("retained sibling request lifecycle permit is missing"));
        let release_first_permit = leased
            .acquire_request_lifecycle(&input)
            .unwrap_or_else(|error| panic!("acquire release-first request permit: {error:?}"))
            .unwrap_or_else(|| panic!("release-first request lifecycle permit is missing"));
        release_first_permit
            .ensure_final_release()
            .unwrap_or_else(|error| panic!("linearize release before close: {error}"));
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(1))
        ));
        drop(retained_sibling_permit);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close after retained sibling drop: {error}"));

        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("restart close-first request lifecycle: {error}"));
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("rebind close-first request lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("republish close-first request lifecycle: {error}"));
        let closed_permit = leased
            .acquire_request_lifecycle(&input)
            .unwrap_or_else(|error| panic!("acquire closed request permit: {error:?}"))
            .unwrap_or_else(|| panic!("production request lifecycle permit is missing"));
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(1))
        ));
        assert!(matches!(
            closed_permit.ensure_final_release(),
            Err(KernelError::GuardDenied(ref reason))
                if reason == RUNTIME_ADMISSION_CLOSED_REASON
        ));
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiesce closed request permit: {error}"));

        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("restart request lifecycle: {error}"));
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("rebind request lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("republish request lifecycle: {error}"));
        let failed_worker_permit = leased
            .acquire_request_lifecycle(&input)
            .unwrap_or_else(|error| panic!("acquire worker-failure request permit: {error:?}"))
            .unwrap_or_else(|| panic!("worker-failure request lifecycle permit is missing"));
        ready.store(false, Ordering::Release);
        assert!(matches!(
            failed_worker_permit.ensure_final_release(),
            Err(KernelError::GuardDenied(ref reason))
                if reason == RUNTIME_ADMISSION_CLOSED_REASON
        ));
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiesce worker-failure request permit: {error}"));

        ready.store(true, Ordering::Release);
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("restart dropped request lifecycle: {error}"));
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("rebind dropped request lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("republish dropped request lifecycle: {error}"));
        let cancelled_permit = leased
            .acquire_request_lifecycle(&input)
            .unwrap_or_else(|error| panic!("acquire cancelled request permit: {error:?}"))
            .unwrap_or_else(|| panic!("cancelled request lifecycle permit is missing"));
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(1))
        ));
        drop(cancelled_permit);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiesce cancelled request permit: {error}"));
    }

    #[test]
    fn installed_executor_denies_new_effects_after_close_or_worker_failure() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [90_u8; 32])
            .unwrap_or_else(|error| panic!("open executor lifecycle factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[91_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("executor lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile executor lifecycle: {error}"));
        let worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish executor lifecycle: {error}"));

        let identity = ActiveResponseExecutorAuthorityIdentity::new(
            Keypair::from_seed(&[92_u8; 32]).public_key(),
            7,
        )
        .unwrap_or_else(|error| panic!("executor identity: {error}"));
        let readiness_checks = Arc::new(AtomicUsize::new(0));
        let executions = Arc::new(AtomicUsize::new(0));
        let inner: Arc<dyn ActiveResponseExecutorAuthority> =
            Arc::new(CountingActiveResponseExecutorAuthority {
                identity: identity.clone(),
                readiness_checks: Arc::clone(&readiness_checks),
                executions: Arc::clone(&executions),
            });
        let wrapper = Arc::new(
            LifecycleCheckedProductionActiveResponseExecutorAuthority::new(
                inner,
                lifecycle.clone(),
            ),
        );
        let installed: Arc<dyn ActiveResponseExecutorAuthority> = wrapper.clone();
        assert_eq!(installed.identity(), identity);
        installed
            .ensure_ready()
            .unwrap_or_else(|error| panic!("installed executor readiness: {error}"));
        let readiness_before_close = readiness_checks.load(Ordering::Acquire);

        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close executor lifecycle: {error}"));
        let effects = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            wrapper.execute_with_lifecycle(|_| {
                effects.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }),
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(_))
        ));
        assert_eq!(effects.load(Ordering::Acquire), 0);
        assert!(matches!(
            installed.ensure_ready(),
            Err(ActiveResponseExecutorError::NotReady(_))
        ));
        assert_eq!(
            readiness_checks.load(Ordering::Acquire),
            readiness_before_close
        );

        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("restart executor lifecycle: {error}"));
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("rebind executor lifecycle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("republish executor lifecycle: {error}"));
        assert!(matches!(
            wrapper.execute_with_lifecycle(|_| {
                effects.fetch_add(1, Ordering::AcqRel);
                worker.mark_failed_for_test();
                Ok(())
            }),
            Err(ActiveResponseExecutorError::OutcomeUnknown(_))
        ));
        assert_eq!(effects.load(Ordering::Acquire), 1);
        let readiness_after_failure = readiness_checks.load(Ordering::Acquire);
        assert!(matches!(
            wrapper.execute_with_lifecycle(|_| {
                effects.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }),
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(_))
        ));
        assert_eq!(effects.load(Ordering::Acquire), 1);
        assert!(matches!(
            installed.ensure_ready(),
            Err(ActiveResponseExecutorError::NotReady(_))
        ));
        assert_eq!(
            readiness_checks.load(Ordering::Acquire),
            readiness_after_failure
        );
        assert_eq!(executions.load(Ordering::Acquire), 0);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close failed executor lifecycle: {error}"));
    }

    #[test]
    fn late_security_state_hardlink_permanently_closes_effective_admission() {
        let directory = receipt_authority_tempdir();
        let config = factory_config(directory.path());
        let security_state_path = config.runtime.security_state_database_path.clone();
        let hardlink_path = directory
            .path()
            .join("late-security-state-hardlink.sqlite3");
        let factory = open_factory(config, [85_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[86_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let _worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let retained_runtime = lifecycle
            .acquire_runtime_lease()
            .unwrap_or_else(|error| panic!("retain installed runtime: {error}"));

        fs::hard_link(&security_state_path, &hardlink_path)
            .unwrap_or_else(|error| panic!("create late hardlink: {error}"));
        assert!(!retained_runtime.admission_is_open());
        assert!(matches!(
            lifecycle.acquire_consumer_lease(),
            Err(ResponseWorkerTickError::RuntimeAdmissionClosed)
                | Err(ResponseWorkerTickError::Port(_))
        ));
        fs::remove_file(&hardlink_path)
            .unwrap_or_else(|error| panic!("remove late hardlink: {error}"));
        assert!(!retained_runtime.admission_is_open());

        drop(retained_runtime);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close ownership-failed lifecycle: {error}"));
    }

    #[test]
    fn worker_failure_during_post_invocation_blocks_output_after_mutation() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [83_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[84_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let ready = Arc::new(AtomicBool::new(true));
        let worker_port: Arc<dyn ResponseWorkerPort> = Arc::new(ToggleReadyLifecycleWorkerPort {
            ready: Arc::clone(&ready),
        });
        let worker = Arc::new(
            ProductionResponseWorker::new(worker_port)
                .unwrap_or_else(|error| panic!("create toggle worker: {error}")),
        );
        lifecycle
            .bind_worker(&worker)
            .unwrap_or_else(|error| panic!("bind toggle worker: {error}"));
        worker
            .mark_publication_released_for_test()
            .unwrap_or_else(|error| panic!("release toggle worker: {error}"));
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let retained_runtime = lifecycle
            .acquire_runtime_lease()
            .unwrap_or_else(|error| panic!("retain installed runtime: {error}"));
        let mutations = Arc::new(AtomicUsize::new(0));
        let hook = LifecycleCheckedProductionPostInvocationHook::new(
            Box::new(MutatingWorkerFailurePostHook {
                ready: Arc::clone(&ready),
                mutations: Arc::clone(&mutations),
            }),
            lifecycle.clone(),
        );

        let inspection = hook.inspect_with_evidence(
            &PostInvocationContext::synthetic("security-output"),
            &serde_json::json!({"secret": "must-not-release"}),
        );

        assert_eq!(mutations.load(Ordering::Acquire), 1);
        assert!(matches!(
            inspection.verdict,
            PostInvocationVerdict::Block(ref reason)
                if reason == RUNTIME_ADMISSION_CLOSED_REASON
        ));
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        drop(retained_runtime);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("close after installed runtime drop: {error}"));
    }

    #[test]
    fn enforce_kernel_install_retains_first_response_kernel_and_runtime_lease() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [9_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[10_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(Arc::clone(&signer))
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .prepare_startup()
            .unwrap_or_else(|error| panic!("prepare lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let _worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let runtime = factory
            .build(
                Arc::new(chio_manifest::VerifiedManifestRegistry::default()),
                Arc::clone(&signer),
                &test_runtime_policy_hash(),
            )
            .unwrap_or_else(|error| panic!("build production security runtime: {error}"));
        let mut kernel = test_kernel();
        factory
            .install_kernel_authorities_before_publication(&mut kernel)
            .unwrap_or_else(|error| panic!("install kernel authorities: {error}"));
        let submission_authority = Keypair::from_seed(&[17_u8; 32]).public_key();
        kernel
            .set_active_response_submission_authority(submission_authority.clone())
            .unwrap_or_else(|error| panic!("install response submission authority: {error}"));
        let policy_authority = Keypair::from_seed(&[11_u8; 32]).public_key();

        super::super::runtime::install_security_runtime(
            &mut kernel,
            super::super::runtime::ActiveDefenseMode::Enforce,
            Some(runtime),
            Some(unavailable_threshold_resolver()),
            vec![policy_authority.clone()],
            chio_guards::default_runtime_guard_profile(),
            chio_guards::GuardPipeline::new(),
            chio_kernel::PostInvocationPipeline::new(),
        )
        .unwrap_or_else(|error| panic!("install governed security runtime: {error}"));

        assert!(kernel.has_installed_flow_runtime());
        let executor_authority = kernel
            .governed_security_runtime_status()
            .executor_authority
            .unwrap_or_else(|| panic!("installed executor authority is missing"));
        let coordinator = KernelAttestedFindingResponseCoordinator::new_unbound(
            executor_authority,
            Arc::clone(&factory.clock),
        );
        assert_eq!(
            rejected(
                coordinator.ensure_ready(),
                "unbound coordinator must fail closed",
            )
                .kind(),
            PortErrorKind::Unavailable
        );
        let kernel = Arc::new(kernel);
        let mismatched_coordinator = KernelAttestedFindingResponseCoordinator::new_unbound(
            ActiveResponseExecutorAuthorityIdentity::new(
                Keypair::from_seed(&[12_u8; 32]).public_key(),
                1,
            )
            .unwrap_or_else(|error| panic!("mismatched executor identity: {error}")),
            Arc::clone(&factory.clock),
        );
        assert_eq!(
            rejected(
                mismatched_coordinator.bind_kernel(Arc::clone(&kernel)),
                "coordinator must reject a different executor authority",
            )
                .kind(),
            PortErrorKind::Unavailable
        );
        coordinator
            .bind_kernel(Arc::clone(&kernel))
            .unwrap_or_else(|error| panic!("bind exact response kernel: {error}"));
        coordinator
            .ensure_ready()
            .unwrap_or_else(|error| panic!("bound response coordinator: {error}"));
        coordinator
            .bind_kernel(Arc::clone(&kernel))
            .unwrap_or_else(|error| panic!("idempotent exact kernel bind: {error}"));
        let equivalent_runtime = factory
            .build(
                Arc::new(chio_manifest::VerifiedManifestRegistry::default()),
                signer,
                &test_runtime_policy_hash(),
            )
            .unwrap_or_else(|error| panic!("build equivalent security runtime: {error}"));
        let mut equivalent_kernel = test_kernel();
        factory
            .install_kernel_authorities_before_publication(&mut equivalent_kernel)
            .unwrap_or_else(|error| panic!("install equivalent kernel authorities: {error}"));
        equivalent_kernel
            .set_active_response_submission_authority(submission_authority)
            .unwrap_or_else(|error| {
                panic!("install equivalent response submission authority: {error}")
            });
        super::super::runtime::install_security_runtime(
            &mut equivalent_kernel,
            super::super::runtime::ActiveDefenseMode::Enforce,
            Some(equivalent_runtime),
            Some(unavailable_threshold_resolver()),
            vec![policy_authority],
            chio_guards::default_runtime_guard_profile(),
            chio_guards::GuardPipeline::new(),
            chio_kernel::PostInvocationPipeline::new(),
        )
        .unwrap_or_else(|error| panic!("install equivalent governed runtime: {error}"));
        let equivalent_kernel = Arc::new(equivalent_kernel);
        assert_eq!(
            rejected(
                coordinator.bind_kernel(Arc::clone(&equivalent_kernel)),
                "an equivalent kernel cannot replace the retained kernel",
            )
                .kind(),
            PortErrorKind::Conflict
        );
        assert!(coordinator
            .retains_kernel(&kernel)
            .unwrap_or_else(|error| panic!("inspect retained response kernel: {error}")));
        assert!(!coordinator
            .retains_kernel(&equivalent_kernel)
            .unwrap_or_else(|error| panic!("inspect equivalent session kernel: {error}")));
        drop(equivalent_kernel);
        let foreign = Arc::new(test_kernel());
        assert_eq!(
            rejected(
                coordinator.bind_kernel(foreign),
                "coordinator must reject an unready session kernel",
            )
                .kind(),
            PortErrorKind::Unavailable
        );
        let dispatch_lease = lifecycle
            .acquire_dispatch_recorder_lease()
            .unwrap_or_else(|error| panic!("dispatch recorder lease: {error}"));
        let mut recorder = LeasedProductionFlowDispatchOutcomeRecorder {
            inner: Box::new(SuccessfulFlowDispatchOutcomeRecorder),
            lease: Some(dispatch_lease),
            lifecycle: lifecycle.clone(),
        };
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        drop(coordinator);
        drop(kernel);
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(1))
        ));
        assert!(matches!(
            lifecycle.reconcile_and_drain_startup(),
            Err(ResponseWorkerTickError::DispatchRecorderLeasesActive(1))
        ));
        recorder
            .record(DeclassificationDispatchOutcome::Released)
            .unwrap_or_else(|error| panic!("record dispatch outcome: {error}"));
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiescent shutdown after kernel drop: {error}"));
    }

    #[test]
    fn live_consumer_lease_closes_admission_and_blocks_shutdown_and_reconciliation() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [15_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[16_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(signer)
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let _worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let consumer_lease = lifecycle
            .acquire_consumer_lease()
            .unwrap_or_else(|error| panic!("consumer lease: {error}"));

        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::ConsumerLeasesActive(1))
        ));
        assert!(matches!(
            lifecycle.reconcile_and_drain_startup(),
            Err(ResponseWorkerTickError::ConsumerLeasesActive(1))
        ));
        drop(consumer_lease);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiescent consumer shutdown: {error}"));
    }

    #[test]
    fn shadow_kernel_retains_observation_lease_without_declassification_hook() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [13_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[14_u8; 32])));
        let lifecycle = factory
            .declassification_lifecycle(Arc::clone(&signer))
            .unwrap_or_else(|error| panic!("declassification lifecycle: {error}"));
        lifecycle
            .prepare_startup()
            .unwrap_or_else(|error| panic!("prepare lifecycle: {error}"));
        lifecycle
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("reconcile lifecycle: {error}"));
        let _worker = bind_ready_lifecycle_worker(&lifecycle);
        lifecycle
            .publish_runtime_admission()
            .unwrap_or_else(|error| panic!("publish lifecycle: {error}"));
        let runtime = factory
            .build(
                Arc::new(chio_manifest::VerifiedManifestRegistry::default()),
                signer,
                &test_runtime_policy_hash(),
            )
            .unwrap_or_else(|error| panic!("build production security runtime: {error}"));
        let mut kernel = test_kernel();

        super::super::runtime::install_security_runtime(
            &mut kernel,
            super::super::runtime::ActiveDefenseMode::Shadow,
            Some(runtime),
            None,
            Vec::new(),
            chio_guards::default_runtime_guard_profile(),
            chio_guards::GuardPipeline::new(),
            chio_kernel::PostInvocationPipeline::new(),
        )
        .unwrap_or_else(|error| panic!("install shadow security runtime: {error}"));

        assert_eq!(
            kernel.security_pre_dispatch_policy(),
            chio_kernel::SecurityPreDispatchPolicy::Optional
        );
        assert!(kernel.security_pre_dispatch_hook_name().is_none());
        assert!(matches!(
            lifecycle.close_runtime_admission(),
            Err(ResponseWorkerTickError::RuntimeLeasesActive(1))
        ));
        drop(kernel);
        lifecycle
            .close_runtime_admission()
            .unwrap_or_else(|error| panic!("quiescent shutdown after shadow kernel drop: {error}"));
    }

    #[test]
    fn production_factory_reuses_one_declassification_store_and_receipt_sink_authority() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [31_u8; 32])
            .unwrap_or_else(|error| panic!("open production security factory: {error}"));
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[32_u8; 32])));

        let first = factory
            .declassification_lifecycle(Arc::clone(&signer))
            .unwrap_or_else(|error| panic!("first lifecycle: {error}"));
        let second = factory
            .declassification_lifecycle(Arc::clone(&signer))
            .unwrap_or_else(|error| panic!("second lifecycle: {error}"));
        let first_sink = first.receipt_sink();
        let second_sink = second.receipt_sink();
        let indexed_store: Arc<dyn IndexedSecurityEvidenceStore> = factory.receipt_store.clone();

        assert!(Arc::ptr_eq(&first_sink, &second_sink));
        first
            .ensure_authority(
                &factory.security_state_authority,
                &indexed_store,
                &signer,
                &factory.clock,
            )
            .unwrap_or_else(|error| panic!("exact authority: {error}"));
        let foreign_clock: Arc<dyn SecurityClock> = Arc::new(SystemSecurityClock);
        assert!(first
            .ensure_authority(
                &factory.security_state_authority,
                &indexed_store,
                &signer,
                &foreign_clock,
            )
            .is_err());

        let same_key_distinct_custody: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[32_u8; 32])));
        assert_eq!(signer.public_key(), same_key_distinct_custody.public_key());
        assert!(!Arc::ptr_eq(&signer, &same_key_distinct_custody));
        assert!(factory
            .declassification_lifecycle(same_key_distinct_custody)
            .is_err());

        let foreign_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[33_u8; 32])));
        assert!(factory.declassification_lifecycle(foreign_signer).is_err());
    }

    #[test]
    fn production_security_context_authority_preserves_taint_and_reloads_generation() {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [72_u8; 32])
            .unwrap_or_else(|error| panic!("open security context factory: {error}"));
        let agent = Keypair::from_seed(&[73_u8; 32]);
        let agent_id = agent.public_key().to_hex();
        let principal_id = "oauth-subject-production-context";
        let lineage_id = "lineage-production-context-root";
        let isolation_epoch_id = "isolation-production-context-incarnation";
        let capability_generation = 7;
        let capability = security_context_capability(
            &agent,
            "cap-production-context-a",
            "kernel-session-a",
            principal_id,
            lineage_id,
            isolation_epoch_id,
            capability_generation,
        );
        let authority = factory
            .security_invocation_context_authority(
                None,
                &agent_id,
                std::slice::from_ref(&capability),
            )
            .unwrap_or_else(|error| panic!("build security context authority: {error}"));
        let first_context = OperationContext::new(
            KernelSessionId::new("kernel-session-a"),
            KernelRequestId::new("kernel-request-a"),
            agent_id.clone(),
        );
        let operation = security_context_operation(capability.clone());
        let first = authority
            .resolve_security_invocation_context(&first_context, &operation)
            .unwrap_or_else(|error| panic!("resolve first security context: {error}"));
        let first = first.as_v1();
        assert_eq!(first.tenant_id().as_str(), "tenant-production");
        assert_eq!(first.session_id().as_str(), "kernel-session-a");
        assert_eq!(first.principal_id().as_str(), principal_id);
        assert_eq!(first.lineage_root_id().as_str(), lineage_id);
        assert_eq!(first.isolation_epoch_id().as_str(), isolation_epoch_id);
        assert_eq!(first.context_generation(), capability_generation);
        let first_flow_generation = first
            .flow_state_generation()
            .unwrap_or_else(|| panic!("production context omitted flow-state generation"));

        let first_key = FlowStateKey {
            tenant_id: first.tenant_id().clone(),
            principal_id: first.principal_id().clone(),
            lineage_id: first.lineage_root_id().clone(),
            session_id: first.session_id().clone(),
            isolation_epoch_id: first.isolation_epoch_id().clone(),
        };
        let restricted = InformationLabel::try_known(
            BTreeMap::from([(
                first.principal_id().clone(),
                BTreeSet::from([first.principal_id().clone()]),
            )]),
            BTreeSet::new(),
        )
        .unwrap_or_else(|error| panic!("build restricted principal label: {error}"));
        factory
            .security_store
            .join(&FlowJoinRequest {
                key: first_key,
                principal_join: restricted.clone(),
                lineage_join: restricted.clone(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("production-context-taint")
                    .unwrap_or_else(|error| panic!("taint transition: {error}")),
            })
            .unwrap_or_else(|error| panic!("persist principal taint: {error:?}"));

        let restored_authority = factory
            .security_invocation_context_authority(
                Some("tenant-production"),
                &agent_id,
                std::slice::from_ref(&capability),
            )
            .unwrap_or_else(|error| panic!("rebuild restored security context authority: {error}"));
        let restored_context = OperationContext::new(
            KernelSessionId::new("kernel-session-a"),
            KernelRequestId::new("kernel-request-restored"),
            agent_id.clone(),
        );
        let restored = restored_authority
            .resolve_security_invocation_context(
                &restored_context,
                &security_context_operation(capability.clone()),
            )
            .unwrap_or_else(|error| panic!("resolve restored security context: {error}"));
        assert_eq!(restored.as_v1().session_id(), first.session_id());
        assert_eq!(restored.as_v1().lineage_root_id(), first.lineage_root_id());
        assert_eq!(
            restored.as_v1().context_generation(),
            first.context_generation()
        );
        assert!(
            restored
                .as_v1()
                .flow_state_generation()
                .unwrap_or_else(|| panic!("restored context omitted flow-state generation"))
                > first_flow_generation
        );

        let second_capability = security_context_capability(
            &agent,
            "cap-production-context-b",
            "kernel-session-b",
            principal_id,
            lineage_id,
            isolation_epoch_id,
            capability_generation,
        );
        let second_authority = factory
            .security_invocation_context_authority(
                Some("tenant-production"),
                &agent_id,
                std::slice::from_ref(&second_capability),
            )
            .unwrap_or_else(|error| panic!("build second security context authority: {error}"));
        let second_operation = security_context_operation(second_capability);
        let second_context = OperationContext::new(
            KernelSessionId::new("kernel-session-b"),
            KernelRequestId::new("kernel-request-b"),
            agent_id.clone(),
        );
        let second = second_authority
            .resolve_security_invocation_context(&second_context, &second_operation)
            .unwrap_or_else(|error| panic!("resolve second security context: {error}"));
        let second = second.as_v1();
        assert_eq!(second.isolation_epoch_id(), first.isolation_epoch_id());
        assert_eq!(second.lineage_root_id(), first.lineage_root_id());
        assert_ne!(second.session_id(), first.session_id());
        let second_key = FlowStateKey {
            tenant_id: second.tenant_id().clone(),
            principal_id: second.principal_id().clone(),
            lineage_id: second.lineage_root_id().clone(),
            session_id: second.session_id().clone(),
            isolation_epoch_id: second.isolation_epoch_id().clone(),
        };
        let persisted = factory
            .security_store
            .load(&second_key)
            .unwrap_or_else(|error| panic!("load second flow state: {error:?}"))
            .unwrap_or_else(|| panic!("second flow state is missing"));
        assert_eq!(persisted.principal_label, restricted);
        assert_eq!(persisted.lineage_label, restricted);

        let updated = factory
            .security_store
            .join(&FlowJoinRequest {
                key: second_key,
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("production-context-generation-refresh")
                    .unwrap_or_else(|error| panic!("refresh transition: {error}")),
            })
            .unwrap_or_else(|error| panic!("refresh flow generation: {error:?}"));
        let refreshed = second_authority
            .resolve_security_invocation_context(&second_context, &second_operation)
            .unwrap_or_else(|error| panic!("reload security context generation: {error}"));
        assert_eq!(
            refreshed.as_v1().context_generation(),
            capability_generation
        );
        assert_eq!(
            refreshed.as_v1().flow_state_generation(),
            Some(updated.context_generation)
        );
    }

    #[test]
    fn production_security_context_authority_rejects_tenant_principal_capability_and_session_mismatch(
    ) {
        let directory = receipt_authority_tempdir();
        let factory = open_factory(factory_config(directory.path()), [74_u8; 32])
            .unwrap_or_else(|error| panic!("open mismatch factory: {error}"));
        let agent = Keypair::from_seed(&[75_u8; 32]);
        let agent_id = agent.public_key().to_hex();
        let capability = security_context_capability(
            &agent,
            "cap-production-mismatch-tenant",
            "kernel-session-tenant",
            "principal-production-mismatch",
            "lineage-production-mismatch",
            "isolation-production-mismatch",
            3,
        );
        assert!(factory
            .security_invocation_context_authority(
                Some("tenant-foreign"),
                &agent_id,
                std::slice::from_ref(&capability),
            )
            .is_err());

        let principal_capability = security_context_capability(
            &agent,
            "cap-production-mismatch-principal",
            "kernel-session-principal",
            "principal-production-mismatch",
            "lineage-production-mismatch",
            "isolation-production-mismatch",
            3,
        );
        let principal_authority = factory
            .security_invocation_context_authority(
                None,
                &agent_id,
                std::slice::from_ref(&principal_capability),
            )
            .unwrap_or_else(|error| panic!("build principal authority: {error}"));
        let wrong_principal = OperationContext::new(
            KernelSessionId::new("kernel-session-principal"),
            KernelRequestId::new("kernel-request-principal"),
            Keypair::from_seed(&[76_u8; 32]).public_key().to_hex(),
        );
        assert!(matches!(
            principal_authority.resolve_security_invocation_context(
                &wrong_principal,
                &security_context_operation(principal_capability)
            ),
            Err(KernelError::GuardDenied(_))
        ));

        let capability = security_context_capability(
            &agent,
            "cap-production-mismatch-capability",
            "kernel-session-capability",
            "principal-production-mismatch",
            "lineage-production-mismatch",
            "isolation-production-mismatch",
            3,
        );
        let capability_authority = factory
            .security_invocation_context_authority(
                None,
                &agent_id,
                std::slice::from_ref(&capability),
            )
            .unwrap_or_else(|error| panic!("build capability authority: {error}"));
        let valid_context = OperationContext::new(
            KernelSessionId::new("kernel-session-capability"),
            KernelRequestId::new("kernel-request-capability"),
            agent_id.clone(),
        );
        let mut foreign_capability = capability.clone();
        foreign_capability.id = "cap-production-foreign".to_string();
        assert!(matches!(
            capability_authority.resolve_security_invocation_context(
                &valid_context,
                &security_context_operation(foreign_capability)
            ),
            Err(KernelError::GuardDenied(_))
        ));

        let session_capability = security_context_capability(
            &agent,
            "cap-production-mismatch-session",
            "kernel-session-bound",
            "principal-production-mismatch",
            "lineage-production-mismatch",
            "isolation-production-mismatch",
            3,
        );
        let session_authority = factory
            .security_invocation_context_authority(
                None,
                &agent_id,
                std::slice::from_ref(&session_capability),
            )
            .unwrap_or_else(|error| panic!("build session authority: {error}"));
        session_authority
            .resolve_security_invocation_context(
                &OperationContext::new(
                    KernelSessionId::new("kernel-session-bound"),
                    KernelRequestId::new("kernel-request-bound"),
                    agent_id.clone(),
                ),
                &security_context_operation(session_capability.clone()),
            )
            .unwrap_or_else(|error| panic!("bind security session: {error}"));
        assert!(matches!(
            session_authority.resolve_security_invocation_context(
                &OperationContext::new(
                    KernelSessionId::new("kernel-session-crossed"),
                    KernelRequestId::new("kernel-request-crossed"),
                    agent_id,
                ),
                &security_context_operation(session_capability)
            ),
            Err(KernelError::GuardDenied(_))
        ));
    }

    #[test]
    fn production_factory_rejects_aliased_authorities_and_empty_classifier_policy() {
        let directory = receipt_authority_tempdir();
        let mut aliased = factory_config(directory.path());
        aliased.runtime.approval_database_path =
            aliased.runtime.security_state_database_path.clone();
        assert!(open_factory(aliased, [9_u8; 32]).is_err());

        let mut empty_classifier = factory_config(directory.path());
        empty_classifier.runtime.classification_rules.clear();
        assert!(open_factory(empty_classifier, [10_u8; 32]).is_err());
    }
