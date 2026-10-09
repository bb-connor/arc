use super::super::cluster::{build_cluster_state, run_cluster_sync_loop};
use super::super::*;
use super::router;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[path = "init/payload_maintenance.rs"]
mod payload_maintenance;

pub(crate) async fn serve_async(
    config: TrustServiceConfig,
    injected_joint_authority_store: Option<Arc<SqliteAuthorityStore>>,
    finding_rail: Option<Arc<dyn super::super::finding_handlers::FindingRailObserver>>,
    finding_purchase_executor: Option<
        super::super::finding_purchase_routes::SharedFindingPurchaseExecutor,
    >,
    finding_seller_submission_executor: Option<
        super::super::finding_operator_seller_routes::SharedFindingSellerSubmissionExecutor,
    >,
    finding_authority_status_resolver: Option<
        Arc<dyn super::super::finding_challenge_coordinator::FindingAuthorityStatusResolver>,
    >,
    finding_challenge_executor: Option<
        Arc<dyn super::super::finding_challenge_handlers::FindingChallengeSubmissionExecutor>,
    >,
) -> Result<(), CliError> {
    serve_async_inner(
        config,
        injected_joint_authority_store,
        finding_rail,
        finding_purchase_executor,
        finding_seller_submission_executor,
        finding_authority_status_resolver,
        finding_challenge_executor,
    )
    .await
}

async fn serve_async_inner(
    config: TrustServiceConfig,
    injected_joint_authority_store: Option<Arc<SqliteAuthorityStore>>,
    finding_rail: Option<Arc<dyn super::super::finding_handlers::FindingRailObserver>>,
    finding_purchase_executor: Option<
        super::super::finding_purchase_routes::SharedFindingPurchaseExecutor,
    >,
    finding_seller_submission_executor: Option<
        super::super::finding_operator_seller_routes::SharedFindingSellerSubmissionExecutor,
    >,
    finding_authority_status_resolver: Option<
        Arc<dyn super::super::finding_challenge_coordinator::FindingAuthorityStatusResolver>,
    >,
    finding_challenge_executor: Option<
        Arc<dyn super::super::finding_challenge_handlers::FindingChallengeSubmissionExecutor>,
    >,
) -> Result<(), CliError> {
    config.validate()?;
    let payload_maintenance_config = crate::TerminalPayloadMaintenanceConfig::from_env()?;
    payload_maintenance::validate_requested_authority(
        config.joint_authority_db_path.as_deref(),
        payload_maintenance_config,
    )?;
    let transport = crate::server_transport::prepare(&config.transport, config.listen)?;
    let authority_keyring_seed_path = config
        .authority_keyring_config_path
        .as_ref()
        .and(config.authority_seed_path.clone());
    // Keyring custody owns the anchored receipt store; handlers share that same
    // store so one writer serves the database.
    let (authority_keyring, anchored_receipt_store) = match (
        config.authority_keyring_config_path.as_deref(),
        authority_keyring_seed_path.as_deref(),
        config.receipt_db_path.as_deref(),
        config.authority_keyring_receipt_anchor_root.as_deref(),
    ) {
        (Some(keyring_config), Some(seed_path), Some(receipt_path), Some(anchor_root)) => {
            let receipt_store = Arc::new(SqliteReceiptStore::open_for_finding_pool(
                receipt_path,
                anchor_root,
            )?);
            receipt_store.join_writer_on_reaper();
            // Keyring custody writes through this store, so it waits for the
            // seed to finish instead of serving while the writer seeds.
            let seeding = Arc::clone(&receipt_store);
            tokio::task::spawn_blocking(move || {
                await_receipt_writer_seed(&seeding, RECEIPT_WRITER_READY_WAIT)
            })
            .await
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust-control receipt writer readiness task failed: {error}"
                ))
            })??;
            let keyring_receipts: Arc<dyn chio_kernel::ReceiptStore> = receipt_store.clone();
            let (_, composition) = crate::load_keyring_runtime_from_authority_seed(
                keyring_config,
                seed_path,
                keyring_receipts,
            )?;
            (Some(composition), Some(receipt_store))
        }
        (None, None, _, None) => (None, None),
        _ => {
            return Err(CliError::cli_other_error(
                "validated keyring runtime configuration is incomplete".to_string(),
            ));
        }
    };
    // A configured keyring becomes the sole seed signing owner. Every
    // config-only signing helper sees no seed and therefore fails closed.
    let mut config = config;
    if authority_keyring.is_some() {
        config.authority_seed_path = None;
    }
    validate_finding_purchase_runtime_dependencies(
        finding_purchase_executor.is_some(),
        finding_rail.is_some(),
        finding_authority_status_resolver.is_some(),
    )?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    let joint_authority_store = match injected_joint_authority_store {
        Some(store) => {
            validate_injected_joint_authority_store(&config, &store)?;
            Some(store)
        }
        None => open_configured_joint_authority_store(&config)?,
    };
    if let Some(purchase_executor) = finding_purchase_executor.as_ref() {
        let serving_authority = joint_authority_store.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "finding purchase runtime requires the configured joint authority database"
                    .to_string(),
            )
        })?;
        let serving_fence = serving_authority.mutation_fence();
        let purchase_fence = purchase_executor.mutation_fence();
        super::super::config_and_public::validate_finding_market_mutation_fence(
            &serving_fence,
            &purchase_fence,
        )?;
    }
    let fiscal_runtime = compose_trust_fiscal_runtime(
        joint_authority_store.as_ref(),
        config.fiscal_runtime.as_ref(),
    )?;
    let payload_maintenance_owner = payload_maintenance::start_on_existing_authority(
        joint_authority_store.as_ref(),
        payload_maintenance_config,
    )?;
    let listener = transport.bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let budget_store = config
        .budget_db_path
        .as_deref()
        .map(SqliteBudgetStore::open)
        .transpose()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to open trust-control budget store: {error}"
            ))
        })?
        .map(Arc::new);
    let revocation_store = config
        .revocation_db_path
        .as_deref()
        .map(SqliteRevocationStore::open_replication_source)
        .transpose()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to open trust-control revocation store: {error}"
            ))
        })?
        .map(Arc::new);
    let cluster = build_cluster_state(&config, local_addr)?;
    let receipt_store = match anchored_receipt_store {
        Some(store) => Some(store),
        None => {
            let path = config.receipt_db_path.clone();
            tokio::task::spawn_blocking(move || open_service_receipt_store(path.as_deref()))
                .await
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "trust-control receipt store startup task failed: {error}"
                    ))
                })??
        }
    };
    let receipt_store_owner = receipt_store.clone();
    let receipt_query_snapshots = receipt_store
        .as_ref()
        .map(|store| {
            chio_store_sqlite::receipt_query_snapshot::ReceiptQuerySnapshots::start(
                Arc::clone(store),
                chio_store_sqlite::receipt_query_snapshot::ReceiptQuerySnapshotConfig {
                    quota_bytes: config.receipt_query_snapshot_quota_bytes,
                    ..chio_store_sqlite::receipt_query_snapshot::ReceiptQuerySnapshotConfig::default()
                },
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::CLI_OTHER,
                "trust-control receipt query snapshot startup failed",
                source,
            )
        })?;
    let receipt_query_owner = receipt_query_snapshots.clone();
    // Thread the operator-configured memory budget into the admission guard so a
    // lowered `admission_key_cap` actually tightens it. Read the cap before
    // `config` is moved into the state.
    let federation_admission_rate_limiter = Arc::new(Mutex::new(
        FederationAdmissionRateLimiter::from_memory_budget(&config.memory_budget),
    ));
    let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
    let state = TrustServiceState {
        finding_challenge_clock: Arc::new(chio_security_types::clock::SystemClock),
        config,
        authority_keyring,
        authority_keyring_seed_path,
        joint_authority_store,
        fiscal_runtime,
        budget_store,
        revocation_store,
        receipt_store,
        receipt_query_snapshots,
        receipt_query_lane: Arc::new(tokio::sync::Semaphore::new(4)),
        evidence_export_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter,
        cluster,
        cluster_progress,
        finding_rail,
        finding_purchase_executor,
        finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_seller_submission_executor,
        finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_authority_status_resolver,
        finding_challenge_executor,
    };
    let controller = ShutdownController::install();
    let cluster_sync_task = state
        .cluster
        .is_some()
        .then(|| tokio::spawn(run_cluster_sync_loop(state.clone(), controller.subscribe())));

    // Record when the stop signal fires so the post-drain cluster-loop join can
    // share the one drain budget with the HTTP drain instead of adding a second
    // wait on top of it (see the join below). The observer sets the instant once,
    // the moment shutdown is requested.
    let shutdown_at: Arc<OnceLock<Instant>> = Arc::new(OnceLock::new());
    {
        let shutdown_at = Arc::clone(&shutdown_at);
        let signalled = controller.signalled();
        tokio::spawn(async move {
            signalled.await;
            let _ = shutdown_at.set(Instant::now());
        });
    }

    // Trust-control is the single service hosting capability revocation and
    // budget authority for the cluster, so it takes a body cap, the concurrency
    // limit with load-shed, and the connection cap.
    //
    // The generic per-request timeout is deliberately left off. An HA budget
    // authorize parks in the rollback-aware quorum wait, which is bounded on its
    // own (scaled to the cluster's serial per-peer sync cost) and can legitimately
    // outrun any single request ceiling; a blanket timeout firing after the local
    // exposure write but before that wait returns would drop the handler before its
    // rollback branch, leaving a charged, leader-visible write that the client only
    // saw fail. Every other handler is a bounded local store operation or a
    // leader-forward already capped by the peer HTTP timeout, and the drain
    // deadline bounds any handler still running at shutdown.
    let hygiene = ServeHygieneConfig {
        max_body_bytes: Some(1024 * 1024),
        request_timeout: None,
        ..ServeHygieneConfig::default()
    };
    let router = apply_server_hygiene(router::build_router(state), &hygiene);

    info!(listen_addr = %local_addr, "serving Chio trust control service");
    tracing::info!(%local_addr, "Chio trust control service listening");

    let listener = MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
    let server = axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

    // Trust-control writes budget and revocation state synchronously inside its
    // handlers, and a receipt append returns only after the shared writer made
    // it durable, so completing in-flight requests during the drain is the whole
    // fix; no queued receipt write outlives its request.
    let serve_result = run_until_drained(
        server,
        controller.subscribe(),
        hygiene.drain_timeout,
        async { Ok::<(), String>(()) },
    )
    .await;

    // The cluster sync loop watches the same shutdown signal and reacts to it
    // concurrently with the HTTP drain. Once the server has drained, join the loop
    // within whatever remains of the drain window, never a fresh wait on top of it:
    // one in-flight peer call can outlast any bound worth waiting for, and outbound
    // peer sync is best-effort catch-up that resumes on the next boot, so abandoning
    // a still-running call at the deadline never loses a receipt. Anchoring the join
    // at the stop signal keeps the whole teardown inside one drain budget, which the
    // platform stop grace is already sized to cover.
    if let Some(task) = cluster_sync_task {
        let join_budget = shutdown_at.get().map_or(hygiene.drain_timeout, |observed| {
            cluster_join_budget(hygiene.drain_timeout, observed.elapsed())
        });
        let _ = tokio::time::timeout(join_budget, task).await;
    }

    if let Some(owner) = payload_maintenance_owner.as_ref() {
        owner.shutdown().map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::CLI_OTHER,
                "terminal raw payload maintenance server worker joined with a failure",
                source,
            )
        })?;
    }

    // Stop the walker off the async runtime before flushing its store.
    if let Some(snapshots) = receipt_query_owner {
        if let Err(error) = tokio::task::spawn_blocking(move || snapshots.shutdown()).await {
            warn!(%error, "trust-control receipt query snapshot shutdown task failed");
        }
    }

    // Make queued receipt work durable before returning. Whichever owner
    // releases the store last (this guard, a handler detached by a forced
    // drain, or a cluster loop abandoned at its join budget), the writer is
    // joined on its reaper thread, never on an async worker.
    if let Some(store) = receipt_store_owner {
        let flushed = tokio::task::spawn_blocking(move || {
            let flushed = store.flush_receipt_writes().map(|_| ());
            drop(store);
            flushed
        })
        .await;
        match flushed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "trust-control receipt store shutdown flush failed"),
            Err(error) => warn!(%error, "trust-control receipt store shutdown task failed"),
        }
    }

    serve_result.map(|_outcome| ()).map_err(|error| {
        CliError::cli_other_error(format!("trust control service failed: {error}"))
    })
}

/// How long one startup readiness probe waits before it reports a writer that
/// is still seeding.
const RECEIPT_WRITER_READY_WAIT: Duration = Duration::from_secs(30);

/// Startup state of the service's single receipt writer. A failed seed is not
/// a state: it refuses startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptWriterStartup {
    /// The writer verified the persisted history and is serving.
    Ready,
    /// The writer is still verifying a large history. It is the only seed
    /// owner and serves queued appends in order once its head is verified.
    Seeding,
}

/// Open the service's unanchored receipt store and wait for its writer.
///
/// A failed seed (a poisoned verified head or a dead writer) refuses startup. A
/// seed still running after the wait is not a failure, so a large healthy
/// history never becomes a startup refusal, and no second store or reseed is
/// started for it.
pub(crate) fn open_service_receipt_store(
    path: Option<&Path>,
) -> Result<Option<Arc<SqliteReceiptStore>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let store = SqliteReceiptStore::open(path).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to open trust-control receipt store: {error}"
        ))
    })?;
    store.join_writer_on_reaper();
    await_receipt_writer(&store, RECEIPT_WRITER_READY_WAIT)?;
    Ok(Some(Arc::new(store)))
}

/// Wait for the writer's seed to finish, however long a healthy history takes.
/// A failed seed still refuses; a healthy one is never cut off or restarted.
fn await_receipt_writer_seed(store: &SqliteReceiptStore, poll: Duration) -> Result<(), CliError> {
    while await_receipt_writer(store, poll)? == ReceiptWriterStartup::Seeding {}
    Ok(())
}

fn await_receipt_writer(
    store: &SqliteReceiptStore,
    wait: Duration,
) -> Result<ReceiptWriterStartup, CliError> {
    let seeded = store.wait_for_writer_seed(wait).map_err(|error| {
        CliError::cli_other_error(format!(
            "trust-control receipt writer failed startup readiness: {error}"
        ))
    })?;
    if seeded {
        return Ok(ReceiptWriterStartup::Ready);
    }
    warn!(
        wait_ms = wait.as_millis(),
        "trust-control receipt writer is still verifying its history"
    );
    Ok(ReceiptWriterStartup::Seeding)
}

fn validate_finding_purchase_runtime_dependencies(
    has_purchase_executor: bool,
    has_rail: bool,
    has_authority_status_resolver: bool,
) -> Result<(), CliError> {
    if has_purchase_executor && !has_rail {
        return Err(CliError::cli_other_error(
            "finding purchase runtime requires an idempotent settlement rail".to_string(),
        ));
    }
    if has_purchase_executor && !has_authority_status_resolver {
        return Err(CliError::cli_other_error(
            "finding purchase runtime requires an authority-status resolver".to_string(),
        ));
    }
    Ok(())
}

fn validate_injected_joint_authority_store(
    config: &TrustServiceConfig,
    store: &SqliteAuthorityStore,
) -> Result<(), CliError> {
    let configured_path = config.joint_authority_db_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "injected finding challenge authority requires a configured joint authority database"
                .to_string(),
        )
    })?;
    store.verify_database_path(configured_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "injected finding challenge authority does not match the configured joint authority database: {error}"
        ))
    })
}

fn open_configured_joint_authority_store(
    config: &TrustServiceConfig,
) -> Result<Option<Arc<SqliteAuthorityStore>>, CliError> {
    let Some(path) = config.joint_authority_db_path.as_deref() else {
        return Ok(None);
    };
    SqliteAuthorityStore::ensure_serving_supported()?;
    let lock_root = crate::durable_admission_lock_root(path)?;
    crate::create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(path, &lock_root)?;
    Ok(Some(Arc::new(SqliteAuthorityStore::open_serving(
        path, &lock_root,
    )?)))
}

/// Time budget for the post-drain cluster-loop join: whatever remains of the
/// drain window once the HTTP drain returns. `elapsed` is measured from the stop
/// signal, and the HTTP drain returns within `drain_timeout` of that signal, so
/// the drain time already spent plus this budget never exceeds one drain window.
/// Both teardown phases therefore share the single deadline the platform stop
/// grace is sized to cover, instead of stacking two independent waits.
fn cluster_join_budget(drain_timeout: Duration, elapsed_since_signal: Duration) -> Duration {
    drain_timeout.saturating_sub(elapsed_since_signal)
}

#[cfg(test)]
#[path = "init/tests.rs"]
mod tests;

#[cfg(all(test, windows))]
mod windows_authority_tests {
    use super::*;

    #[tokio::test]
    async fn trust_service_rejects_windows_before_creating_joint_authority_state(
    ) -> Result<(), CliError> {
        let directory = tempfile::tempdir()?;
        let state_parent = directory.path().join("state");
        let database = state_parent.join("joint-authority.sqlite3");
        let lock_root = crate::durable_admission_lock_root(&database)?;
        let config = TrustServiceConfig {
            transport: Default::default(),
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            service_token: "service-token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            authority_workload_token: None,
            receipt_db_path: None,
            receipt_query_snapshot_quota_bytes: 2_147_483_648,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
            authority_keyring_receipt_anchor_root: None,
            budget_db_path: None,
            joint_authority_db_path: Some(database.clone()),
            fiscal_runtime: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: false,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            finding_market: None,
        };

        let Err(error) = serve_async(config, None, None, None, None, None, None).await else {
            return Err(CliError::cli_other_error(
                "Windows trust service unexpectedly started with a joint authority database",
            ));
        };

        assert!(error
            .to_string()
            .contains("sqlite authority serving requires Unix file identity and positioned I/O"));
        assert!(!state_parent.exists());
        assert!(!database.exists());
        assert!(!lock_root.exists());
        assert!(std::fs::read_dir(directory.path())?.next().is_none());
        Ok(())
    }
}
