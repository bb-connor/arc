use super::super::cluster::{build_cluster_state, run_cluster_sync_loop};
use super::super::cluster_replay::initialize_cluster_peer_replay_ledger;
use super::super::*;
use super::active_defense::{
    TrustControlActiveDefenseRuntime, TrustControlActiveDefenseRuntimeConfig,
};
use super::router;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub(crate) async fn serve_async(
    config: TrustServiceConfig,
    active_defense_config: TrustControlActiveDefenseRuntimeConfig,
) -> Result<(), CliError> {
    config.validate()?;
    initialize_trust_service_storage(&config)?;
    let authority_keyring = match (
        config.authority_keyring_config_path.as_deref(),
        config.authority_seed_path.as_deref(),
    ) {
        (Some(config_path), Some(seed_path)) => {
            let (_, composition) =
                crate::load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
            let receipt_path = config.receipt_db_path.as_deref().ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring capability authority requires a durable receipt database".to_string(),
                )
            })?;
            let receipt_store: Arc<dyn chio_kernel::ReceiptStore> =
                Arc::new(SqliteReceiptStore::open(receipt_path)?);
            composition.attach_receipt_store(receipt_store)?;
            Some(composition)
        }
        (None, _) => None,
        (Some(_), None) => {
            return Err(CliError::cli_other_error(
                "authority keyring configuration requires an authority seed".to_string(),
            ));
        }
    };
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    let cluster = build_cluster_state(&config, local_addr)?;
    // Thread the operator-configured memory budget into the admission guard so a
    // lowered `admission_key_cap` actually tightens it. Read the cap before
    // `config` is moved into the state.
    let federation_admission_rate_limiter = Arc::new(Mutex::new(
        FederationAdmissionRateLimiter::from_memory_budget(&config.memory_budget),
    ));
    let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
    let dashboard_report_bridge =
        super::super::dashboard_reports::DashboardReportBridge::from_config(&config)?;
    let mut state = TrustServiceState {
        config,
        dashboard_sessions: super::super::dashboard_auth::DashboardSessionStore::production(),
        dashboard_report_bridge,
        authority_keyring,
        #[cfg(test)]
        authority_test_backend: None,
        active_defense: super::TrustControlActiveDefenseService::disabled(),
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter,
        authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
        cluster,
        cluster_progress,
    };
    super::super::cluster::initialize_admission_consensus(&state)?;
    let mut active_defense = TrustControlActiveDefenseRuntime::start(active_defense_config)
        .await
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "trust control active-defense startup failed: {error}"
            ))
        })?;
    state.active_defense = active_defense.service();
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

    info!(
        listen_addr = %local_addr,
        active_defense = active_defense.is_enabled(),
        "serving Chio trust control service"
    );
    eprintln!("Chio trust control service listening on http://{local_addr}");

    let listener = MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
    let server = axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

    // Trust-control writes budget and revocation state synchronously inside its
    // handlers, so completing in-flight requests during the drain is the whole
    // fix; there is no async commit actor to flush.
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

    let active_defense_shutdown = active_defense.shutdown().await;
    match (serve_result, active_defense_shutdown) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(CliError::cli_other_error(format!(
            "trust control service failed: {error}"
        ))),
        (Ok(_), Err(error)) => Err(CliError::cli_other_error(format!(
            "trust control active-defense shutdown refused: {error}"
        ))),
        (Err(serve_error), Err(shutdown_error)) => Err(CliError::cli_other_error(format!(
            "trust control service failed: {serve_error}; active-defense shutdown refused: {shutdown_error}"
        ))),
    }
}

fn initialize_trust_service_storage(config: &TrustServiceConfig) -> Result<(), CliError> {
    if let Some(path) = config.cluster_replay_db_path.as_deref() {
        initialize_cluster_peer_replay_ledger(path)?;
    }
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "trust control service requires one authority backend".to_string(),
            ));
        }
        (Some(path), None) => {
            drop(load_or_create_authority_keypair(path)?);
        }
        (None, Some(path)) => {
            drop(SqliteCapabilityAuthority::open(path)?);
        }
        (None, None) => {}
    }
    if let Some(path) = config.receipt_db_path.as_deref() {
        let receipt_store = SqliteReceiptStore::open(path)?;
        receipt_store
            .ensure_causal_lineage_ready()
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust control causal-lineage authority is unavailable: {error}"
                ))
            })?;
        receipt_store
            .ensure_causal_lineage_fences_ready()
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust control causal-fence authority is unavailable: {error}"
                ))
            })?;
        let security_store = SqliteSecurityStateStore::open(path).map_err(|error| {
            CliError::cli_other_error(format!(
                "trust control issuance-freeze authority is unavailable: {error}"
            ))
        })?;
        security_store
            .ensure_issuance_freezes_ready()
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "trust control issuance-freeze authority is unavailable: {error}"
                ))
            })?;
    }
    Ok(())
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
mod tests {
    use super::cluster_join_budget;
    use std::time::Duration;

    /// The cluster-loop join must not add a second wait on top of the HTTP drain:
    /// for every point at which the drain could return, the drain time already
    /// spent plus the join budget it hands out stays within one drain window, so
    /// the whole teardown fits the platform stop grace rather than overrunning it
    /// and being escalated to a kill.
    #[test]
    fn cluster_join_never_extends_teardown_past_the_drain_window() {
        let drain = Duration::from_secs(25);
        // A drain that ran to its deadline leaves no budget at all.
        assert_eq!(cluster_join_budget(drain, drain), Duration::ZERO);
        for elapsed_ms in [0u64, 1_000, 12_500, 24_000, 25_000] {
            let elapsed = Duration::from_millis(elapsed_ms).min(drain);
            assert!(
                elapsed + cluster_join_budget(drain, elapsed) <= drain,
                "teardown at elapsed={elapsed:?} must stay within the drain window"
            );
        }
    }
}
