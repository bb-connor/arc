use super::super::cluster::{build_cluster_state, run_cluster_sync_loop};
use super::super::*;
use super::router;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};

pub(crate) async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    config.validate()?;
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
    let state = TrustServiceState {
        config,
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter,
        cluster,
        cluster_progress,
    };
    let controller = ShutdownController::install();
    let cluster_sync_task = state
        .cluster
        .is_some()
        .then(|| tokio::spawn(run_cluster_sync_loop(state.clone(), controller.subscribe())));

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

    // The cluster sync loop watches the same shutdown signal and returns after its
    // current per-peer call; join it (bounded) once the HTTP server has drained so
    // a blocking peer sync cannot keep occupying the runtime past the platform stop
    // window. The bound covers one in-flight peer call plus a small margin.
    if let Some(task) = cluster_sync_task {
        let join_bound = CONTROL_HTTP_TIMEOUT.saturating_add(std::time::Duration::from_secs(5));
        let _ = tokio::time::timeout(join_bound, task).await;
    }

    serve_result.map(|_outcome| ()).map_err(|error| {
        CliError::cli_other_error(format!("trust control service failed: {error}"))
    })
}
