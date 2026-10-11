//! Authority admission rejects stale elected custodians and ignores follower relays.
use super::*;

const UNRESOLVED: &str = "authority replication from the elected leader is unresolved";

#[path = "authority_majority_contract.rs"]
mod authority_majority_contract;

/// A wall-clock substitute the test advances explicitly.
struct SteppedClock(std::sync::atomic::AtomicU64);

impl Clock for SteppedClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        FixedClock::new(self.0.load(Ordering::SeqCst)).read()
    }
}

async fn health_json(state: &TrustServiceState) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let response = crate::trust_control::trust_control_health::install_health_routes(Router::new())
        .with_state(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri(HEALTH_PATH)
                .body(axum::body::Body::empty())
                .test_unwrap(),
        )
        .await
        .test_unwrap();
    let status = response.status();
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    (status, body)
}

struct RecoveredCustodian {
    _directory: tempfile::TempDir,
    _exporter: ServedPeer,
    state: TrustServiceState,
    old_issuer: PublicKey,
    new_issuer: PublicKey,
    at: u64,
    former_listener: Option<std::net::TcpListener>,
    third_listener: Option<std::net::TcpListener>,
    third_url: String,
}

fn recovered_lowest_url_custodian() -> RecoveredCustodian {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let custodian_path = directory.path().join("old-custodian.sqlite3");
    let recovered_path = directory.path().join("recovered.sqlite3");
    let recovery_root = Keypair::generate();
    let custodian =
        SqliteCapabilityAuthority::open_with_clock(&custodian_path, fixed_clock(now)).test_unwrap();
    let old_issuer = custodian.status().test_unwrap().public_key;
    let anchor = custodian
        .initialize_replication_with_recovery(
            "lowest-url-recovery",
            Some(&recovery_root.public_key()),
        )
        .test_unwrap();
    let replica =
        SqliteCapabilityAuthority::open_with_clock(&recovered_path, fixed_clock(now)).test_unwrap();
    replica.pin_replication_anchor(&anchor).test_unwrap();
    replica
        .apply_signed_snapshot(&custodian.signed_snapshot().test_unwrap())
        .test_unwrap();
    let recovered =
        SqliteCapabilityAuthority::open_with_clock(&recovered_path, fixed_clock(now + 1))
            .test_unwrap();
    recovered.recover_authority(&recovery_root).test_unwrap();
    let new_issuer = recovered.status().test_unwrap().public_key;
    assert!(!recovered
        .status()
        .test_unwrap()
        .trusted_public_keys
        .contains(&old_issuer));
    let (first_listener, first_url) = ServedPeer::reserve();
    let (second_listener, second_url) = ServedPeer::reserve();
    let ((former_listener, former_url), (listener, recovered_url)) = if first_url < second_url {
        ((first_listener, first_url), (second_listener, second_url))
    } else {
        ((second_listener, second_url), (first_listener, first_url))
    };
    assert!(former_url < recovered_url);
    let (third_listener, third_url) = ServedPeer::reserve_on("127.0.0.2:0");
    let mut exporter_state = state_with_cluster(
        &recovered_url,
        &[former_url.as_str(), third_url.as_str()],
        None,
        None,
        None,
    );
    exporter_state.config.authority_db_path = Some(recovered_path);
    exporter_state.finding_challenge_clock = fixed_clock(now + 1);
    let exporter = ServedPeer::serve(listener, recovered_url, exporter_state, None);
    let mut state = state_with_cluster(
        &former_url,
        &[exporter.url.as_str(), third_url.as_str()],
        None,
        None,
        None,
    );
    state.config.authority_db_path = Some(custodian_path);
    state.finding_challenge_clock = fixed_clock(now);
    assert_authority_freshness_refused(sync_peer(&state, &exporter.url));
    assert_eq!(
        current_leader_url(&state).as_deref(),
        Some(former_url.as_str())
    );
    RecoveredCustodian {
        _directory: directory,
        _exporter: exporter,
        state,
        old_issuer,
        new_issuer,
        at: now,
        former_listener: Some(former_listener),
        third_listener: Some(third_listener),
        third_url,
    }
}

async fn assert_unresolved(response: Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(body.get("error").and_then(Value::as_str), Some(UNRESOLVED));
}

pub(super) fn assert_source_unadmitted_sync(result: Result<(), CliError>) {
    let error = result.test_unwrap_err();
    assert!(
        matches!(error, CliError::Chio(_)),
        "unexpected refusal: {error}"
    );
    assert!(
        [
            UNRESOLVED,
            "cluster authority context changed during inspection"
        ]
        .iter()
        .any(|reason| error.to_string()
            == CliError::cli_other_error(format!(
                "trust control service request failed with 503: {}",
                json!({"error": reason})
            ))
            .to_string()),
        "expected elected-source admission refusal, got {error}"
    );
}

#[tokio::test]
async fn final_f11_repair_lowest_url_former_custodian_refuses_authority_read() {
    let fixture = recovered_lowest_url_custodian();
    assert_ne!(fixture.old_issuer, fixture.new_issuer);
    assert_unresolved(handle_authority_status(State(fixture.state), workload_headers()).await)
        .await;
}

#[tokio::test]
async fn final_f11_repair_lowest_url_former_custodian_is_not_ready() {
    let fixture = recovered_lowest_url_custodian();
    let (status, health) = health_json(&fixture.state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        health
            .pointer("/authority/available")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        health
            .pointer("/cluster/hasQuorum")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[tokio::test]
async fn final_f11_repair_lowest_url_former_custodian_cannot_issue_revoked_key() {
    let fixture = recovered_lowest_url_custodian();
    let payload = IssueCapabilityRequest {
        subject_public_key: Keypair::generate().public_key().to_hex(),
        scope: ChioScope::default(),
        ttl_seconds: 60,
        runtime_attestation: None,
    };
    assert_unresolved(
        handle_issue_capability(State(fixture.state), workload_headers(), Json(payload)).await,
    )
    .await;
}

#[tokio::test]
async fn final_f11_repair_plain_seed_first_issue_uses_owner_startup_provisioning() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    state.config.authority_seed_path = Some(seed.clone());
    service_runtime::provision_service_authority(
        &state.config,
        state.finding_challenge_clock.clone(),
    )
    .test_unwrap();
    let owner_provisioned = seed.exists();
    let response = handle_issue_capability(
        State(state),
        workload_headers(),
        Json(IssueCapabilityRequest {
            subject_public_key: Keypair::generate().public_key().to_hex(),
            scope: ChioScope::default(),
            ttl_seconds: 60,
            runtime_attestation: None,
        }),
    )
    .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .test_unwrap();
    eprintln!("plain-seed first issue: owner provisioned={owner_provisioned}, seed exists after request={}, status={status}, body={}", seed.exists(), String::from_utf8_lossy(&bytes));
    assert_eq!(
        status,
        StatusCode::OK,
        "first authenticated issue failed after seed side effect"
    );
    assert!(
        owner_provisioned,
        "request-time issuance created owner signing custody"
    );
    let issued: IssueCapabilityResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(
        issued.capability.issuer,
        crate::load_existing_authority_keypair(&seed)
            .test_unwrap()
            .public_key()
    );
    assert!(issued.capability.verify_signature().test_unwrap());
}

#[tokio::test]
async fn final_f11_repair_plain_seed_missing_after_startup_is_not_recreated() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    crate::load_or_create_authority_keypair(&seed).test_unwrap();
    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    state.config.authority_seed_path = Some(seed.clone());
    service_runtime::provision_service_authority(
        &state.config,
        state.finding_challenge_clock.clone(),
    )
    .test_unwrap();
    std::fs::remove_file(&seed).test_unwrap();
    let response = handle_issue_capability(
        State(state),
        workload_headers(),
        Json(IssueCapabilityRequest {
            subject_public_key: Keypair::generate().public_key().to_hex(),
            scope: ChioScope::default(),
            ttl_seconds: 60,
            runtime_attestation: None,
        }),
    )
    .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .test_unwrap();
    eprintln!(
        "plain-seed missing after startup: seed exists after request={}, status={status}, body={}",
        seed.exists(),
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !seed.exists(),
        "request recreated missing owner signing custody"
    );
    let refusal: Value = serde_json::from_slice(&bytes).test_unwrap();
    let expected = crate::load_existing_authority_keypair(&seed).test_unwrap_err();
    assert!(
        matches!(&expected, CliError::Io(error) if error.kind() == std::io::ErrorKind::NotFound),
        "unexpected custody loader refusal: {expected}"
    );
    assert_eq!(
        refusal.get("error").and_then(Value::as_str),
        Some(expected.to_string().as_str())
    );
}

/// Three nodes: leader L (signing custodian, lowest URL), followers F and G.
/// Every successful round preserves F's leader-confirmed trust when G relays
/// either a newer or an older envelope; a nonleader cannot replace it.
async fn assert_relays_preserve_admission(force_snapshot: bool) {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let leader_path = directory.path().join("leader.sqlite3");
    let relay_path = directory.path().join("relay.sqlite3");
    let follower_path = directory.path().join("follower.sqlite3");
    let leader_clock = Arc::new(SteppedClock(std::sync::atomic::AtomicU64::new(now)));
    let leader_clock_dyn: Arc<dyn Clock> = leader_clock.clone();
    let custodian =
        SqliteCapabilityAuthority::open_with_clock(&leader_path, leader_clock_dyn.clone())
            .test_unwrap();
    let anchor = custodian
        .initialize_replication("review-follower-relay")
        .test_unwrap();
    let relay =
        SqliteCapabilityAuthority::open_with_clock(&relay_path, fixed_clock(now + 5)).test_unwrap();
    relay.pin_replication_anchor(&anchor).test_unwrap();
    let follower = SqliteCapabilityAuthority::open_with_clock(&follower_path, fixed_clock(now + 5))
        .test_unwrap();
    follower.pin_replication_anchor(&anchor).test_unwrap();

    let (first_listener, first_url) = ServedPeer::reserve();
    let (second_listener, second_url) = ServedPeer::reserve();
    let ((leader_listener, leader_url), (relay_listener, relay_url)) = if first_url < second_url {
        ((first_listener, first_url), (second_listener, second_url))
    } else {
        ((second_listener, second_url), (first_listener, first_url))
    };
    let (follower_listener, follower_url) = ServedPeer::reserve_on("127.0.0.2:0");
    let mut leader_state = state_with_cluster(
        &leader_url,
        &[follower_url.as_str(), relay_url.as_str()],
        None,
        None,
        None,
    );
    leader_state.config.authority_db_path = Some(leader_path.clone());
    leader_state.finding_challenge_clock = leader_clock_dyn.clone();
    let mut relay_state = state_with_cluster(
        &relay_url,
        &[follower_url.as_str(), leader_url.as_str()],
        None,
        None,
        None,
    );
    relay_state.config.authority_db_path = Some(relay_path.clone());
    relay_state.finding_challenge_clock = fixed_clock(now + 5);
    let leader = ServedPeer::serve(leader_listener, leader_url, leader_state, None);
    let relay_peer = ServedPeer::serve(relay_listener, relay_url, relay_state, None);

    let mut state = state_with_cluster(
        &follower_url,
        &[leader.url.as_str(), relay_peer.url.as_str()],
        None,
        None,
        None,
    );
    state.config.authority_db_path = Some(follower_path);
    state.finding_challenge_clock = fixed_clock(now + 5);

    let served_follower = ServedPeer::serve(follower_listener, follower_url, state.clone(), None);
    // Import progresses before either side can serve: L has no authenticated
    // peer agreement yet, and F cannot confirm an unadmitted source.
    assert_source_unadmitted_sync(sync_peer(&state, &leader.url));
    let converged =
        public_authority_status(&state.config, &state.finding_challenge_clock).test_unwrap();
    assert_eq!(
        converged.public_key,
        Some(custodian.status().test_unwrap().public_key.to_hex())
    );
    assert_unresolved(handle_authority_status(State(state.clone()), workload_headers()).await)
        .await;
    // L authenticates F's signed chain through its independent internal export.
    sync_peer(&leader.state, &served_follower.url).test_unwrap();
    let leader_status = load_authority_status_for_state(&leader.state).test_unwrap();
    assert_eq!(leader_status.generation, Some(1));
    let issued = handle_issue_capability(
        State(leader.state.clone()),
        workload_headers(),
        Json(IssueCapabilityRequest {
            subject_public_key: Keypair::generate().public_key().to_hex(),
            scope: ChioScope::default(),
            ttl_seconds: 60,
            runtime_attestation: None,
        }),
    )
    .await;
    assert_eq!(
        issued.status(),
        StatusCode::OK,
        "admitted elected leader could not issue"
    );
    let issued: IssueCapabilityResponse =
        serde_json::from_slice(&to_bytes(issued.into_body(), 64 * 1024).await.test_unwrap())
            .test_unwrap();
    assert_eq!(
        issued.capability.issuer,
        custodian.status().test_unwrap().public_key
    );
    assert!(issued.capability.verify_signature().test_unwrap());
    // F now confirms the same elected source's admitted state.
    sync_peer(&state, &leader.url).test_unwrap();
    assert_eq!(
        current_leader_url(&state).as_deref(),
        Some(leader.url.as_str())
    );
    load_authority_status_for_state(&state).test_unwrap();

    // One second later G pulls a fresh envelope from the leader.
    leader_clock.0.store(now + 1, Ordering::SeqCst);
    relay
        .apply_signed_snapshot(
            &SqliteCapabilityAuthority::open_with_clock(&leader_path, leader_clock_dyn.clone())
                .test_unwrap()
                .signed_snapshot()
                .test_unwrap(),
        )
        .test_unwrap();

    // F's round continues with G. The import succeeds.
    update_peer_state(&state, &relay_peer.url, |peer| {
        peer.force_snapshot = force_snapshot
    });
    let relay_sync = sync_peer(&state, &relay_peer.url);
    eprintln!("F sync from follower G: {relay_sync:?}");
    relay_sync.test_unwrap();
    let term_leader = current_leader_url(&state);
    let read = load_authority_status_for_state(&state).map(|status| status.generation);
    eprintln!(
        "after a fully successful round, leader={term_leader:?}, F trust read ok={}",
        read.is_ok()
    );
    let (health_code, health) = health_json(&state).await;
    eprintln!(
        "F health: {health_code} ok={} authority.available={}",
        health.get("ok").test_unwrap(),
        health.pointer("/authority/available").test_unwrap()
    );
    assert_eq!(read.test_unwrap(), Some(1));
    assert_eq!(health_code, StatusCode::OK);

    // The next leader sync re-confirms (same-second envelope, same digest).
    sync_peer(&state, &leader.url).test_unwrap();
    load_authority_status_for_state(&state).test_unwrap();

    // Opposite order also preserves the leader envelope and the relay peer
    // remains healthy because its older consistent view is not imported.
    leader_clock.0.store(now + 2, Ordering::SeqCst);
    sync_peer(&state, &leader.url).test_unwrap();
    let regress = sync_peer(&state, &relay_peer.url);
    eprintln!("F sync from G holding an older relay: {regress:?}");
    let label = with_peer_state(&state, &relay_peer.url, |peer| peer.health.label()).test_unwrap();
    eprintln!("G as seen by F: {label}");
    regress.test_unwrap();
    assert_eq!(label, "healthy");
    let (health_code, health) = health_json(&state).await;
    eprintln!(
        "F health: {health_code} degradedPeers={} healthyPeers={}",
        health.pointer("/cluster/degradedPeers").test_unwrap(),
        health.pointer("/cluster/healthyPeers").test_unwrap()
    );
}

#[tokio::test]
async fn final_f11_repair_nonleader_relay_preserves_leader_confirmation() {
    assert_relays_preserve_admission(false).await;
}

#[tokio::test]
async fn final_f11_repair_forced_nonleader_relay_preserves_leader_confirmation() {
    assert_relays_preserve_admission(true).await;
}

struct ThreadObservingClock {
    at: u64,
    readers: Mutex<Vec<std::thread::ThreadId>>,
}

impl Clock for ThreadObservingClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        self.readers
            .lock()
            .map_err(|_| chio_security_types::clock::ClockError::Unavailable)?
            .push(std::thread::current().id());
        FixedClock::new(self.at).read()
    }
}

fn observed_follower() -> (ReplicationPair, Arc<ThreadObservingClock>) {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let clock = Arc::new(ThreadObservingClock {
        at: pair.provisioned_at + 60,
        readers: Mutex::new(Vec::new()),
    });
    pair.importer.finding_challenge_clock = clock.clone();
    clock.readers.lock().test_unwrap().clear();
    (pair, clock)
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_repair_authenticated_status_inspects_off_executor() {
    let (pair, clock) = observed_follower();
    let executor = std::thread::current().id();
    let response = handle_authority_status(State(pair.importer), workload_headers()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let readers = clock.readers.lock().test_unwrap();
    assert!(
        !readers.is_empty(),
        "authenticated status skipped authority inspection"
    );
    assert!(
        readers.iter().all(|reader| *reader != executor),
        "actual authority inspection ran on executor {executor:?}: {readers:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_repair_unauthorized_status_does_not_inspect() {
    let (pair, clock) = observed_follower();
    let response = handle_authority_status(State(pair.importer), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        clock.readers.lock().test_unwrap().is_empty(),
        "unauthorized request entered authority inspection"
    );
}

struct HeldReadClock {
    at: u64,
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    first: std::sync::atomic::AtomicBool,
}

impl Clock for HeldReadClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::ClockError;
        if self.first.swap(false, Ordering::SeqCst) {
            self.entered.send(()).map_err(|_| ClockError::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| ClockError::Unavailable)?;
        }
        FixedClock::new(self.at).read()
    }
}

async fn assert_read_context_change_refused(lose_quorum: bool) {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    pair.importer.finding_challenge_clock = Arc::new(HeldReadClock {
        at: pair.provisioned_at + 60,
        entered: entered_tx,
        release: Mutex::new(released),
        first: std::sync::atomic::AtomicBool::new(true),
    });
    let worker_state = pair.importer.clone();
    let read = std::thread::spawn(move || load_authority_status_for_state(&worker_state));
    entered.recv_timeout(Duration::from_secs(30)).test_unwrap();
    if lose_quorum {
        update_peer_state(&pair.importer, &pair.exporter.url, |peer| {
            peer.partitioned = true;
            peer.health = PeerHealth::Unhealthy;
        });
    } else {
        pair.importer
            .cluster
            .as_ref()
            .test_unwrap()
            .lock()
            .test_unwrap()
            .election_term += 1;
    }
    release.send(()).test_unwrap();
    assert_unresolved(read.join().test_unwrap().test_unwrap_err()).await;
}

#[tokio::test]
async fn final_f11_repair_read_rechecks_quorum_after_inspection() {
    assert_read_context_change_refused(true).await;
}

#[tokio::test]
async fn final_f11_repair_read_rechecks_term_after_inspection() {
    assert_read_context_change_refused(false).await;
}

#[test]
fn final_f11_repair_loaded_signer_rechecks_quorum_before_issuance() {
    let pair = replication_pair(AuthorityFault::LaggingImporterClock);
    let state = &pair.exporter.state;
    let admitted = load_authority_status_for_state(state).test_unwrap();
    let authority = load_capability_authority(state).test_unwrap();
    assert_eq!(
        Some(authority.authority_public_key().to_hex()),
        admitted.public_key
    );
    update_peer_state(
        state,
        &cluster_self_url(&pair.importer).test_unwrap(),
        |peer| {
            peer.partitioned = true;
            peer.health = PeerHealth::Unhealthy;
        },
    );
    assert!(matches!(
        authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 60),
        Err(chio_kernel::KernelError::CapabilityIssuanceDenied(reason)) if reason == UNRESOLVED
    ));
}

struct ArmedIssueClock {
    at: u64,
    remaining: AtomicUsize,
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Clock for ArmedIssueClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::ClockError;
        let remaining = self.remaining.load(Ordering::SeqCst);
        if remaining != usize::MAX && self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.remaining.store(usize::MAX, Ordering::SeqCst);
            self.entered.send(()).map_err(|_| ClockError::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| ClockError::Unavailable)?;
        }
        FixedClock::new(self.at).read()
    }
}

#[test]
fn final_f11_repair_signer_rechecks_term_before_artifact_return() {
    let (_directory, source, _follower, _state, now) =
        authority_clock_contract::custodian_and_relay();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let clock = Arc::new(ArmedIssueClock {
        at: now,
        remaining: AtomicUsize::new(usize::MAX),
        entered: entered_tx,
        release: Mutex::new(released),
    });
    let mut state = source.state.clone();
    state.finding_challenge_clock = clock.clone();
    let authority = load_capability_authority(&state).test_unwrap();
    // The wrapper's first admission consumes three clock reads. Hold the
    // underlying SQLite issue's first time read before its artifact returns.
    clock.remaining.store(4, Ordering::SeqCst);
    let issue = std::thread::spawn(move || {
        authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 60)
    });
    entered.recv_timeout(Duration::from_secs(30)).test_unwrap();
    state
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .election_term += 1;
    release.send(()).test_unwrap();
    assert!(matches!(issue.join().test_unwrap(),
        Err(chio_kernel::KernelError::CapabilityIssuanceDenied(reason)) if reason == UNRESOLVED
    ));
}

#[tokio::test]
async fn final_f11_repair_revoked_local_seed_cannot_sign_discovery() {
    let mut fixture = recovered_lowest_url_custodian();
    let mut follower = state_with_cluster(
        &fixture.third_url,
        &[fixture._exporter.url.as_str()],
        None,
        None,
        None,
    );
    follower.config.authority_db_path = fixture.state.config.authority_db_path.clone();
    follower.finding_challenge_clock = fixed_clock(fixture.at + 1);
    let served_follower = ServedPeer::serve(
        fixture.third_listener.take().test_unwrap(),
        fixture.third_url.clone(),
        follower.clone(),
        None,
    );
    assert_source_unadmitted_sync(sync_peer(&follower, &fixture._exporter.url));
    sync_peer(&fixture._exporter.state, &served_follower.url).test_unwrap();
    sync_peer(&follower, &fixture._exporter.url).test_unwrap();
    let admitted = load_authority_status_for_state(&follower).test_unwrap();
    assert_eq!(admitted.public_key, Some(fixture.new_issuer.to_hex()));
    assert!(!admitted
        .trusted_public_keys
        .contains(&fixture.old_issuer.to_hex()));
    assert_eq!(
        resolve_public_registry_signing_key(&follower.config, &follower.finding_challenge_clock)
            .test_unwrap()
            .public_key(),
        fixture.old_issuer
    );
    follower.config.advertise_url = Some("https://trust.example.com".to_string());
    let response = handle_public_passport_verifier_discovery(State(follower)).await;
    if response.status() == StatusCode::OK {
        let signed: SignedPublicVerifierDiscovery = serde_json::from_slice(
            &to_bytes(response.into_body(), 64 * 1024)
                .await
                .test_unwrap(),
        )
        .test_unwrap();
        assert_eq!(signed.body.signer_public_key, fixture.old_issuer);
        panic!("public discovery returned a document signed by the revoked former custodian");
    }
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    let refusal = CliError::cli_other_error(
        "public discovery signer does not own the admitted live authority head".to_string(),
    )
    .to_string();
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some(refusal.as_str())
    );
}

#[tokio::test]
async fn final_f11_repair_mutation_fence_uses_configured_clock_and_skew() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    let source = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap();
    source.rotate().test_unwrap();
    pair.importer
        .config
        .authority_replication_max_future_skew_seconds = 60;
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    assert_eq!(
        load_authority_status_for_state(&pair.importer)
            .test_unwrap()
            .generation,
        Some(2)
    );
    refresh_authority_mutation_fence(&pair.importer).test_unwrap();
    let reopened = public_authority_status(
        &pair.importer.config,
        &pair.importer.finding_challenge_clock,
    )
    .test_unwrap();
    assert_eq!(reopened.generation, Some(2));
    assert!(
        !reopened
            .trusted_public_keys
            .contains(&source.status().test_unwrap().public_key.to_hex()),
        "skew activated the successor early"
    );
}

#[tokio::test]
async fn final_f11_repair_follower_cannot_publish_refused_leader_state() {
    let mut fixture = recovered_lowest_url_custodian();
    let old_path = fixture
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    let old =
        SqliteCapabilityAuthority::open_with_clock(old_path, fixed_clock(fixture.at)).test_unwrap();
    let anchor = old.replication_anchor().test_unwrap();
    let old_envelope = old.signed_snapshot().test_unwrap();
    let follower_path = fixture._directory.path().join("third-follower.sqlite3");
    let follower_authority =
        SqliteCapabilityAuthority::open_with_clock(&follower_path, fixed_clock(fixture.at))
            .test_unwrap();
    follower_authority
        .pin_replication_anchor(&anchor)
        .test_unwrap();
    follower_authority
        .apply_signed_snapshot(&old_envelope)
        .test_unwrap();
    let source_url = cluster_self_url(&fixture.state).test_unwrap();
    let source = ServedPeer::serve(
        fixture.former_listener.take().test_unwrap(),
        source_url,
        fixture.state.clone(),
        None,
    );
    let mut follower = state_with_cluster(
        &fixture.third_url,
        &[source.url.as_str(), fixture._exporter.url.as_str()],
        None,
        None,
        None,
    );
    follower.config.authority_db_path = Some(follower_path);
    let sync = sync_peer(&follower, &source.url);
    match sync {
        Ok(()) => {}
        Err(CliError::Chio(error)) => assert!(
            error.to_string().contains(UNRESOLVED),
            "unexpected authority refusal: {error}"
        ),
        Err(error) => panic!("unexpected synchronization refusal: {error}"),
    }
    let converged =
        public_authority_status(&follower.config, &follower.finding_challenge_clock).test_unwrap();
    assert_eq!(converged.public_key, Some(fixture.old_issuer.to_hex()));
    assert_unresolved(handle_passport_issuer_jwks(State(follower)).await).await;
}

#[tokio::test]
async fn final_f11_repair_peer_identity_alias_cannot_grant_elected_serving_or_issuance() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let path = directory.path().join("authority.sqlite3");
    let authority =
        SqliteCapabilityAuthority::open_with_clock(&path, fixed_clock(now)).test_unwrap();
    authority
        .initialize_replication("alias-source-identity")
        .test_unwrap();
    let (own_listener, own_url) = ServedPeer::reserve();
    let (alias_listener, alias_url) = ServedPeer::reserve_on("127.0.0.2:0");
    let mut state = state_with_cluster(&own_url, &[&alias_url], None, None, None);
    state.config.authority_db_path = Some(path);
    state.finding_challenge_clock = fixed_clock(now);
    // Normal cluster construction removes the node's own URL from its peer
    // entries while the configured authentication allowlist may retain it.
    // Both actual loopback listeners serve clones of ONE logical service.
    state.config.peer_urls.push(own_url.clone());
    state.cluster = build_cluster_state(
        &state.config,
        state.config.listen,
        state.finding_challenge_clock.clone(),
    )
    .test_unwrap();
    let _own = ServedPeer::serve(own_listener, own_url.clone(), state.clone(), None);
    let _alias = ServedPeer::serve(alias_listener, alias_url.clone(), state.clone(), None);
    let sync = sync_peer(&state, &alias_url);
    eprintln!("alias sync result: {sync:?}");
    let local =
        public_authority_status(&state.config, &state.finding_challenge_clock).test_unwrap();
    assert_eq!(
        local.public_key,
        Some(authority.status().test_unwrap().public_key.to_hex())
    );
    assert_eq!(
        current_leader_url(&state).as_deref(),
        Some(own_url.as_str())
    );
    let read = handle_authority_status(State(state.clone()), workload_headers()).await;
    let read_status = read.status();
    let read_body: Value =
        serde_json::from_slice(&to_bytes(read.into_body(), 64 * 1024).await.test_unwrap())
            .test_unwrap();
    let issued = handle_issue_capability(
        State(state.clone()),
        workload_headers(),
        Json(IssueCapabilityRequest {
            subject_public_key: Keypair::generate().public_key().to_hex(),
            scope: ChioScope::default(),
            ttl_seconds: 60,
            runtime_attestation: None,
        }),
    )
    .await;
    let issue_status = issued.status();
    let issue_body: Value =
        serde_json::from_slice(&to_bytes(issued.into_body(), 64 * 1024).await.test_unwrap())
            .test_unwrap();
    eprintln!("alias self_url={own_url}, configured source={alias_url}, read={read_status} {read_body}, issue={issue_status} {issue_body}");
    assert_eq!(
        read_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "one logical service acquired trust quorum through its own URL alias"
    );
    assert_eq!(
        read_body.get("error").and_then(Value::as_str),
        Some(UNRESOLVED)
    );
    assert_eq!(issue_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        issue_body.get("error").and_then(Value::as_str),
        Some(UNRESOLVED)
    );
    assert!(with_peer_state(&state, &alias_url, |peer| peer
        .authority_agreement_confirmation
        .is_none())
    .test_unwrap());
}

#[tokio::test]
async fn final_f11_repair_peer_identity_distinct_node_establishes_signed_quorum() {
    let (_directory, source, follower, state, _) = authority_clock_contract::custodian_and_relay();
    let source_url = cluster_self_url(&source.state).test_unwrap();
    let follower_url = cluster_self_url(&state).test_unwrap();
    assert_ne!(source_url, follower_url);
    let agreement = with_peer_state(&source.state, &follower_url, |peer| {
        peer.authority_agreement_confirmation.clone()
    })
    .test_unwrap()
    .test_unwrap();
    assert_eq!(agreement.leader_url, source_url);
    let admitted = load_authority_status_for_state(&source.state).test_unwrap();
    let authority = load_capability_authority(&source.state).test_unwrap();
    let issued = authority
        .issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 60)
        .test_unwrap();
    assert_eq!(Some(issued.issuer.to_hex()), admitted.public_key);
    assert!(issued.verify_signature().test_unwrap());
    follower
        .state
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .self_url = "http://127.0.0.3:3300".to_string();
    let mismatch = sync_peer(&source.state, &follower.url).test_unwrap_err();
    assert!(
        matches!(mismatch, CliError::Chio(_)),
        "unexpected identity refusal: {mismatch}"
    );
    assert_eq!(
        mismatch.to_string(),
        CliError::cli_other_error(
            "authority peer self identity does not match configured source".to_string()
        )
        .to_string()
    );
    assert!(with_peer_state(&source.state, &follower_url, |peer| peer
        .authority_agreement_confirmation
        .is_none())
    .test_unwrap());
    let read = load_authority_status_for_state(&source.state).test_unwrap_err();
    assert_unresolved(read).await;
    follower
        .state
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .self_url = follower_url.clone();
    sync_peer(&source.state, &follower.url).test_unwrap();
    let recovered = load_authority_status_for_state(&source.state).test_unwrap();
    assert_eq!(recovered.public_key, admitted.public_key);
    let issued = load_capability_authority(&source.state)
        .test_unwrap()
        .issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 60)
        .test_unwrap();
    assert_eq!(Some(issued.issuer.to_hex()), recovered.public_key);
    assert!(issued.verify_signature().test_unwrap());
}

#[tokio::test]
async fn final_f11_repair_peer_identity_mismatch_preserves_newer_signed_convergence() {
    let pair = replication_pair(AuthorityFault::LaggingImporterClock);
    let peer = pair._importer_peer.as_ref().test_unwrap();
    let source_path = pair
        .exporter
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    let peer_path = peer.state.config.authority_db_path.as_ref().test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(
        source_path,
        pair.exporter.state.finding_challenge_clock.clone(),
    )
    .test_unwrap();
    let old = source.status().test_unwrap();
    // The operator authorizes this distinct peer with a copy of current
    // custody; its genuine signed extension remains importable despite an
    // incorrect advertised identity. No agreement is fabricated.
    rusqlite::Connection::open(peer_path)
        .test_unwrap()
        .execute(
            "UPDATE authority_state SET seed_hex = ?1 WHERE singleton_id = 1",
            [source.local_keypair().test_unwrap().seed_hex()],
        )
        .test_unwrap();
    let peer_authority = SqliteCapabilityAuthority::open_with_clock(
        peer_path,
        peer.state.finding_challenge_clock.clone(),
    )
    .test_unwrap();
    let newer = peer_authority.rotate().test_unwrap();
    assert_ne!(newer.public_key, old.public_key);
    peer.state
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .self_url = "http://127.0.0.3:3300".to_string();
    let result = sync_peer(&pair.exporter.state, &peer.url).test_unwrap_err();
    assert!(
        matches!(result, CliError::Chio(_)),
        "unexpected identity refusal: {result}"
    );
    assert_eq!(
        result.to_string(),
        CliError::cli_other_error(
            "authority peer self identity does not match configured source".to_string()
        )
        .to_string()
    );
    let converged = public_authority_status(
        &pair.exporter.state.config,
        &pair.exporter.state.finding_challenge_clock,
    )
    .test_unwrap();
    assert_eq!(converged.generation, Some(2));
    assert_eq!(converged.public_key, Some(newer.public_key.to_hex()));
    assert!(with_peer_state(&pair.exporter.state, &peer.url, |peer| peer
        .authority_agreement_confirmation
        .is_none())
    .test_unwrap());
    assert_unresolved(
        handle_authority_status(State(pair.exporter.state.clone()), workload_headers()).await,
    )
    .await;
}
