use super::*;

const UNRESOLVED_AUTHORITY_TRUST: &str =
    "authority replication from the elected leader is unresolved";

async fn assert_authority_status_refused(
    result: Result<TrustAuthorityStatus, Response>,
    reason: &str,
) {
    let response = result.test_unwrap_err();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .test_unwrap();
    let refusal: Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(refusal.get("error").and_then(Value::as_str), Some(reason));
}

fn freshness_refusal_reason() -> String {
    CliError::from(AuthorityStoreError::Fence(OUTSIDE_FRESHNESS.to_string())).to_string()
}

#[test]
fn final_f11_control_config_requires_explicit_bounded_authority_skew() {
    let mut config = base_config();
    assert_eq!(config.authority_replication_max_future_skew_seconds, 0);
    config.authority_replication_max_future_skew_seconds = 60;
    config.validate().test_unwrap();
    for skew in [61, u64::MAX] {
        config.authority_replication_max_future_skew_seconds = skew;
        assert!(
            matches!(config.validate(), Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message))) if message == "authority envelope future skew exceeds 60 seconds"),
            "unbounded skew {skew} was accepted"
        );
    }
}

#[tokio::test]
async fn final_f11_configured_one_second_skew_recovers_regular_and_snapshot_imports() {
    for force_snapshot in [false, true] {
        let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
        let custodian = SqliteCapabilityAuthority::open_with_clock(
            pair._directory.path().join("exporter-authority.sqlite3"),
            fixed_clock(pair.provisioned_at + 60),
        )
        .test_unwrap();
        let compromised = custodian.status().test_unwrap().public_key;
        custodian.rotate().test_unwrap();
        custodian.retire_issuer(&compromised).test_unwrap();
        pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 59);
        assert_authority_freshness_refused(sync_peer(&pair.importer, &pair.exporter.url));
        assert!(importer_revoked(&pair));
        assert_eq!(peer_view(&pair, |peer| peer.health.label()), "degraded");

        pair.importer
            .config
            .authority_replication_max_future_skew_seconds = 1;
        update_peer_state(&pair.importer, &pair.exporter.url, |peer| {
            peer.force_snapshot = force_snapshot
        });
        sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
        sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
        assert_eq!(peer_view(&pair, |peer| peer.health.label()), "healthy");
        assert_eq!(peer_view(&pair, |peer| peer.authority_error.clone()), None);
        let status = load_authority_status_for_state(&pair.importer).test_unwrap();
        assert_eq!(status.generation, Some(3));
        assert!(
            status.trusted_public_keys.is_empty(),
            "skew must not activate the successor before its signed activation instant"
        );
        pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
        let status = load_authority_status_for_state(&pair.importer).test_unwrap();
        assert_eq!(
            status.trusted_public_keys,
            vec![custodian.status().test_unwrap().public_key.to_hex()]
        );

        // A configured future-issue tolerance never extends the signed expiry.
        pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 360);
        assert_authority_status_refused(
            load_authority_status_for_state(&pair.importer),
            &freshness_refusal_reason(),
        )
        .await;
        assert!(matches!(public_authority_status(
            &pair.importer.config,
            &pair.importer.finding_challenge_clock
        ), Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message))) if message == OUTSIDE_FRESHNESS));
    }
}

#[tokio::test]
async fn final_f11_follower_confirmation_is_bound_to_process_leader_and_term() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();

    // A new election term invalidates the previous successful import even
    // when it elects the same URL. Stream/transport success cannot repair it.
    pair.importer
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .election_term += 1;
    update_peer_success(&pair.importer, &pair.exporter.url);
    update_peer_reachable(&pair.importer, &pair.exporter.url);
    assert_authority_status_refused(
        load_authority_status_for_state(&pair.importer),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();

    let new_leader = "http://127.0.0.0:1";
    {
        let mut cluster = pair
            .importer
            .cluster
            .as_ref()
            .test_unwrap()
            .lock()
            .test_unwrap();
        cluster
            .peers
            .insert(new_leader.into(), PeerSyncState::default());
    }
    update_peer_reachable(&pair.importer, new_leader);
    assert_eq!(
        current_leader_url(&pair.importer).as_deref(),
        Some(new_leader)
    );
    assert_authority_status_refused(
        load_authority_status_for_state(&pair.importer),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    pair.importer
        .cluster
        .as_ref()
        .test_unwrap()
        .lock()
        .test_unwrap()
        .peers
        .remove(new_leader);
    assert_authority_status_refused(
        load_authority_status_for_state(&pair.importer),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();

    // A restarted process holds the same fresh durable envelope but no peer
    // confirmation. Reachability alone must not resurrect verification trust.
    let mut restarted = state_with_cluster(
        IMPORTER_URL,
        &[&pair.exporter.url],
        None,
        pair.importer.config.revocation_db_path.clone(),
        None,
    );
    restarted.config = pair.importer.config.clone();
    restarted.finding_challenge_clock = pair.importer.finding_challenge_clock.clone();
    update_peer_reachable(&restarted, &pair.exporter.url);
    assert_authority_status_refused(
        load_authority_status_for_state(&restarted),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    sync_peer(&restarted, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&restarted).test_unwrap();
}

#[tokio::test]
async fn final_f11_failed_snapshot_fetch_invalidates_authority_confirmation() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();

    pair.exporter
        .snapshot_unavailable
        .store(true, Ordering::SeqCst);
    update_peer_state(&pair.importer, &pair.exporter.url, |peer| {
        peer.force_snapshot = true;
    });
    let snapshot_refusal = sync_peer(&pair.importer, &pair.exporter.url).test_unwrap_err();
    assert!(matches!(&snapshot_refusal, CliError::Chio(_)));
    assert_eq!(
        snapshot_refusal.to_string(),
        CliError::cli_other_error(json!({"error": "snapshot unavailable"}).to_string()).to_string()
    );
    assert_authority_status_refused(
        load_authority_status_for_state(&pair.importer),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    assert!(peer_view(&pair, |peer| peer
        .authority_import_confirmation
        .is_none()));
    assert!(peer_view(&pair, |peer| peer.health.is_reachable()));

    pair.exporter
        .snapshot_unavailable
        .store(false, Ordering::SeqCst);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();
}

fn register_public_request(state: &mut TrustServiceState, signer: &Keypair, now: u64) -> String {
    state.config.advertise_url = Some("https://trust.example.com".into());
    state.config.verifier_challenge_db_path = Some(
        state
            .config
            .authority_db_path
            .as_ref()
            .test_unwrap()
            .with_file_name("oid4vp.sqlite3"),
    );
    let request = build_oid4vp_request_for_service(
        &state.config,
        &CreateOid4vpRequest {
            disclosure_claims: Vec::new(),
            issuer_allowlist: Vec::new(),
            ttl_seconds: Some(600),
            identity_assertion: None,
        },
        now,
    )
    .test_unwrap();
    let transport =
        chio_credentials::build_oid4vp_request_transport(&request, signer).test_unwrap();
    Oid4vpVerifierTransactionStore::open(
        configured_verifier_challenge_db_path(&state.config).test_unwrap(),
    )
    .test_unwrap()
    .register(&request, &transport.request_jwt)
    .test_unwrap();
    request.jti
}

#[tokio::test]
async fn final_f11_public_issuer_trust_reads_require_current_leader_confirmation() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let signer = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap()
    .current_keypair()
    .test_unwrap();
    let request_id = register_public_request(&mut pair.importer, &signer, pair.provisioned_at);

    for after_restart in [false, true] {
        if after_restart {
            update_peer_state(&pair.importer, &pair.exporter.url, |peer| {
                peer.authority_import_confirmation = None;
            });
            update_peer_reachable(&pair.importer, &pair.exporter.url);
        } else {
            pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 59);
            assert!(matches!(
                sync_peer(&pair.importer, &pair.exporter.url),
                Err(CliError::AuthorityStore(AuthorityStoreError::Clock(
                    chio_security_types::clock::ClockError::WallClockRegression
                )))
            ));
            pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
        }
        let mut stale_paths = Vec::new();
        for (path, response) in [
            (
                OID4VCI_JWKS_PATH,
                handle_passport_issuer_jwks(State(pair.importer.clone())).await,
            ),
            (
                OID4VP_VERIFIER_METADATA_PATH,
                handle_oid4vp_verifier_metadata(State(pair.importer.clone())).await,
            ),
            (
                PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH,
                handle_public_passport_verifier_discovery(State(pair.importer.clone())).await,
            ),
            (
                PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH,
                handle_public_passport_discovery_transparency(State(pair.importer.clone())).await,
            ),
            (
                PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
                handle_public_get_oid4vp_request(
                    State(pair.importer.clone()),
                    AxumPath(request_id.clone()),
                )
                .await,
            ),
        ] {
            if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                stale_paths.push((path, response.status()));
            }
        }
        assert!(
            stale_paths.is_empty(),
            "public paths served stale trust; after_restart={after_restart}: {stale_paths:?}"
        );
        sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
        let response = handle_passport_issuer_jwks(State(pair.importer.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn final_f11_public_verification_does_not_activate_future_successor() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    let source = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap();
    let retired = source.status().test_unwrap().public_key;
    source.rotate().test_unwrap();
    source.retire_issuer(&retired).test_unwrap();
    let successor = source.current_keypair().test_unwrap();
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 59);
    pair.importer
        .config
        .authority_replication_max_future_skew_seconds = 1;
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let request_id = register_public_request(&mut pair.importer, &successor, pair.provisioned_at);
    let jwks = handle_passport_issuer_jwks(State(pair.importer.clone())).await;
    let request = handle_public_get_oid4vp_request(
        State(pair.importer.clone()),
        AxumPath(request_id.clone()),
    )
    .await;
    assert_ne!(
        request.status(),
        StatusCode::OK,
        "public OID4VP request verification trusted a future successor"
    );
    assert_ne!(
        jwks.status(),
        StatusCode::OK,
        "JWKS activated a future successor"
    );
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    let request =
        handle_public_get_oid4vp_request(State(pair.importer.clone()), AxumPath(request_id)).await;
    assert_eq!(request.status(), StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_public_issuer_reads_refuse_saturated_public_admission() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    pair.importer.config.advertise_url = Some("https://trust.example.com".into());
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let held = pair
        .importer
        .public_passport_challenge_lane
        .clone()
        .acquire_many_owned(16)
        .await
        .test_unwrap();
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        handle_passport_issuer_jwks(State(pair.importer.clone())),
    )
    .await
    .test_unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "public issuer read bypassed bounded admission"
    );
    assert_eq!(pair.importer.leader_forward_lane.available_permits(), 64);
    assert_eq!(pair.importer.receipt_query_lane.available_permits(), 4);
    drop(held);
    let response = handle_passport_issuer_jwks(State(pair.importer)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

struct HeldHealthClock {
    at: u64,
    held: std::sync::atomic::AtomicBool,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Clock for HeldHealthClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::ClockError;
        if !self.held.swap(true, Ordering::SeqCst) {
            self.entered.send(()).map_err(|_| ClockError::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| ClockError::Unavailable)?;
        }
        FixedClock::new(self.at).read()
    }
}

fn health_request() -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri(HEALTH_PATH)
        .body(axum::body::Body::empty())
        .test_unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_cancelled_health_keeps_independent_admission_until_inspection_ends() {
    use tower::ServiceExt;
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let (entered_tx, mut entered) = tokio::sync::mpsc::unbounded_channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    pair.importer.finding_challenge_clock = Arc::new(HeldHealthClock {
        at: pair.provisioned_at + 60,
        held: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let lane = pair.importer.authority_health_lane.clone();
    let router = crate::trust_control::trust_control_health::install_health_routes(Router::new())
        .with_state(pair.importer.clone());
    let health = tokio::spawn(router.clone().oneshot(health_request()));
    tokio::time::timeout(Duration::from_secs(30), entered.recv())
        .await
        .test_unwrap()
        .test_unwrap();
    assert!(
        !health.is_finished(),
        "authority inspection occupied the async worker"
    );
    assert_eq!(lane.available_permits(), 0);
    health.abort();
    assert!(health.await.test_unwrap_err().is_cancelled());
    assert_eq!(
        lane.available_permits(),
        0,
        "cancellation released live blocking work's permit"
    );
    let refused = router.clone().oneshot(health_request()).await.test_unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pair.importer.leader_forward_lane.available_permits(), 64);
    assert_eq!(pair.importer.receipt_query_lane.available_permits(), 4);

    release.send(()).test_unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(30), lane.clone().acquire_owned())
        .await
        .test_unwrap()
        .test_unwrap();
    drop(returned);
    assert_eq!(lane.available_permits(), 1);
    let healthy = router.oneshot(health_request()).await.test_unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
}

#[tokio::test]
async fn final_f11_former_signing_custodian_refuses_missed_root_recovery() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let custodian_path = directory.path().join("old-custodian.sqlite3");
    let recovered_path = directory.path().join("recovered-leader.sqlite3");
    let recovery_root = Keypair::generate();
    let custodian =
        SqliteCapabilityAuthority::open_with_clock(&custodian_path, fixed_clock(now)).test_unwrap();
    let old_issuer = custodian.status().test_unwrap().public_key;
    let anchor = custodian
        .initialize_replication_with_recovery(
            "custodian-leader-recovery",
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
    assert!(!recovered
        .status()
        .test_unwrap()
        .trusted_public_keys
        .contains(&old_issuer));

    let (listener, recovered_url) = ServedPeer::reserve();
    let mut exporter_state = state_with_cluster(&recovered_url, &[IMPORTER_URL], None, None, None);
    exporter_state.config.authority_db_path = Some(recovered_path);
    exporter_state.finding_challenge_clock = fixed_clock(now + 1);
    let exporter = ServedPeer::serve(listener, recovered_url, exporter_state, None);
    let old_witness = "http://127.0.0.3:3300";
    let mut state = state_with_cluster(
        IMPORTER_URL,
        &[&exporter.url, old_witness],
        None,
        None,
        None,
    );
    state.config.authority_db_path = Some(custodian_path);
    state.finding_challenge_clock = fixed_clock(now);
    update_peer_reachable(&state, old_witness);
    assert_eq!(current_leader_url(&state).as_deref(), Some(IMPORTER_URL));
    load_authority_status_for_state(&state).test_unwrap();

    let import_error = sync_peer(&state, &exporter.url).test_unwrap_err();
    assert!(
        matches!(import_error, CliError::AuthorityStore(AuthorityStoreError::Fence(message)) if message == OUTSIDE_FRESHNESS)
    );
    assert_eq!(
        current_leader_url(&state).as_deref(),
        Some(exporter.url.as_str())
    );
    assert_eq!(custodian.status().test_unwrap().public_key, old_issuer);
    let refused = handle_authority_status(State(state.clone()), workload_headers()).await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE, "former custodian served an issuer revoked by the new elected leader's authenticated root recovery");

    state.config.authority_replication_max_future_skew_seconds = 1;
    sync_peer(&state, &exporter.url).test_unwrap();
    state.finding_challenge_clock = fixed_clock(now + 1);
    let status = load_authority_status_for_state(&state).test_unwrap();
    assert_eq!(status.generation, Some(2));
    assert!(!status.trusted_public_keys.contains(&old_issuer.to_hex()));
    assert_eq!(
        status.trusted_public_keys,
        vec![recovered.status().test_unwrap().public_key.to_hex()]
    );
}

fn custodian_and_relay() -> (tempfile::TempDir, ServedPeer, TrustServiceState, u64) {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let now = unix_timestamp_now().test_unwrap();
    let path = directory.path().join("custodian.sqlite3");
    let authority =
        SqliteCapabilityAuthority::open_with_clock(&path, fixed_clock(now)).test_unwrap();
    let anchor = authority
        .initialize_replication("custodian-role-freshness")
        .test_unwrap();
    let relay_path = directory.path().join("relay.sqlite3");
    let relay =
        SqliteCapabilityAuthority::open_with_clock(&relay_path, fixed_clock(now)).test_unwrap();
    relay.pin_replication_anchor(&anchor).test_unwrap();
    relay
        .apply_signed_snapshot(&authority.signed_snapshot().test_unwrap())
        .test_unwrap();
    let (listener, relay_url) = ServedPeer::reserve();
    let mut relay_state = state_with_cluster(&relay_url, &[IMPORTER_URL], None, None, None);
    relay_state.config.authority_db_path = Some(relay_path);
    relay_state.finding_challenge_clock = fixed_clock(now);
    let relay = ServedPeer::serve(listener, relay_url, relay_state, None);
    let mut state = state_with_cluster(IMPORTER_URL, &[&relay.url], None, None, None);
    state.config.authority_db_path = Some(path.clone());
    state.finding_challenge_clock = fixed_clock(now);
    (directory, relay, state, now)
}

#[tokio::test]
async fn final_f11_clustered_signing_custodian_requires_quorum_and_leader_confirmation() {
    let (_directory, relay, state, _) = custodian_and_relay();
    assert_authority_status_refused(
        load_authority_status_for_state(&state),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    update_peer_reachable(&state, &relay.url);
    assert_authority_status_refused(
        load_authority_status_for_state(&state),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    sync_peer(&state, &relay.url).test_unwrap();
    load_authority_status_for_state(&state).test_unwrap();
}

#[tokio::test]
async fn final_f11_former_custodian_requires_an_unexpired_imported_envelope() {
    let (_directory, relay, mut state, now) = custodian_and_relay();
    sync_peer(&state, &relay.url).test_unwrap();
    load_authority_status_for_state(&state).test_unwrap();
    state.finding_challenge_clock = fixed_clock(now + 300);
    assert_authority_status_refused(
        load_authority_status_for_state(&state),
        &freshness_refusal_reason(),
    )
    .await;
    let mut standalone = state;
    standalone.cluster = None;
    standalone.config.peer_urls.clear();
    load_authority_status_for_state(&standalone).test_unwrap();
}

#[tokio::test]
async fn final_f11_former_custodian_cannot_refresh_leader_confirmation_by_resigning_locally() {
    let (_directory, relay, mut state, now) = custodian_and_relay();
    sync_peer(&state, &relay.url).test_unwrap();
    load_authority_status_for_state(&state).test_unwrap();
    state.finding_challenge_clock = fixed_clock(now + 300);
    SqliteCapabilityAuthority::open_with_clock(
        state.config.authority_db_path.as_ref().test_unwrap(),
        state.finding_challenge_clock.clone(),
    )
    .test_unwrap()
    .signed_snapshot()
    .test_unwrap();
    assert_authority_status_refused(
        load_authority_status_for_state(&state),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
}

#[tokio::test]
async fn final_f11_new_import_waits_for_matching_leader_envelope_confirmation() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    load_authority_status_for_state(&pair.importer).test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap();
    source.rotate().test_unwrap();
    let next = source.signed_snapshot().test_unwrap();
    // Force the concurrent import/read window: the verified durable update
    // committed, but this leader's ephemeral confirmation still names the
    // previous envelope. A reader must not combine those different views.
    SqliteCapabilityAuthority::open_with_clock(
        pair.importer
            .config
            .authority_db_path
            .as_ref()
            .test_unwrap(),
        pair.importer.finding_challenge_clock.clone(),
    )
    .test_unwrap()
    .apply_signed_snapshot(&next)
    .test_unwrap();
    assert_authority_status_refused(
        load_authority_status_for_state(&pair.importer),
        UNRESOLVED_AUTHORITY_TRUST,
    )
    .await;
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let status = load_authority_status_for_state(&pair.importer).test_unwrap();
    assert_eq!(status.generation, Some(2));
}

struct HeldAuthorityViewClock {
    at: u64,
    reads: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Clock for HeldAuthorityViewClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::ClockError;
        if self.reads.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
            self.entered.send(()).map_err(|_| ClockError::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| ClockError::Unavailable)?;
        }
        FixedClock::new(self.at).read()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_public_jwks_uses_the_same_authority_view_as_its_admission() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 60);
    pair.importer.config.advertise_url = Some("https://trust.example.com".into());
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    let previous = load_authority_status_for_state(&pair.importer).test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap();
    source.rotate().test_unwrap();
    let next = source.signed_snapshot().test_unwrap();
    let (entered_tx, mut entered) = tokio::sync::mpsc::unbounded_channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    pair.importer.finding_challenge_clock = Arc::new(HeldAuthorityViewClock {
        at: pair.provisioned_at + 60,
        reads: std::sync::atomic::AtomicUsize::new(0),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let response = tokio::spawn(handle_passport_issuer_jwks(State(pair.importer.clone())));
    tokio::time::timeout(Duration::from_secs(30), entered.recv())
        .await
        .test_unwrap()
        .test_unwrap();
    SqliteCapabilityAuthority::open_with_clock(
        pair.importer
            .config
            .authority_db_path
            .as_ref()
            .test_unwrap(),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap()
    .apply_signed_snapshot(&next)
    .test_unwrap();
    release.send(()).test_unwrap();
    let response = response.await.test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .test_unwrap();
    let jwks: chio_credentials::PortableJwkSet = serde_json::from_slice(&bytes).test_unwrap();
    let keys: BTreeSet<_> = jwks
        .keys
        .iter()
        .map(|entry| entry.jwk.to_public_key().test_unwrap().to_hex())
        .collect();
    assert_eq!(
        keys,
        previous.trusted_public_keys.into_iter().collect(),
        "public JWKS reread a different authority head after admitting the request's signed view"
    );
}

#[test]
fn final_f11_cluster_startup_does_not_substitute_a_native_clock_for_its_owner() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let path = directory.path().join("owned-clock-authority.sqlite3");
    let owner_clock = fixed_clock(100);
    let authority =
        SqliteCapabilityAuthority::open_with_clock(&path, owner_clock.clone()).test_unwrap();
    authority
        .initialize_replication("cluster-clock-owner")
        .test_unwrap();
    let mut config = base_config();
    config.advertise_url = Some("https://node-a".into());
    config.peer_urls = vec!["https://node-b".into()];
    config.authority_db_path = Some(path);
    build_cluster_state(&config, config.listen, owner_clock).test_unwrap();
    assert!(
        authority.status().is_ok(),
        "cluster startup replaced its owner clock and advanced the persisted local floor"
    );
}
