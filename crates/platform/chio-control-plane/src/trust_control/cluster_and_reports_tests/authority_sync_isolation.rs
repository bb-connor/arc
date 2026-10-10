//! Signed authority replicates on its own lane. A refused authority envelope is
//! recorded on the peer, but it never withholds revocations, snapshot recovery
//! or round finalization from that peer.
use super::*;
use chio_kernel::AuthorityStoreError;
use chio_security_types::clock::{Clock, FixedClock};
use std::sync::atomic::{AtomicUsize, Ordering};

// Sort after every loopback exporter so the importing follower consistently
// recognizes the exporter as its elected leader.
const IMPORTER_URL: &str = "http://127.0.0.2:3300";
const REVOKED: &str = "cap-revoked-before-authority-sync";
const REVOKED_LATER: &str = "cap-revoked-while-authority-is-held";
const UNPINNED: &str = "authority replication requires an out-of-band pinned anchor";
const OUTSIDE_FRESHNESS: &str = "authority envelope outside freshness window";
const NO_LIVE_ENVELOPE: &str = "follower has no authenticated live envelope to relay";
const RELAY_REGRESSES: &str = "authority envelope replay regresses issuance time";
const UNPINNED_STARTUP: &str = "clustered trust control requires an out-of-band pinned authority replication anchor in --authority-db; initialize it on the signing custodian with `chio federation authority replication-init` and pin it on every follower with `chio federation authority replication-pin` before starting";

#[path = "authority_clock_contract.rs"]
mod authority_clock_contract;
#[path = "governance_authority.rs"]
mod governance_authority;

/// Holds one numbered authority-snapshot request inside the exporter until
/// the test releases it, so the importer is observable mid-round.
struct AuthorityGate {
    hold_request: usize,
    seen: AtomicUsize,
    entered: std::sync::mpsc::Sender<()>,
    release: tokio::sync::Notify,
}

impl AuthorityGate {
    fn holding(hold_request: usize) -> (Arc<Self>, std::sync::mpsc::Receiver<()>) {
        let (entered, held) = std::sync::mpsc::channel();
        let gate = Self {
            hold_request,
            seen: AtomicUsize::new(0),
            entered,
            release: tokio::sync::Notify::new(),
        };
        (Arc::new(gate), held)
    }

    async fn pass(&self) {
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.hold_request {
            let _ = self.entered.send(());
            self.release.notified().await;
        }
    }
}

/// One peer's internal cluster surface, served over loopback HTTP.
struct ServedPeer {
    url: String,
    gate: Option<Arc<AuthorityGate>>,
    snapshot_unavailable: Arc<std::sync::atomic::AtomicBool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl ServedPeer {
    fn reserve() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").test_unwrap();
        let url = format!("http://{}", listener.local_addr().test_unwrap());
        (listener, url)
    }

    fn serve(
        listener: std::net::TcpListener,
        url: String,
        state: TrustServiceState,
        gate: Option<Arc<AuthorityGate>>,
    ) -> Self {
        use axum::routing::get;
        let held_gate = gate.clone();
        let snapshot_unavailable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let served_snapshot_unavailable = snapshot_unavailable.clone();
        let cluster_snapshot = move |state: State<TrustServiceState>, headers: HeaderMap| {
            let unavailable = served_snapshot_unavailable.clone();
            async move {
                if unavailable.load(Ordering::SeqCst) {
                    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, "snapshot unavailable")
                } else {
                    handle_internal_cluster_snapshot(state, headers).await
                }
            }
        };
        let gated_authority_snapshot =
            move |state: State<TrustServiceState>, headers: HeaderMap| {
                let gate = gate.clone();
                async move {
                    if let Some(gate) = gate {
                        gate.pass().await;
                    }
                    handle_internal_authority_snapshot(state, headers).await
                }
            };
        let router = axum::Router::new()
            .route(
                INTERNAL_CLUSTER_STATUS_PATH,
                get(handle_internal_cluster_status),
            )
            .route(INTERNAL_CLUSTER_SNAPSHOT_PATH, get(cluster_snapshot))
            .route(
                INTERNAL_AUTHORITY_SNAPSHOT_PATH,
                get(gated_authority_snapshot),
            )
            .route(
                INTERNAL_REVOCATIONS_DELTA_PATH,
                get(handle_internal_revocations_delta),
            )
            .with_state(state);
        listener.set_nonblocking(true).test_unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .test_unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).test_unwrap();
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                    })
                    .await
                    .test_unwrap();
            });
        });
        Self {
            url,
            gate: held_gate,
            snapshot_unavailable,
            shutdown: Some(shutdown),
            server: Some(server),
        }
    }
}

impl Drop for ServedPeer {
    fn drop(&mut self) {
        // A held request would otherwise keep graceful shutdown waiting.
        if let Some(gate) = self.gate.as_ref() {
            gate.release.notify_one();
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum AuthorityFault {
    /// The importing node never had its replication anchor provisioned.
    UnpinnedImporter,
    /// The importing node's clock trails the signing custodian's.
    LaggingImporterClock,
    /// The exporting follower holds a pinned anchor but no live envelope.
    ExporterWithoutEnvelope,
    /// The signing custodian pulls a follower that relays an envelope older
    /// than the one the custodian last issued to another follower.
    RelayedEnvelopeRegresses,
}

struct ReplicationPair {
    _directory: tempfile::TempDir,
    exporter: ServedPeer,
    importer: TrustServiceState,
    exporter_revocations: SqliteRevocationStore,
    provisioned_at: u64,
}

fn fixed_clock(unix_seconds: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(unix_seconds))
}

/// An exporter whose revocation store already holds `REVOKED`, and an importer
/// whose signed-authority import from it is refused by `fault`.
fn replication_pair(fault: AuthorityFault) -> ReplicationPair {
    gated_replication_pair(fault, None)
}

fn gated_replication_pair(
    fault: AuthorityFault,
    gate: Option<Arc<AuthorityGate>>,
) -> ReplicationPair {
    let provisioned_at =
        unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let exporter_authority = directory.path().join("exporter-authority.sqlite3");
    let importer_authority = directory.path().join("importer-authority.sqlite3");
    let (listener, exporter_url) = ServedPeer::reserve();

    let mut exporter = state_with_cluster(
        &exporter_url,
        &[IMPORTER_URL],
        None,
        Some(directory.path().join("exporter-revocations.sqlite3")),
        None,
    );
    exporter.config.authority_db_path = Some(exporter_authority.clone());
    let mut importer = state_with_cluster(
        IMPORTER_URL,
        &[exporter_url.as_str()],
        None,
        Some(directory.path().join("importer-revocations.sqlite3")),
        None,
    );
    importer.config.authority_db_path = Some(importer_authority.clone());

    match fault {
        AuthorityFault::UnpinnedImporter => {
            SqliteCapabilityAuthority::open(&exporter_authority)
                .test_unwrap()
                .initialize_replication("unpinned-importer")
                .test_unwrap();
            drop(SqliteCapabilityAuthority::open(&importer_authority).test_unwrap());
        }
        AuthorityFault::LaggingImporterClock => {
            let custodian = SqliteCapabilityAuthority::open_with_clock(
                &exporter_authority,
                fixed_clock(provisioned_at),
            )
            .test_unwrap();
            let anchor = custodian
                .initialize_replication("lagging-importer")
                .test_unwrap();
            let envelope = custodian.signed_snapshot().test_unwrap();
            let follower = SqliteCapabilityAuthority::open_with_clock(
                &importer_authority,
                fixed_clock(provisioned_at),
            )
            .test_unwrap();
            follower.pin_replication_anchor(&anchor).test_unwrap();
            follower.apply_signed_snapshot(&envelope).test_unwrap();
            // The custodian now signs a full minute ahead of the importer's clock.
            exporter.finding_challenge_clock = fixed_clock(provisioned_at + 60);
            importer.finding_challenge_clock = fixed_clock(provisioned_at + 1);
        }
        AuthorityFault::ExporterWithoutEnvelope => {
            let anchor = SqliteCapabilityAuthority::open(&importer_authority)
                .test_unwrap()
                .initialize_replication("exporter-without-envelope")
                .test_unwrap();
            SqliteCapabilityAuthority::open(&exporter_authority)
                .test_unwrap()
                .pin_replication_anchor(&anchor)
                .test_unwrap();
        }
        AuthorityFault::RelayedEnvelopeRegresses => {
            let issued_at = provisioned_at;
            let custodian = SqliteCapabilityAuthority::open_with_clock(
                &importer_authority,
                fixed_clock(issued_at),
            )
            .test_unwrap();
            let anchor = custodian
                .initialize_replication("relayed-envelope-regresses")
                .test_unwrap();
            let relayed = custodian.signed_snapshot().test_unwrap();
            let follower = SqliteCapabilityAuthority::open_with_clock(
                &exporter_authority,
                fixed_clock(issued_at),
            )
            .test_unwrap();
            follower.pin_replication_anchor(&anchor).test_unwrap();
            follower.apply_signed_snapshot(&relayed).test_unwrap();
            // A later pull by another follower advances the custodian's envelope.
            SqliteCapabilityAuthority::open_with_clock(
                &importer_authority,
                fixed_clock(issued_at + 5),
            )
            .test_unwrap()
            .signed_snapshot()
            .test_unwrap();
            exporter.finding_challenge_clock = fixed_clock(issued_at + 10);
            importer.finding_challenge_clock = fixed_clock(issued_at + 10);
        }
    }

    let exporter_revocations = exporter.revocation_store().test_unwrap();
    exporter_revocations
        .upsert_revocation(&RevocationRecord {
            capability_id: REVOKED.to_string(),
            revoked_at: 10,
        })
        .test_unwrap();
    ReplicationPair {
        _directory: directory,
        exporter: ServedPeer::serve(listener, exporter_url, exporter, gate),
        importer,
        exporter_revocations,
        provisioned_at,
    }
}

fn importer_revoked(pair: &ReplicationPair) -> bool {
    importer_holds(pair, REVOKED)
}

fn importer_holds(pair: &ReplicationPair, capability_id: &str) -> bool {
    pair.importer
        .revocation_store()
        .test_unwrap()
        .is_revoked(capability_id)
        .test_unwrap()
}

fn peer_view<T>(pair: &ReplicationPair, view: impl FnOnce(&PeerSyncState) -> T) -> T {
    with_peer_state(&pair.importer, &pair.exporter.url, view).test_unwrap()
}

/// The round reports the authority refusal and records it on the peer.
fn assert_recorded_refusal(
    pair: &ReplicationPair,
    fault: AuthorityFault,
    result: Result<(), CliError>,
) {
    let recorded = peer_view(pair, |peer| peer.last_error.clone());
    let expected = match fault {
        AuthorityFault::UnpinnedImporter => UNPINNED,
        AuthorityFault::LaggingImporterClock => OUTSIDE_FRESHNESS,
        AuthorityFault::RelayedEnvelopeRegresses => RELAY_REGRESSES,
        AuthorityFault::ExporterWithoutEnvelope => {
            // The exporter refuses to serve an envelope it cannot authenticate,
            // and the importer receives exactly that refusal over HTTP.
            let refusal = AuthorityStoreError::Fence(NO_LIVE_ENVELOPE.to_string()).to_string();
            let expected = CliError::cli_other_error(json!({ "error": refusal }).to_string());
            let error = result.test_unwrap_err();
            assert!(
                matches!(error, CliError::Chio(_)),
                "unexpected exporter refusal: {error:?}"
            );
            assert_eq!(error.to_string(), expected.to_string());
            assert_eq!(recorded, Some(expected.to_string()));
            return;
        }
    };
    assert!(
        matches!(
            &result,
            Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message)))
                if message == expected
        ),
        "{fault:?}: expected authority refusal `{expected}`, got {result:?}"
    );
    assert_eq!(
        recorded,
        Some(CliError::from(AuthorityStoreError::Fence(expected.to_string())).to_string()),
        "{fault:?}: authority refusal not recorded"
    );
}

/// A normal round still pulls the revocation through its own lane and
/// finalizes before reporting the authority refusal.
fn assert_round_survives_refused_authority(fault: AuthorityFault) {
    let pair = replication_pair(fault);
    let progress = pair
        .importer
        .cluster_progress
        .as_ref()
        .test_unwrap()
        .subscribe();

    let result = sync_peer(&pair.importer, &pair.exporter.url);

    assert!(
        importer_revoked(&pair),
        "{fault:?}: revocation lane starved"
    );
    assert_eq!(*progress.borrow(), 1, "{fault:?}: round never finalized");
    assert_eq!(
        peer_view(&pair, |peer| peer.delta_records_since_snapshot),
        1,
        "{fault:?}: finalization dropped the pulled revocation"
    );
    assert!(peer_view(&pair, |peer| peer.health.is_reachable()));
    assert_recorded_refusal(&pair, fault, result);
}

/// A forced snapshot still recovers the revocation, clears the snapshot
/// demand and finalizes before reporting the authority refusal.
fn assert_snapshot_survives_refused_authority(fault: AuthorityFault) {
    let pair = replication_pair(fault);
    update_peer_state(&pair.importer, &pair.exporter.url, |peer| {
        peer.force_snapshot = true;
    });
    let progress = pair
        .importer
        .cluster_progress
        .as_ref()
        .test_unwrap()
        .subscribe();

    let result = sync_peer(&pair.importer, &pair.exporter.url);

    assert!(
        importer_revoked(&pair),
        "{fault:?}: snapshot recovery dropped the revocation"
    );
    assert_eq!(
        peer_view(&pair, |peer| peer.snapshot_applied_count),
        1,
        "{fault:?}: snapshot recovery never completed"
    );
    assert!(!peer_view(&pair, |peer| peer.force_snapshot));
    assert_eq!(*progress.borrow(), 1, "{fault:?}: round never finalized");
    assert_recorded_refusal(&pair, fault, result);
}

#[test]
fn unpinned_importer_round_still_replicates_revocations() {
    assert_round_survives_refused_authority(AuthorityFault::UnpinnedImporter);
}

#[test]
fn lagging_importer_clock_round_still_replicates_revocations() {
    assert_round_survives_refused_authority(AuthorityFault::LaggingImporterClock);
}

#[test]
fn exporter_without_envelope_round_still_replicates_revocations() {
    assert_round_survives_refused_authority(AuthorityFault::ExporterWithoutEnvelope);
}

#[test]
fn relayed_envelope_regression_round_still_replicates_revocations() {
    assert_round_survives_refused_authority(AuthorityFault::RelayedEnvelopeRegresses);
}

#[test]
fn unpinned_importer_snapshot_still_recovers_revocations() {
    assert_snapshot_survives_refused_authority(AuthorityFault::UnpinnedImporter);
}

#[test]
fn lagging_importer_clock_snapshot_still_recovers_revocations() {
    assert_snapshot_survives_refused_authority(AuthorityFault::LaggingImporterClock);
}

#[test]
fn exporter_without_envelope_snapshot_still_recovers_revocations() {
    assert_snapshot_survives_refused_authority(AuthorityFault::ExporterWithoutEnvelope);
}

#[test]
fn relayed_envelope_regression_snapshot_still_recovers_revocations() {
    assert_snapshot_survives_refused_authority(AuthorityFault::RelayedEnvelopeRegresses);
}

#[test]
fn authority_refusal_stays_reported_until_an_authority_import_succeeds() {
    let (gate, held) = AuthorityGate::holding(2);
    let mut pair = gated_replication_pair(AuthorityFault::LaggingImporterClock, Some(gate.clone()));
    let refusal =
        CliError::from(AuthorityStoreError::Fence(OUTSIDE_FRESHNESS.to_string())).to_string();
    let progress = pair
        .importer
        .cluster_progress
        .as_ref()
        .test_unwrap()
        .subscribe();

    let first = sync_peer(&pair.importer, &pair.exporter.url);
    assert!(matches!(
        &first,
        Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message)))
            if message == OUTSIDE_FRESHNESS
    ));
    assert_eq!(
        peer_view(&pair, |peer| peer.last_error.clone()),
        Some(refusal.clone())
    );

    // The next round finalizes its streams, then blocks inside the second
    // authority request. A stream success is not an authority success.
    pair.exporter_revocations
        .upsert_revocation(&RevocationRecord {
            capability_id: REVOKED_LATER.to_string(),
            revoked_at: 11,
        })
        .test_unwrap();
    let round = {
        let importer = pair.importer.clone();
        let exporter_url = pair.exporter.url.clone();
        std::thread::spawn(move || sync_peer(&importer, &exporter_url))
    };
    held.recv_timeout(Duration::from_secs(30)).test_unwrap();
    assert!(
        importer_holds(&pair, REVOKED_LATER),
        "revocation lane starved"
    );
    assert_eq!(*progress.borrow(), 2, "stream round never finalized");
    assert_eq!(
        peer_view(&pair, |peer| peer.delta_records_since_snapshot),
        2
    );
    assert_eq!(
        peer_view(&pair, |peer| peer.last_error.clone()),
        Some(refusal.clone()),
        "stream finalization cleared an unresolved authority refusal"
    );

    gate.release.notify_one();
    let second = round.join().test_unwrap();
    assert!(matches!(
        &second,
        Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message)))
            if message == OUTSIDE_FRESHNESS
    ));
    assert_eq!(
        peer_view(&pair, |peer| peer.last_error.clone()),
        Some(refusal)
    );

    // Once the importer's clock reaches the signer's, an authority import
    // succeeds and only then is the refusal resolved.
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 120);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    assert_eq!(peer_view(&pair, |peer| peer.last_error.clone()), None);
    assert_eq!(*progress.borrow(), 3);
}

#[test]
fn clustered_startup_refuses_an_unpinned_authority_database() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let authority_db_path = directory.path().join("authority.sqlite3");
    drop(SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap());
    let mut config = base_config();
    config.advertise_url = Some("https://node-a".to_string());
    config.peer_urls = vec!["https://node-b".to_string()];
    config.authority_db_path = Some(authority_db_path.clone());

    let error = build_cluster_state(&config, config.listen, chio_test_support::clock::clock())
        .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        CliError::cli_other_error(UNPINNED_STARTUP).to_string()
    );

    // A single node replicates no signed authority, so it needs no anchor.
    let mut standalone = config.clone();
    standalone.peer_urls.clear();
    assert!(build_cluster_state(
        &standalone,
        standalone.listen,
        chio_test_support::clock::clock()
    )
    .test_unwrap()
    .is_none());

    SqliteCapabilityAuthority::open(&authority_db_path)
        .test_unwrap()
        .initialize_replication("startup-pin")
        .test_unwrap();
    assert!(
        build_cluster_state(&config, config.listen, chio_test_support::clock::clock())
            .test_unwrap()
            .is_some()
    );
}

#[test]
fn final_f11_refused_authority_is_degraded_until_a_signed_import_recovers() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    assert_authority_freshness_refused(sync_peer(&pair.importer, &pair.exporter.url));
    assert!(importer_revoked(&pair), "revocations must keep progressing");
    assert!(peer_view(&pair, |peer| peer.health.is_reachable()));
    assert_eq!(peer_view(&pair, |peer| peer.health.label()), "degraded");
    update_peer_success(&pair.importer, &pair.exporter.url);
    update_peer_reachable(&pair.importer, &pair.exporter.url);
    assert_eq!(peer_view(&pair, |peer| peer.health.label()), "degraded");

    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 120);
    sync_peer(&pair.importer, &pair.exporter.url).test_unwrap();
    assert_eq!(peer_view(&pair, |peer| peer.health.label()), "healthy");
    assert_eq!(peer_view(&pair, |peer| peer.authority_error.clone()), None);
}

fn workload_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer token".parse().test_unwrap());
    headers
}

fn assert_authority_freshness_refused(result: Result<(), CliError>) {
    assert!(
        matches!(result, Err(CliError::AuthorityStore(AuthorityStoreError::Fence(message))) if message == OUTSIDE_FRESHNESS)
    );
}

#[tokio::test]
async fn final_f11_follower_does_not_serve_issuer_trust_after_envelope_expiry() {
    let mut pair = replication_pair(AuthorityFault::LaggingImporterClock);
    pair.importer.finding_challenge_clock = fixed_clock(pair.provisioned_at + 300);
    let response = handle_authority_status(State(pair.importer), workload_headers()).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "follower served trusted issuer keys at its signed envelope's exclusive expiry"
    );
}

#[tokio::test]
async fn final_f11_known_stale_follower_refuses_authority_reads_and_reports_health() {
    use tower::ServiceExt;

    let pair = replication_pair(AuthorityFault::LaggingImporterClock);
    let custodian = SqliteCapabilityAuthority::open_with_clock(
        pair._directory.path().join("exporter-authority.sqlite3"),
        fixed_clock(pair.provisioned_at + 60),
    )
    .test_unwrap();
    let compromised = custodian.status().test_unwrap().public_key;
    custodian.rotate().test_unwrap();
    custodian.revoke_issuer(&compromised).test_unwrap();
    assert_authority_freshness_refused(sync_peer(&pair.importer, &pair.exporter.url));
    assert!(importer_revoked(&pair));
    let response = handle_authority_status(State(pair.importer.clone()), workload_headers()).await;
    let health = crate::trust_control::trust_control_health::install_health_routes(Router::new())
        .with_state(pair.importer.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri(HEALTH_PATH)
                .body(axum::body::Body::empty())
                .test_unwrap(),
        )
        .await
        .test_unwrap();
    let health: Value =
        serde_json::from_slice(&to_bytes(health.into_body(), 64 * 1024).await.test_unwrap())
            .test_unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a follower whose elected leader's authority import was refused served the old issuer"
    );
    assert_eq!(health["authority"]["available"], false);
    assert_eq!(health["cluster"]["degradedPeers"], 1);
    assert_eq!(health["cluster"]["healthyPeers"], 0);
}

async fn assert_inspection_refused<T>(result: Result<T, Response>, reason: &str) {
    let response = match result {
        Err(response) => response,
        Ok(_) => panic!("authority inspection unexpectedly succeeded"),
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(body.get("error").and_then(Value::as_str), Some(reason));
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_inspection_capacity_is_nonqueued_and_independent() {
    let state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    let held = state
        .authority_inspection_lane
        .clone()
        .acquire_many_owned(8)
        .await
        .test_unwrap();
    assert_inspection_refused(
        inspect_authority_state(&state, |_| -> Result<(), Response> {
            panic!("capacity refusal must precede work")
        })
        .await,
        "authority inspection is at capacity",
    )
    .await;
    assert_eq!(state.authority_health_lane.available_permits(), 1);
    assert_eq!(state.public_passport_challenge_lane.available_permits(), 16);
    assert_eq!(state.leader_forward_lane.available_permits(), 64);
    assert_eq!(state.receipt_query_lane.available_permits(), 4);
    drop(held);
    assert_eq!(
        inspect_authority_state(&state, |_| Ok(7))
            .await
            .test_unwrap(),
        7
    );
}

#[tokio::test(flavor = "current_thread")]
async fn final_f11_inspection_cancellation_keeps_blocking_work_admitted() {
    let state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    let (entered_tx, mut entered) = tokio::sync::mpsc::unbounded_channel();
    let (release, released) = std::sync::mpsc::channel();
    let worker_state = state.clone();
    let worker = tokio::spawn(async move {
        inspect_authority_state(&worker_state, move |_| {
            entered_tx.send(()).test_unwrap();
            released.recv_timeout(Duration::from_secs(30)).test_unwrap();
            Ok(())
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(30), entered.recv())
        .await
        .test_unwrap()
        .test_unwrap();
    assert!(
        !worker.is_finished(),
        "blocking inspection occupied the async worker"
    );
    assert_eq!(state.authority_inspection_lane.available_permits(), 7);
    worker.abort();
    assert!(worker.await.test_unwrap_err().is_cancelled());
    assert_eq!(state.authority_inspection_lane.available_permits(), 7);
    release.send(()).test_unwrap();
    let returned = tokio::time::timeout(
        Duration::from_secs(30),
        state
            .authority_inspection_lane
            .clone()
            .acquire_many_owned(8),
    )
    .await
    .test_unwrap()
    .test_unwrap();
    drop(returned);
    assert_eq!(state.authority_inspection_lane.available_permits(), 8);
}

#[tokio::test]
async fn final_f11_inspection_rechecks_election_term_after_work() {
    let peer_url = "http://127.0.0.2:3301";
    let state = state_with_cluster(IMPORTER_URL, &[peer_url], None, None, None);
    update_peer_reachable(&state, peer_url);
    assert_inspection_refused(
        inspect_authority_state(&state, |state| {
            state
                .cluster
                .as_ref()
                .test_unwrap()
                .lock()
                .test_unwrap()
                .election_term += 1;
            Ok(())
        })
        .await,
        "cluster authority context changed during inspection",
    )
    .await;
}

#[tokio::test]
async fn final_f11_inspection_rechecks_authority_head_after_work() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let mut state = state_with_cluster(IMPORTER_URL, &[], None, None, None);
    let path = directory.path().join("authority.sqlite3");
    SqliteCapabilityAuthority::open_with_clock(&path, state.finding_challenge_clock.clone())
        .test_unwrap();
    state.config.authority_db_path = Some(path);
    assert_inspection_refused(
        inspect_authority_state(&state, |state| {
            SqliteCapabilityAuthority::open_with_clock(
                state.config.authority_db_path.as_ref().test_unwrap(),
                state.finding_challenge_clock.clone(),
            )
            .test_unwrap()
            .rotate()
            .test_unwrap();
            Ok(())
        })
        .await,
        "authority state changed during inspection",
    )
    .await;
    assert_eq!(
        load_authority_status_for_state(&state)
            .test_unwrap()
            .generation,
        Some(2)
    );
}
