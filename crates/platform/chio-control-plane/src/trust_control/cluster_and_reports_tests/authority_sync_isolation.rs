//! Signed authority replicates on its own lane. A refused authority envelope is
//! recorded on the peer, but it never withholds revocations, snapshot recovery
//! or round finalization from that peer.
use super::*;
use chio_kernel::AuthorityStoreError;
use chio_security_types::clock::{Clock, FixedClock};

const IMPORTER_URL: &str = "http://127.0.0.1:3300";
const REVOKED: &str = "cap-revoked-before-authority-sync";
const UNPINNED: &str = "authority replication requires an out-of-band pinned anchor";
const OUTSIDE_FRESHNESS: &str = "authority envelope outside freshness window";
const NO_LIVE_ENVELOPE: &str = "follower has no authenticated live envelope to relay";
const RELAY_REGRESSES: &str = "authority envelope replay regresses issuance time";
const UNPINNED_STARTUP: &str = "clustered trust control requires an out-of-band pinned authority replication anchor in --authority-db; initialize it on the signing custodian with `chio federation authority replication-init` and pin it on every follower with `chio federation authority replication-pin` before starting";

/// One peer's internal cluster surface, served over loopback HTTP.
struct ServedPeer {
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl ServedPeer {
    fn reserve() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").test_unwrap();
        let url = format!("http://{}", listener.local_addr().test_unwrap());
        (listener, url)
    }

    fn serve(listener: std::net::TcpListener, url: String, state: TrustServiceState) -> Self {
        use axum::routing::get;
        let router = axum::Router::new()
            .route(
                INTERNAL_CLUSTER_STATUS_PATH,
                get(handle_internal_cluster_status),
            )
            .route(
                INTERNAL_CLUSTER_SNAPSHOT_PATH,
                get(handle_internal_cluster_snapshot),
            )
            .route(
                INTERNAL_AUTHORITY_SNAPSHOT_PATH,
                get(handle_internal_authority_snapshot),
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
            shutdown: Some(shutdown),
            server: Some(server),
        }
    }
}

impl Drop for ServedPeer {
    fn drop(&mut self) {
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
}

fn fixed_clock(unix_seconds: u64) -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(unix_seconds))
}

/// An exporter whose revocation store already holds `REVOKED`, and an importer
/// whose signed-authority import from it is refused by `fault`.
fn replication_pair(fault: AuthorityFault) -> ReplicationPair {
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
            let provisioned_at = unix_timestamp_now()
                .unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
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
            let issued_at = unix_timestamp_now()
                .unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
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

    exporter
        .revocation_store()
        .test_unwrap()
        .upsert_revocation(&RevocationRecord {
            capability_id: REVOKED.to_string(),
            revoked_at: 10,
        })
        .test_unwrap();
    ReplicationPair {
        _directory: directory,
        exporter: ServedPeer::serve(listener, exporter_url, exporter),
        importer,
    }
}

fn importer_revoked(pair: &ReplicationPair) -> bool {
    pair.importer
        .revocation_store()
        .test_unwrap()
        .is_revoked(REVOKED)
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
fn clustered_startup_refuses_an_unpinned_authority_database() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let authority_db_path = directory.path().join("authority.sqlite3");
    drop(SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap());
    let mut config = base_config();
    config.advertise_url = Some("https://node-a".to_string());
    config.peer_urls = vec!["https://node-b".to_string()];
    config.authority_db_path = Some(authority_db_path.clone());

    let error = build_cluster_state(&config, config.listen).test_unwrap_err();
    assert_eq!(
        error.to_string(),
        CliError::cli_other_error(UNPINNED_STARTUP).to_string()
    );

    // A single node replicates no signed authority, so it needs no anchor.
    let mut standalone = config.clone();
    standalone.peer_urls.clear();
    assert!(build_cluster_state(&standalone, standalone.listen)
        .test_unwrap()
        .is_none());

    SqliteCapabilityAuthority::open(&authority_db_path)
        .test_unwrap()
        .initialize_replication("startup-pin")
        .test_unwrap();
    assert!(build_cluster_state(&config, config.listen)
        .test_unwrap()
        .is_some());
}
