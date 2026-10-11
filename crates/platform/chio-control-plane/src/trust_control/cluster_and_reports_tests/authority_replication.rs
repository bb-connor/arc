use super::*;

/// An actual authenticated peer surface with a private runtime and dynamic URL.
pub(super) struct LoopbackPeer {
    pub(super) state: TrustServiceState,
    pub(super) url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
    finished: std::sync::mpsc::Receiver<Result<(), String>>,
}

impl LoopbackPeer {
    pub(super) fn reserve(address: &str) -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind(address).test_unwrap();
        let url = format!("http://{}", listener.local_addr().test_unwrap());
        (listener, url)
    }

    pub(super) fn serve(
        listener: std::net::TcpListener,
        url: String,
        state: TrustServiceState,
    ) -> Self {
        use axum::routing::get;
        let router = axum::Router::new()
            .route(AUTHORITY_PATH, get(handle_authority_status))
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
            .with_state(state.clone());
        listener.set_nonblocking(true).test_unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (finished_tx, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            use std::future::IntoFuture;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .test_unwrap();
            let outcome = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).test_unwrap();
                let (stopping, stopping_rx) = tokio::sync::oneshot::channel();
                let serving = axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                        let _ = stopping.send(());
                    })
                    .into_future();
                tokio::pin!(serving);
                tokio::select! {
                    result = &mut serving => result.map_err(|error| error.to_string()),
                    _ = stopping_rx => tokio::time::timeout(Duration::from_secs(30), serving)
                        .await
                        .map_err(|_| "loopback peer shutdown timed out".to_string())?
                        .map_err(|error| error.to_string()),
                }
            });
            runtime.shutdown_timeout(Duration::from_secs(5));
            let _ = finished_tx.send(outcome);
        });
        Self {
            state,
            url,
            stop: Some(stop),
            worker: Some(worker),
            finished,
        }
    }
}

impl Drop for LoopbackPeer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(worker) = self.worker.take() else {
            return;
        };
        match self.finished.recv_timeout(Duration::from_secs(40)) {
            Ok(outcome) => {
                let joined = worker.join();
                if !std::thread::panicking() {
                    joined.test_unwrap();
                    outcome.test_unwrap();
                }
            }
            Err(error) => {
                // The deadline prevents a broken fixture from hanging the suite.
                // A disconnected channel still propagates the worker's panic.
                if matches!(error, std::sync::mpsc::RecvTimeoutError::Disconnected) {
                    let joined = worker.join();
                    if !std::thread::panicking() {
                        joined.test_unwrap();
                    }
                }
                if !std::thread::panicking() {
                    panic!("loopback peer did not complete shutdown: {error}");
                }
            }
        }
    }
}

/// Bootstrap convergence first, then authenticate real signed peer agreement.
pub(super) struct AdmittedReplicationPair {
    pub(super) source: LoopbackPeer,
    pub(super) follower: LoopbackPeer,
}

impl AdmittedReplicationPair {
    pub(super) fn new(source_path: PathBuf, follower_path: PathBuf) -> Self {
        let (source_listener, source_url) = LoopbackPeer::reserve("127.0.0.1:0");
        let (follower_listener, follower_url) = LoopbackPeer::reserve("127.0.0.2:0");
        let mut source = state_with_cluster(&source_url, &[&follower_url], None, None, None);
        source.config.authority_db_path = Some(source_path);
        let mut follower = state_with_cluster(&follower_url, &[&source_url], None, None, None);
        follower.config.authority_db_path = Some(follower_path);
        let source = LoopbackPeer::serve(source_listener, source_url, source);
        let follower = LoopbackPeer::serve(follower_listener, follower_url, follower);
        // The first import can converge before the elected source admits trust.
        let initial = sync_peer(&follower.state, &source.url).test_unwrap_err();
        assert!(
            matches!(initial, CliError::Chio(_)),
            "unexpected refusal: {initial}"
        );
        assert_eq!(
            initial.to_string(),
            CliError::cli_other_error(format!(
                "trust control service request failed with 503: {}",
                json!({"error": "cluster authority context changed during inspection"})
            ))
            .to_string(),
            "first convergence import must not imply serving admission"
        );
        sync_peer(&source.state, &follower.url).test_unwrap();
        let source_view = load_authority_status_for_state(&source.state).test_unwrap();
        sync_peer(&follower.state, &source.url).test_unwrap();
        let follower_view = load_authority_status_for_state(&follower.state).test_unwrap();
        assert_eq!(source_view.issuer_state, follower_view.issuer_state);
        assert_eq!(current_leader_url(&source.state), Some(source.url.clone()));
        assert_eq!(
            current_leader_url(&follower.state),
            Some(source.url.clone())
        );
        Self { source, follower }
    }

    /// Refresh only authenticated transport contact, without importing authority.
    pub(super) fn refresh_transport_context(&self) -> Result<(), CliError> {
        for (local, remote) in [
            (&self.source, &self.follower),
            (&self.follower, &self.source),
        ] {
            let client = service_runtime::client::build_cluster_peer_client(
                &remote.url,
                &local.state.config.service_token,
                &local.url,
            )?;
            let status = client.cluster_status()?;
            assert_eq!(status.self_url, remote.url);
            update_peer_reachable(&local.state, &remote.url);
        }
        for local in [&self.source, &self.follower] {
            let view = cluster_consensus_view(&local.state).test_unwrap();
            assert!(view.has_quorum, "fresh authenticated contact: {view:?}");
            assert_eq!(view.leader_url.as_deref(), Some(self.source.url.as_str()));
        }
        Ok(())
    }
}

#[test]
fn unsigned_authority_full_snapshot_cannot_insert_issuer() {
    let root = chio_test_support::private_tempdir().test_unwrap();
    let path = root.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path).test_unwrap();
    authority
        .initialize_replication("deny-unsigned")
        .test_unwrap();
    let before = authority.snapshot().test_unwrap();
    let mut forged = before.clone();
    forged
        .trusted_keys
        .push(chio_kernel::AuthorityTrustedKeySnapshot {
            public_key_hex: Keypair::generate().public_key().to_hex(),
            generation: 1,
            activated_at: before.rotated_at,
            lifecycle: None,
        });
    let mut state = state_with_cluster(
        "http://127.0.0.1:3300",
        &["http://127.0.0.1:3301"],
        None,
        None,
        None,
    );
    let mut snapshot = build_cluster_state_snapshot(&state).test_unwrap();
    snapshot.authority = Some(authority_snapshot_view(forged));
    state.config.authority_db_path = Some(path);
    assert!(matches!(
        apply_cluster_snapshot(&state, "http://127.0.0.1:3301", snapshot),
        Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message)))
            if message == "unsigned authority snapshot"
    ));
    assert_eq!(authority.snapshot().test_unwrap(), before);
}

#[test]
fn unsigned_authority_plaintext_off_loopback_is_refused_even_with_local_override() {
    for url in [
        "http://192.0.2.8:4000",
        "http://10.0.0.5",
        "http://node-a",
        "http://[2001:db8::1]",
    ] {
        assert!(
            matches!(normalize_cluster_config_url(url, true), Err(error)
            if error.to_string().contains("plaintext cluster URLs require a literal loopback address")),
            "plaintext accepted: {url}"
        );
    }
    for url in [
        "https://node-a",
        "http://127.0.0.1:4000",
        "http://[::1]:4000",
    ] {
        assert!(
            normalize_cluster_config_url(url, true).is_ok(),
            "valid transport refused: {url}"
        );
    }
}

pub(super) fn pull_snapshot(
    state: &TrustServiceState,
    wire: &AuthoritySnapshotView,
) -> Result<(), CliError> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").test_unwrap();
    let endpoint = format!("http://{}", listener.local_addr().test_unwrap());
    let body = serde_json::to_vec(wire).test_unwrap();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().test_unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .test_unwrap();
        let mut request = [0; 4096];
        let length = stream.read(&mut request).test_unwrap();
        let headers = String::from_utf8_lossy(&request[..length]);
        assert!(headers.starts_with(&format!("GET {INTERNAL_AUTHORITY_SNAPSHOT_PATH} ")));
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).test_unwrap();
        stream.write_all(&body).test_unwrap();
    });
    let client = crate::trust_control::service_runtime::client::build_cluster_peer_client(
        &endpoint,
        "token",
        "http://127.0.0.1:3300",
    )
    .test_unwrap();
    let result = sync_peer_authority(state, &client);
    peer.join().test_unwrap();
    result.map(|_| ())
}

#[test]
fn authority_replication_both_import_paths_reject_injected_issuer_and_kernel_denies_it() {
    let root = chio_test_support::private_tempdir().test_unwrap();
    let early_time = chio_test_support::clock::unix_seconds()
        .checked_sub(1)
        .test_expect("fixture clock permits an earlier envelope");
    let early_clock = chio_test_support::clock::scope_unix_secs(early_time);
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("source.db"),
        chio_test_support::clock::clock(),
    )
    .test_unwrap();
    let follower_path = root.path().join("follower.db");
    let follower = SqliteCapabilityAuthority::open_with_clock(
        &follower_path,
        chio_test_support::clock::clock(),
    )
    .test_unwrap();
    let anchor = source.initialize_replication("network-test").test_unwrap();
    follower.pin_replication_anchor(&anchor).test_unwrap();
    source.rotate().test_unwrap();
    let signed = source.signed_snapshot().test_unwrap();
    drop(early_clock);
    let pair = AdmittedReplicationPair::new(root.path().join("source.db"), follower_path.clone());
    let imported = follower.signed_snapshot().test_unwrap();
    assert!(
        imported
            .proof
            .as_ref()
            .test_expect("bootstrap proof")
            .issued_at
            > signed.proof.as_ref().test_expect("early proof").issued_at,
        "bootstrap must import a strictly later signed envelope"
    );
    let state = pair.follower.state.clone();
    let template = build_cluster_state_snapshot(&state).test_unwrap();
    let template = serde_json::to_value(template).test_unwrap();
    let attacker = Keypair::generate();
    let mut injected = signed.clone();
    injected
        .snapshot
        .trusted_keys
        .push(chio_kernel::AuthorityTrustedKeySnapshot {
            public_key_hex: attacker.public_key().to_hex(),
            generation: 2,
            activated_at: signed.snapshot.rotated_at,
            lifecycle: None,
        });
    for mut forged in [injected, signed.clone()] {
        if forged.snapshot == signed.snapshot {
            forged.proof = None;
        }
        let before = follower.snapshot().test_unwrap();
        let expected = if forged.proof.is_none() {
            "unsigned authority snapshot"
        } else {
            "authority snapshot differs from authenticated chain"
        };
        assert!(matches!(pull_snapshot(&state, &forged),
            Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message)))
                if message == expected));
        let mut full: ClusterStateSnapshotResponse =
            serde_json::from_value(template.clone()).test_unwrap();
        full.authority = Some(forged);
        assert!(
            matches!(apply_cluster_snapshot(&state, &pair.source.url, full),
            Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message)))
                if message == expected)
        );
        assert_eq!(follower.snapshot().test_unwrap(), before);
        assert_kernel_rejects_issuer(&follower_path, &attacker, root.path());
    }
    let fresh = source.signed_snapshot().test_unwrap();
    pull_snapshot(&state, &fresh).test_unwrap();
    assert_eq!(
        follower.snapshot().test_unwrap(),
        source.snapshot().test_unwrap()
    );
    source.rotate().test_unwrap();
    let mut full: ClusterStateSnapshotResponse = serde_json::from_value(template).test_unwrap();
    full.authority = Some(source.signed_snapshot().test_unwrap());
    apply_cluster_snapshot(&state, &pair.source.url, full).test_unwrap();
    assert_eq!(
        follower.snapshot().test_unwrap(),
        source.snapshot().test_unwrap()
    );
    assert_kernel_rejects_issuer(&follower_path, &attacker, root.path());
}

#[test]
fn authority_replication_rejects_older_signed_envelope_after_bootstrap_without_mutation() {
    let root = chio_test_support::private_tempdir().test_unwrap();
    let early_time = chio_test_support::clock::unix_seconds()
        .checked_sub(1)
        .test_expect("fixture clock permits an earlier envelope");
    let early_clock = chio_test_support::clock::scope_unix_secs(early_time);
    let source_path = root.path().join("source.db");
    let follower_path = root.path().join("follower.db");
    let source =
        SqliteCapabilityAuthority::open_with_clock(&source_path, chio_test_support::clock::clock())
            .test_unwrap();
    let follower = SqliteCapabilityAuthority::open_with_clock(
        &follower_path,
        chio_test_support::clock::clock(),
    )
    .test_unwrap();
    let anchor = source
        .initialize_replication("old-envelope-control")
        .test_unwrap();
    follower.pin_replication_anchor(&anchor).test_unwrap();
    source.rotate().test_unwrap();
    let old = source.signed_snapshot().test_unwrap();
    drop(early_clock);
    let pair = AdmittedReplicationPair::new(source_path, follower_path);
    let state = &pair.follower.state;
    let imported = follower.signed_snapshot().test_unwrap();
    assert!(
        imported
            .proof
            .as_ref()
            .test_expect("bootstrap proof")
            .issued_at
            > old.proof.as_ref().test_expect("early proof").issued_at
    );
    let before = follower.snapshot().test_unwrap();
    for full_import in [false, true] {
        let outcome = if full_import {
            let mut full = build_cluster_state_snapshot(state).test_unwrap();
            full.authority = Some(old.clone());
            apply_cluster_snapshot(state, &pair.source.url, full)
        } else {
            pull_snapshot(state, &old)
        };
        assert!(matches!(outcome,
            Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message)))
                if message == "authority envelope replay regresses issuance time"));
        assert_eq!(follower.snapshot().test_unwrap(), before);
    }
}

fn assert_kernel_rejects_issuer(
    database: &std::path::Path,
    attacker: &Keypair,
    root: &std::path::Path,
) {
    use chio_kernel::{CapabilityAuthority, LocalCapabilityAuthority, ToolCallRequest};
    let policy_path = root.join("kernel.yaml");
    std::fs::write(
        &policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n",
    )
    .test_unwrap();
    let policy = crate::policy::load_policy(&policy_path).test_unwrap();
    let mut kernel = crate::build_kernel(policy, &Keypair::generate());
    kernel.set_capability_authority(Box::new(
        SqliteCapabilityAuthority::open(database).test_unwrap(),
    ));
    let subject = Keypair::generate().public_key();
    let scope: ChioScope = serde_json::from_value(json!({"grants": [{
        "server_id": "test-server", "tool_name": "read", "operations": ["invoke"], "constraints": []
    }], "resource_grants": [], "prompt_grants": []}))
    .test_unwrap();
    let capability = LocalCapabilityAuthority::new(attacker.clone())
        .issue_capability(&subject, scope, 60)
        .test_unwrap();
    let request = ToolCallRequest {
        request_id: "refused-issuer".into(),
        capability,
        tool_name: "read".into(),
        server_id: "test-server".into(),
        agent_id: subject.to_hex(),
        arguments: json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).test_unwrap();
    assert_eq!(response.verdict, chio_kernel::Verdict::Deny);
    let reason = response.reason.as_deref().test_unwrap();
    assert!(
        reason.contains("not found among trusted") || reason.contains("not a trusted CA"),
        "unexpected rejection: {reason}"
    );
    assert!(response.receipt.verify_signature().test_unwrap());
}

#[test]
fn authority_replication_peer_client_rejects_plaintext_and_redirects() {
    use std::io::{Read, Write};
    let build = crate::trust_control::service_runtime::client::build_cluster_peer_client;
    assert!(
        matches!(build("http://192.0.2.1:4000", "token", "http://127.0.0.1"), Err(error)
        if error.to_string().contains("plaintext cluster URLs require a literal loopback address"))
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").test_unwrap();
    let endpoint = format!("http://{}", listener.local_addr().test_unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().test_unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).test_unwrap();
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/authority\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").test_unwrap();
    });
    let client = build(&endpoint, "token", "http://127.0.0.1:3300").test_unwrap();
    // A disabled redirect reaches the bounded decoder with this empty body.
    // Following Location would instead attempt off-loopback network I/O.
    assert!(matches!(
        client.authority_snapshot(),
        Err(CliError::SignedJson(_))
    ));
    server.join().test_unwrap();
}
