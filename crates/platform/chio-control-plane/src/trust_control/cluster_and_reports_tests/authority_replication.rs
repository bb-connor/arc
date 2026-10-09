use super::*;

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
    let source = SqliteCapabilityAuthority::open(root.path().join("source.db")).test_unwrap();
    let follower_path = root.path().join("follower.db");
    let follower = SqliteCapabilityAuthority::open(&follower_path).test_unwrap();
    let anchor = source.initialize_replication("network-test").test_unwrap();
    follower.pin_replication_anchor(&anchor).test_unwrap();
    source.rotate().test_unwrap();
    let signed = source.signed_snapshot().test_unwrap();
    let mut state = state_with_cluster(
        "http://127.0.0.1:3300",
        &["http://127.0.0.1:3301"],
        None,
        None,
        None,
    );
    let template = build_cluster_state_snapshot(&state).test_unwrap();
    let template = serde_json::to_value(template).test_unwrap();
    state.config.authority_db_path = Some(follower_path.clone());
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
            matches!(apply_cluster_snapshot(&state, "http://127.0.0.1:3301", full),
            Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message)))
                if message == expected)
        );
        assert_eq!(follower.snapshot().test_unwrap(), before);
        assert_kernel_rejects_issuer(&follower_path, &attacker, root.path());
    }
    pull_snapshot(&state, &signed).test_unwrap();
    assert_eq!(
        follower.snapshot().test_unwrap(),
        source.snapshot().test_unwrap()
    );
    source.rotate().test_unwrap();
    let mut full: ClusterStateSnapshotResponse = serde_json::from_value(template).test_unwrap();
    full.authority = Some(source.signed_snapshot().test_unwrap());
    apply_cluster_snapshot(&state, "http://127.0.0.1:3301", full).test_unwrap();
    assert_eq!(
        follower.snapshot().test_unwrap(),
        source.snapshot().test_unwrap()
    );
    assert_kernel_rejects_issuer(&follower_path, &attacker, root.path());
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
