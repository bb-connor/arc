use super::*;
use chio_kernel::authority::lifecycle::AuthorityLifecycleChange;
use chio_kernel::authority::replication::{
    AuthorityReplicationAnchor, SignedAuthoritySnapshot, SignedAuthorityTransition,
};

struct MajorityCluster {
    _directory: tempfile::TempDir,
    leader: ServedPeer,
    majority: ServedPeer,
    minority: Option<ServedPeer>,
    minority_url: String,
    at: u64,
    leader_clock: Arc<SteppedClock>,
    minority_clock: Arc<SteppedClock>,
}

fn majority_cluster() -> MajorityCluster {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let at = unix_timestamp_now().test_unwrap();
    let leader_clock = Arc::new(SteppedClock(std::sync::atomic::AtomicU64::new(at)));
    let minority_clock = Arc::new(SteppedClock(std::sync::atomic::AtomicU64::new(at)));
    let (leader_listener, leader_url) = ServedPeer::reserve();
    let (majority_listener, majority_url) = ServedPeer::reserve_on("127.0.0.2:0");
    let (minority_listener, minority_url) = ServedPeer::reserve_on("127.0.0.3:0");
    let leader_path = directory.path().join("leader.sqlite3");
    let owner =
        SqliteCapabilityAuthority::open_with_clock(&leader_path, fixed_clock(at)).test_unwrap();
    let anchor = owner
        .initialize_replication("authority-majority-contract")
        .test_unwrap();
    let envelope = owner.signed_snapshot().test_unwrap();
    let mut leader = state_with_cluster(
        &leader_url,
        &[&majority_url, &minority_url],
        None,
        None,
        None,
    );
    leader.config.authority_db_path = Some(leader_path);
    leader.finding_challenge_clock = leader_clock.clone();
    let mut peers = Vec::new();
    for (name, url, other) in [
        ("majority", &majority_url, &minority_url),
        ("minority", &minority_url, &majority_url),
    ] {
        let path = directory.path().join(format!("{name}.sqlite3"));
        let authority =
            SqliteCapabilityAuthority::open_with_clock(&path, fixed_clock(at)).test_unwrap();
        authority.pin_replication_anchor(&anchor).test_unwrap();
        authority.apply_signed_snapshot(&envelope).test_unwrap();
        let mut state = state_with_cluster(url, &[&leader_url, other], None, None, None);
        state.config.authority_db_path = Some(path);
        state.finding_challenge_clock = fixed_clock(at);
        if name == "minority" {
            state.finding_challenge_clock = minority_clock.clone();
        }
        peers.push(state);
    }
    let leader = ServedPeer::serve(leader_listener, leader_url, leader, None);
    let majority = ServedPeer::serve(majority_listener, majority_url, peers.remove(0), None);
    let minority = ServedPeer::serve(
        minority_listener,
        minority_url.clone(),
        peers.remove(0),
        None,
    );
    sync_peer(&leader.state, &majority.url).test_unwrap();
    sync_peer(&leader.state, &minority.url).test_unwrap();
    load_authority_status_for_state(&leader.state).test_unwrap();
    MajorityCluster {
        _directory: directory,
        leader,
        majority,
        minority: Some(minority),
        minority_url,
        at,
        leader_clock,
        minority_clock,
    }
}

async fn assert_admitted_read_and_issue(state: &TrustServiceState) {
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
    let issue_bytes = to_bytes(issued.into_body(), 64 * 1024).await.test_unwrap();
    eprintln!("fresh majority with failed minority: read={read_status} {read_body}, issue={issue_status} {}", String::from_utf8_lossy(&issue_bytes));
    assert_eq!(
        read_status,
        StatusCode::OK,
        "minority transport failure vetoed fresh signed majority"
    );
    assert_eq!(issue_status, StatusCode::OK);
    let issued: IssueCapabilityResponse = serde_json::from_slice(&issue_bytes).test_unwrap();
    assert_eq!(
        Some(issued.capability.issuer.to_hex()),
        read_body
            .get("publicKey")
            .and_then(Value::as_str)
            .map(str::to_string)
    );
    assert!(issued.capability.verify_signature().test_unwrap());
}

fn retire_old_issuer(
    anchor: &AuthorityReplicationAnchor,
    current: &SignedAuthoritySnapshot,
    signer: &Keypair,
    retired_key: &PublicKey,
    at: u64,
) -> SignedAuthoritySnapshot {
    let proof = current.proof.as_ref().test_unwrap();
    let mut transitions = proof.transitions.clone();
    transitions.push(
        SignedAuthorityTransition::sign_change(
            anchor,
            &current.snapshot,
            &proof.chain_commitment,
            AuthorityLifecycleChange::Retire {
                public_key_hex: retired_key.to_hex(),
            },
            &signer.public_key(),
            at,
            signer,
        )
        .test_unwrap(),
    );
    SignedAuthoritySnapshot::sign(anchor, transitions, at, signer).test_unwrap()
}

fn known_head(state: &TrustServiceState, peer_url: &str) -> Option<String> {
    with_peer_state(state, peer_url, |peer| {
        peer.authority_refused_history
            .as_ref()
            .map(|witness| witness.head().to_string())
    })
    .test_unwrap()
}

#[tokio::test]
async fn final_f11_majority_transport_refusal_does_not_veto_fresh_signed_quorum() {
    let mut cluster = majority_cluster();
    cluster
        .minority
        .as_ref()
        .test_unwrap()
        .authority_snapshot_unavailable
        .store(true, Ordering::SeqCst);
    let refused = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(refused, CliError::Chio(_)),
        "unexpected authority refusal: {refused}"
    );
    assert_eq!(
        refused.to_string(),
        CliError::cli_other_error(json!({"error":"authority snapshot unavailable"}).to_string())
            .to_string()
    );
    drop(cluster.minority.take());
    let unavailable = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(&unavailable, CliError::Chio(error) if error.to_string().contains("trust control service transport failed:")),
        "unexpected closed-peer transport refusal: {unavailable}"
    );
    sync_peer(&cluster.leader.state, &cluster.majority.url).test_unwrap();
    assert!(
        with_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| peer
            .authority_error
            .is_some()
            && !peer.health.is_reachable()
            && peer.authority_refused_history.is_none())
        .test_unwrap()
    );
    assert!(
        crate::trust_control::cluster::cluster_consensus_view(&cluster.leader.state)
            .test_unwrap()
            .has_quorum
    );
    assert_admitted_read_and_issue(&cluster.leader.state).await;
}

#[tokio::test]
async fn final_f11_majority_known_signed_fork_survives_minority_transport_loss() {
    let mut cluster = majority_cluster();
    let source_path = cluster
        .leader
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(source_path, fixed_clock(cluster.at))
        .test_unwrap();
    let old_key = source.local_keypair().test_unwrap();
    let local = source.rotate().test_unwrap();
    let minority = cluster.minority.as_ref().test_unwrap();
    let path = minority
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    rusqlite::Connection::open(path)
        .test_unwrap()
        .execute(
            "UPDATE authority_state SET seed_hex = ?1 WHERE singleton_id = 1",
            [old_key.seed_hex()],
        )
        .test_unwrap();
    let remote =
        SqliteCapabilityAuthority::open_with_clock(path, fixed_clock(cluster.at)).test_unwrap();
    let fork = remote.rotate().test_unwrap();
    assert_ne!(fork.public_key, local.public_key);
    let rejected = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(rejected, CliError::AuthorityStore(AuthorityStoreError::Fence(reason))
        if reason == "peer authority history conflicts with local authenticated history")
    );
    let known = known_head(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    let view = public_authority_verification_status(
        source_path,
        &cluster.leader.state.config,
        &cluster.leader.state.finding_challenge_clock,
    )
    .test_unwrap();
    assert!(
        !view.contains_authenticated_history(&known),
        "fork became part of local history"
    );
    // A later matching prefix must not erase the previously authenticated fork.
    let matching = source.signed_snapshot().test_unwrap();
    *minority.authority_snapshot_override.lock().test_unwrap() = Some(matching.clone());
    sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(known.clone())
    );
    assert_unresolved(
        handle_authority_status(State(cluster.leader.state.clone()), workload_headers()).await,
    )
    .await;
    // This genuine canonical extension is importable and keeps local signing
    // custody, but its different history cannot supersede the known fork.
    let extension = retire_old_issuer(
        &source.replication_anchor().test_unwrap(),
        &matching,
        &source.local_keypair().test_unwrap(),
        &old_key.public_key(),
        cluster.at,
    );
    *minority.authority_snapshot_override.lock().test_unwrap() = Some(extension.clone());
    sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    assert_eq!(source.status().test_unwrap().generation, 3);
    assert_eq!(
        source.current_keypair().test_unwrap().public_key(),
        local.public_key
    );
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(known.clone())
    );
    assert!(
        with_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| peer
            .authority_refused_history
            .as_ref()
            .test_unwrap()
            .has_conflict())
        .test_unwrap()
    );
    drop(cluster.minority.take());
    let unavailable = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(&unavailable, CliError::Chio(error) if error.to_string().contains("trust control service transport failed:"))
    );
    sync_peer(&cluster.leader.state, &cluster.majority.url).test_unwrap();
    assert!(
        crate::trust_control::cluster::cluster_consensus_view(&cluster.leader.state)
            .test_unwrap()
            .has_quorum
    );
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(known)
    );
    assert_unresolved(
        handle_authority_status(State(cluster.leader.state.clone()), workload_headers()).await,
    )
    .await;
    assert_unresolved(
        handle_issue_capability(
            State(cluster.leader.state.clone()),
            workload_headers(),
            Json(IssueCapabilityRequest {
                subject_public_key: Keypair::generate().public_key().to_hex(),
                scope: ChioScope::default(),
                ttl_seconds: 60,
                runtime_attestation: None,
            }),
        )
        .await,
    )
    .await;
}

#[tokio::test]
async fn final_f11_majority_known_newer_survives_replay_refusal_and_transport_loss() {
    let mut cluster = majority_cluster();
    let source_path = cluster
        .leader
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(source_path, fixed_clock(cluster.at))
        .test_unwrap();
    let old = source.status().test_unwrap();
    let old_key = source.local_keypair().test_unwrap();
    let minority = cluster.minority.as_ref().test_unwrap();
    let path = minority
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    rusqlite::Connection::open(path)
        .test_unwrap()
        .execute(
            "UPDATE authority_state SET seed_hex = ?1 WHERE singleton_id = 1",
            [old_key.seed_hex()],
        )
        .test_unwrap();
    let peer_clock = fixed_clock(cluster.at + 1);
    let remote = SqliteCapabilityAuthority::open_with_clock(path, peer_clock).test_unwrap();
    let next = remote.rotate().test_unwrap();
    let extension = remote.signed_snapshot().test_unwrap();
    assert_ne!(old.public_key, next.public_key);
    cluster
        .minority_clock
        .0
        .store(cluster.at + 1, Ordering::SeqCst);
    cluster
        .leader_clock
        .0
        .store(cluster.at + 2, Ordering::SeqCst);
    // A newer signed envelope is authenticated, but actual import still refuses
    // its older issue time relative to the owner's latest exported envelope.
    SqliteCapabilityAuthority::open_with_clock(source_path, fixed_clock(cluster.at + 2))
        .test_unwrap()
        .signed_snapshot()
        .test_unwrap();
    let inspection =
        chio_store_sqlite::authority::SqliteAuthorityInspection::open_existing_with_clock(
            source_path,
            fixed_clock(cluster.at + 2),
        )
        .test_unwrap();
    assert_eq!(
        inspection
            .peer_chain_evidence(&extension)
            .test_unwrap()
            .history,
        chio_store_sqlite::authority::AuthorityPeerHistory::Newer
    );
    let rejected = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(rejected, CliError::AuthorityStore(AuthorityStoreError::Fence(reason))
        if reason == "authority envelope replay regresses issuance time")
    );
    let known = known_head(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    assert_eq!(
        known,
        extension.proof.as_ref().test_unwrap().chain_commitment
    );
    assert_eq!(
        public_authority_status(
            &cluster.leader.state.config,
            &cluster.leader.state.finding_challenge_clock
        )
        .test_unwrap()
        .public_key,
        Some(old.public_key.to_hex())
    );
    drop(cluster.minority.take());
    let unavailable = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(&unavailable, CliError::Chio(error) if error.to_string().contains("trust control service transport failed:"))
    );
    sync_peer(&cluster.leader.state, &cluster.majority.url).test_unwrap();
    assert!(
        crate::trust_control::cluster::cluster_consensus_view(&cluster.leader.state)
            .test_unwrap()
            .has_quorum
    );
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(known)
    );
    assert_unresolved(
        handle_authority_status(State(cluster.leader.state.clone()), workload_headers()).await,
    )
    .await;
}

#[tokio::test]
async fn final_f11_delayed_peer_history_keeps_maximal_witness_and_recovers_after_shorter_relay() {
    let cluster = majority_cluster();
    let source_path = cluster
        .leader
        .state
        .config
        .authority_db_path
        .as_ref()
        .test_unwrap();
    let source = SqliteCapabilityAuthority::open_with_clock(source_path, fixed_clock(cluster.at))
        .test_unwrap();
    let old_key = source.local_keypair().test_unwrap();
    let anchor = source.replication_anchor().test_unwrap();
    let current = source.signed_snapshot().test_unwrap();
    let new_key = Keypair::generate();
    let next = SignedAuthorityTransition::sign(
        &anchor,
        &current.snapshot,
        &current.proof.as_ref().test_unwrap().chain_commitment,
        &new_key.public_key(),
        cluster.at,
        &old_key,
    )
    .test_unwrap();
    let first =
        SignedAuthoritySnapshot::sign(&anchor, vec![next], cluster.at, &new_key).test_unwrap();
    let second = retire_old_issuer(&anchor, &first, &new_key, &old_key.public_key(), cluster.at);
    let inspection =
        chio_store_sqlite::authority::SqliteAuthorityInspection::open_existing_with_clock(
            source_path,
            fixed_clock(cluster.at),
        )
        .test_unwrap();
    let first_evidence = inspection.peer_chain_evidence(&first).test_unwrap();
    let delayed_evidence = inspection.peer_chain_evidence(&second).test_unwrap();
    assert_eq!(
        first_evidence.history,
        chio_store_sqlite::authority::AuthorityPeerHistory::Newer
    );
    assert_eq!(
        delayed_evidence.history,
        chio_store_sqlite::authority::AuthorityPeerHistory::Newer
    );
    update_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| {
        peer.authority_refused_history = Some(AuthorityHistoryWitness::new(&first_evidence));
    });

    // Reproduce the read/record interleaving: another import resolves C1 after
    // C2 was authenticated against the older local transaction but before the
    // peer mutex records C2. A local containment check would incorrectly keep
    // only resolved C1. Install the imported custodian's key explicitly.
    source.apply_signed_snapshot(&first).test_unwrap();
    rusqlite::Connection::open(source_path)
        .test_unwrap()
        .execute(
            "UPDATE authority_state SET seed_hex = ?1 WHERE singleton_id = 1",
            [new_key.seed_hex()],
        )
        .test_unwrap();
    update_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| {
        peer.authority_refused_history
            .as_mut()
            .test_unwrap()
            .observe(&delayed_evidence);
    });
    // An out-of-order older reply was also authenticated before the local
    // import. Its retained membership must preserve the longer C2 witness.
    update_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| {
        peer.authority_refused_history
            .as_mut()
            .test_unwrap()
            .observe(&first_evidence);
    });
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(delayed_evidence.chain_commitment.clone())
    );
    let view = public_authority_verification_status(
        source_path,
        &cluster.leader.state.config,
        &cluster.leader.state.finding_challenge_clock,
    )
    .test_unwrap();
    assert!(view.holds_current_signing_custody);
    assert!(view.contains_authenticated_history(&first_evidence.chain_commitment));
    assert!(!view.contains_authenticated_history(&delayed_evidence.chain_commitment));

    // Actual HTTP observation of the shorter valid relay neither replaces C2
    // nor creates a conflict. C2 remains unresolved until genuine convergence.
    let minority = cluster.minority.as_ref().test_unwrap();
    *minority.authority_snapshot_override.lock().test_unwrap() = Some(first);
    sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    assert_eq!(
        known_head(&cluster.leader.state, &cluster.minority_url),
        Some(delayed_evidence.chain_commitment.clone())
    );
    assert!(
        !with_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| peer
            .authority_refused_history
            .as_ref()
            .test_unwrap()
            .has_conflict())
        .test_unwrap()
    );
    assert_unresolved(
        handle_authority_status(State(cluster.leader.state.clone()), workload_headers()).await,
    )
    .await;
    *minority.authority_snapshot_override.lock().test_unwrap() = Some(second);
    sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap();
    sync_peer(&cluster.leader.state, &cluster.majority.url).test_unwrap();
    assert_eq!(source.status().test_unwrap().generation, 3);
    assert_admitted_read_and_issue(&cluster.leader.state).await;

    // Truly incomparable authenticated knowledge remains a conflict even when
    // the retained maximal head is now encompassed by local history.
    let fork_key = Keypair::generate();
    let fork_transition = SignedAuthorityTransition::sign(
        &anchor,
        &anchor.snapshot,
        &anchor.commitment().test_unwrap(),
        &fork_key.public_key(),
        cluster.at,
        &old_key,
    )
    .test_unwrap();
    let fork = SignedAuthoritySnapshot::sign(&anchor, vec![fork_transition], cluster.at, &fork_key)
        .test_unwrap();
    *minority.authority_snapshot_override.lock().test_unwrap() = Some(fork);
    let refusal = sync_peer(&cluster.leader.state, &cluster.minority_url).test_unwrap_err();
    assert!(
        matches!(refusal, CliError::AuthorityStore(AuthorityStoreError::Fence(reason))
        if reason == "peer authority history conflicts with local authenticated history")
    );
    assert!(
        with_peer_state(&cluster.leader.state, &cluster.minority_url, |peer| peer
            .authority_refused_history
            .as_ref()
            .test_unwrap()
            .has_conflict())
        .test_unwrap()
    );
    let view = public_authority_verification_status(
        source_path,
        &cluster.leader.state.config,
        &cluster.leader.state.finding_challenge_clock,
    )
    .test_unwrap();
    assert!(view.contains_authenticated_history(&delayed_evidence.chain_commitment));
    assert_unresolved(
        handle_authority_status(State(cluster.leader.state.clone()), workload_headers()).await,
    )
    .await;
}
