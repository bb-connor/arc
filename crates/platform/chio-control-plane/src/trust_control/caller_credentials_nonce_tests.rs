use super::*;

/// In-memory peer replay store; after `fault`, every call is unavailable.
#[derive(Debug)]
pub(crate) struct MemoryPeerReplay(Mutex<Option<BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs>>>);

impl MemoryPeerReplay {
    fn fault(&self) {
        *self.0.lock().test_unwrap() = None;
    }

    fn marks(&self) -> BTreeMap<String, i64> {
        let marks = self.high_waters().test_unwrap();
        marks
            .iter()
            .map(|(node, at)| (node.as_str().into(), at.get()))
            .collect()
    }
}

impl PeerReplayHighWaterStore for MemoryPeerReplay {
    fn high_waters(
        &self,
    ) -> Result<BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs>, PeerReplayStoreError> {
        let marks = self.0.lock().test_unwrap();
        marks.clone().ok_or(PeerReplayStoreError::Unavailable)
    }

    fn advance(
        &self,
        node_id: &ClusterPeerNodeId,
        issued_at: PeerIssuedAtSecs,
    ) -> Result<(), PeerReplayStoreError> {
        let mut marks = self.0.lock().test_unwrap();
        let marks = marks.as_mut().ok_or(PeerReplayStoreError::Unavailable)?;
        if marks.get(node_id) >= Some(&issued_at) {
            return Err(PeerReplayStoreError::NotAdvanced);
        }
        marks.insert(node_id.clone(), issued_at);
        Ok(())
    }
}

/// A fresh, empty cluster peer replay store.
pub(crate) fn test_peer_replay_store() -> Arc<MemoryPeerReplay> {
    Arc::new(MemoryPeerReplay(Mutex::new(Some(BTreeMap::new()))))
}

#[test]
fn peer_replay_after_restart_on_a_reset_store_keeps_the_start_plus_lead_floor() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    access
        .peers
        .verify(
            &headers,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &nonce_cache(),
        )
        .test_unwrap();
    let reset = test_peer_replay_store();
    let restarted = test_nonce_cache(&reset, Some(ISSUED_AT + 3), 1);
    let error = access
        .peers
        .verify(
            &headers,
            &target,
            ISSUED_AT + 5,
            Scope::ClusterReplicate,
            &restarted,
        )
        .test_unwrap_err();
    assert_eq!(error, PeerAuthError::Stale);
    assert_eq!(
        error.to_string(),
        "cluster peer signature is outside the freshness window"
    );
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    let started_without_clock = test_nonce_cache(&test_peer_replay_store(), None, 1);
    assert_eq!(
        access
            .peers
            .verify(
                &headers,
                &target,
                ISSUED_AT + 5,
                Scope::ClusterReplicate,
                &started_without_clock,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
    let first_fresh = ISSUED_AT + 3 + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS + 1;
    let in_lead = signed_peer_headers(&keypair, NODE_B, &target, first_fresh - 1, None);
    assert_eq!(
        access
            .peers
            .verify(
                &in_lead,
                &target,
                first_fresh,
                Scope::ClusterReplicate,
                &restarted,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
    let fresh = signed_peer_headers(&keypair, NODE_B, &target, first_fresh, None);
    access
        .peers
        .verify(
            &fresh,
            &target,
            first_fresh,
            Scope::ClusterReplicate,
            &restarted,
        )
        .test_unwrap();
}

#[test]
fn peer_replay_in_the_restart_second_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    access
        .peers
        .verify(
            &headers,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &before_restart,
        )
        .test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT), 1);
    assert_eq!(
        access
            .peers
            .verify(
                &headers,
                &target,
                ISSUED_AT,
                Scope::ClusterReplicate,
                &restarted,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_future_dated_replay_after_restart_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    let led = signed_peer_headers(
        &keypair,
        NODE_B,
        &target,
        ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS,
        None,
    );
    access
        .peers
        .verify(
            &led,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &before_restart,
        )
        .test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT + 1), 1);
    assert_eq!(
        access
            .peers
            .verify(
                &led,
                &target,
                ISSUED_AT + 1,
                Scope::ClusterReplicate,
                &restarted,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
    let far_ahead = signed_peer_headers(
        &keypair,
        NODE_B,
        &target,
        ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS + 1,
        None,
    );
    assert_eq!(
        access
            .peers
            .verify(
                &far_ahead,
                &target,
                ISSUED_AT,
                Scope::ClusterReplicate,
                &before_restart,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_replay_after_restart_with_clock_moved_back_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    let older = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT - 10, None);
    let latest = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    for (headers, now) in [(&older, ISSUED_AT - 10), (&latest, ISSUED_AT)] {
        access
            .peers
            .verify(
                headers,
                &target,
                now,
                Scope::ClusterReplicate,
                &before_restart,
            )
            .test_unwrap();
    }
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT - 20), 1);
    for headers in [&latest, &older] {
        assert_eq!(
            access
                .peers
                .verify(
                    headers,
                    &target,
                    ISSUED_AT - 3,
                    Scope::ClusterReplicate,
                    &restarted,
                )
                .test_unwrap_err(),
            PeerAuthError::Stale
        );
    }
}

fn two_peer_access(node_b: &Keypair, node_c: &Keypair) -> TrustAccessConfig {
    TrustAccessConfig::from_toml_str(&config(&format!(
        "{}{}{}",
        reader(),
        peer(NODE_B, node_b, REPLICA_SCOPES),
        peer(NODE_C, node_c, REPLICA_SCOPES)
    )))
    .test_unwrap()
}

fn verify_at(
    access: &TrustAccessConfig,
    headers: &HeaderMap,
    now: i64,
    nonces: &PeerNonceCache,
) -> Result<AuthenticatedPeer, PeerAuthError> {
    access.peers.verify(
        headers,
        &status_target(),
        now,
        Scope::ClusterReplicate,
        nonces,
    )
}

#[test]
fn peer_without_a_stored_mark_after_restart_gets_the_start_plus_lead_floor() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = two_peer_access(&node_b, &node_c);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = test_nonce_cache(
        &store,
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    let from_b = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT, None);
    verify_at(&access, &from_b, ISSUED_AT, &before_restart).test_unwrap();
    let start = ISSUED_AT - 20;
    let restarted = test_nonce_cache(&store, Some(start), 2);
    let at_floor = start + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS;
    let now = start + 10;
    let c_at_floor = signed_peer_headers(&node_c, NODE_C, &target, at_floor, None);
    assert_eq!(
        verify_at(&access, &c_at_floor, now, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let c_above_floor = signed_peer_headers(&node_c, NODE_C, &target, at_floor + 1, None);
    verify_at(&access, &c_above_floor, now, &restarted).test_unwrap();
    let b_above_start_floor = signed_peer_headers(&node_b, NODE_B, &target, at_floor + 1, None);
    assert_eq!(
        verify_at(&access, &b_above_start_floor, now, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    assert_eq!(
        store.marks(),
        BTreeMap::from([
            (NODE_B.to_string(), ISSUED_AT),
            (NODE_C.to_string(), at_floor + 1),
        ])
    );
}

#[test]
fn peer_high_water_marks_are_independent_per_peer() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = two_peer_access(&node_b, &node_c);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = test_nonce_cache(
        &store,
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    let b_late = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 3, None);
    verify_at(&access, &b_late, ISSUED_AT, &before_restart).test_unwrap();
    let c_early = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT, None);
    verify_at(&access, &c_early, ISSUED_AT, &before_restart).test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT - 30), 2);
    let c_next = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT + 1, None);
    verify_at(&access, &c_next, ISSUED_AT, &restarted).test_unwrap();
    let b_same_second = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 3, None);
    assert_eq!(
        verify_at(&access, &b_same_second, ISSUED_AT, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let b_next = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 4, None);
    verify_at(&access, &b_next, ISSUED_AT, &restarted).test_unwrap();
}

#[test]
fn peer_requests_in_one_second_share_one_durable_mark() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let nonces = nonce_cache_on(&store);
    for _ in 0..3 {
        let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
        verify_at(&access, &headers, ISSUED_AT, &nonces).test_unwrap();
    }
    let earlier = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT - 1, None);
    verify_at(&access, &earlier, ISSUED_AT, &nonces).test_unwrap();
    assert_eq!(
        store.marks(),
        BTreeMap::from([(NODE_B.to_string(), ISSUED_AT)])
    );
}

#[test]
fn peer_replay_store_fault_refuses_with_503() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let nonces = nonce_cache_on(&store);
    store.fault();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let error = verify_at(&access, &headers, ISSUED_AT, &nonces).test_unwrap_err();
    assert_eq!(error, PeerAuthError::PeerReplayStoreUnavailable);
    assert_eq!(
        error.to_string(),
        "cluster peer replay high-water store is unavailable"
    );
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        verify_at(&access, &headers, ISSUED_AT, &nonces).test_unwrap_err(),
        PeerAuthError::PeerReplayStoreUnavailable
    );
    assert_eq!(
        PeerNonceCache::open(store, Some(ISSUED_AT), 1).test_unwrap_err(),
        PeerReplayStoreError::Unavailable
    );
}

#[test]
fn concurrent_duplicate_peer_requests_accept_exactly_once() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let outcomes: Vec<Result<AuthenticatedPeer, PeerAuthError>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| verify_at(&access, &headers, ISSUED_AT, &nonces)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().test_unwrap())
            .collect()
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    for refused in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
        assert_eq!(*refused, PeerAuthError::ReplayedNonce);
    }
}

#[test]
fn peer_replay_after_clock_step_back_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let first = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    access
        .peers
        .verify(&first, &target, ISSUED_AT, Scope::ClusterReplicate, &nonces)
        .test_unwrap();
    let later = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 200, None);
    access
        .peers
        .verify(
            &later,
            &target,
            ISSUED_AT + 200,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap();
    let error = access
        .peers
        .verify(
            &first,
            &target,
            ISSUED_AT + 5,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap_err();
    assert_eq!(error, PeerAuthError::Stale);
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    let behind = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 5, None);
    assert_eq!(
        access
            .peers
            .verify(
                &behind,
                &target,
                ISSUED_AT + 5,
                Scope::ClusterReplicate,
                &nonces,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
    let current = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 200, None);
    access
        .peers
        .verify(
            &current,
            &target,
            ISSUED_AT + 5,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap();
}

#[test]
fn peer_replay_at_the_window_boundary_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    access
        .peers
        .verify(
            &headers,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap();
    let at_boundary = ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS;
    assert_eq!(
        access
            .peers
            .verify(
                &headers,
                &target,
                at_boundary,
                Scope::ClusterReplicate,
                &nonces,
            )
            .test_unwrap_err(),
        PeerAuthError::ReplayedNonce
    );
    assert_eq!(
        access
            .peers
            .verify(
                &headers,
                &target,
                at_boundary + 1,
                Scope::ClusterReplicate,
                &nonces,
            )
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_nonce_quota_keeps_other_peers_admitted() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = TrustAccessConfig::from_toml_str(&config(&format!(
        "{}{}{}",
        reader(),
        peer(NODE_B, &node_b, REPLICA_SCOPES),
        peer(NODE_C, &node_c, REPLICA_SCOPES)
    )))
    .test_unwrap();
    let target = status_target();
    let nonces = test_nonce_cache(
        &test_peer_replay_store(),
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    for index in 0..CLUSTER_PEER_NONCE_CACHE_CAPACITY / 2 {
        nonces
            .record(NODE_B, &format!("{index:064x}"), ISSUED_AT, ISSUED_AT)
            .test_unwrap();
    }
    let from_b = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT, None);
    let error = access
        .peers
        .verify(
            &from_b,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap_err();
    assert_eq!(error, PeerAuthError::PeerNonceQuotaExhausted);
    assert_eq!(
        error.to_string(),
        "cluster peer has no nonce capacity left in the replay cache"
    );
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    let from_c = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT, None);
    access
        .peers
        .verify(
            &from_c,
            &target,
            ISSUED_AT,
            Scope::ClusterReplicate,
            &nonces,
        )
        .test_unwrap();
}
