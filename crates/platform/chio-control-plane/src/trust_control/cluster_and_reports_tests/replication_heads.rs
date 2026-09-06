use super::*;

#[test]
fn cluster_replication_heads_reports_heads_without_materializing() {
    let budget_db = unique_temp_path("cluster-heads-budget", "sqlite3");
    let revocation_db = unique_temp_path("cluster-heads-revocation", "sqlite3");
    {
        let store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        store
            .try_charge_cost("cap-heads", 0, Some(5), 3, None, None)
            .test_unwrap();
        let revocations = SqliteRevocationStore::open(&revocation_db).test_unwrap();
        revocations
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-heads".to_string(),
                revoked_at: 77,
            })
            .test_unwrap();
    }
    let state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        Some(revocation_db.clone()),
        Some(budget_db.clone()),
    );
    let heads = cluster_replication_heads(&state).test_unwrap();
    assert_eq!(heads.budget_seq, 1);
    assert_eq!(heads.tool_seq, 0);
    assert_eq!(
        heads.revocation_cursor_version,
        Some(REVOCATION_SEQUENCE_CURSOR_VERSION)
    );
    let stream_id = heads.revocation_stream_id.as_deref().test_unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(stream_id)
            .test_unwrap()
            .get_version_num(),
        7
    );
    let cursor = heads.revocation_cursor.test_unwrap();
    assert_eq!(cursor.stream_id.as_deref(), Some(stream_id));
    assert_eq!(cursor.revoked_at, 77);
    assert_eq!(cursor.capability_id, "cap-heads");
}

#[test]
fn status_advertises_contiguous_ack_heads() {
    // Wire shape: budgetAckHeads serializes as camelCase originId/eventSeq
    // when non-empty, and is omitted entirely when empty (additive,
    // backward-compatible with older peers who never witness).
    let response = ClusterStatusResponse {
        self_url: "http://node-a".to_string(),
        leader_url: None,
        role: "follower".to_string(),
        has_quorum: true,
        quorum_size: 2,
        reachable_nodes: 2,
        election_term: 1,
        authority_lease: None,
        replication: ClusterReplicationHeadsView::default(),
        peers: Vec::new(),
        budget_ack_heads: vec![BudgetOriginAck {
            origin_id: "http://origin-o".to_string(),
            event_seq: 3,
        }],
    };
    let value = serde_json::to_value(&response).test_unwrap();
    assert_eq!(value["budgetAckHeads"][0]["originId"], "http://origin-o");
    assert_eq!(value["budgetAckHeads"][0]["eventSeq"], 3);

    // Empty ack heads are omitted from the wire (skip_serializing_if).
    let empty = ClusterStatusResponse {
        budget_ack_heads: Vec::new(),
        ..response
    };
    let value = serde_json::to_value(&empty).test_unwrap();
    assert!(value.get("budgetAckHeads").is_none());
}

#[test]
fn apply_cluster_snapshot_seeds_authority_term_for_late_joiner_budget_writes() {
    let source_state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
    let target_state = state_with_cluster(
        "http://node-0",
        &["http://node-a", "http://node-b"],
        None,
        None,
        None,
    );

    for state in [&source_state, &target_state] {
        let cluster = state.cluster.as_ref().test_unwrap();
        let mut guard = cluster.lock().test_unwrap();
        for peer in guard.peers.values_mut() {
            peer.health = PeerHealth::Healthy;
            peer.last_contact_at = Some(unix_timestamp_now());
        }
    }

    let initial_target_consensus = cluster_consensus_view(&target_state).test_unwrap();
    assert_eq!(
        initial_target_consensus.leader_url.as_deref(),
        Some("http://node-0")
    );
    assert_eq!(initial_target_consensus.election_term, 1);

    let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    assert_eq!(snapshot.election_term, 1);
    assert_eq!(
        snapshot.authority_lease.as_ref().test_unwrap().leader_url,
        "http://node-a"
    );

    apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

    let seeded_consensus = cluster_consensus_view(&target_state).test_unwrap();
    assert_eq!(
        seeded_consensus.leader_url.as_deref(),
        Some("http://node-0")
    );
    assert_eq!(seeded_consensus.election_term, 2);
    let seeded_lease = cluster_authority_lease_view(&target_state).test_unwrap();
    assert_eq!(seeded_lease.authority_id, "http://node-0");
    assert_eq!(seeded_lease.lease_epoch, 2);
}
