use super::*;

#[tokio::test]
async fn leader_visibility_responses_add_cluster_metadata_and_reject_scalars() {
    let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
    update_peer_reachable(&state, "http://node-b");

    let response = json_response_with_leader_visibility(&state, json!({ "stored": true }));
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    let body: Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(body["stored"], Value::Bool(true));
    assert_eq!(
        body["handledBy"],
        Value::String("http://node-a".to_string())
    );
    assert_eq!(
        body["leaderUrl"],
        Value::String("http://node-a".to_string())
    );
    assert_eq!(body["visibleAtLeader"], Value::Bool(true));
    assert_eq!(
        body["clusterAuthority"]["authorityId"],
        Value::String("http://node-a".to_string())
    );
    assert_eq!(body["clusterAuthority"]["term"], Value::from(1));
    assert_eq!(body["clusterAuthority"]["leaseValid"], Value::Bool(true));

    let scalar = json_response_with_leader_visibility(&state, "not-an-object");
    assert_eq!(scalar.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(scalar.into_body(), usize::MAX).await.test_unwrap();
    let text = String::from_utf8(body.to_vec()).test_unwrap();
    assert!(text.contains("success responses must be JSON objects"));
}

#[tokio::test]
async fn budget_quorum_commit_metadata_tracks_quorum_witnesses() {
    let state = state_with_cluster(
        "http://node-a",
        &["http://node-b", "http://node-c"],
        None,
        None,
        None,
    );
    update_peer_reachable(&state, "http://node-b");
    update_peer_reachable(&state, "http://node-c");
    update_peer_budget_acks(
        &state,
        "http://node-b",
        &[BudgetOriginAck {
            origin_id: "http://node-a".to_string(),
            event_seq: 9,
        }],
    );
    update_peer_budget_acks(
        &state,
        "http://node-c",
        &[BudgetOriginAck {
            origin_id: "http://node-a".to_string(),
            event_seq: 7,
        }],
    );

    let write = BudgetWriteToken {
        origin_id: "http://node-a".to_string(),
        event_seq: 8,
        budget_term: 1,
    };
    let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
    assert!(commit.quorum_committed);
    assert_eq!(commit.quorum_size, 2);
    assert_eq!(commit.committed_nodes, 2); // self + node-b (acked 9 >= 8)
    assert_eq!(
        commit.witness_urls,
        vec!["http://node-a".to_string(), "http://node-b".to_string()]
    );

    let response = json_response_with_leader_visibility_and_budget_commit(
        &state,
        json!({ "allowed": true }),
        Some(commit),
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    let body: Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(body["budgetCommit"]["budgetSeq"], Value::from(8));
    assert_eq!(body["budgetCommit"]["commitIndex"], Value::from(8));
    assert_eq!(body["budgetCommit"]["quorumCommitted"], Value::Bool(true));
    assert_eq!(body["budgetCommit"]["committedNodes"], Value::from(2));
    assert_eq!(
        body["budgetCommit"]["authorityId"],
        Value::String("http://node-a".to_string())
    );
    assert_eq!(body["budgetCommit"]["budgetTerm"], Value::from(1));
    assert_eq!(
        body["budgetCommit"]["witnessUrls"],
        json!(["http://node-a", "http://node-b"])
    );
}
