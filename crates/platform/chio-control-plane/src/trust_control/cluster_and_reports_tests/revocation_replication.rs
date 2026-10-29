use super::*;
use chio_egress_contract::EgressAllowanceSet;

/// The grant the route table attaches to a verified request from node B.
fn peer_grant() -> Option<axum::Extension<RouteGrant>> {
    Some(axum::Extension(RouteGrant::Peer(
        crate::trust_control::caller_credentials::AuthenticatedPeer {
            node_id: "https://node-b".to_string(),
            issued_at: 0,
            term: None,
            scopes: [crate::trust_control::caller_credentials::Scope::ClusterReplicate]
                .into_iter()
                .collect(),
        },
    )))
}

async fn body_text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .test_unwrap()
            .to_vec(),
    )
    .test_unwrap()
}

#[tokio::test]
async fn revocation_delta_endpoint_serves_only_the_v1_sequence_cursor() {
    let revocation_db = unique_temp_path("revocation-delta-v1", "sqlite3");
    let state = state_with_cluster(
        "https://node-a",
        &["https://node-b"],
        None,
        Some(revocation_db.clone()),
        None,
    );
    let store = state.revocation_store().test_unwrap();
    for capability_id in ["cap-b", "cap-a"] {
        store
            .upsert_revocation(&RevocationRecord {
                capability_id: capability_id.to_string(),
                revoked_at: 10,
            })
            .test_unwrap();
    }
    let stream_id = store.revocation_stream_id().test_unwrap();
    let grant = peer_grant();
    let query = |cursor_version: u8, stream_id: &str| RevocationDeltaQuery {
        cursor_version,
        stream_id: stream_id.to_string(),
        after_seq: 0,
        limit: Some(MAX_LIST_LIMIT),
    };

    let sequence = handle_internal_revocations_delta(
        State(state.clone()),
        Query(query(REVOCATION_CURSOR_VERSION, &stream_id)),
        grant.clone(),
    )
    .await;
    assert_eq!(sequence.status(), StatusCode::OK);
    let sequence: Value = serde_json::from_str(&body_text(sequence).await).test_unwrap();
    assert_eq!(sequence["cursorVersion"], REVOCATION_CURSOR_VERSION);
    assert_eq!(sequence["streamId"], stream_id);
    assert_eq!(sequence["headSeq"], 2);
    assert_eq!(sequence["records"][0]["seq"], 1);
    assert_eq!(sequence["records"][0]["capabilityId"], "cap-b");
    assert_eq!(sequence["records"][1]["seq"], 2);
    assert_eq!(sequence["records"][1]["capabilityId"], "cap-a");

    let wrong_stream = handle_internal_revocations_delta(
        State(state.clone()),
        Query(query(
            REVOCATION_CURSOR_VERSION,
            "01991bb4-e2f7-7e21-b75d-a59be8fbc442",
        )),
        grant.clone(),
    )
    .await;
    assert_eq!(wrong_stream.status(), StatusCode::CONFLICT);

    for version in [2, 4, 99] {
        let refused = handle_internal_revocations_delta(
            State(state.clone()),
            Query(query(version, &stream_id)),
            grant.clone(),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(refused)
            .await
            .contains(&format!("unsupported revocation cursor version {version}")));
    }

    let _ = std::fs::remove_file(revocation_db);
}

#[test]
fn revocation_snapshot_is_projection_bounded_and_epoch_bound() {
    let source_revocation_db = unique_temp_path("cluster-source-revocation-snapshot", "sqlite3");
    let target_revocation_db = unique_temp_path("cluster-target-revocation-snapshot", "sqlite3");
    let source_state = state_with_cluster(
        "https://node-a",
        &["https://node-b"],
        None,
        Some(source_revocation_db.clone()),
        None,
    );
    let target_state = state_with_cluster(
        "https://node-b",
        &["https://node-a"],
        None,
        Some(target_revocation_db.clone()),
        None,
    );
    let source_store = SqliteRevocationStore::open(&source_revocation_db).test_unwrap();
    for revoked_at in 1..=32 {
        source_store
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-one".to_string(),
                revoked_at,
            })
            .test_unwrap();
    }

    let mut snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    assert_eq!(snapshot.revocations.len(), 1);
    assert_eq!(snapshot.revocations[0].revoked_at, 32);
    let stream = snapshot
        .replication
        .revocation_stream
        .as_mut()
        .test_unwrap();
    assert_eq!(stream.cursor_version, REVOCATION_CURSOR_VERSION);
    assert_eq!(stream.head.as_ref().test_unwrap().seq, 32);

    stream.cursor_version = 4;
    let error = apply_cluster_snapshot(&target_state, "https://node-a", snapshot)
        .test_unwrap_err()
        .to_string();
    assert!(error.contains("unsupported revocation cursor version 4"));
    assert!(SqliteRevocationStore::open(&target_revocation_db)
        .test_unwrap()
        .list_revocations_after(MAX_LIST_LIMIT, None, None)
        .test_unwrap()
        .is_empty());
    assert_eq!(
        with_peer_state(&target_state, "https://node-a", |peer| peer
            .snapshot_applied_count),
        Some(0)
    );

    let _ = std::fs::remove_file(source_revocation_db);
    let _ = std::fs::remove_file(target_revocation_db);
}

#[test]
fn revocation_snapshot_refuses_tuple_shapes_and_streamless_projections() {
    let source_revocation_db = unique_temp_path("cluster-source-streamless-snapshot", "sqlite3");
    let target_revocation_db = unique_temp_path("cluster-target-streamless-snapshot", "sqlite3");
    let source_state = state_with_cluster(
        "https://node-a",
        &["https://node-b"],
        None,
        Some(source_revocation_db.clone()),
        None,
    );
    let target_state = state_with_cluster(
        "https://node-b",
        &["https://node-a"],
        None,
        Some(target_revocation_db.clone()),
        None,
    );
    SqliteRevocationStore::open(&source_revocation_db)
        .test_unwrap()
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-origin".to_string(),
            revoked_at: 55,
        })
        .test_unwrap();
    let current = build_cluster_state_snapshot(&source_state).test_unwrap();

    let mut tuple_json = serde_json::to_value(&current).test_unwrap();
    let replication = tuple_json["replication"].as_object_mut().test_unwrap();
    replication.remove("revocationStream");
    replication.insert(
        "revocationCursor".to_string(),
        json!({"cursorVersion": 3, "revokedAt": 55, "capabilityId": "cap-origin"}),
    );
    let refused = serde_json::from_value::<ClusterStateSnapshotResponse>(tuple_json)
        .err()
        .unwrap_or_else(|| panic!("a tuple-cursor snapshot decoded"));
    assert!(refused
        .to_string()
        .starts_with("unknown field `revocationCursor`"));

    let mut streamless = current;
    streamless.replication.revocation_stream = None;
    let error = apply_cluster_snapshot(&target_state, "https://node-a", streamless)
        .test_unwrap_err()
        .to_string();
    assert!(error
        .contains("revocation snapshot carried projection records without a revocation stream"));
    assert!(!SqliteRevocationStore::open(&target_revocation_db)
        .test_unwrap()
        .is_revoked("cap-origin")
        .test_unwrap());
    assert!(peer_revocation_cursor(&target_state, "https://node-a").is_none());

    let _ = std::fs::remove_file(source_revocation_db);
    let _ = std::fs::remove_file(target_revocation_db);
}

#[test]
fn streamless_peer_is_a_transient_revocation_pull_error_that_applies_nothing() {
    let revocation_db = unique_temp_path("cluster-follower-streamless-peer", "sqlite3");
    let state = state_with_cluster(
        "https://node-b",
        &["https://node-a"],
        None,
        Some(revocation_db.clone()),
        None,
    );
    let cursor = RevocationCursor {
        stream_id: "01991bb4-e2f7-7e21-b75d-a59be8fbc441".to_string(),
        seq: 7,
        revoked_at: 5,
        capability_id: "cap-1".to_string(),
    };
    update_peer_revocation_cursor(&state, "https://node-a", cursor.clone());
    let client = service_runtime::client::build_cluster_peer_client(
        &state.config.access,
        "https://node-a",
        &EgressAllowanceSet::default(),
    )
    .test_unwrap();

    let outcome = sync_peer_revocations(
        &state,
        &client,
        "https://node-a",
        None,
        &mut PullRoundBudget::new(),
    );
    let error = match outcome {
        Err(PullError::Transient(error)) => error,
        other => panic!("a streamless peer must be a transient pull error: {other:?}"),
    };
    let CliError::Chio(error) = error else {
        panic!("a streamless peer must surface a registered pull error: {error:?}");
    };
    assert_eq!(
        error.message(),
        "peer advertises no revocation stream; revocations are not replicated from it"
    );
    assert!(state
        .revocation_store()
        .test_unwrap()
        .list_revocations_after(MAX_LIST_LIMIT, None, None)
        .test_unwrap()
        .is_empty());
    let retained = peer_revocation_cursor(&state, "https://node-a").test_unwrap();
    assert_eq!(retained.stream_id, cursor.stream_id);
    assert_eq!(retained.seq, cursor.seq);
    assert_eq!(retained.revoked_at, cursor.revoked_at);
    assert_eq!(retained.capability_id, cursor.capability_id);

    let _ = std::fs::remove_file(revocation_db);
}
