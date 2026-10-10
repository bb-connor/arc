//! A forwarded mutation remains bound to the term authenticated before queueing.
use super::*;
use futures_util::FutureExt;

const TERM_MISMATCH: &str = "cluster authority mutation term does not match the current lease";

#[derive(Clone, Copy)]
enum Operation {
    Issue,
    Rotate,
}

impl Operation {
    fn endpoint(self) -> &'static str {
        match self {
            Self::Issue => ISSUE_CAPABILITY_PATH,
            Self::Rotate => AUTHORITY_PATH,
        }
    }

    async fn invoke(self, state: TrustServiceState, headers: HeaderMap) -> Response {
        match self {
            Self::Issue => {
                handle_issue_capability(
                    State(state),
                    headers,
                    Json(IssueCapabilityRequest {
                        subject_public_key: Keypair::generate().public_key().to_hex(),
                        scope: ChioScope::default(),
                        ttl_seconds: 60,
                        runtime_attestation: None,
                    }),
                )
                .await
            }
            Self::Rotate => handle_rotate_authority(State(state), headers).await,
        }
    }
}

fn forwarded_headers(cluster: &MajorityCluster, operation: Operation, term: u64) -> HeaderMap {
    let issued_at = i64::try_from(unix_timestamp_now().test_unwrap()).test_unwrap();
    let signature = cluster_peer_auth_signature(
        &cluster.leader.state.config.service_token,
        &cluster.majority.url,
        operation.endpoint(),
        issued_at,
        Some(term),
    )
    .test_unwrap();
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (CLUSTER_NODE_ID_HEADER, cluster.majority.url.clone()),
        (CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string()),
        (CLUSTER_AUTH_SIGNATURE_HEADER, signature),
        (CLUSTER_AUTH_TERM_HEADER, term.to_string()),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).test_unwrap());
    }
    headers
}

fn reelect_same_leader(cluster: &MajorityCluster, previous_term: u64) {
    for peer in [&cluster.majority.url, &cluster.minority_url] {
        update_peer_state(&cluster.leader.state, peer, |state| {
            state.partitioned = true
        });
    }
    let unavailable = cluster_consensus_view(&cluster.leader.state).test_unwrap();
    assert!(!unavailable.has_quorum);
    assert_eq!(unavailable.election_term, previous_term + 1);
    for peer in [&cluster.majority.url, &cluster.minority_url] {
        update_peer_state(&cluster.leader.state, peer, |state| {
            state.partitioned = false
        });
    }
    // Obtain current-term signed serving evidence through the real sync path.
    sync_peer(&cluster.leader.state, &cluster.majority.url).test_unwrap();
    let lease = cluster_authority_lease_view(&cluster.leader.state).test_unwrap();
    assert!(lease.lease_valid);
    assert_eq!(lease.leader_url, cluster.leader.url);
    assert_eq!(lease.term, previous_term + 2);
    load_authority_status_for_state(&cluster.leader.state).test_unwrap();
}

fn queued_mutation(operation: Operation, change_term: bool) {
    let cluster = majority_cluster();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .test_unwrap();
    runtime.block_on(async {
        let state = &cluster.leader.state;
        let lease = cluster_authority_lease_view(state).test_unwrap();
        assert!(lease.lease_valid);
        let headers = forwarded_headers(&cluster, operation, lease.term);
        let authenticated = validate_authority_mutation_auth(&headers, state, operation.endpoint())
            .test_unwrap()
            .test_unwrap();
        assert_eq!(authenticated.term, Some(lease.term));
        let before =
            chio_store_sqlite::authority::SqliteAuthorityInspection::open_existing_with_clock(
                state.config.authority_db_path.as_deref().test_unwrap(),
                Arc::clone(&state.finding_challenge_clock),
            )
            .test_unwrap()
            .status()
            .test_unwrap();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = entered.send(());
            let _ = held.recv();
        });
        entered_rx.await.test_unwrap();
        let mut request = Box::pin(operation.invoke(state.clone(), headers));
        assert!(request.as_mut().now_or_never().is_none());
        assert_eq!(state.authority_inspection_lane.available_permits(), 7);
        if change_term {
            reelect_same_leader(&cluster, lease.term);
        }
        // Dropping the sender also releases the worker if a fixture assertion unwinds.
        drop(release);
        worker.await.test_unwrap();
        let response = tokio::time::timeout(Duration::from_secs(30), request)
            .await
            .test_unwrap();
        let status = response.status();
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 64 * 1024)
                .await
                .test_unwrap(),
        )
        .test_unwrap();
        let after =
            chio_store_sqlite::authority::SqliteAuthorityInspection::open_existing_with_clock(
                state.config.authority_db_path.as_deref().test_unwrap(),
                Arc::clone(&state.finding_challenge_clock),
            )
            .test_unwrap()
            .status()
            .test_unwrap();
        if change_term {
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "queued old-term mutation returned {body}"
            );
            assert_eq!(body, json!({"error": TERM_MISMATCH}));
            assert_eq!(after.generation, before.generation);
            assert_eq!(after.public_key, before.public_key);
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "healthy same-term mutation returned {body}"
            );
            match operation {
                Operation::Issue => {
                    let issued: IssueCapabilityResponse =
                        serde_json::from_value(body).test_unwrap();
                    assert!(issued.capability.verify_signature().test_unwrap());
                    assert_eq!(issued.capability.issuer, before.public_key);
                    assert_eq!(after.generation, before.generation);
                }
                Operation::Rotate => {
                    assert_eq!(after.generation, before.generation + 1);
                    assert_ne!(after.public_key, before.public_key);
                }
            }
        }
    });
}

#[test]
fn forwarded_issue_rejects_re_elected_term_after_worker_wait() {
    queued_mutation(Operation::Issue, true);
}

#[test]
fn forwarded_rotate_rejects_re_elected_term_after_worker_wait() {
    queued_mutation(Operation::Rotate, true);
}

#[test]
fn forwarded_issue_accepts_same_term_after_worker_wait() {
    queued_mutation(Operation::Issue, false);
}

#[test]
fn forwarded_rotate_accepts_same_term_after_worker_wait() {
    queued_mutation(Operation::Rotate, false);
}
