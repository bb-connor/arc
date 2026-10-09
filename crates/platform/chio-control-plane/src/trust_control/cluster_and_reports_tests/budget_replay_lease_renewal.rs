//! A budget authorization retried with its original event id after the same
//! leader renewed its lease replays under the lease that admitted it. Nothing
//! new is admitted, and every other mismatch still fails closed.
use super::*;
use chio_kernel::budget_store::BudgetHoldSnapshot;

const NODE_A: &str = "https://node-a";
const NODE_B: &str = "https://node-b";

struct ReplayFixture {
    state: TrustServiceState,
    budget_db: PathBuf,
    original: BudgetEventAuthority,
    original_seq: u64,
}

impl Drop for ReplayFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.budget_db);
    }
}

fn request(case: &str, event: &str, cost_units: u64) -> TryChargeCostRequest {
    TryChargeCostRequest {
        capability_id: format!("cap-replay-{case}"),
        grant_index: 0,
        max_invocations: Some(10),
        cost_units,
        max_cost_per_invocation: Some(200),
        max_total_cost_units: Some(1_000),
        hold_id: Some(format!("hold-replay-{case}-{event}")),
        event_id: Some(format!("replay-{case}:{event}")),
    }
}

/// node-a leads a two-node cluster, has persisted `payload` under its current
/// lease, and node-b has acknowledged that exact event.
fn authorized(case: &str, payload: &TryChargeCostRequest) -> ReplayFixture {
    let budget_db = unique_temp_path(&format!("chio-budget-replay-{case}"), "db");
    let state = state_with_cluster(NODE_A, &[NODE_B], None, None, Some(budget_db.clone()));
    update_peer_reachable(&state, NODE_B);
    let original = current_budget_event_authority(&state)
        .test_unwrap()
        .test_unwrap();
    let store = SqliteBudgetStore::open(&budget_db).test_unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            payload.max_invocations,
            payload.cost_units,
            payload.max_cost_per_invocation,
            payload.max_total_cost_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            Some(&original),
        )
        .test_unwrap());
    let original_seq = store
        .mutation_event_for_event_id(payload.event_id.as_deref().test_unwrap())
        .test_unwrap()
        .test_unwrap()
        .event_seq;
    update_peer_budget_acks(
        &state,
        NODE_B,
        &[BudgetOriginAck {
            origin_id: NODE_A.to_string(),
            event_seq: original_seq,
        }],
    );
    ReplayFixture {
        state,
        budget_db,
        original,
        original_seq,
    }
}

/// The same leader renews its lease: a later term with unchanged leadership
/// and fresh peer health.
fn renew_lease(state: &TrustServiceState) -> BudgetEventAuthority {
    {
        let cluster = state.cluster.as_ref().test_unwrap();
        let mut guard = cluster.lock().test_unwrap();
        guard.election_term = guard.election_term.saturating_add(1);
    }
    update_peer_reachable(state, NODE_B);
    current_budget_event_authority(state)
        .test_unwrap()
        .test_unwrap()
}

type BudgetRows = (
    Option<BudgetUsageRecord>,
    Vec<BudgetMutationRecord>,
    Option<BudgetHoldSnapshot>,
);

fn budget_rows(budget_db: &std::path::Path, payload: &TryChargeCostRequest) -> BudgetRows {
    let store = SqliteBudgetStore::open(budget_db).test_unwrap();
    (
        store
            .get_usage(&payload.capability_id, payload.grant_index)
            .test_unwrap(),
        store
            .list_mutation_events(32, Some(&payload.capability_id), Some(0))
            .test_unwrap(),
        store
            .budget_hold_snapshot(payload.hold_id.as_deref().test_unwrap())
            .test_unwrap(),
    )
}

async fn charge(state: &TrustServiceState, payload: TryChargeCostRequest) -> (StatusCode, Value) {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
    let response = handle_try_charge_cost(State(state.clone()), headers, Json(payload)).await;
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    (status, serde_json::from_slice(&body).test_unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retried_authorization_replays_under_its_original_lease_after_renewal() {
    let payload = request("renewal", "authorize", 100);
    let fixture = authorized("renewal", &payload);
    let renewed = renew_lease(&fixture.state);
    assert_eq!(renewed.authority_id, fixture.original.authority_id);
    assert!(renewed.lease_epoch > fixture.original.lease_epoch);
    let before = budget_rows(&fixture.budget_db, &payload);
    // The ordinary store path keeps its exact-authority contract: the renewed
    // lease alone cannot replay the original event.
    let ordinary = SqliteBudgetStore::open(&fixture.budget_db)
        .test_unwrap()
        .try_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            payload.max_invocations,
            payload.cost_units,
            payload.max_cost_per_invocation,
            payload.max_total_cost_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            Some(&renewed),
        );
    assert!(matches!(
        &ordinary,
        Err(BudgetStoreError::Invariant(message))
            if message == "budget event_id `replay-renewal:authorize` authority metadata does not match the original mutation"
    ));
    assert_eq!(budget_rows(&fixture.budget_db, &payload), before);

    let (status, body) = charge(&fixture.state, request("renewal", "authorize", 100)).await;

    assert_eq!(status, StatusCode::OK, "replay refused: {body}");
    assert_eq!(body["allowed"], json!(true));
    assert_eq!(body["budgetCommit"]["quorumCommitted"], json!(true));
    assert_eq!(
        body["budgetCommit"]["commitIndex"],
        json!(fixture.original_seq)
    );
    assert_eq!(
        body["budgetCommit"]["authorityId"],
        json!(fixture.original.authority_id)
    );
    assert_eq!(
        body["budgetCommit"]["budgetTerm"],
        json!(fixture.original.lease_epoch)
    );
    assert_eq!(
        body["budgetCommit"]["leaseId"],
        json!(fixture.original.lease_id)
    );
    assert_eq!(budget_rows(&fixture.budget_db, &payload), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_authorization_after_renewal_is_admitted_under_the_renewed_lease() {
    let payload = request("new-event", "authorize", 100);
    let fixture = authorized("new-event", &payload);
    let renewed = renew_lease(&fixture.state);
    let fresh = TryChargeCostRequest {
        hold_id: Some("hold-replay-new-event-fresh".to_string()),
        event_id: Some("replay-new-event:fresh".to_string()),
        ..request("new-event", "authorize", 100)
    };
    let fresh_seq = fixture.original_seq + 1;
    update_peer_budget_acks(
        &fixture.state,
        NODE_B,
        &[BudgetOriginAck {
            origin_id: NODE_A.to_string(),
            event_seq: fresh_seq,
        }],
    );

    let (status, body) = charge(&fixture.state, fresh).await;

    assert_eq!(status, StatusCode::OK, "new authorization refused: {body}");
    assert_eq!(body["budgetCommit"]["commitIndex"], json!(fresh_seq));
    assert_eq!(
        body["budgetCommit"]["budgetTerm"],
        json!(renewed.lease_epoch)
    );
    let event = SqliteBudgetStore::open(&fixture.budget_db)
        .test_unwrap()
        .mutation_event_for_event_id("replay-new-event:fresh")
        .test_unwrap()
        .test_unwrap();
    assert_eq!(event.authority, Some(renewed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflicting_payload_under_the_original_event_id_stays_refused_after_renewal() {
    let payload = request("conflict", "authorize", 100);
    let fixture = authorized("conflict", &payload);
    renew_lease(&fixture.state);
    let before = budget_rows(&fixture.budget_db, &payload);
    let conflicting = TryChargeCostRequest {
        cost_units: 150,
        ..request("conflict", "authorize", 100)
    };

    let (status, body) = charge(&fixture.state, conflicting).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"error": "budget authorization failed"}));
    assert_eq!(budget_rows(&fixture.budget_db, &payload), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authorization_admitted_by_another_authority_is_never_replayed() {
    let payload = request("cross-authority", "authorize", 100);
    let budget_db = unique_temp_path("chio-budget-replay-cross-authority", "db");
    let state = state_with_cluster(NODE_A, &[NODE_B], None, None, Some(budget_db.clone()));
    update_peer_reachable(&state, NODE_B);
    let current = current_budget_event_authority(&state)
        .test_unwrap()
        .test_unwrap();
    let foreign = BudgetEventAuthority {
        authority_id: NODE_B.to_string(),
        lease_id: format!("{NODE_B}#term-{}", current.lease_epoch),
        lease_epoch: current.lease_epoch,
    };
    assert!(SqliteBudgetStore::open(&budget_db)
        .test_unwrap()
        .try_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            payload.max_invocations,
            payload.cost_units,
            payload.max_cost_per_invocation,
            payload.max_total_cost_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            Some(&foreign),
        )
        .test_unwrap());
    let before = budget_rows(&budget_db, &payload);

    let (status, body) = charge(&state, request("cross-authority", "authorize", 100)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"error": "budget authorization failed"}));
    assert_eq!(budget_rows(&budget_db, &payload), before);
    let _ = std::fs::remove_file(budget_db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_without_quorum_is_refused_before_touching_the_store() {
    let payload = request("no-quorum", "authorize", 100);
    let fixture = authorized("no-quorum", &payload);
    renew_lease(&fixture.state);
    update_peer_failure(&fixture.state, NODE_B, "peer lost".to_string());
    let before = budget_rows(&fixture.budget_db, &payload);

    let (status, body) = charge(&fixture.state, request("no-quorum", "authorize", 100)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({"error": "cluster quorum is unavailable for trust-control writes"})
    );
    assert_eq!(budget_rows(&fixture.budget_db, &payload), before);
}
