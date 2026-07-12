//! HTTP handlers for the budget-metering surface: budget listing and the
//! authorize/release/reconcile exposure-accounting endpoints.

use super::cluster::{
    budget_authority_guarantee_level, budget_authority_metadata_view,
    current_budget_event_authority, respond_after_budget_write_quorum_commit,
    respond_after_leader_visible_write, rollback_budget_authorize_exposure,
    wait_for_budget_write_quorum_commit, BudgetWriteToken,
};
use super::report_rendering::{
    forward_post_to_leader, json_response_with_leader_visibility_and_budget_commit,
};
use super::report_validation::{budget_visibility_matches, validate_service_auth};
use super::*;
use chio_log_redact::redacted;

fn budget_internal_error(error: &BudgetStoreError, public_message: &'static str) -> Response {
    warn!(reason = %redacted!(error), message = public_message, "budget store operation failed");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, public_message)
}

pub(crate) async fn handle_list_budgets(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match store.list_usages(list_limit(query.limit), query.capability_id.as_deref()) {
        Ok(usages) => usages,
        Err(error) => {
            return budget_internal_error(&error, "budget usage listing failed");
        }
    };

    Json(BudgetListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id: query.capability_id,
        count: usages.len(),
        usages: usages
            .into_iter()
            .map(|usage| BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
                updated_at: usage.updated_at,
                seq: None,
            })
            .collect(),
    })
    .into_response()
}

pub(crate) async fn handle_try_increment_budget(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryIncrementBudgetRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_INCREMENT_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_increment(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return budget_internal_error(&error, "budget increment failed");
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| budget_internal_error(&error, "budget usage lookup failed"))?;
            if budget_visibility_matches(allowed, invocation_count, payload.max_invocations) {
                Ok(Some(TryIncrementBudgetResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count,
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                }))
            } else {
                Ok(None)
            }
        },
    )
}

/// Mint a unique event_id for a budget write whose caller omitted `eventId`, so
/// the mutation event is stored under a KNOWN id and `budget_write_token` can look
/// up THIS write's exact event_seq instead of falling back to the authority MAX
/// (which a concurrent same-authority write to another capability can raise,
/// making the quorum wait target a later event and spuriously roll back / 503 a
/// write that itself reached quorum).
///
/// Uniqueness: a process-local monotonic counter + wall-clock nanos + pid, so it
/// cannot collide with a concurrent write or a caller-supplied id. An omitted
/// `eventId` already carries NO idempotency guarantee (the store would otherwise
/// auto-generate one internally), so minting it here changes no retry semantics.
fn generated_budget_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "cluster-budget-write-{}-{nanos}-{sequence}",
        std::process::id()
    )
}

/// Build the quorum-witness token for a budget write from its origin authority
/// and THIS write's own event_seq.
///
/// The seq is looked up by the write's `event_id` (the mutation event is stored
/// under that id at the seq it was allocated), which is race-free and, for an
/// idempotent retry, resolves to the ORIGINAL event's seq. Deriving it from
/// MAX(event_seq) for the authority would be wrong: a concurrent same-authority
/// commit (or a retry while later same-origin events exist) raises that MAX
/// above this write's seq, so the quorum wait would target a later event and
/// `handle_try_charge_cost` would roll back a write that itself reached quorum.
/// The handlers now always mint an event_id when the
/// caller omitted one (`generated_budget_event_id`), so the by-id lookup is
/// precise; the authority-MAX fallback remains only as a defensive path (row not
/// found) and can only OVER-target the seq (wait longer), never under-target it,
/// so the witness still never over-counts (fail-closed). A single-node write (no
/// authority) carries an unclustered token, and the quorum wait short-circuits.
fn budget_write_token(
    store: &SqliteBudgetStore,
    authority: Option<&BudgetEventAuthority>,
    event_id: Option<&str>,
) -> Result<BudgetWriteToken, Response> {
    let http_error = |error: BudgetStoreError| {
        budget_internal_error(&error, "budget write witness lookup failed")
    };
    match authority {
        Some(current) => {
            let stored = match event_id {
                Some(event_id) => store
                    .mutation_event_witness_for_event_id(event_id)
                    .map_err(http_error)?,
                None => None,
            };
            let (event_seq, origin_id, budget_term) = match stored {
                // Existing event with a stored authority: use ITS origin + term so
                // an idempotent retry after leadership moved targets the ORIGINAL
                // origin peers advertise it under, not the current leader.
                Some((seq, Some(authority_id), lease_epoch)) => (
                    seq,
                    authority_id,
                    lease_epoch.unwrap_or(current.lease_epoch),
                ),
                // Existing event with a legacy null authority: use the current lease.
                Some((seq, None, _)) => (seq, current.authority_id.clone(), current.lease_epoch),
                // No stored event (or no event_id): fall back to the authority MAX
                // under the current lease. Over-targets (waits longer), never
                // under-targets, so the witness still never over-counts.
                None => {
                    let seq = store
                        .max_mutation_event_seq_for_authority(&current.authority_id)
                        .map_err(http_error)?;
                    (seq, current.authority_id.clone(), current.lease_epoch)
                }
            };
            Ok(BudgetWriteToken {
                origin_id,
                event_seq,
                budget_term,
            })
        }
        None => Ok(BudgetWriteToken {
            origin_id: String::new(),
            event_seq: 0,
            budget_term: 0,
        }),
    }
}

pub(crate) async fn handle_try_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_AUTHORIZE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let authority = match current_budget_event_authority(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    // Mint an event_id when the caller omitted one, and use it for BOTH the write
    // and the witness token so the quorum wait targets THIS write's exact
    // event_seq, never a concurrent same-authority write's higher seq.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let decision = match store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        max_invocations: payload.max_invocations,
        requested_exposure_units: payload.cost_units,
        max_cost_per_invocation: payload.max_cost_per_invocation,
        max_total_cost_units: payload.max_total_cost_units,
        hold_id: payload.hold_id.clone(),
        event_id: Some(effective_event_id.clone()),
        authority: authority.clone(),
    }) {
        Ok(decision) => decision,
        Err(error) => {
            return budget_internal_error(&error, "budget authorization failed");
        }
    };
    let (already_captured, admission, denied) = match decision {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => (
            false,
            Some((
                authorized.metadata,
                authorized.authorized_exposure_units,
                0,
                authorized.invocation_count_after,
                authorized.committed_cost_units_after,
            )),
            None,
        ),
        BudgetAuthorizeHoldDecision::AlreadyCaptured(mutation) => (
            true,
            Some((
                mutation.metadata,
                mutation.exposure_units,
                mutation.realized_spend_units,
                mutation.invocation_count_after,
                mutation.committed_cost_units_after,
            )),
            None,
        ),
        BudgetAuthorizeHoldDecision::Denied(denied) => (false, None, Some(denied)),
    };
    if let Some((
        admission_metadata,
        exposure_units,
        realized_spend_units,
        mutation_invocation_count_after,
        mutation_committed_cost_units_after,
    )) = admission
    {
        let event_id = match admission_metadata.event_id {
            Some(event_id) => event_id,
            None => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "budget authorization did not retain its event identity",
                )
            }
        };
        let write = match budget_write_token(&store, authority.as_ref(), Some(&event_id)) {
            Ok(write) => write,
            Err(response) => return response,
        };
        let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index)
        {
            Ok(Some(usage)) => Some(TryChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                allowed: !already_captured,
                decision: if already_captured {
                    BudgetAuthorizeExposureDecision::AlreadyCaptured
                } else {
                    BudgetAuthorizeExposureDecision::Authorized
                },
                event_id: Some(event_id),
                exposure_units: Some(exposure_units),
                realized_spend_units: Some(realized_spend_units),
                mutation_invocation_count_after: Some(mutation_invocation_count_after),
                mutation_committed_cost_units_after: Some(mutation_committed_cost_units_after),
                usage_seq: Some(usage.seq),
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            }),
            Ok(None) => None,
            Err(error) => {
                return budget_internal_error(&error, "budget usage lookup failed");
            }
        };
        drop(store);
        let Some(response) = committed_response else {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "budget exposure state was not visible on the leader after write",
            );
        };
        let commit_index = write.event_seq;
        let budget_commit = match wait_for_budget_write_quorum_commit(&state, write).await {
            Ok(budget_commit) => budget_commit,
            Err(_) => {
                if already_captured {
                    return plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "captured budget authorization replay could not confirm quorum commit; admission retained",
                    );
                }
                let rollback_result = rollback_budget_authorize_exposure(
                    &state,
                    &payload,
                    authority.as_ref(),
                    commit_index,
                );
                return match rollback_result {
                    Ok(()) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "budget authorize became leader-visible at commit index {commit_index} but failed quorum commit; local exposure rollback succeeded"
                        ),
                    ),
                    Err(error) => budget_internal_error(
                        &error,
                        "budget authorize quorum failure and rollback failed; admission retained",
                    ),
                };
            }
        };
        json_response_with_leader_visibility_and_budget_commit(&state, response, budget_commit)
    } else if let Some(denied) = denied {
        respond_after_leader_visible_write(
            &state,
            "budget exposure state was not visible on the leader after write",
            || {
                let usage = store
                    .get_usage(&payload.capability_id, payload.grant_index)
                    .map_err(|error| budget_internal_error(&error, "budget usage lookup failed"))?;
                Ok(Some(TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed: false,
                    decision: BudgetAuthorizeExposureDecision::Denied,
                    event_id: denied.metadata.event_id.clone(),
                    exposure_units: None,
                    realized_spend_units: None,
                    mutation_invocation_count_after: Some(denied.invocation_count_after),
                    mutation_committed_cost_units_after: Some(denied.committed_cost_units_after),
                    usage_seq: usage.as_ref().map(|usage| usage.seq),
                    invocation_count: usage.as_ref().map(|usage| usage.invocation_count),
                    total_cost_exposed: usage.as_ref().map(|usage| usage.total_cost_exposed),
                    total_cost_realized_spend: usage
                        .as_ref()
                        .map(|usage| usage.total_cost_realized_spend),
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                    budget_commit: None,
                }))
            },
        )
    } else {
        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "missing budget decision")
    }
}

pub(crate) async fn handle_reverse_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReverseChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_RELEASE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority =
        match resolve_budget_hold_authority(&state, &mut store, payload.hold_id.as_deref()) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    // Mint an event_id when omitted so the witness waits on this reverse's exact
    // event_seq, not the authority MAX.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    if let Err(error) = store.reverse_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
        payload.hold_id.as_deref(),
        Some(effective_event_id.as_str()),
        authority.as_ref(),
    ) {
        return budget_internal_error(&error, "budget exposure release failed");
    }
    let write = match budget_write_token(
        &store,
        authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReverseChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            write,
        )),
        Ok(None) => None,
        Err(error) => {
            return budget_internal_error(&error, "budget usage lookup failed");
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "released budget exposure state was not visible on the leader after write",
        committed_response,
    )
    .await
}

pub(crate) async fn handle_capture_invocation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CaptureInvocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_CAPTURE_INVOCATION_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(&state, &mut store, Some(&payload.hold_id))
    {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let (decision, mutation) =
        match store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            hold_id: payload.hold_id.clone(),
            event_id: payload.event_id.clone(),
            authority: authority.clone(),
        }) {
            Ok(BudgetInvocationCaptureDecision::Captured(mutation)) => {
                (CaptureInvocationDecision::Captured, mutation)
            }
            Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)) => {
                (CaptureInvocationDecision::AlreadyCaptured, mutation)
            }
            Err(error) => {
                return budget_internal_error(&error, "budget invocation capture failed");
            }
        };
    let Some(event_id) = mutation.metadata.event_id.clone() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capture mutation did not retain its event identity",
        );
    };
    let usage = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => usage,
        Ok(None) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "captured budget usage was not visible on the leader after write",
            )
        }
        Err(error) => {
            return budget_internal_error(&error, "budget usage lookup failed");
        }
    };
    let write = match budget_write_token(&store, authority.as_ref(), Some(&event_id)) {
        Ok(write) => write,
        Err(response) => return response,
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "captured budget invocation state was not visible on the leader after write",
        Some((
            CaptureInvocationResponse {
                capability_id: payload.capability_id,
                grant_index: payload.grant_index,
                hold_id: payload.hold_id,
                event_id,
                decision,
                exposure_units: mutation.exposure_units,
                invocation_count_after: mutation.invocation_count_after,
                usage_invocation_count: usage.invocation_count,
                committed_cost_units_after: mutation.committed_cost_units_after,
                total_cost_exposed_after: usage.total_cost_exposed,
                total_cost_realized_spend_after: usage.total_cost_realized_spend,
                usage_seq: Some(usage.seq),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    mutation.metadata.budget_commit_index,
                    budget_authority_guarantee_level(&state, mutation.metadata.budget_commit_index),
                ),
                budget_commit: None,
            },
            write,
        )),
    )
    .await
}

pub(crate) async fn handle_reduce_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReduceChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let released_exposure_units = payload.release_units();
    match forward_post_to_leader(&state, BUDGET_RECONCILE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority =
        match resolve_budget_hold_authority(&state, &mut store, payload.hold_id.as_deref()) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    // Mint an event_id when omitted so the witness waits on this reconcile's exact
    // event_seq, not the authority MAX.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let reconcile_result = if let (Some(exposure_units), Some(realized_spend_units)) =
        (payload.exposure_units, payload.realized_spend_units)
    {
        store.settle_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            exposure_units,
            realized_spend_units,
            payload.hold_id.as_deref(),
            Some(effective_event_id.as_str()),
            authority.as_ref(),
        )
    } else {
        store.reduce_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            released_exposure_units,
            payload.hold_id.as_deref(),
            Some(effective_event_id.as_str()),
            authority.as_ref(),
        )
    };
    if let Err(error) = reconcile_result {
        return budget_internal_error(&error, "budget reconciliation failed");
    }
    let write = match budget_write_token(
        &store,
        authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReduceChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                released_exposure_units: Some(released_exposure_units),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            write,
        )),
        Ok(None) => None,
        Err(error) => {
            return budget_internal_error(&error, "budget usage lookup failed");
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "reconciled budget spend state was not visible on the leader after write",
        committed_response,
    )
    .await
}

fn resolve_budget_hold_authority(
    state: &TrustServiceState,
    store: &mut SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(Some(authority)) => return Ok(Some(authority)),
            Ok(None) => {}
            Err(error) => {
                return Err(budget_internal_error(
                    &error,
                    "budget hold authority lookup failed",
                ));
            }
        }
    }
    current_budget_event_authority(state)
}

#[cfg(test)]
mod budget_handlers_tests {
    use super::generated_budget_event_id;
    use std::collections::HashSet;

    #[test]
    fn generated_budget_event_id_is_unique_per_call() {
        // Each omitted-eventId write must get a distinct id so the mutation event
        // is stored under a known, unique key and the witness can look up THIS
        // write's exact event_seq.
        let first = generated_budget_event_id();
        let second = generated_budget_event_id();
        assert_ne!(first, second, "consecutive ids must differ");
        assert!(first.starts_with("cluster-budget-write-"));
        // A tight burst (same wall-clock nanos possible) is still all-distinct via
        // the monotonic counter.
        let ids: HashSet<String> = (0..10_000).map(|_| generated_budget_event_id()).collect();
        assert_eq!(ids.len(), 10_000, "all minted ids must be unique");
    }
}
