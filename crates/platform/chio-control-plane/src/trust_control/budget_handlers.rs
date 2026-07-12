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
use super::service_runtime::budget::{
    canonical_revocation_set_from_view, canonical_revocation_set_view, invocation_quota_from_view,
    invocation_quota_view,
};
use super::*;
use chio_store_sqlite::{SqliteBudgetAuthorizationAuthority, SqliteBudgetCurrentAuthority};

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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
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
/// authority) carries a placeholder token and the quorum wait short-circuits when
/// unclustered.
fn budget_write_token(
    store: &SqliteBudgetStore,
    authority: Option<&BudgetEventAuthority>,
    event_id: Option<&str>,
) -> Result<BudgetWriteToken, Response> {
    let http_error = |error: BudgetStoreError| {
        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
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
    let authority_source = match store
        .authorization_authority_source(payload.hold_id.as_deref(), effective_event_id.as_str())
    {
        Ok(source) => source,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let current_authority = match authority_source {
        SqliteBudgetAuthorizationAuthority::Persisted(_) => {
            SqliteBudgetCurrentAuthority::Unavailable
        }
        SqliteBudgetAuthorizationAuthority::Current => {
            match current_budget_event_authority(&state) {
                Ok(authority) => SqliteBudgetCurrentAuthority::Resolved(authority),
                Err(response) => return response,
            }
        }
    };
    let authorization = match store.try_charge_cost_with_ids_and_current_authority_outcome(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
        payload.cost_units,
        payload.max_cost_per_invocation,
        payload.max_total_cost_units,
        payload.hold_id.as_deref(),
        Some(effective_event_id.as_str()),
        current_authority,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let allowed = authorization.allowed;
    let authority = authorization.authority.clone();
    let authorize_event = match load_persisted_authorize_event(
        &store,
        effective_event_id.as_str(),
        &payload,
        allowed,
        authority.as_ref(),
    ) {
        Ok(event) => event,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if allowed {
        let write = match budget_write_token(
            &store,
            authorize_event.authority.as_ref(),
            Some(effective_event_id.as_str()),
        ) {
            Ok(write) => write,
            Err(response) => return response,
        };
        let response = TryChargeCostResponse {
            capability_id: authorize_event.capability_id.clone(),
            grant_index: payload.grant_index,
            allowed,
            invocation_count: Some(authorize_event.invocation_count_after),
            total_cost_exposed: Some(authorize_event.total_cost_exposed_after),
            total_cost_realized_spend: Some(authorize_event.total_cost_realized_spend_after),
            budget_authority: persisted_budget_authority_metadata_view(
                &state,
                &authorize_event,
                Some(authorize_event.event_seq),
            ),
            budget_commit: None,
        };
        drop(store);
        let commit_index = write.event_seq;
        let budget_commit = match wait_for_budget_write_quorum_commit(&state, write).await {
            Ok(budget_commit) => budget_commit,
            Err(_) => {
                let rollback_result = match current_budget_event_authority(&state) {
                    Ok(live_authority) => compensate_authorize_after_quorum_failure(
                        authorization.event_created,
                        authorize_event.authority.as_ref(),
                        live_authority.as_ref(),
                        || {
                            rollback_budget_authorize_exposure(
                                &state,
                                &payload,
                                effective_event_id.as_str(),
                                authorize_event.authority.as_ref(),
                            )
                        },
                    ),
                    Err(_) => Err(BudgetStoreError::Invariant(
                        "budget authorize compensation could not resolve the live authority lease"
                            .to_string(),
                    )),
                };
                return match rollback_result {
                    Ok(true) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "budget authorize became leader-visible at commit index {commit_index} but failed quorum commit; local exposure rollback succeeded"
                        ),
                    ),
                    Ok(false) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "persisted budget authorize retry at commit index {commit_index} could not re-establish current quorum; the previously committed reservation was not compensated"
                        ),
                    ),
                    Err(error) => plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(
                            "budget authorize became leader-visible at commit index {commit_index} but failed quorum commit and local exposure rollback also failed: {error}"
                        ),
                    ),
                };
            }
        };
        json_response_with_leader_visibility_and_budget_commit(&state, response, budget_commit)
    } else {
        respond_after_leader_visible_write(
            &state,
            "budget exposure state was not visible on the leader after write",
            || {
                Ok(Some(TryChargeCostResponse {
                    capability_id: authorize_event.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count: Some(authorize_event.invocation_count_after),
                    total_cost_exposed: Some(authorize_event.total_cost_exposed_after),
                    total_cost_realized_spend: Some(
                        authorize_event.total_cost_realized_spend_after,
                    ),
                    budget_authority: persisted_budget_authority_metadata_view(
                        &state,
                        &authorize_event,
                        None,
                    ),
                    budget_commit: None,
                }))
            },
        )
    }
}

pub(crate) async fn handle_authorize_composite_budget_hold(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CompositeBudgetAuthorizeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(response) = require_remote_composite_linearizability(&state) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_AUTHORIZE_HOLD_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority_source = match store
        .authorization_authority_source(Some(payload.hold_id.as_str()), payload.event_id.as_str())
    {
        Ok(source) => source,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let authority = match remote_composite_authority(&state, authority_source) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let input = match sqlite_composite_authorize_input(&payload, authority.clone()) {
        Ok(input) => input,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let decision = match store.authorize_composite_hold(input) {
        Ok(decision) => decision,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let event = match load_persisted_composite_authorize_event(&store, &payload, &decision) {
        Ok(event) => event,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let write = match budget_write_token(
        &store,
        event.authority.as_ref(),
        Some(payload.event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    drop(store);
    let budget_commit = match wait_for_budget_write_quorum_commit(&state, write).await {
        Ok(Some(commit)) => commit,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "remote composite budget authorization requires HA-linearizable quorum commit",
            );
        }
        Err(response) => return response,
    };
    let Some(budget_authority) =
        persisted_budget_authority_metadata_view(&state, &event, Some(budget_commit.commit_index))
    else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "remote composite budget authorization could not preserve its persisted authority",
        );
    };
    match composite_authorize_response_view(&payload, decision, budget_authority, budget_commit) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_capture_invocation_reservations(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CaptureInvocationReservationsRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(response) = require_remote_composite_linearizability(&state) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_CAPTURE_INVOCATIONS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let Some(requested_authority) =
        budget_event_authority_from_view(payload.budget_authority.as_ref())
    else {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "invocation capture requires the exact persisted budget authority",
        );
    };
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let resolved_authority = match resolve_budget_hold_authority(
        "invocation capture",
        &state,
        &store,
        Some(payload.hold_id.as_str()),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let authority = match verify_requested_budget_authority(
        "invocation capture",
        Some(&requested_authority),
        resolved_authority,
    ) {
        Ok(Some(authority)) => authority,
        Ok(None) => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "invocation capture requires a persisted budget authority",
            );
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let decision = match store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        hold_id: Some(payload.hold_id.clone()),
        event_id: Some(payload.event_id.clone()),
        authority: Some(authority),
    }) {
        Ok(decision) => decision,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if decision.invocation_state != BudgetInvocationReservationState::Captured {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "budget backend returned a non-captured invocation state",
        );
    }
    let event = match load_persisted_invocation_capture_event(&store, &payload, &decision) {
        Ok(event) => event,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let write = match budget_write_token(
        &store,
        event.authority.as_ref(),
        Some(payload.event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    drop(store);
    let budget_commit = match wait_for_budget_write_quorum_commit(&state, write).await {
        Ok(Some(commit)) => commit,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "remote invocation capture requires HA-linearizable quorum commit",
            );
        }
        Err(response) => return response,
    };
    let Some(budget_authority) =
        persisted_budget_authority_metadata_view(&state, &event, Some(budget_commit.commit_index))
    else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "remote invocation capture could not preserve its persisted authority",
        );
    };
    match invocation_capture_response_view(&payload, decision, budget_authority, budget_commit) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_combined_admission_capture_unavailable(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(_payload): Json<CombinedAdmissionCaptureRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "combined admission capture is unavailable because budget and revocation writes do not share one linearizable consensus log",
    )
}

fn remote_composite_authority(
    state: &TrustServiceState,
    source: SqliteBudgetAuthorizationAuthority,
) -> Result<BudgetEventAuthority, Response> {
    match source {
        SqliteBudgetAuthorizationAuthority::Persisted(Some(authority)) => Ok(authority),
        SqliteBudgetAuthorizationAuthority::Persisted(None) => Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "persisted composite budget authorization has no HA authority",
        )),
        SqliteBudgetAuthorizationAuthority::Current => current_budget_event_authority(state)?
            .ok_or_else(|| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "remote composite budget authorization requires an HA authority lease",
                )
            }),
    }
}

fn require_remote_composite_linearizability(state: &TrustServiceState) -> Result<(), Response> {
    if budget_authority_guarantee_level(state, Some(1)) != "ha_linearizable" {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "remote hard composite budgets are unavailable because the current quorum/pull lane is not HA-linearizable",
        ));
    }
    Ok(())
}

fn sqlite_composite_authorize_input(
    payload: &CompositeBudgetAuthorizeRequest,
    authority: BudgetEventAuthority,
) -> Result<SqliteCompositeAuthorizeInput, BudgetStoreError> {
    if let Some(digest) = payload
        .admission_evidence
        .aggregate_binding_digest
        .as_deref()
    {
        validate_admission_digest(digest, "aggregate binding digest")?;
    }
    let authorization_artifact_digests = payload
        .admission_evidence
        .supplemental_binding
        .as_ref()
        .map(|binding| {
            validate_admission_digest(&binding.artifact_digest, "supplemental artifact digest")?;
            validate_admission_digest(
                &binding.request_binding_hash,
                "supplemental request binding hash",
            )?;
            validate_admission_digest(
                &binding.negotiated_features_digest,
                "supplemental negotiated-features digest",
            )?;
            if binding.verifier_id.is_empty() || binding.verifier_id.bytes().any(|byte| byte == 0) {
                return Err(BudgetStoreError::Invariant(
                    "supplemental verifier id is empty or contains NUL".to_string(),
                ));
            }
            Ok(binding.artifact_digest.clone())
        })
        .transpose()?
        .into_iter()
        .collect();
    Ok(SqliteCompositeAuthorizeInput {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        requested_exposure_units: payload.requested_exposure_units,
        max_cost_per_invocation: payload.max_exposure_per_invocation,
        max_total_cost_units: payload.max_total_exposure_units,
        hold_id: payload.hold_id.clone(),
        event_id: payload.event_id.clone(),
        authority: Some(authority),
        invocation_quotas: payload
            .admission_evidence
            .invocation_quotas
            .iter()
            .map(invocation_quota_from_view)
            .collect::<Result<Vec<_>, _>>()?,
        revocation_set: canonical_revocation_set_from_view(
            &payload.admission_evidence.revocation_set,
        )?,
        authorization_artifact_digests,
    })
}

fn validate_admission_digest(value: &str, label: &str) -> Result<(), BudgetStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BudgetStoreError::Invariant(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn composite_authorize_response_view(
    payload: &CompositeBudgetAuthorizeRequest,
    decision: BudgetAuthorizeHoldDecision,
    budget_authority: BudgetAuthorityMetadataView,
    budget_commit: BudgetWriteCommitView,
) -> Result<CompositeBudgetAuthorizeResponse, BudgetStoreError> {
    let (
        allowed,
        hold_id,
        authorized_exposure_units,
        attempted_exposure_units,
        committed_cost_units_after,
        invocation_count_after,
        invocation_counts_after,
        invocation_state,
        monetary_state,
        revocation_set,
    ) = match decision {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => (
            true,
            authorized.hold_id,
            Some(authorized.authorized_exposure_units),
            None,
            authorized.committed_cost_units_after,
            authorized.invocation_count_after,
            authorized.invocation_counts_after,
            authorized.invocation_state,
            authorized.monetary_state,
            authorized.revocation_set,
        ),
        BudgetAuthorizeHoldDecision::Denied(denied) => (
            false,
            denied.hold_id,
            None,
            Some(denied.attempted_exposure_units),
            denied.committed_cost_units_after,
            denied.invocation_count_after,
            denied.invocation_counts_after,
            denied.invocation_state,
            denied.monetary_state,
            denied.revocation_set,
        ),
    };
    if hold_id.as_deref() != Some(payload.hold_id.as_str())
        || revocation_set.as_ref().map(canonical_revocation_set_view)
            != Some(payload.admission_evidence.revocation_set.clone())
    {
        return Err(BudgetStoreError::Invariant(
            "composite authorization decision does not match request identity or revocation set"
                .to_string(),
        ));
    }
    Ok(CompositeBudgetAuthorizeResponse {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        hold_id: payload.hold_id.clone(),
        event_id: payload.event_id.clone(),
        allowed,
        authorized_exposure_units,
        attempted_exposure_units,
        committed_cost_units_after,
        invocation_count_after,
        invocation_counts_after: invocation_counts_after
            .iter()
            .map(invocation_quota_usage_view)
            .collect(),
        invocation_state: invocation_state_view(invocation_state),
        monetary_state: monetary_state_view(monetary_state),
        admission_evidence: payload.admission_evidence.clone(),
        budget_authority: Some(budget_authority),
        budget_commit: Some(budget_commit),
    })
}

fn invocation_capture_response_view(
    payload: &CaptureInvocationReservationsRequest,
    decision: BudgetHoldMutationDecision,
    budget_authority: BudgetAuthorityMetadataView,
    budget_commit: BudgetWriteCommitView,
) -> Result<CaptureInvocationReservationsResponse, BudgetStoreError> {
    if decision.hold_id.as_deref() != Some(payload.hold_id.as_str()) {
        return Err(BudgetStoreError::Invariant(
            "invocation capture decision does not match the requested hold".to_string(),
        ));
    }
    let revocation_set = decision.revocation_set.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "invocation capture decision omitted its canonical revocation set".to_string(),
        )
    })?;
    Ok(CaptureInvocationReservationsResponse {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        hold_id: payload.hold_id.clone(),
        event_id: payload.event_id.clone(),
        exposure_units: decision.exposure_units,
        realized_spend_units: decision.realized_spend_units,
        committed_cost_units_after: decision.committed_cost_units_after,
        invocation_count_after: decision.invocation_count_after,
        invocation_counts_after: decision
            .invocation_counts_after
            .iter()
            .map(invocation_quota_usage_view)
            .collect(),
        invocation_state: invocation_state_view(decision.invocation_state),
        monetary_state: monetary_state_view(decision.monetary_state),
        revocation_set: canonical_revocation_set_view(revocation_set),
        budget_authority: Some(budget_authority),
        budget_commit: Some(budget_commit),
    })
}

fn invocation_quota_usage_view(
    usage: &BudgetInvocationQuotaUsage,
) -> BudgetInvocationQuotaUsageView {
    BudgetInvocationQuotaUsageView {
        quota: invocation_quota_view(&usage.quota),
        reserved_invocations_after: usage.reserved_invocations_after,
        captured_invocations_after: usage.captured_invocations_after,
    }
}

fn invocation_state_view(
    state: BudgetInvocationReservationState,
) -> BudgetInvocationReservationStateView {
    match state {
        BudgetInvocationReservationState::Absent => BudgetInvocationReservationStateView::Absent,
        BudgetInvocationReservationState::Authorized => {
            BudgetInvocationReservationStateView::Authorized
        }
        BudgetInvocationReservationState::Captured => {
            BudgetInvocationReservationStateView::Captured
        }
        BudgetInvocationReservationState::Reversed => {
            BudgetInvocationReservationStateView::Reversed
        }
        BudgetInvocationReservationState::Denied => BudgetInvocationReservationStateView::Denied,
    }
}

fn monetary_state_view(state: BudgetMonetaryHoldState) -> BudgetMonetaryHoldStateView {
    match state {
        BudgetMonetaryHoldState::None => BudgetMonetaryHoldStateView::None,
        BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldStateView::Exposed,
        BudgetMonetaryHoldState::Released => BudgetMonetaryHoldStateView::Released,
        BudgetMonetaryHoldState::Reconciled => BudgetMonetaryHoldStateView::Reconciled,
        BudgetMonetaryHoldState::Captured => BudgetMonetaryHoldStateView::Captured,
        BudgetMonetaryHoldState::Reversed => BudgetMonetaryHoldStateView::Reversed,
    }
}

fn load_persisted_composite_authorize_event(
    store: &SqliteBudgetStore,
    payload: &CompositeBudgetAuthorizeRequest,
    decision: &BudgetAuthorizeHoldDecision,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let event = load_mutation_event_by_id(store, &payload.event_id)?;
    let (
        allowed,
        hold_id,
        committed_cost_units_after,
        invocation_count_after,
        invocation_state,
        monetary_state,
        metadata,
    ) = match decision {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => (
            true,
            authorized.hold_id.as_deref(),
            authorized.committed_cost_units_after,
            authorized.invocation_count_after,
            authorized.invocation_state,
            authorized.monetary_state,
            &authorized.metadata,
        ),
        BudgetAuthorizeHoldDecision::Denied(denied) => (
            false,
            denied.hold_id.as_deref(),
            denied.committed_cost_units_after,
            denied.invocation_count_after,
            denied.invocation_state,
            denied.monetary_state,
            &denied.metadata,
        ),
    };
    let committed_from_event = event
        .total_cost_exposed_after
        .checked_add(event.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "persisted composite authorization committed cost overflowed u64".to_string(),
            )
        })?;
    let usage_seq_matches = if allowed {
        event.usage_seq == Some(event.event_seq)
    } else {
        event.usage_seq.is_none()
    };
    if event.kind != BudgetMutationKind::ReserveInvocations
        || event.allowed != Some(allowed)
        || !usage_seq_matches
        || event.capability_id != payload.capability_id
        || usize::try_from(event.grant_index).ok() != Some(payload.grant_index)
        || event.hold_id.as_deref() != Some(payload.hold_id.as_str())
        || hold_id != Some(payload.hold_id.as_str())
        || event.exposure_units != payload.requested_exposure_units
        || event.realized_spend_units != 0
        || event.max_invocations.is_some()
        || event.max_cost_per_invocation != payload.max_exposure_per_invocation
        || event.max_total_cost_units != payload.max_total_exposure_units
        || event.invocation_count_after != invocation_count_after
        || event.invocation_state != invocation_state
        || event.monetary_state != monetary_state
        || event.authority != metadata.authority
        || committed_from_event != committed_cost_units_after
    {
        return Err(BudgetStoreError::Invariant(format!(
            "persisted composite authorization event `{}` does not match its frozen decision",
            payload.event_id
        )));
    }
    Ok(event)
}

fn load_persisted_invocation_capture_event(
    store: &SqliteBudgetStore,
    payload: &CaptureInvocationReservationsRequest,
    decision: &BudgetHoldMutationDecision,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let event = load_mutation_event_by_id(store, &payload.event_id)?;
    let committed_from_event = event
        .total_cost_exposed_after
        .checked_add(event.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "persisted invocation capture committed cost overflowed u64".to_string(),
            )
        })?;
    if event.kind != BudgetMutationKind::CaptureInvocations
        || event.allowed.is_some()
        || event.usage_seq != Some(event.event_seq)
        || event.capability_id != payload.capability_id
        || usize::try_from(event.grant_index).ok() != Some(payload.grant_index)
        || event.hold_id.as_deref() != Some(payload.hold_id.as_str())
        || decision.hold_id.as_deref() != Some(payload.hold_id.as_str())
        || event.exposure_units != decision.exposure_units
        || event.realized_spend_units != decision.realized_spend_units
        || event.invocation_count_after != decision.invocation_count_after
        || event.invocation_state != decision.invocation_state
        || event.authority != decision.metadata.authority
        || committed_from_event != decision.committed_cost_units_after
        || decision.metadata.budget_commit_index != Some(event.event_seq)
    {
        return Err(BudgetStoreError::Invariant(format!(
            "persisted invocation capture event `{}` does not match its frozen decision",
            payload.event_id
        )));
    }
    Ok(event)
}

fn load_mutation_event_by_id(
    store: &SqliteBudgetStore,
    event_id: &str,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let event_seq = store
        .mutation_event_seq_for_event_id(event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget event `{event_id}` is not persisted"))
        })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant("budget event sequence must be greater than zero".to_string())
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!("budget event `{event_id}` is not readable"))
        })?;
    if event.event_id != event_id || event.event_seq != event_seq {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event `{event_id}` resolved to a different persisted row"
        )));
    }
    Ok(event)
}

fn compensate_authorize_after_quorum_failure(
    event_created: bool,
    authorize_authority: Option<&BudgetEventAuthority>,
    live_authority: Option<&BudgetEventAuthority>,
    compensate: impl FnOnce() -> Result<(), BudgetStoreError>,
) -> Result<bool, BudgetStoreError> {
    if !event_created {
        return Ok(false);
    }
    if authorize_authority != live_authority {
        return Err(BudgetStoreError::Invariant(
            "budget authorize compensation authority does not match the live authority lease"
                .to_string(),
        ));
    }
    compensate()?;
    Ok(true)
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
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let resolved_authority = match resolve_budget_hold_authority(
        "reverse",
        &state,
        &store,
        payload.hold_id.as_deref(),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let requested_authority = budget_event_authority_from_view(payload.budget_authority.as_ref());
    let authority = match verify_requested_budget_authority(
        "reverse",
        requested_authority.as_ref(),
        resolved_authority,
    ) {
        Ok(authority) => authority,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
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
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let reverse_event = match load_persisted_budget_transition(
        &store,
        effective_event_id.as_str(),
        BudgetMutationKind::ReverseExposure,
        &payload.capability_id,
        payload.grant_index,
        payload.hold_id.as_deref(),
        payload.cost_units,
        0,
        authority.as_ref(),
    ) {
        Ok(event) => event,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let write = match budget_write_token(
        &store,
        reverse_event.authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = Some((
        ReverseChargeCostResponse {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            invocation_count: Some(reverse_event.invocation_count_after),
            total_cost_exposed: Some(reverse_event.total_cost_exposed_after),
            total_cost_realized_spend: Some(reverse_event.total_cost_realized_spend_after),
            budget_authority: persisted_budget_authority_metadata_view(
                &state,
                &reverse_event,
                Some(reverse_event.event_seq),
            ),
            budget_commit: None,
        },
        write,
    ));
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "released budget exposure state was not visible on the leader after write",
        committed_response,
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
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let operation = if payload.exposure_units.is_some() && payload.realized_spend_units.is_some() {
        "reconcile"
    } else {
        "release"
    };
    let resolved_authority = match resolve_budget_hold_authority(
        operation,
        &state,
        &store,
        payload.hold_id.as_deref(),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let requested_authority = budget_event_authority_from_view(payload.budget_authority.as_ref());
    let authority = match verify_requested_budget_authority(
        operation,
        requested_authority.as_ref(),
        resolved_authority,
    ) {
        Ok(authority) => authority,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    // Mint an event_id when omitted so the witness waits on this reconcile's exact
    // event_seq, not the authority MAX.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let (transition_kind, transition_exposure_units, transition_realized_spend_units) =
        if let (Some(exposure_units), Some(realized_spend_units)) =
            (payload.exposure_units, payload.realized_spend_units)
        {
            if let Err(error) = store.settle_charge_cost_with_ids_and_authority(
                &payload.capability_id,
                payload.grant_index,
                exposure_units,
                realized_spend_units,
                payload.hold_id.as_deref(),
                Some(effective_event_id.as_str()),
                authority.as_ref(),
            ) {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
            (
                BudgetMutationKind::ReconcileSpend,
                exposure_units,
                realized_spend_units,
            )
        } else {
            if let Err(error) = store.reduce_charge_cost_with_ids_and_authority(
                &payload.capability_id,
                payload.grant_index,
                released_exposure_units,
                payload.hold_id.as_deref(),
                Some(effective_event_id.as_str()),
                authority.as_ref(),
            ) {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
            (
                BudgetMutationKind::ReleaseExposure,
                released_exposure_units,
                0,
            )
        };
    let transition_event = match load_persisted_budget_transition(
        &store,
        effective_event_id.as_str(),
        transition_kind,
        &payload.capability_id,
        payload.grant_index,
        payload.hold_id.as_deref(),
        transition_exposure_units,
        transition_realized_spend_units,
        authority.as_ref(),
    ) {
        Ok(event) => event,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let write = match budget_write_token(
        &store,
        transition_event.authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = Some((
        ReduceChargeCostResponse {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            invocation_count: Some(transition_event.invocation_count_after),
            total_cost_exposed: Some(transition_event.total_cost_exposed_after),
            total_cost_realized_spend: Some(transition_event.total_cost_realized_spend_after),
            released_exposure_units: Some(released_exposure_units),
            budget_authority: persisted_budget_authority_metadata_view(
                &state,
                &transition_event,
                Some(transition_event.event_seq),
            ),
            budget_commit: None,
        },
        write,
    ));
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "reconciled budget spend state was not visible on the leader after write",
        committed_response,
    )
    .await
}

pub(crate) async fn handle_capture_budget_hold(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReduceChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (Some(exposure_units), Some(realized_spend_units)) =
        (payload.exposure_units, payload.realized_spend_units)
    else {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "budget capture requires authorized exposure and realized spend",
        );
    };
    let released_exposure_units = match exposure_units.checked_sub(realized_spend_units) {
        Some(released_exposure_units) if released_exposure_units == payload.cost_units => {
            released_exposure_units
        }
        Some(_) => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "budget capture reduction does not match exposure minus realized spend",
            );
        }
        None => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "realized spend cannot exceed authorized exposure during capture",
            );
        }
    };
    match forward_post_to_leader(&state, BUDGET_CAPTURE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let resolved_authority = match resolve_budget_hold_authority(
        "capture",
        &state,
        &store,
        payload.hold_id.as_deref(),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let requested_authority = budget_event_authority_from_view(payload.budget_authority.as_ref());
    let authority = match verify_requested_budget_authority(
        "capture",
        requested_authority.as_ref(),
        resolved_authority,
    ) {
        Ok(authority) => authority,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let captured = match store.capture_budget_hold(BudgetCaptureHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        exposed_cost_units: exposure_units,
        realized_spend_units,
        hold_id: payload.hold_id.clone(),
        event_id: Some(effective_event_id.clone()),
        authority: authority.clone(),
    }) {
        Ok(captured) => captured,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if captured.monetary_state != BudgetMonetaryHoldState::Captured {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "budget backend returned a non-captured monetary state",
        );
    }
    let capture_event =
        match load_persisted_capture_event(&store, &captured, effective_event_id.as_str()) {
            Ok(event) => event,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
    let write = match budget_write_token(
        &store,
        capture_event.authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = Some((
        ReduceChargeCostResponse {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            invocation_count: Some(capture_event.invocation_count_after),
            total_cost_exposed: Some(capture_event.total_cost_exposed_after),
            total_cost_realized_spend: Some(capture_event.total_cost_realized_spend_after),
            released_exposure_units: Some(released_exposure_units),
            budget_authority: persisted_budget_authority_metadata_view(
                &state,
                &capture_event,
                Some(capture_event.event_seq),
            ),
            budget_commit: None,
        },
        write,
    ));
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "captured budget exposure state was not visible on the leader after write",
        committed_response,
    )
    .await
}

fn persisted_budget_authority_metadata_view(
    state: &TrustServiceState,
    event: &BudgetMutationRecord,
    budget_commit_index: Option<u64>,
) -> Option<BudgetAuthorityMetadataView> {
    let authority = event.authority.as_ref()?;
    let metadata = budget_authority_metadata_view(
        state,
        budget_commit_index,
        budget_authority_guarantee_level(state, budget_commit_index),
    )?;
    budget_authority_metadata_matches_event(&metadata, authority).then_some(metadata)
}

fn budget_authority_metadata_matches_event(
    metadata: &BudgetAuthorityMetadataView,
    authority: &BudgetEventAuthority,
) -> bool {
    metadata.authority_id == authority.authority_id
        && metadata.leader_url == authority.authority_id
        && metadata.budget_term == authority.lease_epoch
        && metadata.lease_id == authority.lease_id
        && metadata.lease_epoch == authority.lease_epoch
}

fn budget_event_authority_from_view(
    authority: Option<&BudgetMutationAuthorityView>,
) -> Option<BudgetEventAuthority> {
    authority.map(|authority| BudgetEventAuthority {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    })
}

fn verify_requested_budget_authority(
    operation: &str,
    requested: Option<&BudgetEventAuthority>,
    resolved: Option<BudgetEventAuthority>,
) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
    match requested {
        Some(requested) if resolved.as_ref() == Some(requested) => Ok(Some(requested.clone())),
        Some(_) => Err(BudgetStoreError::Invariant(format!(
            "requested budget {operation} authority does not match the server-resolved authority"
        ))),
        None => Ok(resolved),
    }
}

fn load_persisted_authorize_event(
    store: &SqliteBudgetStore,
    event_id: &str,
    request: &TryChargeCostRequest,
    allowed: bool,
    authority: Option<&BudgetEventAuthority>,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let grant_index = u32::try_from(request.grant_index).map_err(|_| {
        BudgetStoreError::Invariant("budget authorize grant index exceeds u32".to_string())
    })?;
    let event_seq = store
        .mutation_event_seq_for_event_id(event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget authorize event `{event_id}` is not persisted"
            ))
        })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "budget authorize event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget authorize event `{event_id}` is not readable"
            ))
        })?;
    let expected_monetary_state = if allowed && request.cost_units > 0 {
        BudgetMonetaryHoldState::Exposed
    } else {
        BudgetMonetaryHoldState::None
    };
    let usage_seq_matches = if allowed {
        event.usage_seq.is_some()
    } else {
        event.usage_seq.is_none()
    };
    if event.event_id != event_id
        || event.event_seq != event_seq
        || !usage_seq_matches
        || event.kind != BudgetMutationKind::AuthorizeExposure
        || event.allowed != Some(allowed)
        || event.monetary_state != expected_monetary_state
        || event.invocation_state != BudgetInvocationReservationState::Absent
        || event.capability_id != request.capability_id
        || event.grant_index != grant_index
        || event.hold_id != request.hold_id
        || event.exposure_units != request.cost_units
        || event.realized_spend_units != 0
        || event.max_invocations != request.max_invocations
        || event.max_cost_per_invocation != request.max_cost_per_invocation
        || event.max_total_cost_units != request.max_total_cost_units
        || event.authority.as_ref() != authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget authorize event `{event_id}` does not match the requested mutation"
        )));
    }
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
fn load_persisted_budget_transition(
    store: &SqliteBudgetStore,
    event_id: &str,
    kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: Option<&str>,
    exposure_units: u64,
    realized_spend_units: u64,
    authority: Option<&BudgetEventAuthority>,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let expected_monetary_state = match kind {
        BudgetMutationKind::ReverseExposure => BudgetMonetaryHoldState::Reversed,
        BudgetMutationKind::ReleaseExposure => BudgetMonetaryHoldState::Released,
        BudgetMutationKind::ReconcileSpend => BudgetMonetaryHoldState::Reconciled,
        _ => {
            return Err(BudgetStoreError::Invariant(
                "persisted budget transition requested an unsupported mutation kind".to_string(),
            ));
        }
    };
    let grant_index = u32::try_from(grant_index).map_err(|_| {
        BudgetStoreError::Invariant("budget transition grant index exceeds u32".to_string())
    })?;
    let event_seq = store
        .mutation_event_seq_for_event_id(event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget transition event `{event_id}` is not persisted"
            ))
        })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "budget transition event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget transition event `{event_id}` is not readable"
            ))
        })?;
    if event.event_id != event_id
        || event.event_seq != event_seq
        || event.usage_seq != Some(event_seq)
        || event.kind != kind
        || event.allowed.is_some()
        || event.monetary_state != expected_monetary_state
        || event.invocation_state != BudgetInvocationReservationState::Absent
        || event.capability_id != capability_id
        || event.grant_index != grant_index
        || event.hold_id.as_deref() != hold_id
        || event.exposure_units != exposure_units
        || event.realized_spend_units != realized_spend_units
        || event.authority.as_ref() != authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget transition event `{event_id}` does not match the requested mutation"
        )));
    }
    Ok(event)
}

fn load_persisted_capture_event(
    store: &SqliteBudgetStore,
    captured: &BudgetHoldMutationDecision,
    event_id: &str,
) -> Result<BudgetMutationRecord, BudgetStoreError> {
    let event_seq = captured.metadata.budget_commit_index.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "captured budget decision omitted its persisted commit index".to_string(),
        )
    })?;
    let after_seq = event_seq.checked_sub(1).ok_or_else(|| {
        BudgetStoreError::Invariant(
            "captured budget event sequence must be greater than zero".to_string(),
        )
    })?;
    let event = store
        .list_mutation_events_after_seq(1, after_seq)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "captured budget event `{event_id}` is not persisted"
            ))
        })?;
    let committed_cost_units_after = event
        .total_cost_exposed_after
        .checked_add(event.total_cost_realized_spend_after)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "persisted captured committed cost overflowed u64".to_string(),
            )
        })?;
    if event.event_id != event_id
        || event.event_seq != event_seq
        || event.usage_seq != Some(event_seq)
        || event.kind != BudgetMutationKind::CaptureExposure
        || event.monetary_state != BudgetMonetaryHoldState::Captured
        || event.hold_id != captured.hold_id
        || event.exposure_units != captured.exposure_units
        || event.realized_spend_units != captured.realized_spend_units
        || event.invocation_count_after != captured.invocation_count_after
        || committed_cost_units_after != captured.committed_cost_units_after
        || event.authority != captured.metadata.authority
    {
        return Err(BudgetStoreError::Invariant(format!(
            "captured budget event `{event_id}` does not match its frozen decision"
        )));
    }
    Ok(event)
}

fn resolve_live_terminal_authority(
    operation: &str,
    hold_authority: Option<&BudgetEventAuthority>,
    live_authority: Option<&BudgetEventAuthority>,
) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
    match hold_authority {
        Some(hold_authority) if live_authority == Some(hold_authority) => {
            Ok(Some(hold_authority.clone()))
        }
        Some(_) => Err(BudgetStoreError::Invariant(format!(
            "budget {operation} hold authority does not match the live authority lease"
        ))),
        None => Ok(live_authority.cloned()),
    }
}

fn resolve_budget_hold_authority(
    operation: &str,
    state: &TrustServiceState,
    store: &SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    let hold_authority = if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ));
            }
        }
    } else {
        None
    };
    let live_authority = current_budget_event_authority(state)?;
    resolve_live_terminal_authority(operation, hold_authority.as_ref(), live_authority.as_ref())
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))
}

#[cfg(test)]
mod budget_handlers_tests {
    use super::{
        budget_authority_metadata_matches_event, compensate_authorize_after_quorum_failure,
        generated_budget_event_id, load_persisted_authorize_event,
        load_persisted_budget_transition, load_persisted_capture_event,
        load_persisted_composite_authorize_event, load_persisted_invocation_capture_event,
        resolve_live_terminal_authority, sqlite_composite_authorize_input,
        verify_requested_budget_authority, BudgetAuthorityMetadataView,
        BudgetAuthorizeHoldDecision, BudgetInvocationAdmissionEvidenceView,
        BudgetInvocationQuotaView, BudgetInvocationReservationState, BudgetMonetaryHoldState,
        BudgetMutationAuthorityView, BudgetMutationKind, BudgetQuotaKeyView,
        BudgetQuotaProfileView, CanonicalRevocationSetView, CaptureInvocationReservationsRequest,
        CompositeBudgetAuthorizeRequest, TryChargeCostRequest,
    };
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::{canonical_json_bytes, sha256_hex};
    use chio_kernel::budget_store::{
        BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest, BudgetEventAuthority,
    };
    use chio_kernel::BudgetStore;
    use chio_store_sqlite::SqliteBudgetStore;
    use chio_test_support::prelude::*;

    fn test_budget_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

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

    #[test]
    fn composite_handler_conversion_preserves_persisted_quota_and_capture_evidence() {
        let path = test_budget_path("chio-handler-composite-wire");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let ids = vec!["cap-composite".to_string(), "cap-root".to_string()];
        let canonical = canonical_json_bytes(&ids).test_unwrap();
        let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
        digest_input.extend_from_slice(&canonical);
        let payload = CompositeBudgetAuthorizeRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            requested_exposure_units: 10,
            max_exposure_per_invocation: Some(20),
            max_total_exposure_units: Some(100),
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:authorize".to_string(),
            admission_evidence: BudgetInvocationAdmissionEvidenceView {
                invocation_quotas: vec![
                    BudgetInvocationQuotaView {
                        key: BudgetQuotaKeyView {
                            profile: BudgetQuotaProfileView::GrantInvocation,
                            owner_id: "cap-composite".to_string(),
                            grant_index: Some(0),
                        },
                        max_invocations: 3,
                    },
                    BudgetInvocationQuotaView {
                        key: BudgetQuotaKeyView {
                            profile: BudgetQuotaProfileView::AggregateFamilyInvocation,
                            owner_id: "22".repeat(32),
                            grant_index: None,
                        },
                        max_invocations: 2,
                    },
                ],
                revocation_set: CanonicalRevocationSetView {
                    ids,
                    digest: sha256_hex(&digest_input),
                },
                aggregate_binding_digest: Some("44".repeat(32)),
                supplemental_binding: None,
            },
        };
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        let input = sqlite_composite_authorize_input(&payload, authority.clone()).test_unwrap();
        assert_eq!(input.authority.as_ref(), Some(&authority));
        assert_eq!(input.invocation_quotas.len(), 2);
        assert_eq!(
            input.revocation_set.digest(),
            payload.admission_evidence.revocation_set.digest
        );
        let decision = store.authorize_composite_hold(input).test_unwrap();
        let event =
            load_persisted_composite_authorize_event(&store, &payload, &decision).test_unwrap();
        assert_eq!(event.kind, BudgetMutationKind::ReserveInvocations);
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = &decision else {
            panic!("expected composite authorization");
        };
        assert_eq!(authorized.invocation_counts_after.len(), 2);
        assert_eq!(
            event.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(event.monetary_state, BudgetMonetaryHoldState::Exposed);

        let capture_payload = CaptureInvocationReservationsRequest {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            hold_id: payload.hold_id.clone(),
            event_id: "hold-composite:capture-invocations".to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
        };
        let captured = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: capture_payload.capability_id.clone(),
                grant_index: capture_payload.grant_index,
                hold_id: Some(capture_payload.hold_id.clone()),
                event_id: Some(capture_payload.event_id.clone()),
                authority: Some(authority),
            })
            .test_unwrap();
        let capture_event =
            load_persisted_invocation_capture_event(&store, &capture_payload, &captured)
                .test_unwrap();
        assert_eq!(capture_event.kind, BudgetMutationKind::CaptureInvocations);
        assert_eq!(
            capture_event.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn requested_transition_authority_must_match_the_server_resolved_authority() {
        let resolved = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert_eq!(
            verify_requested_budget_authority("capture", Some(&resolved), Some(resolved.clone()),)
                .test_unwrap(),
            Some(resolved.clone())
        );

        let mismatched = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-8".to_string(),
            lease_epoch: 8,
        };
        for operation in ["reverse", "release", "reconcile", "capture"] {
            let error = verify_requested_budget_authority(
                operation,
                Some(&mismatched),
                Some(resolved.clone()),
            )
            .test_expect_err("transition authority mismatch must fail closed");
            let message = error.to_string();
            assert!(message.contains(operation));
            assert!(message.contains("does not match the server-resolved authority"));
        }
    }

    #[test]
    fn terminal_live_authority_mismatch_is_rejected_before_store_mutation() {
        let path = test_budget_path("chio-handler-terminal-live-authority");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let hold_authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-terminal-authority",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-terminal-authority"),
                Some("hold-terminal-authority:authorize"),
                Some(&hold_authority),
            )
            .test_unwrap());
        let usage_before = store
            .get_usage("cap-terminal-authority", 0)
            .test_unwrap()
            .test_unwrap();
        let events_before = store
            .list_mutation_events(100, Some("cap-terminal-authority"), Some(0))
            .test_unwrap();

        let next_authority = BudgetEventAuthority {
            authority_id: "budget-secondary".to_string(),
            lease_id: "budget-secondary#term-8".to_string(),
            lease_epoch: 8,
        };
        for live in [None, Some(&next_authority)] {
            let error = resolve_live_terminal_authority("capture", Some(&hold_authority), live)
                .test_expect_err("detached or changed authority must fail closed");
            assert!(error.to_string().contains("live authority lease"));
            assert_eq!(
                store
                    .get_usage("cap-terminal-authority", 0)
                    .test_unwrap()
                    .test_unwrap(),
                usage_before
            );
            assert_eq!(
                store
                    .list_mutation_events(100, Some("cap-terminal-authority"), Some(0))
                    .test_unwrap(),
                events_before
            );
        }

        assert_eq!(
            resolve_live_terminal_authority(
                "capture",
                Some(&hold_authority),
                Some(&hold_authority),
            )
            .test_unwrap(),
            Some(hold_authority)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_authority_metadata_never_splices_a_different_live_lease() {
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        let mut metadata = BudgetAuthorityMetadataView {
            authority_id: authority.authority_id.clone(),
            leader_url: authority.authority_id.clone(),
            budget_term: authority.lease_epoch,
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
            lease_expires_at: 5_000,
            lease_ttl_ms: 750,
            guarantee_level: "ha_quorum_commit".to_string(),
            budget_commit_index: Some(42),
        };
        assert!(budget_authority_metadata_matches_event(
            &metadata, &authority
        ));

        metadata.leader_url = "budget-secondary".to_string();
        assert!(!budget_authority_metadata_matches_event(
            &metadata, &authority
        ));
        metadata.leader_url.clone_from(&authority.authority_id);
        metadata.lease_expires_at = 9_000;
        metadata.lease_epoch = 8;
        assert!(!budget_authority_metadata_matches_event(
            &metadata, &authority
        ));
    }

    #[test]
    fn persisted_authorize_retry_never_runs_fresh_write_compensation() {
        let compensation_calls = std::cell::Cell::new(0_u32);
        let compensated = compensate_authorize_after_quorum_failure(false, None, None, || {
            compensation_calls.set(compensation_calls.get() + 1);
            Ok(())
        })
        .test_unwrap();
        assert!(!compensated);
        assert_eq!(compensation_calls.get(), 0);

        let compensated = compensate_authorize_after_quorum_failure(true, None, None, || {
            compensation_calls.set(compensation_calls.get() + 1);
            Ok(())
        })
        .test_unwrap();
        assert!(compensated);
        assert_eq!(compensation_calls.get(), 1);
    }

    #[test]
    fn stale_term_quorum_failure_cannot_restore_usage_or_append_reverse() {
        let path = test_budget_path("chio-handler-stale-term-compensation");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let old_authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "budget-primary#term-7".to_string(),
            lease_epoch: 7,
        };
        let next_authority = BudgetEventAuthority {
            authority_id: "budget-secondary".to_string(),
            lease_id: "budget-secondary#term-8".to_string(),
            lease_epoch: 8,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-stale-compensation",
                0,
                Some(1),
                100,
                Some(100),
                Some(100),
                Some("hold-stale-compensation"),
                Some("hold-stale-compensation:authorize"),
                Some(&old_authority),
            )
            .test_unwrap());
        let usage_before = store
            .get_usage("cap-stale-compensation", 0)
            .test_unwrap()
            .test_unwrap();
        let events_before = store
            .list_mutation_events(10, Some("cap-stale-compensation"), Some(0))
            .test_unwrap();
        let compensation_calls = std::cell::Cell::new(0_u32);

        let error = compensate_authorize_after_quorum_failure(
            true,
            Some(&old_authority),
            Some(&next_authority),
            || {
                compensation_calls.set(compensation_calls.get() + 1);
                store.reverse_charge_cost_with_ids_and_authority(
                    "cap-stale-compensation",
                    0,
                    100,
                    Some("hold-stale-compensation"),
                    Some("hold-stale-compensation:rollback"),
                    Some(&old_authority),
                )
            },
        )
        .test_expect_err("stale-term compensation must fail closed");
        assert!(error.to_string().contains("live authority lease"));
        assert_eq!(compensation_calls.get(), 0);
        assert_eq!(
            store
                .get_usage("cap-stale-compensation", 0)
                .test_unwrap()
                .test_unwrap(),
            usage_before
        );
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-stale-compensation"), Some(0))
                .test_unwrap(),
            events_before
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_allowed_authorize_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-authorize-allowed-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        let request = TryChargeCostRequest {
            capability_id: "cap-authorize-allowed".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            cost_units: 100,
            max_cost_per_invocation: Some(200),
            max_total_cost_units: Some(1_000),
            hold_id: Some("hold-authorize-allowed-0".to_string()),
            event_id: Some("hold-authorize-allowed-0:authorize".to_string()),
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-authorize-allowed",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-authorize-allowed-1"),
                Some("hold-authorize-allowed-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot = load_persisted_authorize_event(
            &store,
            "hold-authorize-allowed-0:authorize",
            &request,
            true,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 100);
        assert_eq!(snapshot.total_cost_realized_spend_after, 0);
        let current = store
            .get_usage("cap-authorize-allowed", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 110);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_denied_authorize_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-authorize-denied-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-authorize-denied",
                0,
                Some(10),
                80,
                Some(100),
                Some(100),
                Some("hold-authorize-denied-base"),
                Some("hold-authorize-denied-base:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        let request = TryChargeCostRequest {
            capability_id: "cap-authorize-denied".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            cost_units: 30,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(100),
            hold_id: Some("hold-authorize-denied-attempt".to_string()),
            event_id: Some("hold-authorize-denied-attempt:authorize".to_string()),
        };
        assert!(!store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-authorize-denied",
                0,
                20,
                Some("hold-authorize-denied-base"),
                Some("hold-authorize-denied-base:release"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(!store
            .try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.cost_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot = load_persisted_authorize_event(
            &store,
            "hold-authorize-denied-attempt:authorize",
            &request,
            false,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 80);
        assert_eq!(snapshot.total_cost_realized_spend_after, 0);
        let current = store
            .get_usage("cap-authorize-denied", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 1);
        assert_eq!(current.total_cost_exposed, 60);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_capture_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-capture-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-capture",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-capture-0"),
                Some("hold-capture-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        let captured = store
            .capture_budget_hold(BudgetCaptureHoldRequest {
                capability_id: "cap-capture".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 70,
                hold_id: Some("hold-capture-0".to_string()),
                event_id: Some("hold-capture-0:capture".to_string()),
                authority: Some(authority.clone()),
            })
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-capture",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-capture-1"),
                Some("hold-capture-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());

        let snapshot =
            load_persisted_capture_event(&store, &captured, "hold-capture-0:capture").test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        assert_eq!(snapshot.total_cost_realized_spend_after, 70);
        assert_eq!(
            snapshot.authority.as_ref(),
            captured.metadata.authority.as_ref()
        );
        let current = store
            .get_usage("cap-capture", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 10);
        assert_eq!(current.total_cost_realized_spend, 70);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_reverse_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-reverse-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-reverse-0"),
                Some("hold-reverse-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                100,
                Some("hold-reverse-0"),
                Some("hold-reverse-0:reverse"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-reverse-1"),
                Some("hold-reverse-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-reverse",
                0,
                100,
                Some("hold-reverse-0"),
                Some("hold-reverse-0:reverse"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-reverse-0:reverse",
            BudgetMutationKind::ReverseExposure,
            "cap-reverse",
            0,
            Some("hold-reverse-0"),
            100,
            0,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 0);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        let current = store
            .get_usage("cap-reverse", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 1);
        assert_eq!(current.total_cost_exposed, 10);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_release_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-release-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-release-0"),
                Some("hold-release-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                25,
                Some("hold-release-0"),
                Some("hold-release-0:release"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-release-1"),
                Some("hold-release-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-release",
                0,
                25,
                Some("hold-release-0"),
                Some("hold-release-0:release"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-release-0:release",
            BudgetMutationKind::ReleaseExposure,
            "cap-release",
            0,
            Some("hold-release-0"),
            25,
            0,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 75);
        let current = store
            .get_usage("cap-release", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 85);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_reconcile_snapshot_stays_frozen_after_later_same_grant_write() {
        let path = test_budget_path("chio-handler-reconcile-snapshot");
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                Some(10),
                100,
                Some(200),
                Some(1_000),
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .settle_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                100,
                70,
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:reconcile"),
                Some(&authority),
            )
            .test_unwrap();
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                Some(10),
                10,
                Some(200),
                Some(1_000),
                Some("hold-reconcile-1"),
                Some("hold-reconcile-1:authorize"),
                Some(&authority),
            )
            .test_unwrap());
        store
            .settle_charge_cost_with_ids_and_authority(
                "cap-reconcile",
                0,
                100,
                70,
                Some("hold-reconcile-0"),
                Some("hold-reconcile-0:reconcile"),
                Some(&authority),
            )
            .test_unwrap();

        let snapshot = load_persisted_budget_transition(
            &store,
            "hold-reconcile-0:reconcile",
            BudgetMutationKind::ReconcileSpend,
            "cap-reconcile",
            0,
            Some("hold-reconcile-0"),
            100,
            70,
            Some(&authority),
        )
        .test_unwrap();
        assert_eq!(snapshot.invocation_count_after, 1);
        assert_eq!(snapshot.total_cost_exposed_after, 0);
        assert_eq!(snapshot.total_cost_realized_spend_after, 70);
        let current = store
            .get_usage("cap-reconcile", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(current.invocation_count, 2);
        assert_eq!(current.total_cost_exposed, 10);
        assert_eq!(current.total_cost_realized_spend, 70);

        let _ = fs::remove_file(path);
    }
}
