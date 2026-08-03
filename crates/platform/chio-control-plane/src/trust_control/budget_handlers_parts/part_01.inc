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
use serde::de::DeserializeOwned;

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
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let admission_managed = match store.is_admission_authority_managed() {
        Ok(managed) => managed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    if admission_managed {
        let result = match super::cluster::propose_admission_command(
            &state,
            generated_budget_event_id(),
            AdmissionCommandKind::IncrementInvocation,
            &payload,
        )
        .await
        {
            Ok(result) => result,
            Err(response) => return response,
        };
        return match serde_json::from_str::<TryIncrementBudgetResponse>(&result.response_json) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("persisted invocation increment result is invalid: {error}"),
            ),
        };
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
                    budget_commit: None,
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
/// authority) carries a local sentinel token and the quorum wait short-circuits
/// when unclustered.
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
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let admission_managed = match store.is_admission_authority_managed() {
        Ok(managed) => managed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    if admission_managed {
        return plain_http_error(
            StatusCode::CONFLICT,
            "admission-managed budget stores require the composite authorization endpoint",
        );
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
            decision: BudgetAuthorizeExposureDecision::Authorized,
            hold_id: authorize_event.hold_id.clone(),
            event_id: Some(authorize_event.event_id.clone()),
            exposure_units: Some(authorize_event.exposure_units),
            realized_spend_units: Some(authorize_event.realized_spend_units),
            mutation_invocation_count_after: Some(authorize_event.invocation_count_after),
            mutation_committed_cost_units_after: authorize_event
                .total_cost_exposed_after
                .checked_add(authorize_event.total_cost_realized_spend_after),
            usage_seq: authorize_event.usage_seq,
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
                    decision: BudgetAuthorizeExposureDecision::Denied,
                    hold_id: authorize_event.hold_id.clone(),
                    event_id: Some(authorize_event.event_id.clone()),
                    exposure_units: Some(authorize_event.exposure_units),
                    realized_spend_units: Some(authorize_event.realized_spend_units),
                    mutation_invocation_count_after: Some(authorize_event.invocation_count_after),
                    mutation_committed_cost_units_after: authorize_event
                        .total_cost_exposed_after
                        .checked_add(authorize_event.total_cost_realized_spend_after),
                    usage_seq: authorize_event.usage_seq,
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
    if payload.existing_only {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "existingOnly is reserved for the committed authorization query endpoint",
        );
    }
    if let Err(error) = sqlite_fresh_composite_authorize_input(
        &payload,
        BudgetEventAuthority {
            authority_id: "pure-validation".to_string(),
            lease_id: "pure-validation".to_string(),
            lease_epoch: 1,
        },
        state.config.partition_escrow_authority.as_deref(),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let result = match super::cluster::propose_admission_command(
        &state,
        payload.event_id.clone(),
        AdmissionCommandKind::CompositeAuthorize,
        &payload,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match serde_json::from_str::<CompositeBudgetAuthorizeResponse>(&result.response_json) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("persisted composite authorize result is invalid: {error}"),
        ),
    }
}

pub(crate) async fn handle_query_committed_composite_budget_authorization(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CompositeBudgetAuthorizeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if !payload.existing_only {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "committed authorization queries require existingOnly",
        );
    }
    if let Err(error) = sqlite_composite_authorize_input(
        &payload,
        BudgetEventAuthority {
            authority_id: "pure-validation".to_string(),
            lease_id: "pure-validation".to_string(),
            lease_epoch: 1,
        },
        state.config.partition_escrow_authority.as_deref(),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if state.cluster.is_none() || state.config.budget_db_path.is_none() {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "committed authorization queries require configured HA consensus storage",
        );
    }
    match super::cluster::query_committed_composite_authorization(&state, payload).await {
        Ok(response_json) => {
            let mut response = response_json.into_response();
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(response) => response,
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
    if let Err(error) = budget_admission_operation_binding(
        Some(payload.operation_id.as_str()),
        Some(payload.request_binding_hash.as_str()),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let Some(authority) = payload.budget_authority.as_ref() else {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "invocation capture requires the exact persisted budget authority",
        );
    };
    if authority.authority_id.is_empty()
        || authority.lease_id.is_empty()
        || authority.lease_epoch == 0
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "invocation capture authority is incomplete",
        );
    }
    let result = match super::cluster::propose_admission_command(
        &state,
        payload.event_id.clone(),
        AdmissionCommandKind::CaptureInvocations,
        &payload,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match serde_json::from_str::<CaptureInvocationReservationsResponse>(&result.response_json) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("persisted invocation capture result is invalid: {error}"),
        ),
    }
}

pub(crate) async fn handle_combined_admission_capture(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CombinedAdmissionCaptureRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = budget_admission_operation_binding(
        Some(payload.operation_id.as_str()),
        Some(payload.request_binding_hash.as_str()),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if state.cluster.is_none()
        || state.config.budget_db_path.is_none()
        || state.config.revocation_db_path.is_none()
    {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "combined admission capture requires configured HA consensus storage",
        );
    }
    let operation_id = payload.operation_id.clone();
    let result = match super::cluster::propose_admission_command(
        &state,
        operation_id,
        AdmissionCommandKind::CombinedCapture,
        &payload,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    match serde_json::from_str::<CombinedAdmissionCaptureResponse>(&result.response_json) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_admission_capture_point_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<AdmissionCapturePointQueryRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = budget_admission_operation_binding(
        Some(payload.capture_request.operation_id.as_str()),
        Some(payload.capture_request.request_binding_hash.as_str()),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if state.cluster.is_none()
        || state.config.budget_db_path.is_none()
        || state.config.revocation_db_path.is_none()
    {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission capture point queries require configured HA consensus storage",
        );
    }
    match super::cluster::query_admission_capture_consensus(&state, payload).await {
        Ok(response) => Json(response).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_invocation_capture_point_query(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CaptureInvocationPointQueryRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = budget_admission_operation_binding(
        Some(payload.capture_request.operation_id.as_str()),
        Some(payload.capture_request.request_binding_hash.as_str()),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if state.cluster.is_none() || state.config.budget_db_path.is_none() {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invocation capture point queries require configured HA consensus storage",
        );
    }
    match super::cluster::query_invocation_capture_consensus(&state, payload).await {
        Ok(response) => Json(response).into_response(),
        Err(response) => response,
    }
}

pub(crate) enum PreparedSqliteCompositeAuthorization {
    NonFamily(SqliteCompositeAuthorizeInput),
    AggregateFamily {
        authorization: SqliteCompositeAuthorizeInput,
        evidence: SqliteAggregateFamilyEvidence,
    },
}

impl PreparedSqliteCompositeAuthorization {
    #[cfg(test)]
    pub(crate) fn input(&self) -> &SqliteCompositeAuthorizeInput {
        match self {
            Self::NonFamily(authorization) | Self::AggregateFamily { authorization, .. } => {
                authorization
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn authorize(
        self,
        store: &SqliteBudgetStore,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        match self {
            Self::NonFamily(authorization) => store.authorize_composite_hold(authorization),
            Self::AggregateFamily {
                authorization,
                evidence,
            } => store.authorize_aggregate_family_composite_hold(authorization, evidence),
        }
    }

    pub(crate) fn authorize_in_transaction(
        self,
        transaction: &rusqlite::Transaction<'_>,
        existing_only: bool,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        match (self, existing_only) {
            (Self::NonFamily(authorization), false) => {
                SqliteBudgetStore::authorize_composite_hold_in_transaction(
                    transaction,
                    authorization,
                )
            }
            (
                Self::AggregateFamily {
                    authorization,
                    evidence,
                },
                false,
            ) => SqliteBudgetStore::authorize_aggregate_family_composite_hold_in_transaction(
                transaction,
                authorization,
                evidence,
            ),
            (Self::NonFamily(authorization), true) => {
                SqliteBudgetStore::replay_composite_hold_in_transaction(transaction, authorization)
            }
            (
                Self::AggregateFamily {
                    authorization,
                    evidence,
                },
                true,
            ) => SqliteBudgetStore::replay_aggregate_family_composite_hold_in_transaction(
                transaction,
                authorization,
                evidence,
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum PartitionEscrowAuthorizationValidation {
    FreshProposal,
    PersistedCommit,
}

/// Deterministic committed-command parser. This validates the sealed authority
/// and exact persisted proof, but never reads the wall clock or a live source.
pub(crate) fn sqlite_composite_authorize_input(
    payload: &CompositeBudgetAuthorizeRequest,
    authority: BudgetEventAuthority,
    partition_escrow_authority: Option<
        &super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
    >,
) -> Result<PreparedSqliteCompositeAuthorization, BudgetStoreError> {
    sqlite_composite_authorize_input_with_validation(
        payload,
        authority,
        partition_escrow_authority,
        PartitionEscrowAuthorizationValidation::PersistedCommit,
    )
}

/// Fresh proposal parser. This is the only parser allowed to require that the
/// sealed proof and its underlying source are valid at the current wall clock.
pub(crate) fn sqlite_fresh_composite_authorize_input(
    payload: &CompositeBudgetAuthorizeRequest,
    authority: BudgetEventAuthority,
    partition_escrow_authority: Option<
        &super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
    >,
) -> Result<PreparedSqliteCompositeAuthorization, BudgetStoreError> {
    sqlite_composite_authorize_input_with_validation(
        payload,
        authority,
        partition_escrow_authority,
        PartitionEscrowAuthorizationValidation::FreshProposal,
    )
}

fn sqlite_composite_authorize_input_with_validation(
    payload: &CompositeBudgetAuthorizeRequest,
    authority: BudgetEventAuthority,
    partition_escrow_authority: Option<
        &super::service_runtime::budget::SealedPartitionEscrowRemoteAuthority,
    >,
    partition_escrow_validation: PartitionEscrowAuthorizationValidation,
) -> Result<PreparedSqliteCompositeAuthorization, BudgetStoreError> {
    BudgetAdmissionOperationBinding::new(
        payload.operation_id.clone(),
        payload.request_binding_hash.clone(),
    )?;
    let invocation_quotas = payload
        .admission_evidence
        .invocation_quotas
        .iter()
        .map(invocation_quota_from_view)
        .collect::<Result<Vec<_>, _>>()?;
    let has_family_quota = invocation_quotas
        .iter()
        .any(|quota| quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation);
    let aggregate_family_evidence = match (
        has_family_quota,
        payload
            .admission_evidence
            .aggregate_root_capability_id
            .as_deref(),
        payload
            .admission_evidence
            .aggregate_binding_digest
            .as_deref(),
    ) {
        (true, Some(root_capability_id), Some(root_binding_digest)) => {
            if root_capability_id.is_empty()
                || root_capability_id.len() > 512
                || root_capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(BudgetStoreError::Invariant(
                    "aggregate root capability ID is empty, oversized, or contains NUL".to_string(),
                ));
            }
            validate_admission_digest(root_binding_digest, "aggregate root binding digest")?;
            Some(SqliteAggregateFamilyEvidence {
                root_capability_id: root_capability_id.to_string(),
                root_binding_digest: root_binding_digest.to_string(),
            })
        }
        (true, _, _) => {
            return Err(BudgetStoreError::Invariant(
                "aggregate-family quota requires root capability ID and binding digest evidence"
                    .to_string(),
            ));
        }
        (false, None, None) => None,
        (false, _, _) => {
            return Err(BudgetStoreError::Invariant(
                "aggregate root evidence requires an aggregate-family quota".to_string(),
            ));
        }
    };
    let supplemental_artifact_digest = payload
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
            if binding.not_before >= binding.expires_at
                || binding.verified_at < binding.not_before
                || binding.verified_at >= binding.expires_at
                || binding.broker_capability_id.is_empty()
                || binding.broker_capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(BudgetStoreError::Invariant(
                    "supplemental admission provenance is invalid".to_string(),
                ));
            }
            validate_admission_digest(
                &binding.request_constraint_digest,
                "supplemental request constraint digest",
            )?;
            validate_admission_digest(
                &binding.claim_binding_digest,
                "supplemental claim binding digest",
            )?;
            Ok(binding.artifact_digest.clone())
        })
        .transpose()?;
    let partition_escrow_evidence = payload
        .admission_evidence
        .partition_escrow_evidence
        .as_ref()
        .map(|binding| {
            validate_admission_digest(&binding.digest, "partition escrow evidence digest")?;
            let evidence = chio_kernel::partition_escrow::PartitionEscrowAdmissionEvidence::from_canonical_json_bytes(
                binding.canonical_json.as_bytes(),
            )
            .map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "partition escrow admission evidence is invalid: {error}"
                ))
            })?;
            let digest = evidence.digest().map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "partition escrow admission evidence digest failed: {error}"
                ))
            })?;
            if digest != binding.digest
                || evidence.quotas().len() != invocation_quotas.len()
                || evidence
                    .quotas()
                    .iter()
                    .zip(&invocation_quotas)
                    .any(|(escrow, local)| {
                        escrow.global_quota().profile() != local.key().profile().as_str()
                            || escrow.global_quota().owner_id() != local.key().owner_id()
                            || escrow.global_quota().grant_index() != local.key().grant_index()
                            || escrow.local_allocated_invocations() != local.max_invocations()
                    })
            {
                return Err(BudgetStoreError::Invariant(
                    "partition escrow evidence changed its digest or local quota projection"
                        .to_string(),
                ));
            }
            chio_kernel::budget_store::PartitionEscrowCommitEvidence::from_canonical_json(
                binding.canonical_json.clone(),
                binding.digest.clone(),
            )
        })
        .transpose()?;
    match (
        partition_escrow_authority,
        partition_escrow_evidence.as_ref(),
    ) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(BudgetStoreError::Conflict(
                "ordinary HA authority rejects partition escrow evidence".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(BudgetStoreError::Invariant(
                "sealed partition escrow authority requires exact signed allocation evidence"
                    .to_string(),
            ));
        }
        (Some(authority), Some(evidence)) => {
            match partition_escrow_validation {
                PartitionEscrowAuthorizationValidation::FreshProposal => {
                    authority.validate_fresh_authorization_evidence_now(evidence)?;
                }
                PartitionEscrowAuthorizationValidation::PersistedCommit => {
                    authority.validate_persisted_commit_evidence(evidence)?;
                }
            }
        }
    }
    let mut authorization_artifact_digests = supplemental_artifact_digest
        .into_iter()
        .chain(
            partition_escrow_evidence
                .iter()
                .map(|evidence| evidence.evidence_digest().to_string()),
        )
        .collect::<Vec<_>>();
    authorization_artifact_digests.sort();
    authorization_artifact_digests.dedup();
    let authorization = SqliteCompositeAuthorizeInput {
        operation_id: payload.operation_id.clone(),
        request_binding_hash: payload.request_binding_hash.clone(),
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        requested_exposure_units: payload.requested_exposure_units,
        max_cost_per_invocation: payload.max_exposure_per_invocation,
        max_total_cost_units: payload.max_total_exposure_units,
        hold_id: payload.hold_id.clone(),
        event_id: payload.event_id.clone(),
        authority: Some(authority),
        invocation_quotas,
        revocation_set: canonical_revocation_set_from_view(
            &payload.admission_evidence.revocation_set,
        )?,
        authorization_artifact_digests,
        partition_escrow_evidence,
    };
    Ok(match aggregate_family_evidence {
        Some(evidence) => PreparedSqliteCompositeAuthorization::AggregateFamily {
            authorization,
            evidence,
        },
        None => PreparedSqliteCompositeAuthorization::NonFamily(authorization),
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

pub(crate) fn budget_admission_operation_binding(
    operation_id: Option<&str>,
    request_binding_hash: Option<&str>,
) -> Result<Option<BudgetAdmissionOperationBinding>, BudgetStoreError> {
    match (operation_id, request_binding_hash) {
        (None, None) => Ok(None),
        (Some(operation_id), Some(request_binding_hash)) => BudgetAdmissionOperationBinding::new(
            operation_id.to_string(),
            request_binding_hash.to_string(),
        )
        .map(Some),
        _ => Err(BudgetStoreError::Invariant(
            "budget admission ownership requires both operation_id and request_binding_hash"
                .to_string(),
        )),
    }
}

pub(crate) fn invocation_capture_request_from_view(
    request: &CaptureInvocationReservationsRequest,
) -> Result<BudgetCaptureInvocationRequest, BudgetStoreError> {
    let authority = request.budget_authority.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "invocation capture query requires persisted budget authority".to_string(),
        )
    })?;
    if authority.authority_id.is_empty()
        || authority.lease_id.is_empty()
        || authority.lease_epoch == 0
    {
        return Err(BudgetStoreError::Invariant(
            "invocation capture query authority is incomplete".to_string(),
        ));
    }
    Ok(BudgetCaptureInvocationRequest {
        capability_id: request.capability_id.clone(),
        grant_index: request.grant_index,
        hold_id: Some(request.hold_id.clone()),
        event_id: Some(request.event_id.clone()),
        authority: Some(BudgetEventAuthority {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        }),
        admission_operation: budget_admission_operation_binding(
            Some(request.operation_id.as_str()),
            Some(request.request_binding_hash.as_str()),
        )?,
    })
}

pub(crate) fn composite_authorize_response_view(
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
        operation_id: payload.operation_id.clone(),
        request_binding_hash: payload.request_binding_hash.clone(),
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

pub(crate) fn invocation_capture_response_view(
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
        operation_id: payload.operation_id.clone(),
        request_binding_hash: payload.request_binding_hash.clone(),
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
    if let Err(error) = budget_admission_operation_binding(
        payload.operation_id.as_deref(),
        payload.request_binding_hash.as_deref(),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    match admission_consensus_terminal_event(
        &state,
        "reverse",
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        payload.budget_authority.as_ref(),
    ) {
        Ok(Some(event_id)) => {
            return propose_admission_terminal_command::<_, ReverseChargeCostResponse>(
                &state,
                event_id,
                AdmissionCommandKind::ReverseExposure,
                &payload,
                "reverse exposure",
            )
            .await;
        }
        Ok(None) => {}
        Err(response) => return response,
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
            hold_id: reverse_event.hold_id.clone(),
            event_id: Some(reverse_event.event_id.clone()),
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
    if let Err(error) = budget_admission_operation_binding(
        payload.operation_id.as_deref(),
        payload.request_binding_hash.as_deref(),
    ) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let released_exposure_units = payload.release_units();
    let (operation, admission_kind) = match classify_reduce_command(&payload) {
        Ok(classification) => classification,
        Err(response) => return response,
    };
    match admission_consensus_terminal_event(
        &state,
        operation,
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        payload.budget_authority.as_ref(),
    ) {
        Ok(Some(event_id)) => {
            return propose_admission_terminal_command::<_, ReduceChargeCostResponse>(
                &state,
                event_id,
                admission_kind,
                &payload,
                operation,
            )
            .await;
        }
        Ok(None) => {}
        Err(response) => return response,
    }
    match forward_post_to_leader(&state, BUDGET_RECONCILE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
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
            hold_id: transition_event.hold_id.clone(),
            event_id: Some(transition_event.event_id.clone()),
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
    let admission_operation = match budget_admission_operation_binding(
        payload.operation_id.as_deref(),
        payload.request_binding_hash.as_deref(),
    ) {
        Ok(binding) => binding,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
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
    match admission_consensus_terminal_event(
        &state,
        "capture",
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        payload.budget_authority.as_ref(),
    ) {
        Ok(Some(event_id)) => {
            return propose_admission_terminal_command::<_, ReduceChargeCostResponse>(
                &state,
                event_id,
                AdmissionCommandKind::CaptureExposure,
                &payload,
                "capture exposure",
            )
            .await;
        }
        Ok(None) => {}
        Err(response) => return response,
    }
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
        admission_operation,
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
            hold_id: capture_event.hold_id.clone(),
            event_id: Some(capture_event.event_id.clone()),
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
