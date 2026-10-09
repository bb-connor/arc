use super::cluster::{
    cluster_authority_lease_view, cluster_consensus_view, cluster_self_url, current_leader_url,
    update_peer_failure, update_peer_reachable,
};
use super::*;

pub(crate) fn json_response_with_leader_visibility<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
) -> Response {
    json_response_with_leader_visibility_and_budget_commit(state, payload, None)
}

pub(crate) fn json_response_with_leader_visibility_and_budget_commit<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
    budget_commit: Option<BudgetWriteCommitView>,
) -> Response {
    let mut value = match serde_json::to_value(payload) {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to serialize trust control response: {error}"),
            );
        }
    };
    let Value::Object(map) = &mut value else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust control success responses must be JSON objects",
        );
    };
    if let Some(self_url) = cluster_self_url(state) {
        let leader_url = current_leader_url(state).unwrap_or_else(|| self_url.clone());
        map.insert("handledBy".to_string(), Value::String(self_url));
        map.insert("leaderUrl".to_string(), Value::String(leader_url));
        map.insert("visibleAtLeader".to_string(), Value::Bool(true));
        if let Some(authority_lease) = cluster_authority_lease_view(state) {
            let authority_lease = match serde_json::to_value(authority_lease) {
                Ok(value) => value,
                Err(error) => {
                    return plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to serialize cluster authority lease metadata: {error}"),
                    );
                }
            };
            map.insert("clusterAuthority".to_string(), authority_lease);
        }
    }
    if let Some(budget_commit) = budget_commit {
        let budget_commit = match serde_json::to_value(budget_commit) {
            Ok(value) => value,
            Err(error) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to serialize budget quorum commit metadata: {error}"),
                );
            }
        };
        map.insert("budgetCommit".to_string(), budget_commit);
    }
    Json(value).into_response()
}

#[cfg(test)]
pub(crate) fn authority_snapshot_view(
    snapshot: chio_kernel::AuthoritySnapshot,
) -> AuthoritySnapshotView {
    AuthoritySnapshotView {
        snapshot,
        proof: None,
    }
}

pub(crate) fn revocation_cursor_view(cursor: RevocationCursor) -> RevocationCursorView {
    RevocationCursorView {
        cursor_version: cursor.cursor_version,
        stream_id: cursor.stream_id,
        seq: cursor.seq,
        revoked_at: cursor.revoked_at,
        capability_id: cursor.capability_id,
    }
}

pub(crate) fn budget_cursor_view(cursor: BudgetCursor) -> BudgetCursorView {
    BudgetCursorView {
        seq: cursor.seq,
        updated_at: cursor.updated_at,
        capability_id: cursor.capability_id,
        grant_index: cursor.grant_index,
    }
}

pub(crate) fn revocation_cursor_from_view(view: RevocationCursorView) -> RevocationCursor {
    RevocationCursor {
        cursor_version: view.cursor_version,
        stream_id: view.stream_id,
        seq: view.seq,
        revoked_at: view.revoked_at,
        capability_id: view.capability_id,
    }
}

pub(crate) fn stored_tool_receipt_views(
    records: Vec<StoredToolReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

pub(crate) fn stored_child_receipt_views(
    records: Vec<StoredChildReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

pub(crate) fn stored_lineage_views(
    records: Vec<StoredCapabilitySnapshot>,
) -> Vec<StoredLineageView> {
    records
        .into_iter()
        .map(|record| StoredLineageView {
            seq: record.seq,
            snapshot: record.snapshot,
        })
        .collect()
}

fn decision_kind(decision: Option<&Decision>) -> &'static str {
    match decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

/// Mirror of the store-side `receipt_decision_kind` logic so that
/// CLI-driven filter queries against `chio_tool_receipts.decision_kind`
/// see the same value that was persisted at write time.
///
/// Trace and advisory receipts carry no `Decision` and store their
/// semantics-derived kind (e.g. `trace_observation`) in the column,
/// so a plain `decision_kind(receipt.decision)` would produce `"none"`
/// and miss those rows.
pub(crate) fn receipt_decision_kind(receipt: &ChioReceipt) -> &'static str {
    let semantics = receipt.semantic_fields();
    if !semantics.is_authorized(receipt.decision.as_ref())
        && matches!(&receipt.decision, Some(Decision::Allow))
    {
        return semantics.receipt_kind.as_str();
    }
    match receipt.decision.as_ref() {
        Some(decision) => decision_kind(Some(decision)),
        None => semantics.receipt_kind.as_str(),
    }
}

pub(crate) fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

fn forwarded_control_response(response: ureq::Response) -> Result<Response, CliError> {
    let status = StatusCode::from_u16(response.status()).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to map forwarded trust-control response status: {error}"
        ))
    })?;
    let content_type = response.header(CONTENT_TYPE.as_str()).map(str::to_owned);
    let body = response.into_string().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to decode forwarded trust-control response body: {error}"
        ))
    })?;

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder.body(axum::body::Body::from(body)).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to build forwarded trust-control response: {error}"
        ))
    })
}

/// Leader forwards admitted at once on one node: an explicit resource bound,
/// one eighth of Tokio's default 512-thread blocking pool.
pub(crate) const LEADER_FORWARD_PERMITS: usize = 64;

/// Why a leader forward attempt produced no transport outcome.
enum LeaderForwardRefusal {
    /// Every forward permit was held, so the attempt never started.
    AtCapacity,
    /// The blocking forward panicked or its runtime shut down.
    Aborted(tokio::task::JoinError),
}

impl LeaderForwardRefusal {
    fn into_response(self, writes: &str, error: fn(StatusCode, &str) -> Response) -> Response {
        match self {
            Self::AtCapacity => error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("cluster leader forwarding is at capacity for {writes}"),
            ),
            Self::Aborted(join_error) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cluster leader forwarding for {writes} did not complete: {join_error}"),
            ),
        }
    }
}

/// Runs one blocking leader forward on Tokio's blocking pool.
///
/// Admission never waits: without a free permit the attempt is refused before
/// any network I/O. The permit moves into the blocking closure and is released
/// only when that closure returns, after the leader's response is read in
/// full and the forwarded response is built, so a request future dropped
/// mid-forward keeps its permit until that work has actually ended.
async fn run_leader_forward<T>(
    state: &TrustServiceState,
    forward: impl FnOnce() -> T + Send + 'static,
) -> Result<T, LeaderForwardRefusal>
where
    T: Send + 'static,
{
    let permit = Arc::clone(&state.leader_forward_lane)
        .try_acquire_owned()
        .map_err(|_| LeaderForwardRefusal::AtCapacity)?;
    tokio::task::spawn_blocking(move || {
        let outcome = forward();
        drop(permit);
        outcome
    })
    .await
    .map_err(LeaderForwardRefusal::Aborted)
}

fn forwarded_request_json<B: Serialize>(body: &B, request: &str) -> Result<Value, CliError> {
    serde_json::to_value(body).map_err(|error| {
        CliError::cli_other_error(format!("failed to serialize {request}: {error}"))
    })
}

fn post_json_to_control_service(
    client: &TrustControlClient,
    path: &str,
    json: Value,
) -> Result<Response, CliError> {
    let endpoint = client.endpoints.first().ok_or_else(|| {
        CliError::cli_other_error("trust control client requires at least one endpoint".to_string())
    })?;
    let url = format!("{endpoint}{path}");
    match client
        .http
        .post(&url)
        .set(AUTHORIZATION.as_str(), &format!("Bearer {}", client.token))
        .send_json(json)
    {
        Ok(response) => forwarded_control_response(response),
        Err(ureq::Error::Status(_, response)) => forwarded_control_response(response),
        Err(ureq::Error::Transport(error)) => Err(CliError::cli_other_error(format!(
            "trust control service transport failed: {error}"
        ))),
    }
}

pub(crate) async fn forward_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for trust-control writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before trust-control write forwarding",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
        let attempt = match forwarded_request_json(body, "forwarded trust control request") {
            Ok(json) => {
                let request_path = path.to_owned();
                run_leader_forward(state, move || {
                    post_json_to_control_service(&client, &request_path, json)
                })
                .await
                .map_err(|refusal| {
                    refusal.into_response("trust-control writes", plain_http_error)
                })?
            }
            Err(error) => Err(error),
        };
        match attempt {
            Ok(response) => return Ok(Some(response)),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_authority_lease) = cluster_authority_lease_view(state) else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease is unavailable for trust-control writes",
                    ));
                };
                if !next_authority_lease.lease_valid {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease expired before trust-control write forwarding",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward control-plane write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward control-plane write to cluster leader",
    ))
}

pub(crate) async fn forward_authority_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for authority writes",
        ));
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for authority writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority write forwarding",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for authority writes",
        ));
    };
    let mut authority_term = authority_lease.term;
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = service_runtime::client::build_cluster_peer_client(
            &leader_url,
            &state.config.service_token,
            &self_url,
        )
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
        let (attempt, attempt_term) = match forwarded_request_json(body, "trust control request") {
            Ok(json) => {
                let peer_state = state.clone();
                let target = leader_url.clone();
                let request_path = path.to_owned();
                run_leader_forward(state, move || {
                    let term = leader_confirmed_authority_term(
                        &peer_state,
                        &client,
                        &target,
                        authority_term,
                    );
                    let forwarded = client
                        .post_internal_json::<_, Value>(&request_path, &json, Some(term))
                        .map(|value| {
                            #[cfg(test)]
                            forward_finalization_pause::pause_if_armed(&value);
                            Json(value).into_response()
                        });
                    (forwarded, term)
                })
                .await
                .map_err(|refusal| refusal.into_response("authority writes", plain_http_error))?
            }
            Err(error) => (Err(error), authority_term),
        };
        authority_term = attempt_term;
        match attempt {
            Ok(response) => return Ok(Some(response)),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for authority writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for authority writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                let Some(next_authority_lease) = cluster_authority_lease_view(state) else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease is unavailable for authority writes",
                    ));
                };
                if !next_authority_lease.lease_valid {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease expired before authority write forwarding",
                    ));
                }
                if next_leader == leader_url && next_authority_lease.term == authority_term {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward authority write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
                authority_term = next_authority_lease.term;
            }
        }
    }

    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward authority write to cluster leader",
    ))
}

/// The leader's own authority term when its status confirms a valid lease it
/// holds, otherwise `term`. A reachable status marks the leader reachable.
fn leader_confirmed_authority_term(
    state: &TrustServiceState,
    client: &TrustControlClient,
    leader_url: &str,
    term: u64,
) -> u64 {
    let Ok(status) = client.cluster_status() else {
        return term;
    };
    update_peer_reachable(state, leader_url);
    if status.has_quorum && status.leader_url.as_deref() == Some(leader_url) {
        if let Some(lease) = status.authority_lease.as_ref() {
            if lease.lease_valid && lease.leader_url == leader_url {
                return lease.term;
            }
        }
    }
    term
}

pub(crate) async fn forward_scim_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
                    scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
        let attempt = match forwarded_request_json(body, "trust control request") {
            Ok(json) => {
                let request_path = path.to_owned();
                run_leader_forward(state, move || {
                    client
                        .post_json::<_, Value>(&request_path, &json)
                        .map(|value| {
                            #[cfg(test)]
                            forward_finalization_pause::pause_if_armed(&value);
                            scim_json_response(StatusCode::CREATED, &value)
                        })
                })
                .await
                .map_err(|refusal| {
                    refusal.into_response("trust-control writes", scim_error_response)
                })?
            }
            Err(error) => Err(error),
        };
        match attempt {
            Ok(response) => return Ok(Some(response)),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward scim write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(scim_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward scim write to cluster leader",
    ))
}

pub(crate) async fn forward_scim_delete_to_leader(
    state: &TrustServiceState,
    path: &str,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
                    scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
        let request_path = path.to_owned();
        let attempt = run_leader_forward(state, move || {
            client.delete_json::<Value>(&request_path).map(|value| {
                #[cfg(test)]
                forward_finalization_pause::pause_if_armed(&value);
                scim_json_response(StatusCode::OK, &value)
            })
        })
        .await
        .map_err(|refusal| refusal.into_response("trust-control writes", scim_error_response))?;
        match attempt {
            Ok(response) => return Ok(Some(response)),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward scim delete to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(scim_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward scim delete to cluster leader",
    ))
}

/// Test-only pause inside the builders of forwarded leader responses. A pause
/// armed for a token blocks the build of any leader reply whose `FIELD` holds
/// that token, so a test can observe where response finalization runs.
#[cfg(test)]
pub(crate) mod forward_finalization_pause {
    use serde_json::Value;
    use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};
    use std::time::Duration;

    pub(crate) const FIELD: &str = "finalizationPause";
    /// Bounds one pause, so a build that blocks the only async worker ends
    /// instead of hanging the test binary.
    const PAUSE_GUARD: Duration = Duration::from_secs(10);

    struct Gate {
        token: String,
        released: Mutex<bool>,
        wake: Condvar,
        reached: tokio::sync::mpsc::UnboundedSender<()>,
    }

    static ARMED: LazyLock<Mutex<Vec<Arc<Gate>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

    /// Releases its paused builds when released or dropped.
    pub(crate) struct Pause(Arc<Gate>);

    impl Pause {
        pub(crate) fn release(&self) {
            *self
                .0
                .released
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = true;
            self.0.wake.notify_all();
        }
    }

    impl Drop for Pause {
        fn drop(&mut self) {
            self.release();
            ARMED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|gate| !Arc::ptr_eq(gate, &self.0));
        }
    }

    /// Arms a pause for replies carrying `token`. Each delivery on the
    /// returned receiver means one build has reached the pause.
    pub(crate) fn arm(token: &str) -> (Pause, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (reached, reached_rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(Gate {
            token: token.to_owned(),
            released: Mutex::new(false),
            wake: Condvar::new(),
            reached,
        });
        ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&gate));
        (Pause(gate), reached_rx)
    }

    pub(crate) fn pause_if_armed(reply: &Value) {
        let Some(token) = reply.get(FIELD).and_then(Value::as_str) else {
            return;
        };
        let gate = ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|gate| gate.token == token)
            .cloned();
        let Some(gate) = gate else {
            return;
        };
        if gate.reached.send(()).is_err() {
            return;
        }
        let released = gate.released.lock().unwrap_or_else(PoisonError::into_inner);
        let (_released, _timed_out) = gate
            .wake
            .wait_timeout_while(released, PAUSE_GUARD, |released| !*released)
            .unwrap_or_else(PoisonError::into_inner);
    }
}
