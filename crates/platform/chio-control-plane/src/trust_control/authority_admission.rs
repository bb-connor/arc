//! Bounded authority inspection and process-local admission checks.
use super::super::cluster::cluster_consensus_view;
use super::*;

const AUTHORITY_CHANGED: &str = "authority state changed during inspection";
const CLUSTER_CHANGED: &str = "cluster authority context changed during inspection";

#[derive(PartialEq, Eq)]
struct InspectionClusterContext {
    self_url: String,
    leader_url: String,
    election_term: u64,
}

fn inspection_cluster_context(
    state: &TrustServiceState,
) -> Result<Option<InspectionClusterContext>, Response> {
    if state.cluster.is_none() {
        return Ok(None);
    }
    let view = cluster_consensus_view(state)
        .ok_or_else(|| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, CLUSTER_CHANGED))?;
    let leader_url = view
        .leader_url
        .filter(|_| view.has_quorum)
        .ok_or_else(|| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, CLUSTER_CHANGED))?;
    Ok(Some(InspectionClusterContext {
        self_url: view.self_url,
        leader_url,
        election_term: view.election_term,
    }))
}

/// Bound blocking work before submission. The blocking task owns admission
/// through completion even when the caller aborts its async future.
pub(crate) async fn run_blocking_authority_operation<T, F>(
    state: &TrustServiceState,
    operation: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    run_blocking_authority_task(state, move |state| {
        let context = inspection_cluster_context(state)?;
        let result = operation(state)?;
        if context != inspection_cluster_context(state)? {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                CLUSTER_CHANGED,
            ));
        }
        Ok(result)
    })
    .await
}

/// Submit an operation that owns final admission inside its commit transaction.
/// The worker checks initial quorum/context and holds the same process permit;
/// it adds no refusal after an operation may have durably committed. A guard
/// observation is not atomic with an unrelated database's commit.
pub(crate) async fn run_authority_commit<T, F>(
    state: &TrustServiceState,
    commit: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    run_blocking_authority_task(state, move |state| {
        inspection_cluster_context(state)?;
        commit(state)
    })
    .await
}

async fn run_blocking_authority_task<T, F>(
    state: &TrustServiceState,
    operation: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    let permit = state
        .authority_inspection_lane
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authority inspection is at capacity",
            )
        })?;
    let inspected_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(&inspected_state)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection did not complete",
        )
    })?
}

/// Inspect inside an already-admitted, bounded blocking worker. This guard
/// creates no task, permit or file lock. Complete it successfully before the
/// surrounding registry transaction persists any mutation. The caller binds
/// any artifact's actual signer to the admitted live head before and after
/// signing; an opaque result cannot establish that binding for the caller.
pub(crate) fn inspect_authority_state_blocking<T, F>(
    state: &TrustServiceState,
    inspect: F,
) -> Result<T, Response>
where
    F: FnOnce(&TrustServiceState) -> Result<T, Response>,
{
    let context = inspection_cluster_context(state)?;
    let before = authority_view_bytes(state)?;
    let result = inspect(state)?;
    if before != authority_view_bytes(state)? {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            AUTHORITY_CHANGED,
        ));
    }
    if context != inspection_cluster_context(state)? {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            CLUSTER_CHANGED,
        ));
    }
    Ok(result)
}

fn authority_view_bytes(state: &TrustServiceState) -> Result<Vec<u8>, Response> {
    canonical_json_bytes(&load_authority_status_for_state(state)?).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection could not authenticate its view",
        )
    })
}
