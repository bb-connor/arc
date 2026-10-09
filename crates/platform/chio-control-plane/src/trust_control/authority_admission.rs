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
        let context = inspection_cluster_context(&inspected_state)?;
        let result = operation(&inspected_state)?;
        if context != inspection_cluster_context(&inspected_state)? {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                CLUSTER_CHANGED,
            ));
        }
        Ok(result)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection did not complete",
        )
    })?
}

/// Inspect an admitted authority view on the blocking pool. A term/quorum or
/// authority-head/live-key-set change before return refuses the result. The
/// caller must additionally bind any artifact's actual signer to this view.
pub(crate) async fn inspect_authority_state<T, F>(
    state: &TrustServiceState,
    inspect: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState) -> Result<T, Response> + Send + 'static,
{
    run_blocking_authority_operation(state, move |state| {
        let before = authority_view_bytes(state)?;
        let result = inspect(state)?;
        if before != authority_view_bytes(state)? {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                AUTHORITY_CHANGED,
            ));
        }
        Ok(result)
    })
    .await
}

fn authority_view_bytes(state: &TrustServiceState) -> Result<Vec<u8>, Response> {
    canonical_json_bytes(&load_authority_status_for_state(state)?).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority inspection could not authenticate its view",
        )
    })
}
