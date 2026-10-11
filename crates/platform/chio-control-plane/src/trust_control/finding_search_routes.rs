//! Public finding search routes. A search runs on the blocking pool behind
//! its own non-queued admission lane, never on an async worker.

use super::*;

/// Public finding searches this node runs at once: an explicit bound on the
/// blocking-pool threads this unauthenticated route can hold. Each search
/// reads through the authority store's single serving connection, so more
/// permits would only park threads behind that connection.
const FINDING_SEARCH_PERMITS: usize = 8;

/// Admission for public finding searches. No other route draws on it, so this
/// route can exhaust only its own permits.
static FINDING_SEARCH_LANE: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(FINDING_SEARCH_PERMITS)));

/// GET /v1/findings/search (public).
pub(crate) async fn handle_search_findings_get(
    State(state): State<TrustServiceState>,
    Query(query): Query<FindingSearchQuery>,
) -> Response {
    search_findings_in_lane(&FINDING_SEARCH_LANE, state, query).await
}

/// POST /v1/findings/search (public).
pub(crate) async fn handle_search_findings_post(
    State(state): State<TrustServiceState>,
    Json(query): Json<FindingSearchQuery>,
) -> Response {
    search_findings_in_lane(&FINDING_SEARCH_LANE, state, query).await
}

/// Runs one finding search on the blocking pool under a permit from `lane`.
///
/// Admission never waits: without a free permit the search is refused at once
/// with 503. The permit moves into the blocking closure and is released only
/// after the response is built, so a search dropped mid-flight keeps its
/// permit until that work has ended.
pub(super) async fn search_findings_in_lane(
    lane: &Arc<tokio::sync::Semaphore>,
    state: TrustServiceState,
    query: FindingSearchQuery,
) -> Response {
    let Ok(permit) = Arc::clone(lane).try_acquire_owned() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding search is at capacity",
        );
    };
    tokio::task::spawn_blocking(move || {
        let response = run_finding_search(&state, &query);
        drop(permit);
        response
    })
    .await
    .unwrap_or_else(|_| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "finding search did not complete",
        )
    })
}
