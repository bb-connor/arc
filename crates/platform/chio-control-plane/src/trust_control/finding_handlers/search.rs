//! The bounded, paginated public finding descriptor index.

use super::*;

/// Search query DTO shared by the GET and POST variants.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FindingSearchQuery {
    #[serde(default)]
    pub topic_prefix: Option<String>,
    #[serde(default)]
    pub context_sha256: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchRowView {
    finding_id: String,
    artifact_sha256: String,
    topic: String,
    context_sha256: String,
    issued_at: u64,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    admission: Option<FindingSearchAdmissionView>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingSearchResponse {
    results: Vec<FindingSearchRowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    count: usize,
}

pub(super) fn run_finding_search(
    state: &TrustServiceState,
    query: &FindingSearchQuery,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let (config, store) = match finding_market_context(state) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let status_store = match finding_status_store(state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let purchase_store = match state.joint_authority_store.as_ref() {
        Some(authority) => authority.finding_purchase_store(),
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "finding market requires the joint authority store",
            )
        }
    };
    if query.topic_prefix.is_none() && query.context_sha256.is_none() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "search requires a topic prefix or a context digest",
        );
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let now = clock_now;
    let rows = match store.search_findings(
        query.topic_prefix.as_deref(),
        query.context_sha256.as_deref(),
        query.cursor.as_deref(),
        limit,
        now,
    ) {
        Ok(rows) => rows,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let next_cursor = if rows.len() == limit {
        rows.last().map(|row| row.finding_id.clone())
    } else {
        None
    };
    let status_operator_authority_status = state
        .finding_authority_status_resolver
        .as_ref()
        .and_then(|resolver| {
            resolver
                .resolve(&config.status_feed_operator.authority, now)
                .ok()
        });
    let venue_authority_status = state
        .finding_authority_status_resolver
        .as_ref()
        .and_then(|resolver| resolver.resolve(&config.venue, now).ok());
    let results: Vec<FindingSearchRowView> = rows
        .into_iter()
        .map(|row| {
            let admission = current_admission_view(
                &store,
                &purchase_store,
                &status_store,
                &config,
                state.finding_authority_status_resolver.as_deref(),
                status_operator_authority_status.as_ref(),
                venue_authority_status.as_ref(),
                &row.finding_id,
                now,
            );
            FindingSearchRowView {
                finding_id: row.finding_id,
                artifact_sha256: row.artifact_sha256,
                topic: row.topic,
                context_sha256: row.context_sha256,
                issued_at: row.issued_at,
                expires_at: row.expires_at,
                admission,
            }
        })
        .collect();
    let count = results.len();
    Json(FindingSearchResponse {
        results,
        next_cursor,
        count,
    })
    .into_response()
}
