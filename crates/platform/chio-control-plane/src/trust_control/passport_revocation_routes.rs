//! Public passport revocation feed routes: the signed epoch root over this
//! operator's passport revocation oracle and bounded pages of its leaves.

use super::passport_handlers::public_authority_trust::run_public_authority_trust_read;
use super::*;

use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, sign_passport_revocation_root,
};

const FEED_REQUIRES_REGISTRY: &str = "passport revocation feed requires --passport-statuses-file";
const FEED_REQUIRES_AUTHORITY: &str =
    "passport revocation feed requires a configured trust-control authority";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PassportRevocationLeavesQuery {
    after: u64,
}

pub(crate) async fn handle_public_passport_revocation_root(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        let Some(registry) = state.config.passport_statuses_file.as_deref() else {
            return plain_http_error(StatusCode::CONFLICT, FEED_REQUIRES_REGISTRY);
        };
        let Some(status) = status else {
            return plain_http_error(StatusCode::CONFLICT, FEED_REQUIRES_AUTHORITY);
        };
        let clock = &state.finding_challenge_clock;
        let authority =
            match resolve_public_authority_signing_key_for_status(&state.config, clock, status) {
                Ok(authority) => authority,
                Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
            };
        let now = match clock.unix_millis() {
            Ok(now) => now.get(),
            Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
        };
        match sign_passport_revocation_root(registry, authority, now) {
            Ok(signed) => Json(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        }
    })
    .await
}

pub(crate) async fn handle_public_passport_revocation_leaves(
    State(state): State<TrustServiceState>,
    Query(query): Query<PassportRevocationLeavesQuery>,
) -> Response {
    let Some(registry) = state.config.passport_statuses_file.clone() else {
        return plain_http_error(StatusCode::CONFLICT, FEED_REQUIRES_REGISTRY);
    };
    let Ok(permit) = Arc::clone(&state.public_passport_challenge_lane).try_acquire_owned() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation feed is at capacity",
        );
    };
    let page = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        passport_revocation_leaves_page(&registry, query.after)
    })
    .await;
    match page {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(error)) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation feed read did not complete",
        ),
    }
}
