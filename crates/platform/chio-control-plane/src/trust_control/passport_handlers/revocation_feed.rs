//! Public passport revocation feed: the signed epoch root over this
//! operator's passport revocation oracle and bounded pages of its leaves.
//! Both reads hold a non-queued permit of the public passport lane through
//! blocking completion.

use super::*;

use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, sign_passport_revocation_root, PassportRevocationFeedError,
    PassportRevocationRootDocument,
};
use chio_revocation_oracle::SqliteRevocationOracle;

const FEED_REQUIRES_REGISTRY: &str = "passport revocation feed requires --passport-statuses-file";
const FEED_REQUIRES_AUTHORITY: &str =
    "passport revocation feed requires a configured trust-control authority";
const FEED_ORACLE_NOT_OPEN: &str = "passport revocation oracle is not open";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PassportRevocationLeavesQuery {
    after: u64,
}

fn feed_error_response(error: &PassportRevocationFeedError) -> Response {
    match error {
        PassportRevocationFeedError::CursorOutOfRange(_) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        PassportRevocationFeedError::OracleUnavailable(_)
        | PassportRevocationFeedError::RegistryUnavailable(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation feed state is unavailable",
        ),
        PassportRevocationFeedError::Signing(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation root signing failed",
        ),
        PassportRevocationFeedError::OracleBehindRegistry { .. }
        | PassportRevocationFeedError::OracleMissingRevocation { .. }
        | PassportRevocationFeedError::ClockBehindOracle { .. }
        | PassportRevocationFeedError::BeyondJsonPrecision(_)
        | PassportRevocationFeedError::UnsupportedSchema(_)
        | PassportRevocationFeedError::UnpublishableLeaf { .. } => {
            plain_http_error(StatusCode::CONFLICT, &error.to_string())
        }
    }
}

/// The registry path and the oracle opened beside it at startup.
fn feed_sources(
    state: &TrustServiceState,
) -> Result<(PathBuf, Arc<SqliteRevocationOracle>), Response> {
    let Some(registry) = state.config.passport_statuses_file.clone() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            FEED_REQUIRES_REGISTRY,
        ));
    };
    let Some(oracle) = state.passport_revocation_oracle.clone() else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            FEED_ORACLE_NOT_OPEN,
        ));
    };
    Ok((registry, oracle))
}

pub(crate) async fn handle_public_passport_revocation_root(
    State(state): State<TrustServiceState>,
) -> Response {
    run_public_authority_trust_read(&state, |state, status| {
        let (registry, oracle) = match feed_sources(state) {
            Ok(sources) => sources,
            Err(response) => return response,
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
        match sign_passport_revocation_root(&oracle, &registry, authority, now) {
            Ok(signed) => Json(PassportRevocationRootDocument::new(signed)).into_response(),
            Err(error) => feed_error_response(&error),
        }
    })
    .await
}

pub(crate) async fn handle_public_passport_revocation_leaves(
    State(state): State<TrustServiceState>,
    Query(query): Query<PassportRevocationLeavesQuery>,
) -> Response {
    let (registry, oracle) = match feed_sources(&state) {
        Ok(sources) => sources,
        Err(response) => return response,
    };
    let Ok(permit) = Arc::clone(&state.public_passport_challenge_lane).try_acquire_owned() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation feed is at capacity",
        );
    };
    let page = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        passport_revocation_leaves_page(&oracle, &registry, query.after)
    })
    .await;
    match page {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(error)) => feed_error_response(&error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "passport revocation feed read did not complete",
        ),
    }
}
