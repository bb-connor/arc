//! Public issuer-trust inspection shares bounded public admission. It never
//! occupies an authenticated forwarding or receipt-read lane.
use super::*;

async fn inspect_public_authority_trust<T, F>(
    state: &TrustServiceState,
    inspect: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&TrustServiceState, Option<&TrustAuthorityStatus>) -> Result<T, Response>
        + Send
        + 'static,
{
    let permit = Arc::clone(&state.public_passport_challenge_lane)
        .try_acquire_owned()
        .map_err(|_| {
            plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "public authority trust inspection is at capacity",
            )
        })?;
    let inspected_state = state.clone();
    tokio::task::spawn_blocking(move || {
        // The blocking worker owns admission through success, refusal, panic
        // and cancellation of the caller's async future.
        let _permit = permit;
        let admitted_status = if inspected_state.cluster.is_some()
            && inspected_state.config.authority_db_path.is_some()
        {
            Some(
                super::super::report_validation::load_authority_status_for_state(&inspected_state)?,
            )
        } else {
            None
        };
        inspect(&inspected_state, admitted_status.as_ref())
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "public authority trust inspection did not complete",
        )
    })?
}

pub(super) async fn run_public_authority_trust_read<F>(
    state: &TrustServiceState,
    read: F,
) -> Response
where
    F: FnOnce(&TrustServiceState, Option<&TrustAuthorityStatus>) -> Response + Send + 'static,
{
    inspect_public_authority_trust(state, move |state, status| Ok(read(state, status)))
        .await
        .unwrap_or_else(std::convert::identity)
}

pub(super) async fn public_oid4vp_trusted_keys(
    state: &TrustServiceState,
) -> Result<Vec<PublicKey>, Response> {
    inspect_public_authority_trust(state, |state, status| {
        match status {
            Some(status) => trusted_public_keys_from_status(status),
            None => resolve_public_oid4vp_verifier_trusted_public_keys(
                &state.config,
                &state.finding_challenge_clock,
            ),
        }
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))
    })
    .await
}
