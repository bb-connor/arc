//! The acceptance instant and the network phase every passport door shares.
use super::*;

/// One reading of the request-handling state clock, in seconds and in
/// milliseconds. A clock failure fails closed.
pub(super) fn acceptance_instant(state: &TrustServiceState) -> Result<(u64, u64), Response> {
    let now = state
        .finding_challenge_clock
        .unix_millis()
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()))?;
    Ok((now.as_secs(), now.get()))
}

/// Runs the partner door's network phase for `binding` on the bounded
/// portable fetch lane.
pub(super) async fn prepare_partner_door(
    state: &TrustServiceState,
    binding: PartnerPassportBinding,
) -> Result<PreparedPartnerDoor, Response> {
    let door = Arc::clone(&state.partner_revocation_door);
    let config = state.config.clone();
    let clock = Arc::clone(&state.finding_challenge_clock);
    match run_portable_issuer_fetch(move || door.prepare(&config, clock, &binding)).await {
        Ok(Ok(door)) => Ok(door),
        Ok(Err(error)) => Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
        Err(refusal) => Err(refusal.into_response(plain_http_error)),
    }
}
