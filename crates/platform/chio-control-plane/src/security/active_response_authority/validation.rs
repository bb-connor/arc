//! Bounded authenticated-envelope validation shared by transport and fuzzing.
use super::*;

/// Request authenticated against the expected deployment and client.
/// Construction and decoding are available only through the verifier below.
pub(super) struct VerifiedAuthorityRequest(SignedActiveResponseAuthorityRequest);
impl VerifiedAuthorityRequest {
    pub(super) fn request(&self) -> &SignedActiveResponseAuthorityRequest {
        &self.0
    }
    pub(super) fn into_request(self) -> SignedActiveResponseAuthorityRequest {
        self.0
    }
}

pub(super) fn decode_authority_request(
    bytes: &[u8],
    config: &ActiveResponseAuthorityProtocolServerConfig,
    now_unix_seconds: u64,
) -> PortResult<VerifiedAuthorityRequest> {
    if bytes.len() > MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES {
        return Err(rejected("frame_bound"));
    }
    let request: SignedActiveResponseAuthorityRequest =
        serde_json::from_slice(bytes).map_err(|_| rejected("decode"))?;
    let canonical = canonical_json_bytes(&request).map_err(|_| rejected("canonical"))?;
    if canonical != bytes {
        return Err(rejected("canonical"));
    }
    validate_authority_request(&request, config, now_unix_seconds)?;
    Ok(VerifiedAuthorityRequest(request))
}

fn validate_authority_request(
    request: &SignedActiveResponseAuthorityRequest,
    config: &ActiveResponseAuthorityProtocolServerConfig,
    now_unix_seconds: u64,
) -> PortResult<()> {
    let body = &request.body;
    if body.schema != ACTIVE_RESPONSE_AUTHORITY_SCHEMA {
        return Err(rejected("schema"));
    }
    if body.deployment_digest != config.deployment_digest {
        return Err(rejected("deployment"));
    }
    if body.store_digest != config.store_digest {
        return Err(rejected("store"));
    }
    validate_request_freshness(
        body.issued_at_unix_seconds,
        config.maximum_clock_skew_seconds,
        now_unix_seconds,
    )?;
    if body.client != config.trusted_client {
        return Err(rejected("client"));
    }
    if request.algorithm != config.trusted_client.algorithm()
        || request.signature.algorithm() != request.algorithm
    {
        return Err(rejected("algorithm"));
    }
    let canonical = active_response_authority_request_signing_bytes(body)?;
    if !config.trusted_client.verify(&canonical, &request.signature) {
        return Err(rejected("signature"));
    }
    Ok(())
}

pub(super) fn validate_request_freshness(
    issued_at: u64,
    maximum_skew: u64,
    now: u64,
) -> PortResult<()> {
    let latest = now
        .checked_add(maximum_skew)
        .ok_or_else(|| rejected("time_overflow"))?;
    let earliest = now.saturating_sub(maximum_skew);
    if issued_at < earliest || issued_at > latest {
        return Err(rejected("freshness"));
    }
    Ok(())
}

fn rejected(rule: &'static str) -> PortError {
    // All callers provide a static rule, never an input value.
    let code = format!(
        "urn:chio:error:transport:response-authority-{}",
        rule.replace('_', "-")
    );
    match ErrorCode::new(code) {
        Ok(code) => PortError::new(PortErrorKind::IntegrityFailure, code),
        Err(_) => PortError::integrity_failure(),
    }
}
