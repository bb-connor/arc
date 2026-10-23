//! `operator_static_bearer`: the `--auth-token` static bearer at the edge.
//!
//! The presented token's SHA-256 is compared in constant time with the
//! configured token's; the token itself is never held. The principal and
//! tenant are the ones the single `operator_static_bearer` rule names, and
//! the issuer is `urn:chio:operator`. The root's own expiry is its
//! assertion expiry, and the replay key is `(operator_static_bearer,
//! urn:chio:operator, token_digest ":" expires_at)`, so exactly one live
//! root exists per token and a fresh root follows expiry.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::{Sha256Digest, OPERATOR_ISSUER};
use chio_core::sha256;
use serde_json::Map;
use subtle::ConstantTimeEq as _;

use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::exchange::{MatchInput, RootExchange};
use super::super::replay::{ReplayKey, ReplayNamespace};

const KIND: AnchorKind = AnchorKind::OperatorStaticBearer;

/// The configured static bearer token, held only as its SHA-256.
pub struct StaticBearerToken {
    digest: [u8; 32],
}

impl StaticBearerToken {
    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            digest: *sha256(token.as_bytes()).as_bytes(),
        }
    }
}

/// Verify the bearer `token` against `configured` at `now` (Unix seconds).
pub fn verify(
    exchange: &RootExchange,
    configured: &StaticBearerToken,
    token: &str,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    let presented = sha256(token.as_bytes());
    if !bool::from(presented.as_bytes().ct_eq(&configured.digest)) {
        return Err(RootExchangeError::StaticBearerMismatch);
    }
    let claims = Map::new();
    let (rule, _) = exchange.match_rule(MatchInput {
        kind: KIND,
        issuer: OPERATOR_ISSUER,
        alg: None,
        claims: &claims,
        scope_values: &[],
        provider_id: None,
    })?;
    let principal = rule
        .principal
        .as_ref()
        .ok_or(RootExchangeError::ClaimMissing("principal"))?;
    let tenant = rule
        .tenant_value
        .as_ref()
        .ok_or(RootExchangeError::ClaimMissing("tenant"))?;
    let expires_at = now
        .saturating_add(rule.capability_ttl())
        .min(exchange.policy.policy().valid_until);
    if expires_at <= now {
        return Err(RootExchangeError::RootLifetimeEmpty);
    }
    let token_digest = Sha256Digest::from_hash(presented);
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::Assertion(KIND),
            issuer: OPERATOR_ISSUER.to_owned(),
            id: format!("{token_digest}:{expires_at}"),
        },
        issuer: OPERATOR_ISSUER.to_owned(),
        principal: principal.as_str().to_owned(),
        tenant: tenant.as_str().to_owned(),
        token_iat: now,
        token_exp: expires_at,
        jws: None,
        artifact_digest: None,
        request_digest: token_digest,
        claims,
        scope_values: Vec::new(),
        provider_id: None,
        scope_bound: None,
        holder: None,
    })
}
