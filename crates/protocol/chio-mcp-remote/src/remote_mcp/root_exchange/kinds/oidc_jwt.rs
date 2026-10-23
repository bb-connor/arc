//! `oidc_jwt`: a generic OIDC access token presented as a bearer at the edge.
//!
//! The token verifies against its rule's provider record: `iss` equals the
//! record issuer, some `aud` is in the record's audiences, and the key is the
//! record's key for `kid`. The replay key is `(oidc_jwt, issuer, jti)` when
//! `jti` is present, else the digest of the token bytes. A rule whose record
//! has a Microsoft Entra issuer is refused when the exchange is built.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::Sha256Digest;
use serde_json::{Map, Value};

use super::super::claims::{scope_values, string};
use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::exchange::RootExchange;
use super::super::key_lookup::IdpKeyLookup;
use super::bearer_jws::{self, BearerJwsKind};

fn replay_id(
    claims: &Map<String, Value>,
    token_digest: &Sha256Digest,
) -> Result<String, RootExchangeError> {
    Ok(match string(claims, "jti")? {
        Some(jti) => format!("jti:{jti}"),
        None => format!("token:{token_digest}"),
    })
}

const OIDC_JWT: BearerJwsKind = BearerJwsKind {
    kind: AnchorKind::OidcJwt,
    scope_values,
    replay_id,
};

/// Verify the bearer `token` at `now` (Unix seconds).
pub async fn verify(
    exchange: &RootExchange,
    token: &str,
    now: u64,
    keys: &dyn IdpKeyLookup,
) -> Result<AnchorEvidence, RootExchangeError> {
    bearer_jws::verify(exchange, &OIDC_JWT, token, now, keys).await
}
