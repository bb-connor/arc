//! Claim rules of an Identity Assertion JWT Authorization Grant.

use chio_core::root_authority::{EnterpriseProviderIdentity, Identifier, JwsAlgorithm};
use serde_json::{Map, Value};

use super::claims::{
    audience_is, mapped_claim, required_seconds, required_string, scope_values, seconds, string,
};
use super::error::RootExchangeError;
use super::jws::VerifiedJws;

/// The JWS `typ` of an ID-JAG, per draft-ietf-oauth-identity-assertion-authz-grant-04
/// section 3.1.
pub const ID_JAG_MEDIA_TYPE: &str = "oauth-id-jag+jwt";

/// The local authorization server and protected resource the ID-JAG targets.
#[derive(Debug, Clone, Copy)]
pub struct IdJagAudience<'a> {
    /// The local authorization server issuer; the ID-JAG `aud`.
    pub authorization_server: &'a str,
    /// The advertised protected resource; the ID-JAG `resource` when present.
    pub protected_resource: &'a str,
}

/// Time bounds of one rule.
#[derive(Debug, Clone, Copy)]
pub struct IdJagTiming {
    pub now: u64,
    pub max_clock_skew_secs: u64,
    pub max_assertion_lifetime_secs: u64,
}

/// An ID-JAG whose signature and claims verified.
#[derive(Debug, Clone)]
pub struct VerifiedIdJag {
    pub issuer: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    pub alg: JwsAlgorithm,
    pub kid: Identifier,
    pub principal: String,
    pub tenant: String,
    pub scope_values: Vec<String>,
    pub claims: Map<String, Value>,
}

/// Check the claims of a signature-verified ID-JAG against its provider
/// record and the authenticated client.
pub fn verify_id_jag_claims(
    jws: &VerifiedJws,
    record: &EnterpriseProviderIdentity,
    audience: IdJagAudience<'_>,
    client_id: &str,
    timing: IdJagTiming,
) -> Result<VerifiedIdJag, RootExchangeError> {
    if jws.header().typ.as_deref() != Some(ID_JAG_MEDIA_TYPE) {
        return Err(RootExchangeError::TypMismatch);
    }
    let claims = jws.claims();
    let issuer = required_string(claims, "iss")?;
    if issuer != record.issuer.as_str() {
        return Err(RootExchangeError::IssuerMismatch);
    }
    if !audience_is(claims, audience.authorization_server) {
        return Err(RootExchangeError::AudienceMismatch);
    }
    if required_string(claims, "client_id")? != client_id {
        return Err(RootExchangeError::ClientIdMismatch);
    }
    if string(claims, "resource")?.is_some_and(|resource| resource != audience.protected_resource) {
        return Err(RootExchangeError::ResourceMismatch);
    }
    let exp = required_seconds(claims, "exp")?;
    let iat = required_seconds(claims, "iat")?;
    let skew = timing.max_clock_skew_secs;
    if timing.now >= exp.saturating_add(skew) {
        return Err(RootExchangeError::AssertionExpired);
    }
    if iat > timing.now.saturating_add(skew) {
        return Err(RootExchangeError::AssertionIssuedInFuture);
    }
    if seconds(claims, "nbf")?.is_some_and(|nbf| nbf > timing.now.saturating_add(skew)) {
        return Err(RootExchangeError::AssertionNotYetValid);
    }
    let lifetime = exp.saturating_sub(iat);
    if exp <= iat || lifetime > timing.max_assertion_lifetime_secs {
        return Err(RootExchangeError::AssertionLifetimeTooLong {
            lifetime,
            max: timing.max_assertion_lifetime_secs,
        });
    }
    let jti = required_string(claims, "jti")?;
    let principal = mapped_claim(
        claims,
        record.subject_mapping.principal_source.as_str(),
        "principal",
    )?;
    let tenant = mapped_claim(
        claims,
        record.subject_mapping.tenant_id_field.as_str(),
        "tenant",
    )?;
    Ok(VerifiedIdJag {
        issuer: issuer.to_owned(),
        jti: jti.to_owned(),
        iat,
        exp,
        alg: jws.header().alg,
        kid: jws.header().kid.clone(),
        principal,
        tenant,
        scope_values: scope_values(claims)?,
        claims: claims.clone(),
    })
}
