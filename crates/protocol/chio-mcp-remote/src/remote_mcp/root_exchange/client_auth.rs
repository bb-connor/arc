//! Confidential client authentication with `private_key_jwt` (RFC 7523 section 2.2).

use std::collections::BTreeMap;

use chio_core::root_authority::Jwk;

use super::claims::{audience_is, required_seconds, required_string, string};
use super::error::RootExchangeError;
use super::jws::{CompactJws, VerifyingKey};
use super::replay::{ExchangeReplayStore, ReplayBinding, ReplayKey, ReplayNamespace};

pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Longest admitted client assertion, `exp - iat`.
pub const MAX_CLIENT_ASSERTION_LIFETIME_SECS: u64 = 60;

/// A registered confidential client and its public key.
#[derive(Debug, Clone)]
pub struct ConfidentialClient {
    pub client_id: String,
    pub key: Jwk,
}

#[derive(Debug, Clone)]
struct RegisteredClient {
    kid: String,
    key: VerifyingKey,
}

/// Registered confidential clients. Public clients are absent, so they can
/// never authenticate here.
#[derive(Debug, Clone, Default)]
pub struct ClientRegistry {
    clients: BTreeMap<String, RegisteredClient>,
}

impl ClientRegistry {
    /// Refuses duplicate client ids and keys that cannot verify.
    pub fn new(clients: Vec<ConfidentialClient>) -> Result<Self, RootExchangeError> {
        let mut registry = BTreeMap::new();
        for client in clients {
            let key = VerifyingKey::from_jwk(&client.key).ok_or(
                RootExchangeError::ClientAssertionInvalid("registered key is unusable"),
            )?;
            let registered = RegisteredClient {
                kid: client.key.kid.as_str().to_owned(),
                key,
            };
            if registry.insert(client.client_id, registered).is_some() {
                return Err(RootExchangeError::ClientAssertionInvalid(
                    "client id is registered twice",
                ));
            }
        }
        Ok(Self { clients: registry })
    }
}

/// The client-authentication members of a token request.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientCredentials<'a> {
    pub client_id: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

/// A client whose assertion verified and whose `jti` is now spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub client_id: String,
}

/// Where and when the client authenticates.
#[derive(Debug, Clone, Copy)]
pub struct ClientAuthContext<'a> {
    pub token_endpoint: &'a str,
    pub now: u64,
    pub max_clock_skew_secs: u64,
}

/// Authenticate a confidential client. Every refusal leaves no replay state
/// except a spent `jti` of an assertion that otherwise verified.
pub fn authenticate_client(
    registry: &ClientRegistry,
    credentials: ClientCredentials<'_>,
    context: ClientAuthContext<'_>,
    replay: &dyn ExchangeReplayStore,
) -> Result<AuthenticatedClient, RootExchangeError> {
    let assertion = credentials
        .client_assertion
        .ok_or(RootExchangeError::ClientAssertionMissing)?;
    if credentials.client_assertion_type != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
        return Err(RootExchangeError::ClientAssertionTypeUnsupported);
    }
    let jws = CompactJws::parse(assertion)
        .map_err(|_| RootExchangeError::ClientAssertionInvalid("not a compact JWS"))?;
    let claim = |error: RootExchangeError| match error {
        RootExchangeError::ClaimMissing(_) => {
            RootExchangeError::ClientAssertionInvalid("claim missing")
        }
        _ => RootExchangeError::ClientAssertionInvalid("claim malformed"),
    };
    let issuer = required_string(&jws.claims, "iss").map_err(claim)?;
    if string(&jws.claims, "sub").map_err(claim)? != Some(issuer) {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "sub differs from iss",
        ));
    }
    if credentials
        .client_id
        .is_some_and(|client_id| client_id != issuer)
    {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "client_id differs from iss",
        ));
    }
    let client = registry
        .clients
        .get(issuer)
        .ok_or(RootExchangeError::ClientNotConfidential)?;
    if jws.header.kid != client.kid {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "kid is not the registered key",
        ));
    }
    jws.verify_with(&client.key)
        .map_err(|_| RootExchangeError::ClientAssertionSignatureInvalid)?;
    if !audience_is(&jws.claims, context.token_endpoint) {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "aud is not the token endpoint",
        ));
    }
    let exp = required_seconds(&jws.claims, "exp").map_err(claim)?;
    let iat = required_seconds(&jws.claims, "iat").map_err(claim)?;
    if exp <= iat || exp - iat > MAX_CLIENT_ASSERTION_LIFETIME_SECS {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "lifetime exceeds 60 seconds",
        ));
    }
    let skew = context.max_clock_skew_secs;
    if context.now >= exp.saturating_add(skew) {
        return Err(RootExchangeError::ClientAssertionInvalid("expired"));
    }
    if iat > context.now.saturating_add(skew) {
        return Err(RootExchangeError::ClientAssertionInvalid(
            "issued in the future",
        ));
    }
    let jti = required_string(&jws.claims, "jti").map_err(claim)?;
    let key = ReplayKey {
        namespace: ReplayNamespace::ClientAssertion,
        issuer: issuer.to_owned(),
        id: jti.to_owned(),
    };
    match replay
        .bind(&key, exp.saturating_add(skew), context.now)
        .map_err(RootExchangeError::ReplayStoreUnavailable)?
    {
        ReplayBinding::Bound => Ok(AuthenticatedClient {
            client_id: issuer.to_owned(),
        }),
        ReplayBinding::AlreadyBound => Err(RootExchangeError::ClientAssertionReplay),
    }
}
