//! `chio_local_as`: an access token of the local authorization server, and
//! its RFC 8693 re-exchange.
//!
//! A local access token verifies against the local authorization server's
//! Ed25519 key. Its sender constraint (`cnf`) binds both paths: the request
//! presenting it must satisfy the same mTLS and attestation bindings the
//! token names, and a token confirmed by a Chio sender key refuses because
//! no DPoP proof can be held here. The principal is the token `sub`, the
//! tenant the local authorization server issuer, and the recorded issuer is
//! `urn:chio:local-as`.
//!
//! Issuance spends `(chio_local_as, urn:chio:local-as, jti)` and anchors at
//! the token's `exp`. A re-exchange spends the subject token's `jti` once in
//! its own namespace, so a token whose root was minted at issuance can still
//! be re-exchanged once. It narrows the requested `scope` and `resource` to
//! a subset of the subject token's, inherits the subject root's
//! `assertion_exp`, and its root scope is the subject root's within the
//! rule ceiling. It is open to the client the subject token was issued to,
//! public clients included.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core::capability::anchor::AnchorKind;
use chio_core::capability::scope::ChioScope;
use chio_core::crypto::PublicKey;
use chio_core::root_authority::{Jwk, JwsAlgorithm, Sha256Digest};
use chio_core::sha256;
use serde_json::{json, Map, Value};

use super::super::claims::{required_seconds, required_string, scope_values, string};
use super::super::error::{RootExchangeError, SenderConstraintFailure};
use super::super::evidence::AnchorEvidence;
use super::super::jws::{CompactJws, VerifyingKey};
use super::super::replay::{ReplayKey, ReplayNamespace};
use crate::sender_constraint::{validate_sender_constraint, ConfirmationWire};
use crate::{ChioSenderConstraintClaims, SenderConstraintError, SenderRequest};

const KIND: AnchorKind = AnchorKind::ChioLocalAs;

/// Issuer recorded for `chio_local_as` roots.
pub const LOCAL_AS_ISSUER: &str = "urn:chio:local-as";

/// The local authorization server whose access tokens anchor roots.
#[derive(Debug, Clone, Copy)]
pub struct LocalAuthorizationServer<'a> {
    /// The key that signs local access tokens.
    pub key: &'a PublicKey,
    /// The `iss` of local access tokens; the tenant value of their roots.
    pub issuer: &'a str,
}

/// The transport and headers of the request presenting a local token,
/// which its sender constraint is checked against.
#[derive(Clone, Copy)]
pub struct PresentedSender<'a>(SenderRequest<'a>);

impl<'a> From<SenderRequest<'a>> for PresentedSender<'a> {
    fn from(request: SenderRequest<'a>) -> Self {
        Self(request)
    }
}

/// The stored root a subject token resolves to.
#[derive(Debug, Clone, Copy)]
pub struct SubjectRoot<'a> {
    pub scope: &'a ChioScope,
    pub assertion_exp: u64,
}

/// The narrowing members of a re-exchange request.
#[derive(Debug, Clone, Copy)]
pub struct ReExchangeRequest<'a> {
    pub scope: Option<&'a [String]>,
    pub resource: Option<&'a str>,
    pub client_id: Option<&'a str>,
    /// SHA-256 of the exact request body.
    pub request_digest: Sha256Digest,
}

/// A local access token whose signature, issuer, lifetime and sender
/// constraint verified.
struct LocalToken {
    claims: Map<String, Value>,
    jti: String,
    iat: u64,
    exp: u64,
    principal: String,
    token_digest: Sha256Digest,
}

fn sender_failure(error: SenderConstraintError) -> RootExchangeError {
    RootExchangeError::SenderConstraintUnmet(match error {
        SenderConstraintError::DpopUnavailable => SenderConstraintFailure::DpopUnavailable,
        SenderConstraintError::UnsupportedSchema => SenderConstraintFailure::Confirmation,
        SenderConstraintError::MtlsBinding => SenderConstraintFailure::Mtls,
        SenderConstraintError::AttestationBinding => SenderConstraintFailure::Attestation,
    })
}

/// The token's `cnf`, read through the closed confirmation profile.
fn confirmation(
    claims: &Map<String, Value>,
) -> Result<Option<ChioSenderConstraintClaims>, RootExchangeError> {
    let Some(cnf) = claims.get("cnf") else {
        return Ok(None);
    };
    let wire: ConfirmationWire = serde_json::from_value(cnf.clone()).map_err(|_| {
        RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation)
    })?;
    ChioSenderConstraintClaims::try_from(wire)
        .map(Some)
        .map_err(|_| {
            RootExchangeError::SenderConstraintUnmet(SenderConstraintFailure::Confirmation)
        })
}

fn local_key(server: &LocalAuthorizationServer<'_>) -> Result<VerifyingKey, RootExchangeError> {
    let jwk: Jwk = serde_json::from_value(json!({
        "kid": "local-as",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode(server.key.ed25519_bytes().map_err(|_| RootExchangeError::IdpKeyUnusable)?),
    }))
    .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
    VerifyingKey::from_jwk(&jwk).ok_or(RootExchangeError::IdpKeyUnusable)
}

fn verify_token(
    server: &LocalAuthorizationServer<'_>,
    token: &str,
    sender: PresentedSender<'_>,
    now: u64,
) -> Result<LocalToken, RootExchangeError> {
    let jws = CompactJws::parse(token)?;
    if jws.header().alg != JwsAlgorithm::EdDSA {
        return Err(RootExchangeError::AlgorithmNotAdmitted);
    }
    let jws = jws.verify_with(&local_key(server)?)?;
    let claims = jws.claims();
    if required_string(claims, "iss")? != server.issuer {
        return Err(RootExchangeError::IssuerMismatch);
    }
    let exp = required_seconds(claims, "exp")?;
    if now >= exp {
        return Err(RootExchangeError::AssertionExpired);
    }
    let iat = required_seconds(claims, "iat")?;
    if iat > now {
        return Err(RootExchangeError::AssertionIssuedInFuture);
    }
    if iat >= exp {
        return Err(RootExchangeError::ClaimInvalid("exp"));
    }
    validate_sender_constraint(confirmation(claims)?.as_ref(), sender.0).map_err(sender_failure)?;
    Ok(LocalToken {
        jti: required_string(claims, "jti")?.to_owned(),
        principal: required_string(claims, "sub")?.to_owned(),
        claims: claims.clone(),
        iat,
        exp,
        token_digest: Sha256Digest::from_hash(sha256(token.as_bytes())),
    })
}

/// Verify a local access token presented by `sender` at `now` (Unix
/// seconds) for the root issued with it.
pub fn verify(
    server: &LocalAuthorizationServer<'_>,
    token: &str,
    sender: PresentedSender<'_>,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    let local = verify_token(server, token, sender, now)?;
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::Assertion(KIND),
            issuer: LOCAL_AS_ISSUER.to_owned(),
            id: local.jti,
        },
        issuer: LOCAL_AS_ISSUER.to_owned(),
        principal: local.principal,
        tenant: server.issuer.to_owned(),
        token_iat: local.iat,
        token_exp: local.exp,
        jws: None,
        artifact_digest: Some(local.token_digest),
        request_digest: local.token_digest,
        claims: local.claims,
        scope_values: Vec::new(),
        provider_id: None,
        scope_bound: None,
        holder: None,
    })
}

/// Verify an RFC 8693 re-exchange of the local `subject_token`, whose
/// stored root is `subject_root`, presented by `sender` at `now`.
pub fn verify_reexchange(
    server: &LocalAuthorizationServer<'_>,
    subject_token: &str,
    request: ReExchangeRequest<'_>,
    subject_root: SubjectRoot<'_>,
    sender: PresentedSender<'_>,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    let local = verify_token(server, subject_token, sender, now)?;
    if request.client_id.is_some_and(|client_id| {
        string(&local.claims, "client_id").ok().flatten() != Some(client_id)
    }) {
        return Err(RootExchangeError::ReExchangeClientMismatch);
    }
    let token_scope = scope_values(&local.claims)?;
    if request
        .scope
        .is_some_and(|requested| requested.iter().any(|value| !token_scope.contains(value)))
    {
        return Err(RootExchangeError::ReExchangeWidens);
    }
    let token_resource = string(&local.claims, "resource")?;
    if request
        .resource
        .is_some_and(|resource| token_resource != Some(resource))
    {
        return Err(RootExchangeError::ReExchangeWidens);
    }
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::LocalReExchange,
            issuer: LOCAL_AS_ISSUER.to_owned(),
            id: local.jti,
        },
        issuer: LOCAL_AS_ISSUER.to_owned(),
        principal: local.principal,
        tenant: server.issuer.to_owned(),
        token_iat: local.iat,
        token_exp: subject_root.assertion_exp,
        jws: None,
        artifact_digest: Some(local.token_digest),
        request_digest: request.request_digest,
        claims: local.claims,
        scope_values: Vec::new(),
        provider_id: None,
        scope_bound: Some(subject_root.scope.clone()),
        holder: None,
    })
}
