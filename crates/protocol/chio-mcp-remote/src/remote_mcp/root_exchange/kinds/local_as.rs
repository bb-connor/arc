//! `chio_local_as`: an authorization code redeemed at the local
//! authorization server, and the RFC 8693 re-exchange of the access token
//! issued for it.
//!
//! Both paths check a sender constraint (`cnf`) against the request: the
//! one the authorization request bound to the code, or the one the subject
//! token names. The request must satisfy the mTLS and attestation bindings
//! it names, and a Chio sender key refuses because no DPoP proof can be held
//! here. The constraint is carried on the evidence for the access token
//! issued with the root. The principal is the code's subject or the token
//! `sub`, the tenant the local authorization server issuer, and the
//! recorded issuer is `urn:chio:local-as`.
//!
//! Issuance spends `(chio_local_as_issue, urn:chio:local-as, hex
//! SHA-256(code))` and anchors at the issued token's `exp`, so it consumes
//! the code, never the token's `jti`. A re-exchange spends
//! `(chio_local_as, urn:chio:local-as, jti)` of the subject token once, so a
//! freshly issued token can be re-exchanged exactly once. A local access
//! token verifies against the local authorization server's Ed25519 key. The
//! requested `scope` and `resource` must be a
//! subset of the subject token's and the requested root scope a subset of
//! the subject root's; the root takes the requested root scope, or the
//! subject root's, within the rule ceiling, records the requested `scope`
//! values, and inherits the subject root's `assertion_exp`. It is open to the client the subject token was issued to,
//! public clients included.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core::capability::anchor::AnchorKind;
use chio_core::capability::scope::ChioScope;
use chio_core::crypto::PublicKey;
use chio_core::root_authority::{Jwk, JwsAlgorithm, Sha256Digest};
use chio_core::sha256;
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::super::claims::{required_seconds, required_string, scope_values, string};
use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::jws::{CompactJws, VerifyingKey};
use super::super::replay::{ReplayKey, ReplayNamespace};
use crate::{ChioSenderConstraintClaims, SenderRequest};

const KIND: AnchorKind = AnchorKind::ChioLocalAs;

const CODE_REQUEST_DIGEST_DOMAIN: &[u8] = b"chio.root-exchange.local-as-code-request.v1\0";

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

/// An authorization code the local authorization server redeemed after
/// checking its client, redirect URI, PKCE verifier, resource and sender
/// constraint.
///
/// Only that redemption constructs it, and its members are read-only:
///
/// ```
/// use chio_mcp_remote::root_exchange::kinds::local_as::RedeemedCode;
/// fn present(_code: &RedeemedCode) {}
/// ```
///
/// ```compile_fail
/// use chio_mcp_remote::root_exchange::kinds::local_as::RedeemedCode;
/// use chio_core::root_authority::Sha256Digest;
/// let forged = RedeemedCode {
///     code: "never-issued",
///     code_expires_at: u64::MAX,
///     subject: "victim",
///     client_id: "allowed-client",
///     resource: "https://edge.example/mcp",
///     scopes: &[],
///     sender_constraint: None,
///     token_exp: u64::MAX,
///     request_digest: Sha256Digest::from_bytes([0; 32]),
/// };
/// ```
///
/// ```compile_fail,E0616
/// use chio_mcp_remote::root_exchange::kinds::local_as::RedeemedCode;
/// fn retarget(code: &mut RedeemedCode) {
///     code.subject = "victim".into();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RedeemedCode {
    code_digest: Sha256Digest,
    issuer: String,
    subject: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
    issued_at: u64,
    code_expires_at: u64,
    token_exp: u64,
    request_digest: Sha256Digest,
}

/// What a passed local authorization code redemption establishes.
pub(crate) struct CodeRedemption<'a> {
    pub(crate) code: &'a str,
    /// The `iss` of the local authorization server that redeemed the code.
    pub(crate) issuer: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) redirect_uri: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) scopes: &'a [String],
    /// The sender constraint the authorization request bound to the code.
    pub(crate) sender_constraint: Option<&'a ChioSenderConstraintClaims>,
    /// The `iat` of the access token issued for the code.
    pub(crate) issued_at: u64,
    /// Unix seconds from which the code is no longer redeemable.
    pub(crate) code_expires_at: u64,
    /// The `exp` of the access token issued for the code.
    pub(crate) token_exp: u64,
}

#[derive(Serialize)]
struct CodeRequestDigestInput<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
    resource: &'a str,
}

impl RedeemedCode {
    /// The redeemed code of a redemption the local authorization server
    /// passed. Its request digest covers the code digest, redirect URI,
    /// client and resource the redemption checked.
    pub(crate) fn from_redemption(
        redemption: CodeRedemption<'_>,
    ) -> Result<Self, RootExchangeError> {
        let code_digest = Sha256Digest::from_hash(sha256(redemption.code.as_bytes()));
        let code_hex = code_digest.to_bare_hex();
        let canonical = chio_core::canonical_json_bytes(&CodeRequestDigestInput {
            grant_type: "authorization_code",
            code: &code_hex,
            redirect_uri: redemption.redirect_uri,
            client_id: redemption.client_id,
            resource: redemption.resource,
        })
        .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        Ok(Self {
            code_digest,
            issuer: redemption.issuer.to_owned(),
            subject: redemption.subject.to_owned(),
            client_id: redemption.client_id.to_owned(),
            resource: redemption.resource.to_owned(),
            scopes: redemption.scopes.to_vec(),
            sender_constraint: redemption.sender_constraint.cloned(),
            issued_at: redemption.issued_at,
            code_expires_at: redemption.code_expires_at,
            token_exp: redemption.token_exp,
            request_digest: Sha256Digest::of_domain(CODE_REQUEST_DIGEST_DOMAIN, &canonical),
        })
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    #[must_use]
    pub fn sender_constraint(&self) -> Option<&ChioSenderConstraintClaims> {
        self.sender_constraint.as_ref()
    }

    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub fn token_exp(&self) -> u64 {
        self.token_exp
    }

    #[must_use]
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
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
    /// The requested OAuth scope values, a subset of the subject token's.
    pub scope: Option<&'a [String]>,
    pub resource: Option<&'a str>,
    pub client_id: Option<&'a str>,
    /// The requested root capability scope, a subset of the subject root's.
    pub root_scope: Option<&'a ChioScope>,
    /// SHA-256 of the exact request body.
    pub request_digest: Sha256Digest,
}

/// A local access token whose signature, issuer, lifetime and sender
/// constraint verified.
struct LocalToken {
    claims: Map<String, Value>,
    jti: String,
    iat: u64,
    principal: String,
    token_digest: Sha256Digest,
    sender_constraint: Option<ChioSenderConstraintClaims>,
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
    let sender_constraint = super::sender::check(claims, sender.0)?;
    Ok(LocalToken {
        jti: required_string(claims, "jti")?.to_owned(),
        principal: required_string(claims, "sub")?.to_owned(),
        claims: claims.clone(),
        iat,
        token_digest: Sha256Digest::from_hash(sha256(token.as_bytes())),
        sender_constraint,
    })
}

/// Verify the authorization `code` that `server` redeemed for `sender`, at
/// `now` (Unix seconds), for the root the access token issued for it names.
pub fn verify_issue(
    server: &LocalAuthorizationServer<'_>,
    code: &RedeemedCode,
    sender: PresentedSender<'_>,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    if code.issuer != server.issuer {
        return Err(RootExchangeError::IssuerMismatch);
    }
    if now >= code.code_expires_at {
        return Err(RootExchangeError::AssertionExpired);
    }
    if code.issued_at > now {
        return Err(RootExchangeError::AssertionIssuedInFuture);
    }
    if code.token_exp <= now {
        return Err(RootExchangeError::ClaimInvalid("exp"));
    }
    super::sender::check_constraint(code.sender_constraint.as_ref(), sender.0)?;
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), Value::String(code.issuer.clone()));
    claims.insert("sub".to_owned(), Value::String(code.subject.clone()));
    claims.insert("aud".to_owned(), Value::String(code.resource.clone()));
    claims.insert(
        "client_id".to_owned(),
        Value::String(code.client_id.clone()),
    );
    claims.insert("resource".to_owned(), Value::String(code.resource.clone()));
    if !code.scopes.is_empty() {
        claims.insert("scope".to_owned(), Value::String(code.scopes.join(" ")));
    }
    claims.insert("iat".to_owned(), Value::from(code.issued_at));
    claims.insert("exp".to_owned(), Value::from(code.token_exp));
    let principal = required_string(&claims, "sub")?.to_owned();
    required_string(&claims, "client_id")?;
    required_string(&claims, "resource")?;
    let scope_values = scope_values(&claims)?;
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey::new(
            ReplayNamespace::LocalAsIssue,
            LOCAL_AS_ISSUER,
            code.code_digest.to_bare_hex(),
        )?,
        issuer: LOCAL_AS_ISSUER.to_owned(),
        principal,
        tenant: server.issuer.to_owned(),
        token_iat: code.issued_at,
        token_exp: code.token_exp,
        jws: None,
        artifact_digest: Some(code.code_digest),
        request_digest: code.request_digest,
        claims,
        scope_values,
        provider_id: None,
        scope_bound: None,
        holder: None,
        sender_constraint: code.sender_constraint.clone(),
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
    let root_scope = match request.root_scope {
        Some(narrowed) if !narrowed.is_subset_of(subject_root.scope) => {
            return Err(RootExchangeError::ReExchangeWidens);
        }
        Some(narrowed) => narrowed.clone(),
        None => subject_root.scope.clone(),
    };
    let mut claims = local.claims;
    if let Some(requested) = request.scope {
        claims.insert("scope".to_owned(), Value::String(requested.join(" ")));
    }
    let scope_values = scope_values(&claims)?;
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey::new(ReplayNamespace::Assertion(KIND), LOCAL_AS_ISSUER, local.jti)?,
        issuer: LOCAL_AS_ISSUER.to_owned(),
        principal: local.principal,
        tenant: server.issuer.to_owned(),
        token_iat: local.iat,
        token_exp: subject_root.assertion_exp,
        jws: None,
        artifact_digest: Some(local.token_digest),
        request_digest: request.request_digest,
        claims,
        scope_values,
        provider_id: None,
        scope_bound: Some(root_scope),
        holder: None,
        sender_constraint: local.sender_constraint,
    })
}
