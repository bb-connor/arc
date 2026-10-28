//! Token requests that carry an ID-JAG.

use chio_core::root_authority::Sha256Digest;

use super::claims::is_scope_token;
use super::client_auth::ClientCredentials;
use super::error::RootExchangeError;

pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const TOKEN_TYPE_CHIO_CAPABILITY: &str = "urn:chio:params:oauth:token-type:capability-v1";

const REQUEST_DIGEST_DOMAIN: &[u8] = b"chio.root-exchange-request.v1\0";

/// What the token response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedTokenType {
    /// A local access token naming the root (the default).
    AccessToken,
    /// The canonical root capability itself.
    ChioCapability,
}

/// Upper bound on a token request body.
pub const MAX_TOKEN_REQUEST_BYTES: usize = 32 * 1024;

const PARAMETERS: [&str; 11] = [
    "grant_type",
    "assertion",
    "subject_token",
    "subject_token_type",
    "requested_token_type",
    "scope",
    "client_id",
    "client_assertion_type",
    "client_assertion",
    "client_secret",
    "resource",
];

/// A token request presenting an ID-JAG, by either grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagGrant {
    id_jag: String,
    client_id: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    requested_token_type: RequestedTokenType,
    requested_scope: Option<Vec<String>>,
    resource: Option<String>,
    request_digest: Sha256Digest,
}

/// The request members the digest binds. Client authentication is excluded,
/// so a retry with a fresh client assertion names the same request.
#[derive(serde::Serialize)]
struct RequestDigestInput<'a> {
    grant_type: &'a str,
    id_jag: &'a str,
    requested_token_type: RequestedTokenType,
    scope: Option<&'a [String]>,
    client_id: Option<&'a str>,
    resource: Option<&'a str>,
}

/// The values of an RFC 6749 section 3.3 `scope`: scope tokens separated by
/// single spaces.
fn scope_tokens(scope: &str) -> Result<Vec<String>, RootExchangeError> {
    scope
        .split(' ')
        .map(|token| {
            if is_scope_token(token) {
                Ok(token.to_owned())
            } else {
                Err(RootExchangeError::RequestedScopeMalformed)
            }
        })
        .collect()
}

/// Whether an `Authorization` header value uses the HTTP Basic scheme, the
/// carrier of `client_secret_basic` (RFC 6749 section 2.3.1).
fn is_http_basic(authorization: &[u8]) -> bool {
    authorization
        .split(|byte| *byte == b' ')
        .next()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"Basic"))
}

impl IdJagGrant {
    /// Parse an `application/x-www-form-urlencoded` token request together
    /// with the request's `Authorization` header, if any.
    ///
    /// Per RFC 6749 section 3.2, unrecognized parameters are ignored, and per
    /// section 3.1 a parameter sent without a value is treated as omitted. A
    /// recognized parameter that appears twice refuses, even when one
    /// occurrence is empty. A recognized value that is not valid UTF-8, a
    /// `scope` outside the section 3.3 syntax, a `client_secret` or HTTP Basic
    /// credentials next to a `client_assertion` (section 2.3: one
    /// authentication method per request), or an unsupported grant, subject
    /// token type or requested token type refuses.
    pub fn parse(body: &[u8], authorization: Option<&[u8]>) -> Result<Self, RootExchangeError> {
        if body.len() > MAX_TOKEN_REQUEST_BYTES {
            return Err(RootExchangeError::MalformedRequest(
                "body exceeds the size bound",
            ));
        }
        let mut seen = [false; PARAMETERS.len()];
        let mut values: [Option<String>; PARAMETERS.len()] = Default::default();
        for (name, value) in url::form_urlencoded::parse(body) {
            let Some(index) = PARAMETERS.iter().position(|known| *known == name) else {
                continue;
            };
            let (Some(was_seen), Some(slot)) = (seen.get_mut(index), values.get_mut(index)) else {
                continue;
            };
            if std::mem::replace(was_seen, true) {
                return Err(RootExchangeError::MalformedRequest("repeated parameter"));
            }
            if value.is_empty() {
                continue;
            }
            if value.contains(char::REPLACEMENT_CHARACTER) {
                return Err(RootExchangeError::MalformedRequest(
                    "parameter is not valid UTF-8",
                ));
            }
            *slot = Some(value.into_owned());
        }
        let [grant_type, assertion, subject_token, subject_token_type, requested_token_type, scope, client_id, client_assertion_type, client_assertion, client_secret, resource] =
            values;
        if client_assertion.is_some()
            && (client_secret.is_some() || authorization.is_some_and(is_http_basic))
        {
            return Err(RootExchangeError::ClientAuthenticationAmbiguous);
        }
        let requested_scope = scope.as_deref().map(scope_tokens).transpose()?;
        let mut requested = RequestedTokenType::AccessToken;
        let id_jag = match grant_type.as_deref() {
            Some(GRANT_TYPE_JWT_BEARER) => {
                if subject_token.is_some()
                    || subject_token_type.is_some()
                    || requested_token_type.is_some()
                {
                    return Err(RootExchangeError::MalformedRequest(
                        "token-exchange parameter on a jwt-bearer grant",
                    ));
                }
                assertion.ok_or(RootExchangeError::MalformedRequest("assertion is missing"))?
            }
            Some(GRANT_TYPE_TOKEN_EXCHANGE) => {
                if assertion.is_some() {
                    return Err(RootExchangeError::MalformedRequest(
                        "assertion on a token-exchange grant",
                    ));
                }
                if subject_token_type.as_deref() != Some(TOKEN_TYPE_ID_JAG) {
                    return Err(RootExchangeError::UnsupportedSubjectTokenType);
                }
                requested = match requested_token_type.as_deref() {
                    None | Some(TOKEN_TYPE_ACCESS_TOKEN) => RequestedTokenType::AccessToken,
                    Some(TOKEN_TYPE_CHIO_CAPABILITY) => RequestedTokenType::ChioCapability,
                    Some(_) => return Err(RootExchangeError::UnsupportedRequestedTokenType),
                };
                subject_token.ok_or(RootExchangeError::MalformedRequest(
                    "subject_token is missing",
                ))?
            }
            _ => return Err(RootExchangeError::UnsupportedGrantType),
        };
        let digest_input = RequestDigestInput {
            grant_type: grant_type.as_deref().unwrap_or_default(),
            id_jag: &id_jag,
            requested_token_type: requested,
            scope: requested_scope.as_deref(),
            client_id: client_id.as_deref(),
            resource: resource.as_deref(),
        };
        let canonical = chio_core::canonical_json_bytes(&digest_input)
            .map_err(|_| RootExchangeError::MalformedRequest("request does not canonicalize"))?;
        let request_digest = Sha256Digest::of_domain(REQUEST_DIGEST_DOMAIN, &canonical);
        Ok(Self {
            id_jag,
            client_id,
            client_assertion_type,
            client_assertion,
            requested_token_type: requested,
            requested_scope,
            resource,
            request_digest,
        })
    }

    /// The presented ID-JAG compact JWS.
    #[must_use]
    pub fn id_jag(&self) -> &str {
        &self.id_jag
    }

    /// The requested `scope` values, absent when the request sent none.
    #[must_use]
    pub fn requested_scope(&self) -> Option<&[String]> {
        self.requested_scope.as_deref()
    }

    /// The RFC 8707 `resource` parameter, when present.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    #[must_use]
    pub fn requested_token_type(&self) -> RequestedTokenType {
        self.requested_token_type
    }

    /// `SHA-256("chio.root-exchange-request.v1\0" || canonical_json(request))`
    /// over the grant type, the ID-JAG, the requested token type, the
    /// requested scope, the client id and the RFC 8707 `resource`. Client
    /// authentication is not part of it.
    #[must_use]
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn client_credentials(&self) -> ClientCredentials<'_> {
        ClientCredentials {
            client_id: self.client_id.as_deref(),
            client_assertion_type: self.client_assertion_type.as_deref(),
            client_assertion: self.client_assertion.as_deref(),
        }
    }
}
