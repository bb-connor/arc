//! Token requests that carry an ID-JAG.

use chio_core::root_authority::Sha256Digest;
use chio_core::sha256;

use super::client_auth::ClientCredentials;
use super::error::RootExchangeError;

pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Upper bound on a token request body.
pub const MAX_TOKEN_REQUEST_BYTES: usize = 32 * 1024;

const PARAMETERS: [&str; 8] = [
    "grant_type",
    "assertion",
    "subject_token",
    "subject_token_type",
    "requested_token_type",
    "client_id",
    "client_assertion_type",
    "client_assertion",
];

/// A token request presenting an ID-JAG, by either grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagGrant {
    id_jag: String,
    client_id: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    request_digest: Sha256Digest,
}

impl IdJagGrant {
    /// Parse an `application/x-www-form-urlencoded` token request.
    ///
    /// Per RFC 6749 section 3.2, unrecognized parameters are ignored, and per
    /// section 3.1 a parameter sent without a value is treated as omitted. A
    /// repeated recognized parameter, a recognized value that is not valid
    /// UTF-8, or an unsupported grant, subject token type or requested token
    /// type refuses.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        if body.len() > MAX_TOKEN_REQUEST_BYTES {
            return Err(RootExchangeError::MalformedRequest(
                "body exceeds the size bound",
            ));
        }
        let mut values: [Option<String>; 8] = Default::default();
        for (name, value) in url::form_urlencoded::parse(body) {
            let Some(index) = PARAMETERS.iter().position(|known| *known == name) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            if value.contains(char::REPLACEMENT_CHARACTER) {
                return Err(RootExchangeError::MalformedRequest(
                    "parameter is not valid UTF-8",
                ));
            }
            let Some(slot) = values.get_mut(index) else {
                continue;
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(RootExchangeError::MalformedRequest("repeated parameter"));
            }
        }
        let [grant_type, assertion, subject_token, subject_token_type, requested_token_type, client_id, client_assertion_type, client_assertion] =
            values;
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
                if requested_token_type
                    .as_deref()
                    .is_some_and(|requested| requested != TOKEN_TYPE_ACCESS_TOKEN)
                {
                    return Err(RootExchangeError::UnsupportedRequestedTokenType);
                }
                subject_token.ok_or(RootExchangeError::MalformedRequest(
                    "subject_token is missing",
                ))?
            }
            _ => return Err(RootExchangeError::UnsupportedGrantType),
        };
        Ok(Self {
            id_jag,
            client_id,
            client_assertion_type,
            client_assertion,
            request_digest: Sha256Digest::from_hash(sha256(body)),
        })
    }

    /// The presented ID-JAG compact JWS.
    #[must_use]
    pub fn id_jag(&self) -> &str {
        &self.id_jag
    }

    /// SHA-256 of the exact request body.
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
