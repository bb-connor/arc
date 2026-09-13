//! The wire shape a receiver in the composed alternative sees, assembled out of
//! shipped formats.
//!
//! One call is an A2A `SendMessageRequest` whose single data part carries an
//! MCP `tools/call` request, presented over a channel the caller authenticated
//! with an X509-SVID, accompanied by the credential an RFC 8693 token exchange
//! issued. Nothing here is a shape this project chose: `src/spec.rs` carries
//! the field-by-field inventory, and the corpora check the serialized request
//! against it.
//!
//! Two facts about this assembly decide most of what follows. The credential's
//! signature covers its own claim set and nothing else, and no format in the
//! set defines a signature over the message or the tool call, so the body is
//! covered only by the channel, which is the caller. A value therefore reaches
//! the receiver attested either by the caller or by the caller's own
//! authorization server, and `spec::AttestedBy` records which for every slot.

use crate::jose::{sign_compact, CompactJws};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The MCP revision this alternative speaks. Every request carries it, because
/// the specification requires it on every request.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
pub const JSONRPC_VERSION: &str = "2.0";
pub const MCP_METHOD_TOOLS_CALL: &str = "tools/call";

/// Token type identifiers, RFC 8693 section 3.
pub const ISSUED_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const ISSUED_TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const TOKEN_TYPE_BEARER: &str = "Bearer";

/// JOSE header values. `EdDSA` is the JOSE identifier for Ed25519.
pub const JOSE_ALG: &str = "EdDSA";
pub const JOSE_TYP: &str = "JWT";

/// The media type of a part carrying a JSON-RPC request.
pub const PART_MEDIA_TYPE: &str = "application/json";

/// Scope values this deployment's two organizations agreed. RFC 6749 gives the
/// syntax of `scope` and leaves the values to the authorization server, so
/// these strings are an operator convention and are recorded as one in the
/// carrier ledger.
pub const SCOPE_AGREEMENT_PREFIX: &str = "agreement:";
pub const SCOPE_AGREEMENT_VERSION_PREFIX: &str = "agreement-version:";
pub const SCOPE_ACTION_PREFIX: &str = "action:";

/// A2A `Role`, in the protojson encoding of the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2aRole {
    #[serde(rename = "ROLE_USER")]
    User,
    #[serde(rename = "ROLE_AGENT")]
    Agent,
}

/// A2A `Part`. The `data` variant of the content oneof carries the tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct A2aPart {
    pub data: Value,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub media_type: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, Value>,
}

/// A2A `Message`. `message_id` is created by the message creator;
/// `context_id` and `task_id` name records the server generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct A2aMessage {
    pub message_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub context_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub task_id: String,
    pub role: A2aRole,
    pub parts: Vec<A2aPart>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reference_task_ids: Vec<String>,
}

/// A2A `SendMessageConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct A2aSendMessageConfiguration {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub accepted_output_modes: Vec<String>,
    pub return_immediately: bool,
}

/// A2A `SendMessageRequest`, the body of `message:send`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct A2aSendMessageRequest {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub tenant: String,
    pub message: A2aMessage,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub configuration: Option<A2aSendMessageConfiguration>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, Value>,
}

/// The params of an MCP `tools/call` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCallToolParams {
    pub name: String,
    pub arguments: Value,
    /// Reserved by MCP for metadata. Required protocol fields live here, and
    /// so does anything an operator adds under a vendor prefix.
    #[serde(rename = "_meta", skip_serializing_if = "BTreeMap::is_empty", default)]
    pub meta: BTreeMap<String, Value>,
}

/// One MCP request, as JSON-RPC 2.0 carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: McpCallToolParams,
}

/// The actor claim of RFC 8693 section 4.1: the party to whom authority has
/// been delegated. Nesting expresses a chain, outermost being the current
/// actor; only identity claims belong inside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorClaim {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub iss: Option<String>,
    /// A further delegation step, if the chain is longer than one hop.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub act: Option<Box<ActorClaim>>,
}

/// The claim set of the issued token: the registered claims of RFC 7519 plus
/// the three RFC 8693 defines. Timestamps are NumericDate, in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenClaims {
    pub iss: String,
    /// The subject the authority belongs to, as a SPIFFE ID.
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub jti: String,
    /// Space-delimited scope values, RFC 6749 section 3.3.
    pub scope: String,
    pub client_id: String,
    pub act: ActorClaim,
}

impl TokenClaims {
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split(' ').filter(|value| !value.is_empty())
    }

    /// The value of the first scope carrying `prefix`, if any.
    pub fn scope_value(&self, prefix: &str) -> Option<&str> {
        self.scopes().find_map(|value| value.strip_prefix(prefix))
    }
}

/// The JOSE header of the issued token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoseHeader {
    pub alg: String,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
}

impl JoseHeader {
    pub fn ed25519(kid: &str) -> Self {
        Self {
            alg: JOSE_ALG.to_string(),
            typ: JOSE_TYP.to_string(),
            kid: Some(kid.to_string()),
        }
    }
}

/// A successful token exchange response, RFC 8693 section 2.2.1. The receiver
/// reads `access_token`; the rest is what the caller's exchange returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

impl TokenExchangeResponse {
    pub fn compact(&self) -> Result<CompactJws, crate::jose::JoseError> {
        CompactJws::parse(&self.access_token)
    }
}

/// One call as it reaches the receiver: the message body, the credential the
/// transport presented with it, and what the channel proved about the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedEnvelope {
    pub request: A2aSendMessageRequest,
    /// Absent when the case under test presents no credential, which is what a
    /// caller has after its authorization server refuses the exchange.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential: Option<TokenExchangeResponse>,
    /// The SPIFFE ID in the URI SAN of the X509-SVID the peer presented.
    pub peer_spiffe_id: String,
    /// Possession of the private key of that SVID, over the canonical encoding
    /// of `request`. This stands for mutual TLS: the receiver knows the bytes
    /// reached it from the holder of that key. It is a channel property, not a
    /// signature a third party could check later, and no format in the set
    /// defines one that is.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub channel_proof: Option<String>,
}

impl ComposedEnvelope {
    /// The MCP request inside the message's first data part, if it is one.
    pub fn tool_call(&self) -> Option<McpRequest> {
        let part = self.request.message.parts.first()?;
        serde_json::from_value::<McpRequest>(part.data.clone()).ok()
    }

    /// Byte size of what crosses the wire for this call: the message body plus
    /// the credential the transport carries beside it.
    pub fn wire_bytes(&self) -> Result<usize, serde_json::Error> {
        let body = serde_json::to_vec(&self.request)?.len();
        let credential = self
            .credential
            .as_ref()
            .map(|credential| credential.access_token.len())
            .unwrap_or(0);
        Ok(body + credential)
    }
}

/// Build a credential from a claim set. `raw_claims` overrides the encoded
/// payload, so a case can transmit bytes that parse to something other than
/// their canonical form.
pub fn issue_credential(
    header: &JoseHeader,
    claims: &TokenClaims,
    raw_claims: Option<Vec<u8>>,
    signer: &chio_core_types::crypto::Keypair,
) -> Result<TokenExchangeResponse, String> {
    let header_bytes =
        chio_core_types::crypto::canonical_json_bytes(header).map_err(|error| error.to_string())?;
    let claims_bytes = match raw_claims {
        Some(raw) => raw,
        None => chio_core_types::crypto::canonical_json_bytes(claims)
            .map_err(|error| error.to_string())?,
    };
    Ok(TokenExchangeResponse {
        access_token: sign_compact(&header_bytes, &claims_bytes, signer),
        issued_token_type: ISSUED_TOKEN_TYPE_JWT.to_string(),
        token_type: TOKEN_TYPE_BEARER.to_string(),
        expires_in: claims.exp.saturating_sub(claims.iat),
        scope: claims.scope.clone(),
    })
}
