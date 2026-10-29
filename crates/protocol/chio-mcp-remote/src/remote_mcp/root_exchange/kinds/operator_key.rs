//! `chio_operator_key`: an operator root request through the admin route.
//!
//! The request names its `request_id`, `principal`, `tenant_value`,
//! `scope`, `holder` and `expires_at`. Its signature verifies against the
//! pinned `--operator-key` under the signing wrapper's
//! `chio.operator-root-request.v1` id; only a verified request yields
//! evidence. The replay key is the request id, the issuer
//! `urn:chio:operator-key`, the root scope the requested scope within the
//! rule ceiling, and the request's `expires_at` its assertion expiry.

use chio_core::canonical::UntrustedJsonError;
use chio_core::capability::anchor::AnchorKind;
use chio_core::capability::scope::ChioScope;
use chio_core::crypto::{sign_wrapped, verify_wrapped, PublicKey, Signature, SigningBackend};
use chio_core::root_authority::{HolderClass, Identifier, Sha256Digest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::replay::{ReplayKey, ReplayNamespace};

const KIND: AnchorKind = AnchorKind::ChioOperatorKey;

/// Issuer recorded for `chio_operator_key` roots.
pub const OPERATOR_KEY_ISSUER: &str = "urn:chio:operator-key";

/// Signing-wrapper schema id of a signed operator root request.
pub const CHIO_OPERATOR_ROOT_REQUEST_SCHEMA: &str = "chio.operator-root-request.v1";

/// Upper bound on an operator root request body, signed or unsigned.
pub const MAX_OPERATOR_ROOT_REQUEST_BYTES: usize = 64 * 1024;

/// The body of an operator root request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRootRequest {
    pub request_id: Identifier,
    pub principal: Identifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_value: Option<Identifier>,
    pub scope: ChioScope,
    pub holder: HolderClass,
    pub expires_at: u64,
}

impl OperatorRootRequest {
    /// Decode a request body strictly: a body over the size bound, a
    /// repeated member, or an unknown or ill-typed member refuses.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        decode_document(body)
    }

    fn signing_body(&self) -> OperatorRootRequestSigningBody<'_> {
        OperatorRootRequestSigningBody {
            schema: CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            request_id: &self.request_id,
            principal: &self.principal,
            tenant_value: self.tenant_value.as_ref(),
            scope: &self.scope,
            holder: self.holder,
            expires_at: self.expires_at,
        }
    }
}

fn decode_document<T: DeserializeOwned>(body: &[u8]) -> Result<T, RootExchangeError> {
    crate::input::document(body, MAX_OPERATOR_ROOT_REQUEST_BYTES).map_err(|error| {
        RootExchangeError::OperatorRootRequestMalformed(match error {
            UntrustedJsonError::TooLarge { .. } => "body exceeds the size bound",
            UntrustedJsonError::Decode(_) => "body does not have the request shape",
            _ => "body is not duplicate-free UTF-8 JSON",
        })
    })
}

/// What the operator signs: every member of the signed request except
/// `signature`.
#[derive(Serialize)]
struct OperatorRootRequestSigningBody<'a> {
    schema: &'static str,
    request_id: &'a Identifier,
    principal: &'a Identifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_value: Option<&'a Identifier>,
    scope: &'a ChioScope,
    holder: HolderClass,
    expires_at: u64,
}

#[derive(Serialize)]
struct SignedOperatorRootRequestWire<'a> {
    schema: &'static str,
    request_id: &'a Identifier,
    principal: &'a Identifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_value: Option<&'a Identifier>,
    scope: &'a ChioScope,
    holder: HolderClass,
    expires_at: u64,
    signature: &'a Signature,
}

/// A `chio.operator-root-request.v1`: the request members, `schema`, and
/// the operator's `signature` over the canonical JSON of the rest.
#[derive(Debug, Clone)]
pub struct SignedOperatorRootRequest {
    request: OperatorRootRequest,
    signature: Signature,
}

impl SignedOperatorRootRequest {
    /// Sign `request` with the operator key `backend` holds. A request
    /// without `tenant_value` refuses before any signing call.
    pub fn sign(
        request: OperatorRootRequest,
        backend: &dyn SigningBackend,
    ) -> Result<Self, RootExchangeError> {
        if request.tenant_value.is_none() {
            return Err(RootExchangeError::OperatorRootRequestMissingTenant);
        }
        let (outcome, _) = sign_wrapped(
            backend,
            CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            &request.signing_body(),
        )
        .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        Ok(Self {
            request,
            signature: outcome.signature,
        })
    }

    /// Decode a signed request strictly: the size bound, duplicate-free
    /// JSON, a `schema` member equal to `chio.operator-root-request.v1`, a
    /// canonical hex `signature`, and the request members with no other.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        let mut members: Map<String, Value> = decode_document(body)?;
        match members.remove("schema") {
            Some(Value::String(schema)) if schema == CHIO_OPERATOR_ROOT_REQUEST_SCHEMA => {}
            _ => {
                return Err(RootExchangeError::OperatorRootRequestMalformed(
                    "schema is not chio.operator-root-request.v1",
                ))
            }
        }
        let signature = match members.remove("signature") {
            None => {
                return Err(RootExchangeError::OperatorRootRequestMalformed(
                    "signature is missing",
                ))
            }
            Some(Value::String(text)) => Signature::from_hex(&text)
                .ok()
                .filter(|signature| signature.to_hex() == text),
            Some(_) => None,
        }
        .ok_or(RootExchangeError::OperatorRootRequestMalformed(
            "signature is not a canonical hex signature",
        ))?;
        let request = serde_json::from_value::<OperatorRootRequest>(Value::Object(members))
            .map_err(|_| {
                RootExchangeError::OperatorRootRequestMalformed(
                    "body does not have the request shape",
                )
            })?;
        Ok(Self { request, signature })
    }

    /// The canonical JSON of the signed request.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, RootExchangeError> {
        let request = &self.request;
        chio_core::canonical_json_bytes(&SignedOperatorRootRequestWire {
            schema: CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            request_id: &request.request_id,
            principal: &request.principal,
            tenant_value: request.tenant_value.as_ref(),
            scope: &request.scope,
            holder: request.holder,
            expires_at: request.expires_at,
            signature: &self.signature,
        })
        .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))
    }

    /// Verify the signature under `pinned_operator_key`, the key the
    /// operator configured; the request carries no key of its own.
    pub fn verify(
        self,
        pinned_operator_key: &PublicKey,
    ) -> Result<VerifiedOperatorRootRequest, RootExchangeError> {
        let body = self.request.signing_body();
        match verify_wrapped(
            pinned_operator_key,
            CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            &body,
            &self.signature,
        ) {
            Ok(()) => {}
            Err(
                chio_core::Error::SignatureRejected
                | chio_core::Error::SignatureAlgorithmMismatch { .. },
            ) => return Err(RootExchangeError::OperatorRootRequestSignatureInvalid),
            Err(error) => return Err(RootExchangeError::Canonicalization(error.to_string())),
        }
        let signed_bytes = chio_core::canonical_json_bytes(&body)
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        let request_digest = Sha256Digest::from_hash(chio_core::sha256(&signed_bytes));
        Ok(VerifiedOperatorRootRequest {
            request: self.request,
            request_digest,
        })
    }
}

/// An operator root request whose signature verified against the pinned
/// operator key, with the digest of its signed bytes.
#[derive(Debug, Clone)]
pub struct VerifiedOperatorRootRequest {
    request: OperatorRootRequest,
    request_digest: Sha256Digest,
}

impl VerifiedOperatorRootRequest {
    /// Wrap a request the operator-key verifier accepted, given the exact
    /// signed bytes.
    #[cfg(test)]
    pub(in crate::root_exchange) fn from_verified(
        request: OperatorRootRequest,
        signed_bytes: &[u8],
    ) -> Self {
        Self {
            request,
            request_digest: Sha256Digest::from_hash(chio_core::sha256(signed_bytes)),
        }
    }

    #[must_use]
    pub fn request(&self) -> &OperatorRootRequest {
        &self.request
    }

    /// SHA-256 of the canonical JSON the operator signed.
    #[must_use]
    pub fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
}

/// Evidence of a verified operator root request at `now` (Unix seconds).
///
/// A request without `tenant_value` refuses: the delegation context commits
/// a tenant for every root.
pub fn verify(
    verified: &VerifiedOperatorRootRequest,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    let request = &verified.request;
    let tenant = request
        .tenant_value
        .as_ref()
        .ok_or(RootExchangeError::OperatorRootRequestMissingTenant)?;
    if request.expires_at <= now {
        return Err(RootExchangeError::RootLifetimeEmpty);
    }
    Ok(AnchorEvidence {
        kind: KIND,
        replay_key: ReplayKey {
            namespace: ReplayNamespace::Assertion(KIND),
            issuer: OPERATOR_KEY_ISSUER.to_owned(),
            id: request.request_id.as_str().to_owned(),
        },
        issuer: OPERATOR_KEY_ISSUER.to_owned(),
        principal: request.principal.as_str().to_owned(),
        tenant: tenant.as_str().to_owned(),
        token_iat: now,
        token_exp: request.expires_at,
        jws: None,
        artifact_digest: None,
        request_digest: verified.request_digest,
        claims: Map::new(),
        scope_values: Vec::new(),
        provider_id: None,
        scope_bound: Some(request.scope.clone()),
        holder: Some(request.holder),
        sender_constraint: None,
    })
}
