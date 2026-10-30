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
    pub tenant_value: Identifier,
    pub scope: ChioScope,
    pub holder: HolderClass,
    pub expires_at: u64,
}

impl OperatorRootRequest {
    /// Decode a request body strictly: a body over the size bound, a
    /// repeated member, an absent `tenant_value`, or an unknown or ill-typed
    /// member refuses.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        Self::from_members(decode_document(body)?)
    }

    /// The request held by an admitted JSON object; an absent `tenant_value`
    /// refuses with its own typed refusal before the object is decoded.
    fn from_members(members: Map<String, Value>) -> Result<Self, RootExchangeError> {
        if !members.contains_key("tenant_value") {
            return Err(RootExchangeError::OperatorRootRequestMissingTenant);
        }
        serde_json::from_value::<OperatorRootRequest>(Value::Object(members)).map_err(|_| {
            RootExchangeError::OperatorRootRequestMalformed("body does not have the request shape")
        })
    }

    fn signing_body(&self) -> OperatorRootRequestSigningBody<'_> {
        OperatorRootRequestSigningBody {
            schema: CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            request_id: &self.request_id,
            principal: &self.principal,
            tenant_value: &self.tenant_value,
            scope: &self.scope,
            holder: self.holder,
            expires_at: self.expires_at,
        }
    }
}

fn decode_document(body: &[u8]) -> Result<Map<String, Value>, RootExchangeError> {
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
    tenant_value: &'a Identifier,
    scope: &'a ChioScope,
    holder: HolderClass,
    expires_at: u64,
}

/// A `chio.operator-root-request.v1`: the request members, `schema`, and
/// the operator's `signature` over the canonical JSON of the rest.
///
/// The signed body is kept exactly as received (every member except
/// `signature`), so the signature and the request digest cover what the
/// operator signed; the typed request is decoded from the same members and
/// only enforces their shape.
#[derive(Debug, Clone)]
pub struct SignedOperatorRootRequest {
    request: OperatorRootRequest,
    signed_body: Map<String, Value>,
    signed_canonical: Vec<u8>,
    signature: Signature,
}

impl SignedOperatorRootRequest {
    /// Sign `request` with the operator key `backend` holds. A request whose
    /// signed form would exceed [`MAX_OPERATOR_ROOT_REQUEST_BYTES`] refuses,
    /// since no reader would admit it.
    pub fn sign(
        request: OperatorRootRequest,
        backend: &dyn SigningBackend,
    ) -> Result<Self, RootExchangeError> {
        let Value::Object(signed_body) = serde_json::to_value(request.signing_body())
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?
        else {
            return Err(RootExchangeError::Canonicalization(
                "signing body is not a JSON object".to_owned(),
            ));
        };
        let (outcome, canonical) = sign_wrapped(
            backend,
            CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            &Value::Object(signed_body.clone()),
        )
        .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        let signed = Self {
            request,
            signed_body,
            signed_canonical: canonical.into_vec(),
            signature: outcome.signature,
        };
        if signed.to_canonical_json()?.len() > MAX_OPERATOR_ROOT_REQUEST_BYTES {
            return Err(RootExchangeError::OperatorRootRequestMalformed(
                "signed request exceeds the size bound",
            ));
        }
        Ok(signed)
    }

    /// Decode a signed request strictly: the size bound, duplicate-free
    /// JSON, a `schema` member equal to `chio.operator-root-request.v1`, a
    /// canonical hex `signature`, a body with a canonical JSON form, and the
    /// request members with no other.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        let mut signed_body = decode_document(body)?;
        match signed_body.get("schema") {
            Some(Value::String(schema)) if schema == CHIO_OPERATOR_ROOT_REQUEST_SCHEMA => {}
            _ => {
                return Err(RootExchangeError::OperatorRootRequestMalformed(
                    "schema is not chio.operator-root-request.v1",
                ))
            }
        }
        let signature = match signed_body.remove("signature") {
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
        let signed_canonical = chio_core::canonical_json_bytes(&signed_body).map_err(|_| {
            RootExchangeError::OperatorRootRequestMalformed("body has no canonical JSON form")
        })?;
        let mut members = signed_body.clone();
        members.remove("schema");
        let request = OperatorRootRequest::from_members(members)?;
        Ok(Self {
            request,
            signed_body,
            signed_canonical,
            signature,
        })
    }

    /// The canonical JSON of the signed request: the signed body and its
    /// `signature`.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, RootExchangeError> {
        let mut wire = self.signed_body.clone();
        wire.insert(
            "signature".to_owned(),
            Value::String(self.signature.to_hex()),
        );
        chio_core::canonical_json_bytes(&wire)
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))
    }

    /// Verify the signature over the signed body as received, under
    /// `pinned_operator_key`, the key the operator configured; the request
    /// carries no key of its own.
    pub fn verify(
        self,
        pinned_operator_key: &PublicKey,
    ) -> Result<VerifiedOperatorRootRequest, RootExchangeError> {
        match verify_wrapped(
            pinned_operator_key,
            CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
            &self.signed_body,
            &self.signature,
        ) {
            Ok(()) => {}
            Err(
                chio_core::Error::SignatureRejected
                | chio_core::Error::SignatureAlgorithmMismatch { .. },
            ) => return Err(RootExchangeError::OperatorRootRequestSignatureInvalid),
            Err(error) => return Err(RootExchangeError::Canonicalization(error.to_string())),
        }
        Ok(VerifiedOperatorRootRequest {
            request: self.request,
            request_digest: Sha256Digest::from_hash(chio_core::sha256(&self.signed_canonical)),
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
pub fn verify(
    verified: &VerifiedOperatorRootRequest,
    now: u64,
) -> Result<AnchorEvidence, RootExchangeError> {
    let request = &verified.request;
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
        tenant: request.tenant_value.as_str().to_owned(),
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
