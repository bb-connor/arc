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
use chio_core::root_authority::{HolderClass, Identifier, Sha256Digest};
use serde::Deserialize;
use serde_json::Map;

use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::replay::{ReplayKey, ReplayNamespace};

const KIND: AnchorKind = AnchorKind::ChioOperatorKey;

/// Issuer recorded for `chio_operator_key` roots.
pub const OPERATOR_KEY_ISSUER: &str = "urn:chio:operator-key";

/// Upper bound on an operator root request body.
pub const MAX_OPERATOR_ROOT_REQUEST_BYTES: usize = 64 * 1024;

/// The body of an operator root request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRootRequest {
    pub request_id: Identifier,
    pub principal: Identifier,
    #[serde(default)]
    pub tenant_value: Option<Identifier>,
    pub scope: ChioScope,
    pub holder: HolderClass,
    pub expires_at: u64,
}

impl OperatorRootRequest {
    /// Decode a request body strictly: a body over the size bound, a
    /// repeated member, or an unknown or ill-typed member refuses.
    pub fn parse(body: &[u8]) -> Result<Self, RootExchangeError> {
        crate::input::document(body, MAX_OPERATOR_ROOT_REQUEST_BYTES).map_err(|error| {
            RootExchangeError::OperatorRequestMalformed(match error {
                UntrustedJsonError::TooLarge { .. } => "body exceeds the size bound",
                UntrustedJsonError::Decode(_) => "body does not have the request shape",
                _ => "body is not duplicate-free UTF-8 JSON",
            })
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
        .ok_or(RootExchangeError::OperatorRequestTenantMissing)?;
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
    })
}
