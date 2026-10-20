//! The `root_anchor` of a root capability and the closed set of anchor kinds.

use serde::{Deserialize, Serialize};

use crate::root_authority::Sha256Digest;

/// Domain prefix of `root_anchor.context_digest`.
pub const DELEGATION_CONTEXT_DIGEST_DOMAIN: &[u8] = b"chio.delegation-context.v1\0";

/// Domain prefix of `root_anchor.root_policy_digest`.
pub const ROOT_POLICY_DIGEST_DOMAIN: &[u8] = b"chio.root-policy.v1\0";

/// How a root capability was anchored. The set is closed; unknown kinds reject at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    OauthIdJag,
    EntraJwt,
    EntraAgentId,
    OidcJwt,
    OauthIntrospection,
    ChioLocalAs,
    ChioOperatorKey,
    OperatorStaticBearer,
}

impl AnchorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OauthIdJag => "oauth_id_jag",
            Self::EntraJwt => "entra_jwt",
            Self::EntraAgentId => "entra_agent_id",
            Self::OidcJwt => "oidc_jwt",
            Self::OauthIntrospection => "oauth_introspection",
            Self::ChioLocalAs => "chio_local_as",
            Self::ChioOperatorKey => "chio_operator_key",
            Self::OperatorStaticBearer => "operator_static_bearer",
        }
    }

    /// Kinds that verify against an enterprise provider record.
    #[must_use]
    pub const fn is_provider_backed(self) -> bool {
        matches!(
            self,
            Self::OauthIdJag
                | Self::EntraJwt
                | Self::EntraAgentId
                | Self::OidcJwt
                | Self::OauthIntrospection
        )
    }

    /// Kinds whose assertion is a JWS verified against identity-provider keys.
    #[must_use]
    pub const fn is_jws_verified(self) -> bool {
        matches!(
            self,
            Self::OauthIdJag | Self::EntraJwt | Self::EntraAgentId | Self::OidcJwt
        )
    }

    /// Kinds that admit Microsoft Entra tokens.
    #[must_use]
    pub const fn is_entra(self) -> bool {
        matches!(self, Self::EntraJwt | Self::EntraAgentId)
    }
}

/// The signed `root_anchor` member of a root `chio.capability.v1` body.
///
/// A delegated token carries its root's anchor byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootAnchor {
    pub kind: AnchorKind,
    /// `SHA-256("chio.delegation-context.v1\0" || canonical_json(context))`.
    pub context_digest: Sha256Digest,
    /// `SHA-256("chio.root-policy.v1\0" || canonical_json(policy signing body))`.
    pub root_policy_digest: Sha256Digest,
    /// Equals `exchange.exchanged_at` of the delegation context.
    pub anchored_at: u64,
    /// Equals `anchor.token_exp` of the delegation context. The root's
    /// `expires_at` never exceeds it.
    pub assertion_exp: u64,
}
