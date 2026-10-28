//! `chio.delegation-context.v1`: the content-addressed record of one root exchange.

use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::anchor::{AnchorKind, DELEGATION_CONTEXT_DIGEST_DOMAIN};
use crate::crypto::PublicKey;
use crate::error::Result;

use super::claims::{RecordedClaims, SaltedCommitment};
use super::jwk::JwsAlgorithm;
use super::wire::{
    canonical_public_key, check_schema, validated_type, Identifier, Sha256Digest, Uri,
};
use super::RootAuthorityShapeError;

pub const CHIO_DELEGATION_CONTEXT_SCHEMA: &str = "chio.delegation-context.v1";

/// Issuer recorded for `operator_static_bearer` roots.
pub const OPERATOR_ISSUER: &str = "urn:chio:operator";

/// `salt_ref` of the subject commitment.
pub const SUBJECT_SALT_REF: &str = "anchor.sub";

/// `salt_ref` of the tenant commitment.
pub const TENANT_SALT_REF: &str = "anchor.tenant";

/// Who holds the root capability's subject key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderClass {
    /// The edge session; the subject private key is discarded at mint.
    EdgeSession,
    /// A Chio-aware caller whose sender key is the subject.
    Caller,
}

impl HolderClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeSession => "edge_session",
            Self::Caller => "caller",
        }
    }
}

/// The members of [`DelegationAnchor`]; [`DelegationAnchor::new`] validates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationAnchorFields {
    pub kind: AnchorKind,
    pub issuer: Uri,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_identity_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_snapshot_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<JwsAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<Sha256Digest>,
    pub artifact_retained: bool,
    pub replay_key_digest: Sha256Digest,
    pub token_iat: u64,
    pub token_exp: u64,
    pub subject: SaltedCommitment,
    pub tenant: SaltedCommitment,
    pub claims: RecordedClaims,
}

validated_type!(
    /// The verified assertion an exchange anchored a root to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    DelegationAnchor(DelegationAnchorFields)
);

impl DelegationAnchorFields {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        let kind = self.kind.as_str();
        let presence = |field: &'static str, present: bool, wanted: bool| match (present, wanted) {
            (false, true) => Err(RootAuthorityShapeError::RequiredFor { field, kind }),
            (true, false) => Err(RootAuthorityShapeError::ForbiddenFor { field, kind }),
            _ => Ok(()),
        };
        let provider_backed = self.kind.is_provider_backed();
        presence(
            "provider_record_id",
            self.provider_record_id.is_some(),
            provider_backed,
        )?;
        presence(
            "provider_identity_digest",
            self.provider_identity_digest.is_some(),
            provider_backed,
        )?;
        let jws = [
            ("key_snapshot_digest", self.key_snapshot_digest.is_some()),
            ("kid", self.kid.is_some()),
            ("alg", self.alg.is_some()),
            ("artifact_digest", self.artifact_digest.is_some()),
        ];
        if self.kind.is_jws_verified() {
            for (field, present) in jws {
                presence(field, present, true)?;
            }
        } else {
            presence("artifact_digest", self.artifact_digest.is_some(), false)?;
        }
        if self.kind == AnchorKind::OperatorStaticBearer {
            if self.issuer.as_str() != OPERATOR_ISSUER {
                return Err(RootAuthorityShapeError::NotAdmittedFor {
                    field: "issuer",
                    kind,
                });
            }
            if !self.claims.is_empty() {
                return Err(RootAuthorityShapeError::ForbiddenFor {
                    field: "claims",
                    kind,
                });
            }
            for (field, present) in jws {
                presence(field, present, false)?;
            }
        }
        if !self.kind.is_entra() {
            if let Some(field) = self.claims.entra_only_claim() {
                return Err(RootAuthorityShapeError::ForbiddenFor { field, kind });
            }
        }
        if self.kind != AnchorKind::OauthIdJag && self.artifact_retained {
            return Err(RootAuthorityShapeError::NotAdmittedFor {
                field: "artifact_retained",
                kind,
            });
        }
        if self.subject.salt_ref.as_str() != SUBJECT_SALT_REF {
            return Err(RootAuthorityShapeError::Const {
                field: "subject.salt_ref",
                expected: SUBJECT_SALT_REF,
            });
        }
        if self.tenant.salt_ref.as_str() != TENANT_SALT_REF {
            return Err(RootAuthorityShapeError::Const {
                field: "tenant.salt_ref",
                expected: TENANT_SALT_REF,
            });
        }
        self.claims.validate()
    }
}

/// The exchange that minted the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationExchange {
    /// Equals the issuer key of the minted root.
    #[serde(deserialize_with = "canonical_public_key")]
    pub exchange_key: PublicKey,
    pub exchanged_at: u64,
    pub request_digest: Sha256Digest,
    pub holder: HolderClass,
}

/// The members of [`DelegationContext`]; [`DelegationContext::new`] validates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationContextFields {
    pub schema: String,
    pub anchor: DelegationAnchor,
    pub exchange: DelegationExchange,
    /// `rule_id` of the root policy rule that matched.
    pub root_policy_rule_id: Identifier,
    /// Equals the scope hash of the minted root.
    pub effective_root_scope_hash: Sha256Digest,
}

validated_type!(
    /// `chio.delegation-context.v1`. Unsigned; bound into the signed root
    /// through `root_anchor.context_digest`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    DelegationContext(DelegationContextFields)
);

impl DelegationContextFields {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_DELEGATION_CONTEXT_SCHEMA)
    }
}

impl DelegationContext {
    /// `SHA-256("chio.delegation-context.v1\0" || canonical_json(context))`.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let canonical = canonical_json_bytes(self)?;
        Ok(Sha256Digest::of_domain(
            DELEGATION_CONTEXT_DIGEST_DOMAIN,
            &canonical,
        ))
    }
}
