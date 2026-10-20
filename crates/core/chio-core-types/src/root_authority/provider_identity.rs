//! `chio.enterprise-provider-identity.v1`: the identity projection a root policy rule pins.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::error::Result;

use super::jwk::Jwk;
use super::wire::{
    check_items, check_schema, check_unique, validated_serde, HttpsUrl, Identifier, Sha256Digest,
    Uri,
};
use super::RootAuthorityShapeError;

pub const CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA: &str = "chio.enterprise-provider-identity.v1";

/// Domain prefix of `provider_identity_digest`.
pub const PROVIDER_IDENTITY_DIGEST_DOMAIN: &[u8] = b"chio.enterprise-provider-identity.v1\0";

/// Record kinds a root policy rule may reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRecordKind {
    OidcJwks,
    OauthIntrospection,
}

impl ProviderRecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OidcJwks => "oidc_jwks",
            Self::OauthIntrospection => "oauth_introspection",
        }
    }
}

/// An inline JWKS held by the provider record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineJwks {
    pub keys: Vec<Jwk>,
}

/// The claims that name the principal and the tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectMapping {
    pub principal_source: Identifier,
    pub tenant_id_field: Identifier,
}

/// The unsigned, content-addressed identity projection of one enterprise provider record.
///
/// An `oidc_jwks` record has exactly one of `jwks_url` or `jwks` and no
/// `introspection_url`; an `oauth_introspection` record has
/// `introspection_url` and no key source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct EnterpriseProviderIdentity {
    pub schema: String,
    pub provider_id: Identifier,
    pub kind: ProviderRecordKind,
    pub issuer: Uri,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<HttpsUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<InlineJwks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_url: Option<HttpsUrl>,
    /// The record's `trust_boundary.allowed_audiences`.
    pub audiences: Vec<Uri>,
    pub subject_mapping: SubjectMapping,
    pub trust_material_ref: Identifier,
}

validated_serde!(EnterpriseProviderIdentity);

impl EnterpriseProviderIdentity {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA)?;
        check_items("audiences", self.audiences.len(), 0, 32)?;
        check_unique("audiences", &self.audiences)?;
        if let Some(jwks) = &self.jwks {
            check_items("jwks.keys", jwks.keys.len(), 1, 64)?;
        }
        let kind = self.kind.as_str();
        match self.kind {
            ProviderRecordKind::OidcJwks => {
                if self.jwks_url.is_some() == self.jwks.is_some() {
                    return Err(RootAuthorityShapeError::ExactlyOne {
                        fields: "jwks_url, jwks",
                    });
                }
                if self.introspection_url.is_some() {
                    return Err(RootAuthorityShapeError::ForbiddenFor {
                        field: "introspection_url",
                        kind,
                    });
                }
            }
            ProviderRecordKind::OauthIntrospection => {
                if self.introspection_url.is_none() {
                    return Err(RootAuthorityShapeError::RequiredFor {
                        field: "introspection_url",
                        kind,
                    });
                }
                if self.jwks_url.is_some() || self.jwks.is_some() {
                    return Err(RootAuthorityShapeError::ForbiddenFor {
                        field: "jwks_url, jwks",
                        kind,
                    });
                }
            }
        }
        Ok(())
    }

    /// `SHA-256("chio.enterprise-provider-identity.v1\0" || canonical_json(projection))`.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let canonical = canonical_json_bytes(self)?;
        Ok(Sha256Digest::of_domain(
            PROVIDER_IDENTITY_DIGEST_DOMAIN,
            &canonical,
        ))
    }
}
