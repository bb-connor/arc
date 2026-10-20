//! Enterprise provider records as seen by the exchange.

use chio_control_plane::enterprise_federation::{EnterpriseProviderKind, EnterpriseProviderRecord};
use chio_core::root_authority::{
    EnterpriseProviderIdentity, EnterpriseProviderIdentityFields, HttpsUrl, Identifier,
    ProviderRecordKind, Sha256Digest, SubjectMapping, Uri,
    CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA,
};

use super::error::RootExchangeError;

/// A provider record that a root policy rule may reference, with its
/// identity projection. The projection and its digest are computed together
/// at construction and cannot be changed apart.
#[derive(Debug, Clone)]
pub struct ProviderRecord {
    identity: EnterpriseProviderIdentity,
    identity_digest: Sha256Digest,
    enabled: bool,
}

fn invalid(record: &EnterpriseProviderRecord, reason: impl Into<String>) -> RootExchangeError {
    RootExchangeError::ProviderRecordInvalid {
        record: record.provider_id.clone(),
        reason: reason.into(),
    }
}

impl ProviderRecord {
    /// Project `record` onto `chio.enterprise-provider-identity.v1`. Records
    /// with validation errors, a `scim` or `saml` kind, or a member the
    /// projection needs missing or malformed are refused.
    pub fn from_record(record: &EnterpriseProviderRecord) -> Result<Self, RootExchangeError> {
        if !record.validation_errors.is_empty() {
            return Err(invalid(record, "record carries validation errors"));
        }
        let kind = match record.kind {
            EnterpriseProviderKind::OidcJwks => ProviderRecordKind::OidcJwks,
            EnterpriseProviderKind::OauthIntrospection => ProviderRecordKind::OauthIntrospection,
            EnterpriseProviderKind::Scim | EnterpriseProviderKind::Saml => {
                return Err(invalid(record, "record kind is never referenced by a rule"));
            }
        };
        let https = |value: &Option<String>, field: &str| {
            value
                .as_deref()
                .map(HttpsUrl::new)
                .transpose()
                .map_err(|error| invalid(record, format!("{field}: {error}")))
        };
        let identity = EnterpriseProviderIdentity::new(EnterpriseProviderIdentityFields {
            schema: CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA.to_owned(),
            provider_id: Identifier::new(record.provider_id.as_str())
                .map_err(|error| invalid(record, error.to_string()))?,
            kind,
            issuer: Uri::new(
                record
                    .issuer
                    .as_deref()
                    .ok_or_else(|| invalid(record, "issuer is missing"))?,
            )
            .map_err(|error| invalid(record, error.to_string()))?,
            jwks_url: https(&record.jwks_url, "jwks_url")?,
            jwks: None,
            introspection_url: https(&record.introspection_url, "introspection_url")?,
            audiences: record
                .trust_boundary
                .allowed_audiences
                .iter()
                .map(|audience| Uri::new(audience.as_str()))
                .collect::<Result<_, _>>()
                .map_err(|error| invalid(record, error.to_string()))?,
            subject_mapping: SubjectMapping {
                principal_source: Identifier::new(record.subject_mapping.principal_source.as_str())
                    .map_err(|error| invalid(record, error.to_string()))?,
                tenant_id_field: Identifier::new(
                    record
                        .subject_mapping
                        .tenant_id_field
                        .as_deref()
                        .ok_or_else(|| {
                            invalid(record, "subject_mapping.tenant_id_field is missing")
                        })?,
                )
                .map_err(|error| invalid(record, error.to_string()))?,
            },
            trust_material_ref: Identifier::new(
                record
                    .provenance
                    .trust_material_ref
                    .as_deref()
                    .ok_or_else(|| invalid(record, "provenance.trust_material_ref is missing"))?,
            )
            .map_err(|error| invalid(record, error.to_string()))?,
        })
        .map_err(|error| invalid(record, error.to_string()))?;
        let identity_digest = identity
            .digest()
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        Ok(Self {
            identity,
            identity_digest,
            enabled: record.enabled,
        })
    }
}

impl ProviderRecord {
    #[must_use]
    pub fn identity(&self) -> &EnterpriseProviderIdentity {
        &self.identity
    }

    /// `provider_identity_digest` of [`Self::identity`].
    #[must_use]
    pub fn identity_digest(&self) -> &Sha256Digest {
        &self.identity_digest
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
