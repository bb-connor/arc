//! The `chio.enterprise-provider-identity.v1` projection of a provider record.

use chio_core_types::root_authority::{
    EnterpriseProviderIdentity, EnterpriseProviderIdentityFields, HttpsUrl, Identifier,
    ProviderRecordKind, RootAuthorityShapeError, SubjectMapping, Uri,
    CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA,
};

use super::{EnterpriseProviderKind, EnterpriseProviderRecord};

/// Why a provider record has no identity projection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderIdentityError {
    #[error("record carries validation errors")]
    ValidationErrors,
    #[error("record kind is never referenced by a rule")]
    KindNotReferenced,
    #[error("issuer is missing")]
    IssuerMissing,
    #[error("subject_mapping.tenant_id_field is missing")]
    TenantIdFieldMissing,
    #[error("provenance.trust_material_ref is missing")]
    TrustMaterialRefMissing,
    #[error("{field}: {source}")]
    Url {
        field: &'static str,
        source: RootAuthorityShapeError,
    },
    #[error(transparent)]
    Shape(#[from] RootAuthorityShapeError),
}

fn https(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<HttpsUrl>, ProviderIdentityError> {
    value
        .map(HttpsUrl::new)
        .transpose()
        .map_err(|source| ProviderIdentityError::Url { field, source })
}

impl EnterpriseProviderRecord {
    /// Project this record onto `chio.enterprise-provider-identity.v1`.
    /// Records with validation errors, a `scim` or `saml` kind, or a member
    /// the projection needs missing or malformed are refused.
    pub fn identity(&self) -> Result<EnterpriseProviderIdentity, ProviderIdentityError> {
        if !self.validation_errors.is_empty() {
            return Err(ProviderIdentityError::ValidationErrors);
        }
        let kind = match self.kind {
            EnterpriseProviderKind::OidcJwks => ProviderRecordKind::OidcJwks,
            EnterpriseProviderKind::OauthIntrospection => ProviderRecordKind::OauthIntrospection,
            EnterpriseProviderKind::Scim | EnterpriseProviderKind::Saml => {
                return Err(ProviderIdentityError::KindNotReferenced);
            }
        };
        let identity = EnterpriseProviderIdentity::new(EnterpriseProviderIdentityFields {
            schema: CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA.to_owned(),
            provider_id: Identifier::new(self.provider_id.as_str())?,
            kind,
            issuer: Uri::new(
                self.issuer
                    .as_deref()
                    .ok_or(ProviderIdentityError::IssuerMissing)?,
            )?,
            jwks_url: https(self.jwks_url.as_deref(), "jwks_url")?,
            jwks: None,
            introspection_url: https(self.introspection_url.as_deref(), "introspection_url")?,
            audiences: self
                .trust_boundary
                .allowed_audiences
                .iter()
                .map(|audience| Uri::new(audience.as_str()))
                .collect::<Result<_, _>>()?,
            subject_mapping: SubjectMapping {
                principal_source: Identifier::new(self.subject_mapping.principal_source.as_str())?,
                tenant_id_field: Identifier::new(
                    self.subject_mapping
                        .tenant_id_field
                        .as_deref()
                        .ok_or(ProviderIdentityError::TenantIdFieldMissing)?,
                )?,
            },
            trust_material_ref: Identifier::new(
                self.provenance
                    .trust_material_ref
                    .as_deref()
                    .ok_or(ProviderIdentityError::TrustMaterialRefMissing)?,
            )?,
        })?;
        Ok(identity)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
