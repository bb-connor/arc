//! `chio.enterprise-providers.v1`: the enterprise identity-provider registry
//! vocabulary. Loading and persisting the registry file belong to the service.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::root_authority::{
    EnterpriseProviderIdentity, EnterpriseProviderIdentityFields, HttpsUrl, Identifier,
    ProviderRecordKind, RootAuthorityShapeError, SubjectMapping, Uri,
    CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA,
};

pub const ENTERPRISE_PROVIDER_REGISTRY_VERSION: &str = "chio.enterprise-providers.v1";

/// The provider family whose claim conventions map a bearer to a principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtProviderProfile {
    Generic,
    Auth0,
    Okta,
    AzureAd,
}

impl JwtProviderProfile {
    /// Every profile, in the order operators see them.
    pub const ALL: [Self; 4] = [Self::Generic, Self::Auth0, Self::Okta, Self::AzureAd];

    /// The name the registry file and the command line use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Auth0 => "auth0",
            Self::Okta => "okta",
            Self::AzureAd => "azure-ad",
        }
    }
}

/// A name that is not one of [`JwtProviderProfile::ALL`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownJwtProviderProfile(pub String);

impl fmt::Display for UnknownJwtProviderProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported jwt provider profile `{}`", self.0)
    }
}

impl core::error::Error for UnknownJwtProviderProfile {}

impl FromStr for JwtProviderProfile {
    type Err = UnknownJwtProviderProfile;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.as_str() == name)
            .ok_or_else(|| UnknownJwtProviderProfile(name.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnterpriseProviderKind {
    #[serde(rename = "oidc_jwks")]
    OidcJwks,
    #[serde(rename = "oauth_introspection")]
    OauthIntrospection,
    #[serde(rename = "scim")]
    Scim,
    #[serde(rename = "saml")]
    Saml,
}

impl EnterpriseProviderKind {
    /// The registry name of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OidcJwks => "oidc_jwks",
            Self::OauthIntrospection => "oauth_introspection",
            Self::Scim => "scim",
            Self::Saml => "saml",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderProvenance {
    #[serde(default)]
    pub configured_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_mapping_source: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseTrustBoundary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tenants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_organizations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseSubjectMapping {
    pub principal_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderRecord {
    pub provider_id: String,
    pub kind: EnterpriseProviderKind,
    pub enabled: bool,
    #[serde(default)]
    pub provenance: EnterpriseProviderProvenance,
    #[serde(default)]
    pub trust_boundary: EnterpriseTrustBoundary,
    #[serde(default, with = "jwt_provider_profile_serde")]
    pub provider_profile: Option<JwtProviderProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    pub subject_mapping: EnterpriseSubjectMapping,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProviderRegistry {
    pub version: String,
    pub providers: BTreeMap<String, EnterpriseProviderRecord>,
}

impl Default for EnterpriseProviderRegistry {
    fn default() -> Self {
        Self {
            version: ENTERPRISE_PROVIDER_REGISTRY_VERSION.to_owned(),
            providers: BTreeMap::new(),
        }
    }
}

/// Why a decoded registry is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnterpriseProviderRegistryError {
    UnsupportedVersion(String),
    ProviderKeyMismatch,
}

impl fmt::Display for EnterpriseProviderRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported enterprise provider registry version `{version}`"
            ),
            Self::ProviderKeyMismatch => {
                formatter.write_str("enterprise provider map key must match provider_id")
            }
        }
    }
}

impl core::error::Error for EnterpriseProviderRegistryError {}

/// What a record lacks for the `chio.enterprise-provider-identity.v1`
/// projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderProjectionRefusal {
    ValidationErrors,
    KindNotReferenced,
    Missing(&'static str),
    Malformed {
        field: &'static str,
        error: RootAuthorityShapeError,
    },
}

impl fmt::Display for ProviderProjectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationErrors => formatter.write_str("record carries validation errors"),
            Self::KindNotReferenced => {
                formatter.write_str("record kind is never referenced by a rule")
            }
            Self::Missing(field) => write!(formatter, "{field} is missing"),
            Self::Malformed { field, error } => write!(formatter, "{field}: {error}"),
        }
    }
}

impl core::error::Error for ProviderProjectionRefusal {}

impl EnterpriseProviderRecord {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        require_non_empty(&self.provider_id, "provider_id", &mut errors);
        require_non_empty(
            &self.provenance.configured_from,
            "provenance.configured_from",
            &mut errors,
        );
        require_non_empty(
            self.provenance
                .trust_material_ref
                .as_deref()
                .unwrap_or_default(),
            "provenance.trust_material_ref",
            &mut errors,
        );
        require_non_empty(
            &self.subject_mapping.principal_source,
            "subject_mapping.principal_source",
            &mut errors,
        );

        match self.kind {
            EnterpriseProviderKind::OidcJwks => {
                require_non_empty(
                    self.issuer.as_deref().unwrap_or_default(),
                    "issuer",
                    &mut errors,
                );
                if is_blank(self.discovery_url.as_deref()) && is_blank(self.jwks_url.as_deref()) {
                    errors.push("oidc_jwks provider requires discovery_url or jwks_url".to_owned());
                }
            }
            EnterpriseProviderKind::OauthIntrospection => {
                require_non_empty(
                    self.issuer.as_deref().unwrap_or_default(),
                    "issuer",
                    &mut errors,
                );
                require_non_empty(
                    self.introspection_url.as_deref().unwrap_or_default(),
                    "introspection_url",
                    &mut errors,
                );
            }
            EnterpriseProviderKind::Scim => {
                require_non_empty(
                    self.scim_base_url.as_deref().unwrap_or_default(),
                    "scim_base_url",
                    &mut errors,
                );
            }
            EnterpriseProviderKind::Saml => {
                require_non_empty(
                    self.saml_entity_id.as_deref().unwrap_or_default(),
                    "saml_entity_id",
                    &mut errors,
                );
                require_non_empty(
                    self.saml_metadata_url.as_deref().unwrap_or_default(),
                    "saml_metadata_url",
                    &mut errors,
                );
            }
        }

        if let Some(issuer) = self.issuer.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_issuers, issuer) {
                errors.push(format!(
                    "issuer `{issuer}` falls outside trust_boundary.allowed_issuers"
                ));
            }
        }
        if let Some(tenant_id) = self.tenant_id.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_tenants, tenant_id) {
                errors.push(format!(
                    "tenant_id `{tenant_id}` falls outside trust_boundary.allowed_tenants"
                ));
            }
        }
        if let Some(organization_id) = self.organization_id.as_deref() {
            if !allowlist_matches(&self.trust_boundary.allowed_organizations, organization_id) {
                errors.push(format!(
                    "organization_id `{organization_id}` falls outside trust_boundary.allowed_organizations"
                ));
            }
        }

        errors
    }

    pub fn is_validated_enabled(&self) -> bool {
        self.enabled && self.validation_errors.is_empty()
    }

    /// Project the record onto `chio.enterprise-provider-identity.v1`.
    /// Records with validation errors, a `scim` or `saml` kind, or a member
    /// the projection needs missing or malformed are refused.
    pub fn root_identity(&self) -> Result<EnterpriseProviderIdentity, ProviderProjectionRefusal> {
        if !self.validation_errors.is_empty() {
            return Err(ProviderProjectionRefusal::ValidationErrors);
        }
        let kind = match self.kind {
            EnterpriseProviderKind::OidcJwks => ProviderRecordKind::OidcJwks,
            EnterpriseProviderKind::OauthIntrospection => ProviderRecordKind::OauthIntrospection,
            EnterpriseProviderKind::Scim | EnterpriseProviderKind::Saml => {
                return Err(ProviderProjectionRefusal::KindNotReferenced);
            }
        };
        let malformed = |field: &'static str| {
            move |error: RootAuthorityShapeError| ProviderProjectionRefusal::Malformed {
                field,
                error,
            }
        };
        let https = |value: &Option<String>, field: &'static str| {
            value
                .as_deref()
                .map(HttpsUrl::new)
                .transpose()
                .map_err(malformed(field))
        };
        EnterpriseProviderIdentity::new(EnterpriseProviderIdentityFields {
            schema: CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA.to_owned(),
            provider_id: Identifier::new(self.provider_id.as_str())
                .map_err(malformed("provider_id"))?,
            kind,
            issuer: Uri::new(required(self.issuer.as_deref(), "issuer")?)
                .map_err(malformed("issuer"))?,
            jwks_url: https(&self.jwks_url, "jwks_url")?,
            jwks: None,
            introspection_url: https(&self.introspection_url, "introspection_url")?,
            audiences: self
                .trust_boundary
                .allowed_audiences
                .iter()
                .map(|audience| Uri::new(audience.as_str()))
                .collect::<Result<_, _>>()
                .map_err(malformed("trust_boundary.allowed_audiences"))?,
            subject_mapping: SubjectMapping {
                principal_source: Identifier::new(self.subject_mapping.principal_source.as_str())
                    .map_err(malformed("subject_mapping.principal_source"))?,
                tenant_id_field: Identifier::new(required(
                    self.subject_mapping.tenant_id_field.as_deref(),
                    "subject_mapping.tenant_id_field",
                )?)
                .map_err(malformed("subject_mapping.tenant_id_field"))?,
            },
            trust_material_ref: Identifier::new(required(
                self.provenance.trust_material_ref.as_deref(),
                "provenance.trust_material_ref",
            )?)
            .map_err(malformed("provenance.trust_material_ref"))?,
        })
        .map_err(malformed("identity"))
    }
}

impl EnterpriseProviderRegistry {
    pub fn validated_provider(&self, provider_id: &str) -> Option<&EnterpriseProviderRecord> {
        self.providers
            .get(provider_id)
            .filter(|record| record.is_validated_enabled())
    }

    /// Stores `record` with its validation errors recomputed and returns the
    /// stored copy.
    pub fn upsert(&mut self, mut record: EnterpriseProviderRecord) -> EnterpriseProviderRecord {
        record.validation_errors = record.validate();
        ENTERPRISE_PROVIDER_REGISTRY_VERSION.clone_into(&mut self.version);
        self.providers
            .insert(record.provider_id.clone(), record.clone());
        record
    }

    pub fn remove(&mut self, provider_id: &str) -> bool {
        self.providers.remove(provider_id).is_some()
    }

    /// Checks a decoded registry and recomputes every record's validation
    /// errors. An unknown version or a map key that differs from its
    /// record's `provider_id` refuses the whole registry.
    pub fn revalidated(mut self) -> Result<Self, EnterpriseProviderRegistryError> {
        if self.version != ENTERPRISE_PROVIDER_REGISTRY_VERSION {
            return Err(EnterpriseProviderRegistryError::UnsupportedVersion(
                self.version,
            ));
        }
        let mut normalized = BTreeMap::new();
        for (provider_id, mut record) in self.providers {
            if provider_id != record.provider_id {
                return Err(EnterpriseProviderRegistryError::ProviderKeyMismatch);
            }
            record.validation_errors = record.validate();
            normalized.insert(provider_id, record);
        }
        self.providers = normalized;
        Ok(self)
    }
}

fn required<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, ProviderProjectionRefusal> {
    value.ok_or(ProviderProjectionRefusal::Missing(field))
}

fn require_non_empty(value: &str, field: &str, errors: &mut Vec<String>) {
    if is_blank(Some(value)) {
        errors.push(format!("{field} is required"));
    }
}

fn allowlist_matches(allowlist: &[String], value: &str) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let value = value.trim();
    allowlist
        .iter()
        .map(|candidate| candidate.trim())
        .any(|candidate| !candidate.is_empty() && candidate == value)
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

mod jwt_provider_profile_serde {
    use alloc::string::{String, ToString};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::JwtProviderProfile;

    pub fn serialize<S>(
        value: &Option<JwtProviderProfile>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.map(JwtProviderProfile::as_str).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<JwtProviderProfile>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|name| name.parse())
            .transpose()
            .map_err(|error: super::UnknownJwtProviderProfile| {
                serde::de::Error::custom(error.to_string())
            })
    }
}

#[cfg(test)]
#[path = "enterprise_provider_tests.rs"]
mod tests;
