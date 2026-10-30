use std::collections::BTreeSet;

use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::access::TrustAccessError;
use super::scope::Scope;
use super::{is_clean_text, is_lowercase_hex_32};
use crate::trust_control::plain_http_error;

const MAX_CREDENTIAL_ID_BYTES: usize = 128;
const MAX_TENANT_ID_BYTES: usize = 256;

/// Who holds a caller credential. Deployment-kind routes (receipt append,
/// budgets, capability issue, settlement, authority reads, admission
/// authority) refuse a caller-kind credential whatever its scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum CredentialKind {
    Caller,
    Deployment,
}

/// The tenants a credential may act for inside its deployment: the keyword
/// `"deployment"` or `{ tenant = ".." }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantAuthority {
    Deployment,
    Tenant(String),
}

/// A caller credential secret: non-empty, without surrounding whitespace or
/// control characters. Zeroized on drop and never printed.
pub struct CredentialSecret(Zeroizing<String>);

impl CredentialSecret {
    pub fn parse(value: String) -> Result<Self, InvalidCredentialSecret> {
        let value = Zeroizing::new(value);
        if !is_clean_text(&value, usize::MAX) {
            return Err(InvalidCredentialSecret);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

impl std::fmt::Debug for CredentialSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialSecret([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "credential secret must be non-empty, without surrounding whitespace or control characters"
)]
pub struct InvalidCredentialSecret;

/// One `[[credentials]]` entry of an access configuration document, before
/// validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEntry {
    id: String,
    kind: CredentialKind,
    secret_sha256: String,
    scopes: Vec<String>,
    deployment: String,
    tenant_authority: TenantAuthority,
}

impl CredentialEntry {
    /// The entry granting the holder of `secret` these scopes, identified by
    /// the secret's SHA-256 digest only.
    #[must_use]
    pub fn new(
        id: String,
        kind: CredentialKind,
        secret: &CredentialSecret,
        scopes: Vec<String>,
        deployment: String,
        tenant_authority: TenantAuthority,
    ) -> Self {
        Self {
            id,
            kind,
            secret_sha256: hex::encode(secret.sha256()),
            scopes,
            deployment,
            tenant_authority,
        }
    }
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

pub(super) fn parse_secret_digest(id: &str, value: &str) -> Result<[u8; 32], TrustAccessError> {
    let mut digest = [0_u8; 32];
    if !is_lowercase_hex_32(value) || hex::decode_to_slice(value, &mut digest).is_err() {
        return Err(TrustAccessError::InvalidSecretDigest(id.to_string()));
    }
    Ok(digest)
}

struct CredentialRecord {
    id: String,
    kind: CredentialKind,
    secret_sha256: [u8; 32],
    scopes: BTreeSet<Scope>,
    tenant_authority: TenantAuthority,
}

impl std::fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("secret_sha256", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("tenant_authority", &self.tenant_authority)
            .finish()
    }
}

/// Every caller credential of one deployment. Secrets are held only as
/// SHA-256 digests.
#[derive(Debug)]
pub struct CallerCredentials {
    deployment: String,
    records: Vec<CredentialRecord>,
}

impl CallerCredentials {
    pub(super) fn from_entries(
        deployment: &str,
        entries: Vec<CredentialEntry>,
    ) -> Result<Self, TrustAccessError> {
        if entries.is_empty() {
            return Err(TrustAccessError::NoCredentials);
        }
        let mut records: Vec<CredentialRecord> = Vec::with_capacity(entries.len());
        for entry in entries {
            if !valid_credential_id(&entry.id) {
                return Err(TrustAccessError::InvalidCredentialId(entry.id));
            }
            if records.iter().any(|record| record.id == entry.id) {
                return Err(TrustAccessError::DuplicateCredentialId(entry.id));
            }
            if entry.deployment != deployment {
                return Err(TrustAccessError::ForeignDeployment {
                    credential: entry.id,
                    credential_deployment: entry.deployment,
                    deployment: deployment.to_string(),
                });
            }
            let secret_sha256 = parse_secret_digest(&entry.id, &entry.secret_sha256)?;
            if let Some(other) = records
                .iter()
                .find(|record| bool::from(record.secret_sha256.ct_eq(&secret_sha256)))
            {
                return Err(TrustAccessError::DuplicateSecret(
                    other.id.clone(),
                    entry.id,
                ));
            }
            if entry.scopes.is_empty() {
                return Err(TrustAccessError::NoScopes(entry.id));
            }
            let mut scopes = BTreeSet::new();
            for name in &entry.scopes {
                let Some(scope) = Scope::parse(name) else {
                    return Err(TrustAccessError::UnknownScope {
                        credential: entry.id,
                        scope: name.clone(),
                    });
                };
                if scope.is_cluster() {
                    return Err(TrustAccessError::ClusterScopeOnCredential {
                        credential: entry.id,
                        scope,
                    });
                }
                if !scopes.insert(scope) {
                    return Err(TrustAccessError::DuplicateScope {
                        credential: entry.id,
                        scope,
                    });
                }
            }
            if let TenantAuthority::Tenant(tenant) = &entry.tenant_authority {
                if !is_clean_text(tenant, MAX_TENANT_ID_BYTES) {
                    return Err(TrustAccessError::InvalidTenant {
                        credential: entry.id,
                        tenant: tenant.clone(),
                    });
                }
            }
            records.push(CredentialRecord {
                id: entry.id,
                kind: entry.kind,
                secret_sha256,
                scopes,
                tenant_authority: entry.tenant_authority,
            });
        }
        Ok(Self {
            deployment: deployment.to_string(),
            records,
        })
    }

    /// The one deployment credential of `TrustAccess::single_client`.
    pub(super) fn single_client(
        deployment: &str,
        credential_id: &str,
        secret: &CredentialSecret,
    ) -> Result<Self, TrustAccessError> {
        if !valid_credential_id(credential_id) {
            return Err(TrustAccessError::InvalidCredentialId(
                credential_id.to_string(),
            ));
        }
        let record = CredentialRecord {
            id: credential_id.to_string(),
            kind: CredentialKind::Deployment,
            secret_sha256: secret.sha256(),
            scopes: Scope::ALL
                .iter()
                .copied()
                .filter(|scope| {
                    !scope.is_cluster()
                        && !matches!(
                            scope,
                            Scope::ReceiptOpeningsRead
                                | Scope::ReceiptOpeningsErase
                                | Scope::RootExchangeSign
                        )
                })
                .collect(),
            tenant_authority: TenantAuthority::Deployment,
        };
        Ok(Self {
            deployment: deployment.to_string(),
            records: vec![record],
        })
    }

    #[must_use]
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Whether some credential of `kind` holds `scope`.
    #[must_use]
    pub fn any_holds(&self, kind: CredentialKind, scope: Scope) -> bool {
        self.records
            .iter()
            .any(|record| record.kind == kind && record.scopes.contains(&scope))
    }

    /// Credential ids, kinds, scopes and tenant authorities, never secrets.
    pub fn summaries(
        &self,
    ) -> impl Iterator<Item = (&str, CredentialKind, &BTreeSet<Scope>, &TenantAuthority)> {
        self.records.iter().map(|record| {
            (
                record.id.as_str(),
                record.kind,
                &record.scopes,
                &record.tenant_authority,
            )
        })
    }

    /// Resolve the bearer credential. Every record is compared in constant
    /// time; the loop never exits early on a match.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedCaller, CallerAuthError> {
        let token = bearer_token(headers).ok_or(CallerAuthError::Unauthenticated)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for record in &self.records {
            if bool::from(record.secret_sha256.ct_eq(&digest)) {
                matched = Some(record);
            }
        }
        let record = matched.ok_or(CallerAuthError::Unauthenticated)?;
        Ok(AuthenticatedCaller {
            credential_id: record.id.clone(),
            kind: record.kind,
            deployment: self.deployment.clone(),
            tenant_authority: record.tenant_authority.clone(),
            scopes: record.scopes.clone(),
        })
    }

    /// Authenticate the bearer credential and require `required_scope`.
    pub fn validate_caller(
        &self,
        headers: &HeaderMap,
        required_scope: Scope,
    ) -> Result<AuthenticatedCaller, CallerAuthError> {
        let caller = self.authenticate(headers)?;
        if !caller.scopes.contains(&required_scope) {
            return Err(CallerAuthError::MissingScope(required_scope));
        }
        Ok(caller)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let header = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = header.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

/// The authenticated caller a route handler receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub credential_id: String,
    pub kind: CredentialKind,
    pub deployment: String,
    pub tenant_authority: TenantAuthority,
    pub scopes: BTreeSet<Scope>,
}

impl AuthenticatedCaller {
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The receipt read boundary this caller is entitled to.
    #[must_use]
    pub fn receipt_read_context(&self) -> chio_kernel::ReceiptReadContext {
        match &self.tenant_authority {
            TenantAuthority::Deployment => chio_kernel::ReceiptReadContext::admin_service(),
            TenantAuthority::Tenant(tenant) => {
                chio_kernel::ReceiptReadContext::authenticated_tenant(tenant.clone())
            }
        }
    }

    /// The tenant a request acts for. A tenant credential acts only for its
    /// own tenant; naming another tenant refuses.
    pub fn tenant_for_request(
        &self,
        requested: Option<&str>,
    ) -> Result<Option<String>, CallerAuthError> {
        match (&self.tenant_authority, requested) {
            (TenantAuthority::Deployment, requested) => Ok(requested.map(str::to_string)),
            (TenantAuthority::Tenant(tenant), None) => Ok(Some(tenant.clone())),
            (TenantAuthority::Tenant(tenant), Some(requested)) if requested == tenant => {
                Ok(Some(tenant.clone()))
            }
            (TenantAuthority::Tenant(_), Some(_)) => Err(CallerAuthError::CrossTenant),
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallerAuthError {
    #[error("missing or invalid trust-control credential")]
    Unauthenticated,
    #[error("trust-control credential lacks scope {0}")]
    MissingScope(Scope),
    #[error("route requires a deployment credential")]
    DeploymentCredentialRequired,
    #[error("tenant credential cannot use a deployment-only route")]
    TenantCredentialOnDeploymentRoute,
    #[error("tenant credential cannot act for another tenant")]
    CrossTenant,
    #[error("cluster peer authentication is refused on a caller route")]
    PeerAuthenticationOnCallerRoute,
}

impl CallerAuthError {
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            CallerAuthError::Unauthenticated | CallerAuthError::PeerAuthenticationOnCallerRoute => {
                StatusCode::UNAUTHORIZED
            }
            CallerAuthError::MissingScope(_)
            | CallerAuthError::DeploymentCredentialRequired
            | CallerAuthError::TenantCredentialOnDeploymentRoute
            | CallerAuthError::CrossTenant => StatusCode::FORBIDDEN,
        }
    }

    #[must_use]
    pub fn into_response(self) -> Response {
        let status = self.status();
        let mut response = plain_http_error(status, &self.to_string());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
