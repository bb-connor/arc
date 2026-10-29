//! Credential role presets. Each shipped caller role gets the credential kind
//! and the exact scope set its trust-control routes require, and nothing more.
//! `receipt-openings:read` belongs only to kernel hosts; no preset carries
//! `receipt-openings:erase`, `attestation:write`, `settlement:write` or
//! `root-exchange:sign`.

use super::caller_credentials::{CredentialKind, Scope};

/// A shipped caller role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialRole {
    /// A kernel-hosting process (`chio mcp serve-http`, `chio mcp serve`,
    /// `chio run`, `chio api protect`) that keeps its receipts, revocations,
    /// budgets, capability authority and durable admission in trust-control.
    KernelHost,
    /// An operator: the `chio trust` administration commands and the receipt
    /// dashboard.
    Operator,
    /// The authority workload of a hosted MCP edge: authority status and
    /// capability issuance only.
    AuthorityWorkload,
    /// A reader confined to one tenant's receipts, reports and evidence.
    TenantReader,
}

const KERNEL_HOST_SCOPES: &[Scope] = &[
    Scope::AdmissionAuthorityWrite,
    Scope::AuthorityRead,
    Scope::BudgetsRead,
    Scope::BudgetsWrite,
    Scope::CapabilitiesIssue,
    Scope::LineageWrite,
    Scope::ReceiptOpeningsRead,
    Scope::ReceiptsAppend,
    Scope::ReceiptsRead,
    Scope::ReportsRead,
    Scope::RevocationsRead,
    Scope::RevocationsWrite,
];

const OPERATOR_SCOPES: &[Scope] = &[
    Scope::AdminEmergency,
    Scope::AuthorityAdmin,
    Scope::CertificationsRead,
    Scope::CertificationsWrite,
    Scope::CreditRead,
    Scope::CreditWrite,
    Scope::EvidenceRead,
    Scope::EvidenceWrite,
    Scope::FederationRead,
    Scope::FederationWrite,
    Scope::FindingsRead,
    Scope::FindingsWrite,
    Scope::FiscalRead,
    Scope::FiscalWrite,
    Scope::LineageRead,
    Scope::MetricsRead,
    Scope::PassportRead,
    Scope::PassportWrite,
    Scope::ReceiptsAdmin,
    Scope::ReceiptsRead,
    Scope::RegistryWrite,
    Scope::ReportsRead,
    Scope::ReputationRead,
    Scope::ReputationWrite,
    Scope::RevocationsRead,
    Scope::RevocationsWrite,
    Scope::ScimWrite,
];

const AUTHORITY_WORKLOAD_SCOPES: &[Scope] = &[Scope::AuthorityRead, Scope::CapabilitiesIssue];

const TENANT_READER_SCOPES: &[Scope] =
    &[Scope::EvidenceRead, Scope::ReceiptsRead, Scope::ReportsRead];

impl CredentialRole {
    pub const ALL: &'static [CredentialRole] = &[
        CredentialRole::KernelHost,
        CredentialRole::Operator,
        CredentialRole::AuthorityWorkload,
        CredentialRole::TenantReader,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CredentialRole::KernelHost => "kernel-host",
            CredentialRole::Operator => "operator",
            CredentialRole::AuthorityWorkload => "authority-workload",
            CredentialRole::TenantReader => "tenant-reader",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|role| role.as_str() == value)
    }

    /// Kernel hosts and the authority workload call deployment-kind routes;
    /// operators and tenant readers use caller routes only.
    #[must_use]
    pub const fn kind(self) -> CredentialKind {
        match self {
            CredentialRole::KernelHost | CredentialRole::AuthorityWorkload => {
                CredentialKind::Deployment
            }
            CredentialRole::Operator | CredentialRole::TenantReader => CredentialKind::Caller,
        }
    }

    /// The role's scopes, sorted by name.
    #[must_use]
    pub const fn scopes(self) -> &'static [Scope] {
        match self {
            CredentialRole::KernelHost => KERNEL_HOST_SCOPES,
            CredentialRole::Operator => OPERATOR_SCOPES,
            CredentialRole::AuthorityWorkload => AUTHORITY_WORKLOAD_SCOPES,
            CredentialRole::TenantReader => TENANT_READER_SCOPES,
        }
    }

    /// A tenant reader always names its tenant.
    #[must_use]
    pub const fn requires_tenant(self) -> bool {
        matches!(self, CredentialRole::TenantReader)
    }
}

#[cfg(test)]
#[path = "credential_roles_tests.rs"]
mod tests;
