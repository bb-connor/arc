#![deny(unsafe_code)]

pub mod audit;
pub mod authority_ipc;
pub mod budget;
pub mod capability;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod daemon;
pub mod daemon_runtime;
pub mod generic_https;
pub mod inherited_fd;
pub mod ipc_client;
pub mod migration;
pub mod privileged_audit;
pub mod proof;
pub mod protocol;
pub mod provider;
pub mod provision;
pub mod receipt;
pub mod reconcile;
pub mod registration;
pub mod revocation;
pub mod service;
pub mod sqlite;
pub mod store;

mod backend;
mod encrypted_blob_backend;
#[cfg(all(test, target_os = "linux"))]
mod process_boundary_tests;

pub use encrypted_blob_backend::{EncryptedBlobSecretBackend, SealedKeyFd, SealedSigningKeyFd};

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("broker request is invalid: {0}")]
    InvalidRequest(String),
    #[error("broker authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("broker authority is unavailable: {0}")]
    AuthorityUnavailable(String),
    #[error("broker state conflict: {0}")]
    Conflict(String),
    #[error("broker state invariant failed: {0}")]
    Invariant(String),
    #[error("broker storage failed: {0}")]
    Storage(String),
    #[error("broker upstream request failed: {0}")]
    Upstream(String),
    #[error("broker response was rejected: {0}")]
    ResponseRejected(String),
    #[error("broker custody failed: {0}")]
    Custody(String),
}

impl BrokerError {
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::AuthorizationDenied(_) => "authorization_denied",
            Self::AuthorityUnavailable(_) => "authority_unavailable",
            Self::Conflict(_) => "conflict",
            Self::Invariant(_) => "invariant",
            Self::Storage(_) => "storage",
            Self::Upstream(_) => "upstream",
            Self::ResponseRejected(_) => "response_rejected",
            Self::Custody(_) => "custody",
        }
    }

    pub(crate) fn redacted(self) -> Self {
        let code = self.diagnostic_code().to_string();
        match self {
            Self::InvalidRequest(_) => Self::InvalidRequest(code),
            Self::AuthorizationDenied(_) => Self::AuthorizationDenied(code),
            Self::AuthorityUnavailable(_) => Self::AuthorityUnavailable(code),
            Self::Conflict(_) => Self::Conflict(code),
            Self::Invariant(_) => Self::Invariant(code),
            Self::Storage(_) => Self::Storage(code),
            Self::Upstream(_) => Self::Upstream(code),
            Self::ResponseRejected(_) => Self::ResponseRejected(code),
            Self::Custody(_) => Self::Custody(code),
        }
    }
}

pub type Result<T> = std::result::Result<T, BrokerError>;

pub(crate) fn validate_identifier(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} is empty, oversized, padded, or contains a control byte"
        )));
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}
