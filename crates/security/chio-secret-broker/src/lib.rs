#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![deny(unsafe_code)]

pub mod audit;
pub mod authority_ipc;
pub mod budget;
pub mod capability;
pub mod daemon;
pub mod daemon_runtime;
#[cfg(target_os = "linux")]
pub mod docker_adapter;
pub mod generic_https;
#[cfg(target_os = "linux")]
mod host_https;
pub mod inherited_fd;
pub mod ipc_client;
#[cfg(feature = "kernel-admission")]
pub mod kernel_admission;
pub mod migration;
#[cfg(all(feature = "native-mcp", target_os = "linux"))]
pub mod native_mcp;
#[cfg(unix)]
pub mod prepared_mcp;
pub mod privileged_audit;
pub mod proof;
pub mod protocol;
pub mod provider;
pub mod provision;
pub mod receipt;
pub mod reconcile;
pub mod registration;
#[cfg(target_os = "linux")]
pub mod repository_adapter;
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
    #[error(transparent)]
    UntrustedInput(#[from] chio_core_types::canonical::UntrustedJsonError),
    #[error(transparent)]
    Clock(#[from] chio_security_types::clock::ClockError),
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
    /// Bounded broker wire reason. Typed error sources retain their registered
    /// URNs; each one has a distinct wire spelling accepted by the IPC grammar.
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        use chio_core_types::canonical::UntrustedJsonError;
        use chio_security_types::clock::ClockError;
        match self {
            Self::UntrustedInput(error) => match error {
                UntrustedJsonError::TooLarge { .. } => "signed_json_too_large",
                UntrustedJsonError::NotUtf8(_) => "signed_json_not_utf8",
                UntrustedJsonError::SignedInput(_) => "signed_json_invalid_input",
                UntrustedJsonError::Decode(_) => "signed_json_invalid_shape",
                UntrustedJsonError::Canonicalization(_) => "signed_json_canonicalization",
                UntrustedJsonError::NonCanonical => "signed_json_noncanonical",
            },
            Self::Clock(error) => match error {
                ClockError::Unavailable => "clock_unavailable",
                ClockError::BeforeEpoch => "clock_before_epoch",
                ClockError::Overflow => "clock_overflow",
                ClockError::WallClockRegression => "clock_wall_clock_regression",
                ClockError::MonotonicRegression => "clock_monotonic_regression",
                ClockError::Expired => "clock_expired",
                ClockError::NotYetValid => "clock_not_yet_valid",
                ClockError::InvalidWindow => "clock_invalid_window",
            },
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
            Self::UntrustedInput(error) => Self::UntrustedInput(error),
            Self::Clock(error) => Self::Clock(error),
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

#[cfg(test)]
pub(crate) fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

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
