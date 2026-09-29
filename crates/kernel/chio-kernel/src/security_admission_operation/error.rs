//! Errors retain redacted parser causes and fallible trusted time.

#[derive(Debug, thiserror::Error)]
pub enum AdmissionOperationError {
    #[error(transparent)]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error(transparent)]
    UntrustedInput(chio_core::canonical::SharedUntrustedJsonError),
    #[error("invalid admission operation: {0}")]
    Invalid(String),

    #[error("admission operation conflict: {0}")]
    Conflict(String),

    #[error("admission operation arithmetic overflow: {0}")]
    Overflow(String),

    #[error("admission operation storage unavailable: {0}")]
    Unavailable(String),
}

impl From<chio_core::canonical::UntrustedJsonError> for AdmissionOperationError {
    fn from(error: chio_core::canonical::UntrustedJsonError) -> Self {
        Self::UntrustedInput(error.into())
    }
}
