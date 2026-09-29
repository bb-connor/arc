use serde::{Deserialize, Serialize};
use core::fmt;
use super::IdError;
use super::ErrorCode;


#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortErrorKind {
    Unavailable,
    Conflict,
    InvalidData,
    IntegrityFailure,
}

#[derive(Clone)]
pub struct PortError {
    kind: PortErrorKind,
    code: ErrorCode,
    source: Option<alloc::sync::Arc<dyn core::error::Error + Send + Sync>>,
}

impl PortError {
    #[must_use]
    pub const fn new(kind: PortErrorKind, code: ErrorCode) -> Self {
        Self { kind, code, source: None }
    }

    /// Preserve a private cause while exposing only the registered rule.
    pub fn with_source(
        kind: PortErrorKind,
        code: &'static str,
        source: impl core::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self { kind, code: ErrorCode(code.to_string()), source: Some(alloc::sync::Arc::new(source)) }
    }

    #[must_use]
    pub const fn kind(&self) -> PortErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    #[must_use]
    pub fn unavailable() -> Self {
        Self::new(
            PortErrorKind::Unavailable,
            ErrorCode("store.unavailable".to_string()),
        )
    }

    #[must_use]
    pub fn conflict() -> Self {
        Self::new(
            PortErrorKind::Conflict,
            ErrorCode("store.conflict".to_string()),
        )
    }

    #[must_use]
    pub fn invalid_data() -> Self {
        Self::new(
            PortErrorKind::InvalidData,
            ErrorCode("store.invalid_data".to_string()),
        )
    }

    #[must_use]
    pub fn integrity_failure() -> Self {
        Self::new(
            PortErrorKind::IntegrityFailure,
            ErrorCode("store.integrity_failure".to_string()),
        )
    }
}

impl From<crate::clock::ClockError> for PortError {
    fn from(error: crate::clock::ClockError) -> Self {
        Self::new(
            PortErrorKind::Unavailable,
            ErrorCode(error.code().to_string()),
        )
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.code)
    }
}

impl core::error::Error for PortError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source.as_deref().map(|source| -> &(dyn core::error::Error + 'static) { source })
    }
}

impl fmt::Debug for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortError").field("kind", &self.kind).field("code", &self.code).finish_non_exhaustive()
    }
}

impl PartialEq for PortError {
    fn eq(&self, other: &Self) -> bool { self.kind == other.kind && self.code == other.code }
}
impl Eq for PortError {}

pub type PortResult<T> = Result<T, PortError>;

impl From<IdError> for PortError {
    fn from(_: IdError) -> Self {
        Self::new(
            PortErrorKind::InvalidData,
            ErrorCode("invalid.identifier".to_string()),
        )
    }
}
