#[derive(thiserror::Error)]
pub enum ChioRuntimeError {
    #[error("{0}")]
    UntrustedInput(#[from] chio_core_types::canonical::UntrustedJsonError),
    #[error("{0}")]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error("runtime admission rejected: {code}: {detail}")]
    Rejected { code: &'static str, detail: String },
    #[error("duplicate runtime admission bundle")]
    DuplicateAdmissionBundle,
    #[error("runtime admission store failed: {0}")]
    Store(String),
    #[error("runtime admission IO failed")]
    Io(#[from] std::io::Error),
    #[error("runtime admission JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("runtime admission SQLite failed")]
    Sqlite(#[from] rusqlite::Error),
    #[error("runtime admission canonical JSON failed: {0}")]
    Canonical(String),
}

impl ChioRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UntrustedInput(error) => error.code(),
            Self::Clock(error) => error.code(),
            ChioRuntimeError::Rejected { code, .. } => code,
            ChioRuntimeError::DuplicateAdmissionBundle => "duplicate_admission_bundle",
            ChioRuntimeError::Sqlite(_) => "runtime_admission_store",
            ChioRuntimeError::Store(_) => "runtime_admission_store",
            ChioRuntimeError::Io(_) => "runtime_admission_io",
            ChioRuntimeError::Json(_) => "runtime_admission_json",
            ChioRuntimeError::Canonical(_) => "runtime_admission_canonical",
        }
    }
}

impl std::fmt::Debug for ChioRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChioRuntimeError")
            .field("code", &self.code())
            .finish_non_exhaustive()
    }
}
