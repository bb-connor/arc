#[derive(Debug, thiserror::Error)]
pub enum SwarmAuthorityError {
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    DigestMismatch(String),
    #[error("{0}")]
    SignatureInvalid(String),
    #[error("{0}")]
    UnsupportedSchema(String),
    /// The bundle requires a feature this verifier does not support.
    #[error("{0}")]
    Unsupported(String),
    #[error("swarm authority canonical JSON failed: {0}")]
    Canonical(String),
}

impl SwarmAuthorityError {
    #[must_use]
    pub fn runtime_detail(&self) -> String {
        match self {
            SwarmAuthorityError::Rejected(detail)
            | SwarmAuthorityError::DigestMismatch(detail)
            | SwarmAuthorityError::SignatureInvalid(detail)
            | SwarmAuthorityError::UnsupportedSchema(detail)
            | SwarmAuthorityError::Unsupported(detail) => detail.clone(),
            SwarmAuthorityError::Canonical(detail) => {
                format!("swarm authority canonical JSON failed: {detail}")
            }
        }
    }
}
