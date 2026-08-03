use thiserror::Error;

pub type Result<T> = std::result::Result<T, KeyringError>;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("invalid {kind}: {reason}")]
    InvalidIdentifier {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("unsupported schema `{0}`")]
    UnsupportedSchema(String),
    #[error("key algorithm does not match public key or signature")]
    AlgorithmMismatch,
    #[error("derived key identifier does not match event key")]
    KeyIdMismatch,
    #[error("event sequence mismatch: expected {expected}, received {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("event predecessor hash mismatch")]
    PredecessorMismatch,
    #[error("event log or authority identity mismatch")]
    IdentityMismatch,
    #[error("invalid event time ordering")]
    InvalidTimeOrdering,
    #[error("invalid authorization set for operation")]
    InvalidAuthorizationSet,
    #[error("event authorization signature is invalid")]
    InvalidSignature,
    #[error("duplicate event or key identifier")]
    DuplicateIdentifier,
    #[error("key-log state invariant failed: {0}")]
    StateInvariant(&'static str),
    #[error("unknown key identifier")]
    UnknownKey,
    #[error("trusted artifact-time evidence is invalid")]
    InvalidArtifactTimeEvidence,
    #[error("witness threshold or checkpoint binding is invalid")]
    InvalidWitnessActivation,
    #[error("durable checkpoint equivocation detected")]
    EquivocationDetected,
    #[error("checkpoint validation failed: {0}")]
    InvalidCheckpoint(&'static str),
    #[error("numeric value is outside the supported range")]
    NumericRange,
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    #[error("storage operation failed: {0}")]
    Storage(String),
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("keyring synchronization primitive is unavailable")]
    Synchronization,
}

impl From<chio_core_types::Error> for KeyringError {
    fn from(error: chio_core_types::Error) -> Self {
        Self::Canonical(error.to_string())
    }
}

impl From<serde_json::Error> for KeyringError {
    fn from(error: serde_json::Error) -> Self {
        Self::Canonical(error.to_string())
    }
}

impl From<rusqlite::Error> for KeyringError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
