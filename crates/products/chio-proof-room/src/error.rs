//! Typed local verification failures. HTTP surfaces project stable public codes.

#[derive(Debug, thiserror::Error)]
pub enum ProofRoomError {
    #[error("proof-room.input.task-failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("{0}")]
    Input(#[from] chio_core_types::canonical::UntrustedJsonError),
    #[error("{0}")]
    Validation(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("proof-room.listen.invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("proof-room.serve: {0}")]
    Serve(std::io::Error),
}

impl From<String> for ProofRoomError {
    fn from(message: String) -> Self {
        Self::Validation(message)
    }
}
impl From<&str> for ProofRoomError {
    fn from(message: &str) -> Self {
        Self::Validation(message.to_owned())
    }
}
