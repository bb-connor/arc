use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommerceOrderError {
    #[error("commerce input rejected: {0}")]
    Input(#[source] chio_core_types::canonical::SharedUntrustedJsonError),
    #[error("commerce evidence exceeds the verification budget")]
    EvidenceLimit,
    #[error("unsupported commerce schema for {field}: {schema}")]
    UnsupportedSchema { field: &'static str, schema: String },
    #[error("invalid commerce artifact {field}: {message}")]
    InvalidArtifact {
        field: &'static str,
        message: String,
    },
    #[error("{field} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    #[error("commerce replay failed: {0}")]
    ReplayFailed(String),
    #[error("commerce replay failed: {0}")]
    ReplayDigestMismatch(String),
    #[error("commerce replay failed: {0}")]
    ReplaySignatureInvalid(String),
    #[error("commerce payment failed: {0}")]
    PaymentFailed(String),
    #[error("commerce payment failed: {0}")]
    PaymentDigestMismatch(String),
    #[error("commerce payment failed: {0}")]
    PaymentSignatureInvalid(String),
    #[error("commerce mandate failed: {0}")]
    MandateFailed(String),
    #[error("commerce mandate failed: {0}")]
    MandateDigestMismatch(String),
    #[error("commerce provider trust failed: {0}")]
    ProviderTrustFailed(String),
    #[error("commerce provider trust failed: {0}")]
    ProviderTrustSignatureInvalid(String),
    #[error("commerce settlement failed: {0}")]
    SettlementFailed(String),
    #[error("commerce settlement failed: {0}")]
    SettlementDigestMismatch(String),
    #[error("commerce settlement failed: {0}")]
    SettlementSignatureInvalid(String),
    #[error("commerce coverage failed: {0}")]
    CoverageFailed(String),
}
