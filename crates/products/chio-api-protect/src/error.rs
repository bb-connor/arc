//! Error types for the protect proxy.

use thiserror::Error;

/// Errors produced by the protect proxy.
#[derive(Debug, Error)]
pub enum ProtectError {
    #[error("authority clock rejected the operation: {0}")]
    Clock(#[from] chio_security_types::clock::ClockError),

    #[error("{0}")]
    Input(#[from] chio_core_types::canonical::UntrustedJsonError),

    #[error("failed to load OpenAPI spec: {0}")]
    SpecLoad(String),

    #[error("failed to parse OpenAPI spec: {0}")]
    SpecParse(#[from] chio_openapi::OpenApiError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("upstream request failed: {0}")]
    Upstream(String),

    #[error("evaluation failed: {0}")]
    Evaluation(String),

    #[error(
        "approval required (approval_id={approval_id:?}, kernel_receipt_id={kernel_receipt_id})"
    )]
    PendingApproval {
        approval_id: Option<String>,
        kernel_receipt_id: String,
    },

    #[error("receipt signing failed: {0}")]
    ReceiptSign(String),

    #[error("receipt persistence failed: {0}")]
    ReceiptStore(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
}
