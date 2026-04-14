//! Error types for the protect proxy.

use thiserror::Error;

/// Errors produced by the protect proxy.
#[derive(Debug, Error)]
pub enum ProtectError {
    #[error("failed to load OpenAPI spec: {0}")]
    SpecLoad(String),

    #[error("failed to parse OpenAPI spec: {0}")]
    SpecParse(#[from] arc_openapi::OpenApiError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("upstream request failed: {0}")]
    Upstream(String),

    #[error("receipt signing failed: {0}")]
    ReceiptSign(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
}
