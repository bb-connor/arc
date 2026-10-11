// Edge error type and receipt-write error accounting helpers.
use super::{AcpRequestError, BridgeError, ClockError};

/// Errors produced by the ACP edge.
#[derive(thiserror::Error)]
pub enum AcpEdgeError {
    #[error("{0}")]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("{}", .0.code())]
    Clock(#[from] ClockError),
    #[error("urn:chio:error:transport:task-capacity-exceeded")]
    TaskCapacity,

    /// A deferred task failed; retries retain the original local cause.
    #[error("{0}")]
    Deferred(#[source] std::sync::Arc<AcpEdgeError>),

    #[error("urn:chio:error:transport:invalid-request-shape")]
    Serialization(#[from] serde_json::Error),

    #[error("urn:chio:error:transport:invalid-request-shape")]
    UnknownMethod,

    /// A tool was not found.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("{0}")]
    InvalidRequest(#[from] AcpRequestError),

    /// Access was denied.
    #[error("urn:chio:error:policy:decision-denied")]
    TaskOwnerMismatch,

    /// The kernel reported an error.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Features(#[from] chio_core::error::Error),

    /// Manifest error.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Manifest(#[from] chio_manifest::ManifestError),

    #[error("urn:chio:error:transport:invalid-request-shape")]
    Admission(#[from] chio_manifest::VerifiedManifestAdmissionError),

    /// Cross-protocol orchestration failed.
    #[error("urn:chio:error:transport:upstream-failure")]
    Bridge(#[from] BridgeError),
}

pub(super) fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

pub(super) fn record_receipt_write_bridge_error(error: &BridgeError) {
    if matches!(error, BridgeError::Kernel(_)) {
        record_receipt_write_error();
    }
}

impl std::fmt::Debug for AcpEdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
