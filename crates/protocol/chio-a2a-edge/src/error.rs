// Edge error type and receipt-write error accounting helpers.

/// Errors produced by the A2A edge.
#[derive(Debug, thiserror::Error)]
pub enum A2aEdgeError {
    #[error("{0}")]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("{}", .0.code())]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error("urn:chio:error:transport:task-capacity-exceeded")]
    TaskCapacity,

    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The requested operation or execution mode is not supported.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(&'static str),

    /// The requested task does not exist or is inaccessible to this caller.
    #[error("task not found: {0}")]
    TaskNotFound(String),

    /// The task has reached a terminal state that cannot be cancelled.
    #[error("task is not cancelable: {0}")]
    TaskNotCancelable(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest construction failed.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),

    /// Cross-protocol orchestration failed.
    #[error("bridge error: {0}")]
    Bridge(#[from] BridgeError),
}

fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

fn record_receipt_write_bridge_error(error: &BridgeError) {
    if matches!(error, BridgeError::Kernel(_)) {
        record_receipt_write_error();
    }
}
