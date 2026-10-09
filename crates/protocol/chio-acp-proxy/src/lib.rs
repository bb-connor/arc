//! # chio-acp-proxy
//!
//! Security proxy for the Agent Client Protocol (ACP). Sits between an
//! editor/IDE client and an ACP coding agent, intercepting JSON-RPC
//! messages to enforce Chio capability-based access control.
//!
//! The proxy:
//!
//! 1. Spawns the ACP agent as a subprocess with stdio transport.
//! 2. Forwards JSON-RPC messages bidirectionally (client <-> agent).
//! 3. Intercepts `session/request_permission` to enforce capability tokens.
//! 4. Intercepts `fs/read_text_file` and `fs/write_text_file` to validate
//!    path-scoped capabilities.
//! 5. Intercepts `terminal/create` to run command guards.
//! 6. Generates unsigned audit entries for all `tool_call` events observed
//!    in `session/update` notifications. These can be promoted to signed
//!    Chio receipts by a downstream component with key material.

#![forbid(unsafe_code)]
pub use attestation::{
    AcpAttestationMode, AcpCapabilityRequest, AcpReceiptRequest, AcpVerdict, CapabilityCheckError,
    CapabilityChecker, ReceiptSigner,
};
pub use compliance::{
    generate_compliance_certificate, generate_compliance_certificate_with_coverage,
    verify_compliance_certificate, verify_compliance_certificate_with_clock,
    CertificateVerificationResult, CertificateVerificationScope, ComplianceBundleError,
    ComplianceCertificate, ComplianceCertificateBody, ComplianceCertificateError,
    ComplianceCheckStatus, ComplianceChecks, ComplianceConfig, ComplianceCoverage,
    ComplianceProfile, ComplianceReceiptEntry, ComplianceToolTarget, VerificationMode,
    COMPLIANCE_CERTIFICATE_SCHEMA, COMPLIANCE_CERTIFICATE_SCHEMA_V1,
};
pub use config::AcpProxyConfig;
pub use fs_guard::FsGuard;
pub use interceptor::{Direction, InterceptResult, MessageInterceptor};
pub use kernel_checker::KernelCapabilityChecker;
pub use kernel_signer::{KernelReceiptSigner, KernelSignerCheckpointHealth};
pub use permission::{MappedPermission, PermissionDecision, PermissionMapper};
pub use protocol::{
    extract_method, json_rpc_error, json_rpc_error_with_data, parse_session_update, AcpMethod,
    CreateTerminalParams, JsonRpcError, JsonRpcMessage, KillTerminalParams, PermissionOption,
    ReadTextFileParams, ReleaseTerminalParams, RequestPermissionParams, SessionCancelParams,
    SessionUpdate, SessionUpdateNotification, ToolCallEvent, ToolCallUpdateEvent,
    WriteTextFileParams,
};
pub use proxy::AcpProxy;
pub use receipt::{
    AcpCapabilityAuditContext, AcpEnforcementMode, AcpToolCallAuditEntry, ReceiptLogger,
};
pub use telemetry::{
    compliance_certificate_event, derive_trace_id, receipt_to_span, receipt_to_span_with_authority,
    session_root_span, JsonFileExporter, LoggingSpanExporter, ReceiptAuthorityFields, ReceiptSpan,
    ReceiptSpanExporter, SpanAttribute, SpanEvent, TelemetryConfig, TelemetryExportError,
};
pub use terminal_guard::TerminalGuard;
pub use transport::AcpTransport;

mod rejection;
pub use rejection::{AcpGuardError, AcpProtocolError};
mod receipt_error;
pub use receipt_error::{ReceiptAuthorizationError, ReceiptBinding, ReceiptSignError};
mod clock;
pub use clock::{AcpAuditError, AcpClock};
mod input;
pub use input::{AcpFrameReader, AcpMessage, MAX_ACP_MESSAGE_BYTES};

#[cfg(feature = "otel")]
pub mod otel;

// ---------- modules ----------

mod attestation;
mod compliance;
mod config;
mod fs_guard;
mod interceptor;
mod kernel_checker;
mod kernel_signer;
mod permission;
mod protocol;
mod proxy;
mod receipt;
mod telemetry;
mod terminal_guard;
#[cfg(test)]
mod tests;
mod transport;

// ---------- error type ----------

/// Errors produced by the ACP proxy.
#[derive(thiserror::Error)]
pub enum AcpProxyError {
    #[error("{0}")]
    Audit(#[from] AcpAuditError),
    #[error("{0}")]
    Receipt(#[from] ReceiptSignError),
    #[error("{0}")]
    SharedInput(#[from] chio_core::canonical::SharedUntrustedJsonError),
    #[error("{0}")]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("urn:chio:error:transport:upstream-failure")]
    Io(#[from] std::io::Error),
    #[error("urn:chio:error:transport:invalid-request-shape")]
    TruncatedFrame,
    #[error("urn:chio:error:transport:upstream-failure")]
    ClosedTransport,
    #[error("{0}")]
    Capability(#[from] CapabilityCheckError),

    /// A JSON-RPC semantic error.
    #[error("{0}")]
    Protocol(#[from] AcpProtocolError),
    /// A local guard rejected access.
    #[error("{0}")]
    Guard(#[from] AcpGuardError),
    /// A required child pipe was unavailable.
    #[error("urn:chio:error:transport:upstream-failure")]
    PipeUnavailable,
}

impl std::fmt::Debug for AcpProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
