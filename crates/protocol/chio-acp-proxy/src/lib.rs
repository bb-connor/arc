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

mod rejection;
pub use rejection::{AcpGuardError, AcpProtocolError};
mod receipt_error;
pub use receipt_error::{ReceiptAuthorizationError, ReceiptBinding, ReceiptSignError};
mod clock;
use chio_security_types::clock::Clock;
pub use clock::{AcpAuditError, AcpClock};
mod input;
use chio_core::crypto::PublicKey;
pub use input::{AcpFrameReader, AcpMessage, MAX_ACP_MESSAGE_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "otel")]
pub mod otel;

// ---------- source files (include! pattern) ----------

include!("protocol.rs");
include!("config.rs");
include!("fs_guard.rs");
include!("terminal_guard.rs");
include!("permission.rs");
include!("receipt.rs");
include!("attestation.rs");
include!("kernel_signer.rs");
include!("kernel_checker.rs");
include!("compliance.rs");
include!("telemetry.rs");
include!("interceptor.rs");
include!("transport.rs");
include!("proxy.rs");
#[cfg(test)]
mod tests;

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
