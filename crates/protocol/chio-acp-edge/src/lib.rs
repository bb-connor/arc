//! # chio-acp-edge
//!
//! Edge crate that exposes Chio tools as ACP (Agent Client Protocol)
//! capabilities. This allows ACP-compatible editors and IDEs to access Chio
//! tools over ACP-shaped permission and invocation surfaces.
//!
//! Responsibilities:
//!
//! 1. Map Chio tool definitions to ACP capability advertisements.
//! 2. Intercept ACP `session/request_permission` calls.
//! 3. Expose truthful ACP lifecycle semantics: permission preview, blocking
//!    `tool/invoke`, and deferred-task `tool/stream` / `tool/cancel` /
//!    `tool/resume`.
//! 4. Route every invocation through the Chio kernel.
//! 5. Evaluate `BridgeFidelity` per tool.
//!
//! Kernel entrypoints emit signed Chio receipts. Original request bytes are
//! bounded and validated before protocol projection.

#![forbid(unsafe_code)]
pub use config::AcpEdgeConfig;
pub use edge::ChioAcpEdge;
pub use types::{
    AcpCapability, AcpCategory, AcpInvocationResult, AcpInvocationTask, AcpJsonRpcResponse,
    AcpKernelExecutionContext, AcpTaskStatus, PermissionDecision, PermissionRequest,
};

mod request_error;
pub use request_error::{AcpField, AcpFieldViolation, AcpRequestError};

use chio_security_types::clock::ClockError;

use chio_cross_protocol::error::BridgeError;

#[cfg(feature = "fuzz")]
pub mod fuzz;

pub mod metrics;
pub use metrics::{
    receipt_write_outcome_for_verdict, receipt_write_total, render_acp_edge_metrics_prometheus,
    CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW, RECEIPT_WRITE_OUTCOME_DENY,
    RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

// ---------- modules ----------

mod error;
pub use error::AcpEdgeError;
mod bridge;
mod config;
mod conversion;
mod edge;
mod jsonrpc;
#[cfg(test)]
mod tests;
mod types;
