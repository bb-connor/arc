//! # chio-a2a-edge
//!
//! Edge crate that exposes Chio tools as A2A (Agent-to-Agent) skills. This is
//! the reverse direction from `chio-a2a-adapter`: instead of consuming a remote
//! A2A server, this crate *serves* Chio tools to A2A clients.
//!
//! Responsibilities:
//!
//! 1. Publish an A2A Agent Card at `/.well-known/agent-card.json`.
//! 2. Accept `SendMessage` requests and route them through the Chio kernel by
//!    default.
//! 3. Expose a truthful blocking `message/send` surface plus deferred
//!    receipt-bearing `message/stream` task lifecycle.
//! 4. Evaluate `BridgeFidelity` per tool to signal translation quality.
//!
//! Kernel-backed entrypoints produce signed Chio receipts. The streaming
//! surface is truthful but bounded: `message/stream` creates a deferred task,
//! `task/get` resolves the terminal receipt-bearing result, and `task/cancel`
//! can cancel a deferred task before execution.
//!
//! ## Modules
//!
//! The implementation is split into focused source fragments that share this
//! crate-root module scope (via `include!`):
//!
//! - `error`: the [`A2aEdgeError`] type and receipt-write accounting helpers.
//! - `config`: the [`A2aEdgeConfig`] published in the Agent Card.
//! - `types`: A2A protocol wire types and the kernel execution context.
//! - `bridge`: capability bridge, skill candidates, fidelity, orchestration.
//! - `conversion`: message conversion and Chio metadata envelope builders.
//! - `edge`: the [`ChioA2aEdge`] server.

#![forbid(unsafe_code)]

pub mod metrics;
pub use metrics::{
    receipt_write_outcome_for_verdict, receipt_write_total, render_a2a_edge_metrics_prometheus,
    CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW, RECEIPT_WRITE_OUTCOME_DENY,
    RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

#[cfg(feature = "otel")]
pub mod otel;

// ---------- modules ----------
pub use config::A2aEdgeConfig;
pub use edge::ChioA2aEdge;
pub use error::A2aEdgeError;
pub use jsonrpc::MAX_A2A_REQUEST_BYTES;
pub use types::{
    A2aJsonRpcResponse, A2aKernelExecutionContext, A2aMessage, A2aPart, A2aSkillEntry,
    AgentCapabilities, AgentCard, AgentInterface, SendMessageRequest, TaskResponse, TaskStatus,
};

mod bridge;
mod config;
mod conversion;
mod edge;
mod error;
mod jsonrpc;
#[cfg(test)]
mod tests;
mod types;
