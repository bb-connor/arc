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

use chio_security_types::clock::{AuthorityDeadline, ClockError, ClockReading};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    token::CapabilityToken,
};
use chio_core::session::OperationTerminalState;
use chio_cross_protocol::capability_bridge::{CapabilityBridge, CrossProtocolCapabilityRef};
use chio_cross_protocol::discovery::{
    target_protocol_for_tool_with_registry, DiscoveryProtocol, TargetProtocolRegistry,
};
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::{CrossProtocolExecutionRequest, OpenAiTargetExecutor};
use chio_cross_protocol::lifecycle::{
    runtime_lifecycle_contract, runtime_lifecycle_metadata, RuntimeLifecycleSurface,
};
use chio_cross_protocol::orchestrator::{CrossProtocolOrchestrator, OrchestratedToolCall};
use chio_cross_protocol::semantic_hints::{semantic_hints_for_tool, BridgeFidelity};

use chio_kernel::{
    capability_matches_request_with_model_metadata,
    capability_request_requires_dpop_with_model_metadata, dpop, ChioKernel, SignedExecutionNonce,
    ToolCallOutput, Verdict as KernelVerdict,
};
use chio_manifest::{
    BridgeSecurityMetadata, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
};
use chio_mcp_edge::McpTargetExecutor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(feature = "fuzz")]
pub mod fuzz;

pub mod metrics;
pub use metrics::{
    receipt_write_outcome_for_verdict, receipt_write_total, render_acp_edge_metrics_prometheus,
    CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW, RECEIPT_WRITE_OUTCOME_DENY,
    RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

// ---------- source fragments (include! pattern) ----------
//
// Each fragment merges into this crate-root module scope; item paths and
// visibility resolve as if the fragments were inlined here.

include!("error.rs");
include!("config.rs");
include!("types.rs");
include!("bridge.rs");
include!("conversion.rs");
include!("edge.rs");
include!("jsonrpc.rs");
include!("tests/all.rs");

#[cfg(test)]
#[path = "tests/nonce_preflight.rs"]
mod nonce_preflight_tests;
