//! Shared HTTP substrate response types.

use arc_kernel::SignedExecutionNonce;
use serde::{Deserialize, Serialize};

use crate::{GuardEvidence, HttpReceipt, Verdict};

/// Response body for sidecar HTTP request evaluation.
///
/// Phase 1.1 added the optional `execution_nonce` sibling field. On an
/// `Allow` verdict from a kernel configured with
/// `ExecutionNonceConfig`, the response carries a short-lived signed
/// nonce that the client MUST re-present before executing the tool call.
/// The field is `None` on `Deny`/`Cancel`/`Incomplete` and on legacy
/// deployments without a nonce config, preserving wire-level backward
/// compatibility (existing SDKs continue to parse the payload because
/// missing JSON fields deserialize into `None` via `#[serde(default)]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    #[serde(default)]
    pub evidence: Vec<GuardEvidence>,
    /// Optional signed execution nonce. Present only when the kernel
    /// issues one (allow verdict + strict/opt-in nonce mode). See
    /// `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,
}

/// Response body for receipt verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReceiptResponse {
    pub valid: bool,
}

/// Sidecar health states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Response body for sidecar health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: SidecarStatus,
    pub version: String,
}
