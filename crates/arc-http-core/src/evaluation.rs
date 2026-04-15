//! Shared HTTP substrate response types.

use serde::{Deserialize, Serialize};

use crate::{GuardEvidence, HttpReceipt, Verdict};

/// Response body for sidecar HTTP request evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    #[serde(default)]
    pub evidence: Vec<GuardEvidence>,
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
