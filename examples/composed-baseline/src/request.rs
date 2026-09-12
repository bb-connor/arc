//! The wire shape a receiver in the composed alternative sees.
//!
//! One tool call, carried over a channel authenticated by a pinned peer key,
//! accompanied by a decision the sender's policy engine signed. This is the
//! shape the off-the-shelf parts produce: an MCP-style tool invocation, a
//! caller identity, a detached policy decision, a caller-chosen request
//! identifier for the replay table, and a context object the policy engine
//! evaluates against.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Schema tag carried inside every signed decision. Domain separation, so a
/// document the same key signed for another purpose cannot be presented here.
pub const AUTHORIZATION_SCHEMA: &str = "composed-baseline.policy-decision.v1";

/// The decision a policy engine signed. The receiver sees the exact bytes the
/// signer covered (`ComposedRequest::authorization_json`) and parses them
/// itself, which is how a detached signature over a JSON document travels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub schema: String,
    pub decision_id: String,
    pub agreement_id: String,
    /// Workload identity of the caller, in the form a federated trust domain
    /// issues.
    pub principal: String,
    /// Receiver this decision was issued for. Carried, but only the hardened
    /// profile checks it.
    pub audience: String,
    pub action: String,
    pub resource: String,
    /// SHA-256 over the canonical encoding of the arguments the decision covers.
    pub tool_args_sha256: String,
    pub verdict: String,
    pub policy_id: String,
    pub policy_version: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// One tool call as the composed receiver receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedRequest {
    /// Caller-chosen identifier. The replay table is keyed by it.
    pub request_id: String,
    pub tool_name: String,
    pub tool_args: Value,
    pub caller: String,
    /// Attributes the policy engine evaluates. In the composed wiring these
    /// arrive with the request, which is how every policy-decision-point
    /// integration passes a request context.
    pub context: BTreeMap<String, Value>,
    /// The exact bytes the sender's policy engine signed.
    pub authorization_json: String,
    /// Hex Ed25519 over `authorization_json`'s bytes.
    pub authorization_sig: String,
}

/// The request plus the peer's signature over it. The peer signature stands in
/// for the channel's mutual authentication: possession of the pinned key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedEnvelope {
    pub request: ComposedRequest,
    /// Hex Ed25519 over the canonical encoding of `request`. Absent when the
    /// case under test removes it.
    pub peer_sig: Option<String>,
}

impl ComposedRequest {
    /// Byte size of the request as it crosses the wire, for the bandwidth
    /// column of the comparison.
    pub fn wire_bytes(&self) -> Result<usize, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| bytes.len())
    }
}
