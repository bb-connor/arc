//! Host-guest ABI for WASM guard invocation.
//!
//! This module defines the data types that cross the WASM boundary and the
//! trait that any WASM runtime backend must implement.

use serde::{Deserialize, Serialize};

use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// ABI constants
// ---------------------------------------------------------------------------

/// Return code from the guest `evaluate` function indicating "allow".
pub const VERDICT_ALLOW: i32 = 0;

/// Return code from the guest `evaluate` function indicating "deny".
pub const VERDICT_DENY: i32 = 1;

// ---------------------------------------------------------------------------
// Data types exchanged across the WASM boundary
// ---------------------------------------------------------------------------

/// Read-only request context passed to the WASM guard.
///
/// This is serialized as JSON and written into guest linear memory before
/// calling `evaluate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRequest {
    /// Tool being invoked.
    pub tool_name: String,
    /// Server hosting the tool.
    pub server_id: String,
    /// Agent making the request.
    pub agent_id: String,
    /// Tool arguments as an opaque JSON value.
    pub arguments: serde_json::Value,
    /// Capability scopes granted (serialized scope names).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional session metadata for stateful guards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_metadata: Option<serde_json::Value>,
}

/// Verdict returned by a WASM guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// The guard allows the request.
    Allow,
    /// The guard denies the request with an optional reason.
    Deny { reason: Option<String> },
}

impl GuardVerdict {
    /// Returns `true` if the verdict allows the request.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the verdict denies the request.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Trait that abstracts the WASM runtime engine.
///
/// Implementors load a `.wasm` module, instantiate it with fuel metering,
/// and execute the guest `evaluate` function.
pub trait WasmGuardAbi: Send + Sync {
    /// Load a WASM module from raw bytes.
    ///
    /// The `fuel_limit` controls the maximum number of fuel units the guest
    /// may consume before the runtime terminates it (fail-closed).
    fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64)
        -> Result<(), WasmGuardError>;

    /// Invoke the loaded guard with the given request.
    ///
    /// Returns the guard's verdict. If the guest traps, runs out of fuel,
    /// or returns an unexpected value, the implementation must return
    /// `Err(WasmGuardError)`, and the caller will treat the invocation as
    /// denied (fail-closed).
    fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError>;

    /// Return the name of the runtime backend (e.g. "wasmtime", "mock").
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Guest-side deny reason protocol
// ---------------------------------------------------------------------------

/// Structured deny response optionally written by the guest into shared memory.
///
/// The guest may write this as JSON starting at offset 0 in a designated
/// "deny_reason" exported memory region. If the region is absent or the
/// JSON is malformed, the host uses a generic denial message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestDenyResponse {
    /// Human-readable reason for the denial.
    pub reason: String,
}
