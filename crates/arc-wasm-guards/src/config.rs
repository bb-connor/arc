//! Configuration for WASM guards loaded via `arc.yaml`.

use serde::{Deserialize, Serialize};

/// Default fuel limit per guard invocation (10 million instructions).
pub const DEFAULT_FUEL_LIMIT: u64 = 10_000_000;

/// Configuration entry for a single WASM guard in `arc.yaml`.
///
/// Example YAML:
///
/// ```yaml
/// wasm_guards:
///   - name: custom-pii-guard
///     path: /etc/arc/guards/pii_guard.wasm
///     fuel_limit: 5000000
///     priority: 100
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmGuardConfig {
    /// Human-readable name for this guard (used in receipts and logs).
    pub name: String,

    /// Filesystem path to the `.wasm` module.
    pub path: String,

    /// Maximum fuel units the guest may consume per invocation.
    /// Defaults to 10,000,000 if omitted.
    #[serde(default = "default_fuel_limit")]
    pub fuel_limit: u64,

    /// Guard evaluation priority. Lower values run first.
    /// Defaults to 1000 if omitted.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// If true, a failure in this guard is treated as advisory (logged but
    /// not blocking). Defaults to `false` (fail-closed).
    #[serde(default)]
    pub advisory: bool,
}

fn default_fuel_limit() -> u64 {
    DEFAULT_FUEL_LIMIT
}

fn default_priority() -> u32 {
    1000
}
