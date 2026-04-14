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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_with_defaults() {
        let json = r#"{"name": "pii-guard", "path": "/etc/arc/guards/pii.wasm"}"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with defaults");
        assert_eq!(config.name, "pii-guard");
        assert_eq!(config.fuel_limit, DEFAULT_FUEL_LIMIT);
        assert_eq!(config.priority, 1000);
        assert!(!config.advisory);
    }

    #[test]
    fn config_deserializes_with_overrides() {
        let json = r#"{
            "name": "custom",
            "path": "/opt/guard.wasm",
            "fuel_limit": 5000000,
            "priority": 50,
            "advisory": true
        }"#;
        let config: WasmGuardConfig =
            serde_json::from_str(json).expect("deserialize config with overrides");
        assert_eq!(config.fuel_limit, 5_000_000);
        assert_eq!(config.priority, 50);
        assert!(config.advisory);
    }

    #[test]
    fn config_round_trips_through_json() {
        let original = WasmGuardConfig {
            name: "test".to_string(),
            path: "/tmp/test.wasm".to_string(),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: WasmGuardConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered.name, original.name);
        assert_eq!(recovered.fuel_limit, original.fuel_limit);
    }

    #[test]
    fn config_missing_name_fails() {
        let json = r#"{"path": "/etc/arc/guards/test.wasm"}"#;
        let result: Result<WasmGuardConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn config_missing_path_fails() {
        let json = r#"{"name": "test"}"#;
        let result: Result<WasmGuardConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn config_all_fields_explicit() {
        let json = r#"{
            "name": "pii-guard",
            "path": "/etc/arc/guards/pii.wasm",
            "fuel_limit": 2000000,
            "priority": 50,
            "advisory": true
        }"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize all fields");
        assert_eq!(config.name, "pii-guard");
        assert_eq!(config.fuel_limit, 2_000_000);
        assert_eq!(config.priority, 50);
        assert!(config.advisory);
    }

    #[test]
    fn config_zero_fuel_limit_allowed() {
        let json = r#"{"name": "test", "path": "/test.wasm", "fuel_limit": 0}"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.fuel_limit, 0);
    }

    #[test]
    fn config_max_priority_allowed() {
        let json = r#"{"name": "test", "path": "/test.wasm", "priority": 4294967295}"#;
        let config: WasmGuardConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.priority, u32::MAX);
    }
}
