//! Configuration schema types for `arc.yaml`.
//!
//! Every struct uses `deny_unknown_fields` so that typos in config keys
//! are caught at parse time rather than silently ignored.

use serde::Deserialize;

/// Root configuration parsed from `arc.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArcConfig {
    /// Kernel configuration (required).
    pub kernel: KernelConfig,

    /// Adapter definitions. At least one is required.
    #[serde(default)]
    pub adapters: Vec<AdapterConfig>,

    /// Edge definitions (optional).
    #[serde(default)]
    pub edges: Vec<EdgeConfig>,

    /// Receipt store configuration (optional, defaults applied).
    #[serde(default)]
    pub receipts: ReceiptsConfig,

    /// Logging configuration (optional, defaults applied).
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Kernel section -- the only section that is always required.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfig {
    /// Ed25519 signing key (hex or "generate" for dev mode).
    pub signing_key: String,

    /// Receipt store URI (e.g., "sqlite:///var/arc/receipts.db").
    #[serde(default = "default_receipt_store")]
    pub receipt_store: String,

    /// Log level override for the kernel.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// A single adapter entry that connects to an upstream API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// Unique identifier for this adapter, referenced by edges.
    pub id: String,

    /// Protocol type: "openapi", "grpc", "graphql", etc.
    pub protocol: String,

    /// Upstream URL of the API being protected.
    pub upstream: String,

    /// Path to the API specification file (e.g., an OpenAPI spec).
    #[serde(default)]
    pub spec: Option<String>,

    /// Authentication configuration for the upstream connection.
    #[serde(default)]
    pub auth: Option<AdapterAuthConfig>,
}

/// Authentication block for an adapter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterAuthConfig {
    /// Auth type: "bearer", "api_key", "cookie", "mtls", "none".
    #[serde(rename = "type")]
    pub auth_type: String,

    /// Header name (required for bearer and api_key types).
    #[serde(default)]
    pub header: Option<String>,
}

/// An edge that exposes an adapter through a different protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Unique identifier for this edge.
    pub id: String,

    /// Edge protocol: "mcp", "a2a", etc.
    pub protocol: String,

    /// Adapter ID that this edge exposes. Must reference an existing adapter.
    pub expose_from: String,
}

/// Receipt store configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptsConfig {
    /// Store URI.
    #[serde(default = "default_receipt_store")]
    pub store: String,

    /// Number of receipts between Merkle checkpoints.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,

    /// How many days to retain receipts.
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
}

impl Default for ReceiptsConfig {
    fn default() -> Self {
        Self {
            store: default_receipt_store(),
            checkpoint_interval: default_checkpoint_interval(),
            retention_days: default_retention_days(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: "json" or "text".
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

// -- Default value functions --

fn default_receipt_store() -> String {
    "sqlite:///var/arc/receipts.db".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_checkpoint_interval() -> u64 {
    100
}

fn default_retention_days() -> u64 {
    90
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_default_values() {
        let r = ReceiptsConfig::default();
        assert_eq!(r.store, "sqlite:///var/arc/receipts.db");
        assert_eq!(r.checkpoint_interval, 100);
        assert_eq!(r.retention_days, 90);
    }

    #[test]
    fn logging_default_values() {
        let l = LoggingConfig::default();
        assert_eq!(l.level, "info");
        assert_eq!(l.format, "json");
    }

    #[test]
    fn deny_unknown_fields_kernel() {
        let yaml = r#"
            signing_key: "generate"
            bogus_field: true
        "#;
        let result: Result<KernelConfig, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn deny_unknown_fields_adapter() {
        let yaml = r#"
            id: "test"
            protocol: "openapi"
            upstream: "http://localhost:8000"
            not_a_field: 42
        "#;
        let result: Result<AdapterConfig, _> = serde_yml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_adapter_with_auth() {
        let yaml = r#"
            id: "petstore"
            protocol: "openapi"
            upstream: "http://localhost:8000"
            spec: "./petstore.yaml"
            auth:
              type: "bearer"
              header: "Authorization"
        "#;
        let adapter: AdapterConfig =
            serde_yml::from_str(yaml).unwrap_or_else(|e| panic!("deser failed: {e}"));
        assert_eq!(adapter.id, "petstore");
        let auth = adapter.auth.unwrap_or_else(|| panic!("auth missing"));
        assert_eq!(auth.auth_type, "bearer");
        assert_eq!(
            auth.header.unwrap_or_else(|| panic!("header missing")),
            "Authorization"
        );
    }
}
