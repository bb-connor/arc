use super::*;
use serde_json::json;

fn test_config() -> AcpProxyConfig {
    AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_allowed_command("npm")
}

// ================================================================
// 1. Protocol Parsing Edge Cases
// ================================================================

#[path = "extended_protocol.rs"]
mod protocol;

#[path = "extended_guards.rs"]
mod guards;

#[path = "extended_interceptor.rs"]
mod interceptor;

#[path = "extended_permissions.rs"]
mod permissions;

#[path = "extended_receipts.rs"]
mod receipts;

#[path = "extended_config.rs"]
mod config;
