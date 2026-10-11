use super::*;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_config() -> AcpProxyConfig {
    AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_allowed_command("npm")
}

#[path = "core_guards.rs"]
mod guards;

#[path = "core_receipts.rs"]
mod receipts;

#[path = "core_protocol.rs"]
mod protocol;

#[path = "core_interceptor.rs"]
mod interceptor;
