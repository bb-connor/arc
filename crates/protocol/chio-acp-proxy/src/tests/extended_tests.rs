use crate::config::AcpProxyConfig;

fn test_config() -> AcpProxyConfig {
    AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_allowed_command("npm")
}

// ================================================================
// 1. Protocol Parsing Edge Cases
// ================================================================

mod protocol;

mod guards;

mod interceptor;

mod permissions;

mod receipts;

mod config;
