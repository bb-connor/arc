//! Tool action extraction from PACT tool call requests.
//!
//! Guards need to know *what kind of action* a tool call performs (file access,
//! shell command, network egress, etc.).  This module provides a `ToolAction`
//! enum that guards match on, plus extraction logic that derives the action
//! from `ToolCallRequest.tool_name` and `ToolCallRequest.arguments`.

use serde_json::Value;

/// A categorized action derived from a tool call request.
///
/// This plays the same role as ClawdStrike's `GuardAction` enum, but is
/// produced by inspecting `ToolCallRequest` fields rather than being
/// supplied directly.
#[derive(Clone, Debug)]
pub enum ToolAction {
    /// File system read (path).
    FileAccess(String),
    /// File system write (path, content bytes).
    FileWrite(String, Vec<u8>),
    /// Network egress (host, port).
    NetworkEgress(String, u16),
    /// Shell command execution (command line).
    ShellCommand(String),
    /// MCP tool invocation (tool_name, args).
    McpTool(String, Value),
    /// Patch application (file, diff).
    Patch(String, String),
    /// Unknown / not categorized -- guards that don't match should allow.
    Unknown,
}

impl ToolAction {
    /// Return the path targeted by clearly filesystem-shaped actions.
    pub fn filesystem_path(&self) -> Option<&str> {
        match self {
            Self::FileAccess(path) | Self::FileWrite(path, _) | Self::Patch(path, _) => {
                Some(path.as_str())
            }
            _ => None,
        }
    }
}

/// Extract a `ToolAction` from a tool name and its arguments.
///
/// This uses a best-effort heuristic based on common tool naming conventions.
/// Guards that receive `ToolAction::Unknown` should return `Verdict::Allow`
/// (the guard simply does not apply to that action type).
pub fn extract_action(tool_name: &str, arguments: &Value) -> ToolAction {
    let tool = tool_name.to_lowercase();

    // File read tools
    if matches!(
        tool.as_str(),
        "read_file" | "read" | "file_read" | "get_file" | "cat"
    ) {
        if let Some(path) = extract_path(arguments) {
            return ToolAction::FileAccess(path);
        }
    }

    // File write tools
    if matches!(
        tool.as_str(),
        "write_file" | "write" | "file_write" | "create_file" | "put_file" | "edit_file" | "edit"
    ) {
        if let Some(path) = extract_path(arguments) {
            let content = arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            return ToolAction::FileWrite(path, content);
        }
    }

    // Generic filesystem tools -- disambiguate read vs write by inspecting
    // the `action` parameter or the presence of `content`.
    if matches!(tool.as_str(), "filesystem" | "fs" | "file") {
        if let Some(path) = extract_path(arguments) {
            let is_write = arguments
                .get("action")
                .and_then(|v| v.as_str())
                .map(|a| {
                    let a = a.to_lowercase();
                    a == "write" || a == "create" || a == "append"
                })
                .unwrap_or(false)
                || arguments.get("content").is_some();

            if is_write {
                let content = arguments
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec();
                return ToolAction::FileWrite(path, content);
            } else {
                return ToolAction::FileAccess(path);
            }
        }
    }

    // Patch / apply diff tools
    if matches!(tool.as_str(), "apply_patch" | "patch" | "apply_diff") {
        if let Some(path) = extract_path(arguments) {
            let diff = arguments
                .get("diff")
                .or_else(|| arguments.get("patch"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return ToolAction::Patch(path, diff);
        }
    }

    // Shell / command execution tools
    if matches!(
        tool.as_str(),
        "bash" | "shell" | "run_command" | "exec" | "execute" | "run" | "shell_exec" | "terminal"
    ) {
        if let Some(cmd) = arguments
            .get("command")
            .or_else(|| arguments.get("cmd"))
            .or_else(|| arguments.get("input"))
            .and_then(|v| v.as_str())
        {
            return ToolAction::ShellCommand(cmd.to_string());
        }
    }

    // Network / HTTP tools
    if matches!(
        tool.as_str(),
        "http_request" | "fetch" | "curl" | "http" | "request" | "web_request"
    ) {
        if let Some(url) = arguments
            .get("url")
            .or_else(|| arguments.get("uri"))
            .and_then(|v| v.as_str())
        {
            if let Some((host, port)) = parse_host_port(url) {
                return ToolAction::NetworkEgress(host, port);
            }
        }
    }

    // MCP tool invocations (generic passthrough)
    if tool.starts_with("mcp_") || tool.contains("mcp") {
        return ToolAction::McpTool(tool_name.to_string(), arguments.clone());
    }

    // Fallback: treat as a generic MCP tool invocation so the MCP guard can
    // still apply its block/allow lists.
    ToolAction::McpTool(tool_name.to_string(), arguments.clone())
}

fn extract_path(arguments: &Value) -> Option<String> {
    arguments
        .get("path")
        .or_else(|| arguments.get("file"))
        .or_else(|| arguments.get("file_path"))
        .or_else(|| arguments.get("filename"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn parse_host_port(url: &str) -> Option<(String, u16)> {
    // Try parsing as a URL
    if let Some(rest) = url.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_host_port(host, 443);
        return Some((host, port));
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_host_port(host, 80);
        return Some((host, port));
    }
    // Bare host
    let host = url.split('/').next().unwrap_or(url);
    if host.contains('.') || host == "localhost" {
        let (host, port) = split_host_port(host, 443);
        return Some((host, port));
    }
    None
}

fn split_host_port(host_with_port: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = host_with_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (host_with_port.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_file_access() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("read_file", &args);
        assert!(matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"));
    }

    #[test]
    fn extract_file_write() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "content": "hello"});
        let action = extract_action("write_file", &args);
        assert!(matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"));
    }

    #[test]
    fn extract_shell_command() {
        let args = serde_json::json!({"command": "ls -la"});
        let action = extract_action("bash", &args);
        assert!(matches!(action, ToolAction::ShellCommand(ref c) if c == "ls -la"));
    }

    #[test]
    fn extract_network_egress() {
        let args = serde_json::json!({"url": "https://evil.com/api"});
        let action = extract_action("http_request", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 443) if h == "evil.com"));
    }

    #[test]
    fn extract_network_with_port() {
        let args = serde_json::json!({"url": "http://localhost:8080/health"});
        let action = extract_action("fetch", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 8080) if h == "localhost"));
    }

    #[test]
    fn unknown_tool_becomes_mcp_tool() {
        let args = serde_json::json!({"foo": "bar"});
        let action = extract_action("custom_tool", &args);
        assert!(matches!(action, ToolAction::McpTool(_, _)));
    }

    #[test]
    fn filesystem_tool_read_by_default() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for filesystem tool with path-only params, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_explicit_read_action() {
        let args = serde_json::json!({"path": "/etc/shadow", "action": "read"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for filesystem tool with action=read, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_write_action() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "action": "write", "content": "hi"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"),
            "expected FileWrite for filesystem tool with action=write, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_write_inferred_from_content() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "content": "data"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"),
            "expected FileWrite for filesystem tool with content field, got: {action:?}"
        );
    }

    #[test]
    fn fs_tool_alias() {
        let args = serde_json::json!({"path": "/etc/passwd"});
        let action = extract_action("fs", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/passwd"),
            "expected FileAccess for fs tool alias, got: {action:?}"
        );
    }

    #[test]
    fn file_tool_alias() {
        let args = serde_json::json!({"path": "/etc/passwd"});
        let action = extract_action("file", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/passwd"),
            "expected FileAccess for file tool alias, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_actions_expose_target_path() {
        let read = extract_action(
            "filesystem",
            &serde_json::json!({"path": "/repo/src/lib.rs"}),
        );
        let write = extract_action(
            "filesystem",
            &serde_json::json!({"path": "/repo/src/lib.rs", "action": "write", "content": "hi"}),
        );
        let patch = extract_action(
            "apply_patch",
            &serde_json::json!({"path": "/repo/src/lib.rs", "patch": "@@ -1 +1 @@"}),
        );

        assert_eq!(read.filesystem_path(), Some("/repo/src/lib.rs"));
        assert_eq!(write.filesystem_path(), Some("/repo/src/lib.rs"));
        assert_eq!(patch.filesystem_path(), Some("/repo/src/lib.rs"));
    }
}
