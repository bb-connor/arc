//! Example guard: tool-name-based allow/deny.
//!
//! Demonstrates GEXM-01: basic tool name inspection using the SDK.
//! Allows all tools except those on a deny list.

use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    if tool_is_blocked(req.tool_name.as_str()) {
        GuardVerdict::deny("tool is blocked by policy")
    } else {
        GuardVerdict::allow()
    }
}

fn tool_is_blocked(tool_name: &str) -> bool {
    let trimmed = tool_name.trim();
    if trimmed.is_empty() || trimmed != tool_name {
        return true;
    }
    matches!(trimmed, "dangerous_tool" | "rm_rf" | "drop_database")
}

#[cfg(test)]
mod tests {
    use super::tool_is_blocked;

    #[test]
    fn tool_is_blocked_rejects_padded_blocked_names() {
        assert!(tool_is_blocked("dangerous_tool"));
        assert!(tool_is_blocked(" dangerous_tool "));
        assert!(tool_is_blocked(" safe_tool "));
    }
}
