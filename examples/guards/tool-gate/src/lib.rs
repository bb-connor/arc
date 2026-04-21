//! Example guard: tool-name-based allow/deny.
//!
//! Demonstrates GEXM-01: basic tool name inspection using the SDK.
//! Allows all tools except those on a deny list.

use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    match req.tool_name.as_str() {
        "dangerous_tool" | "rm_rf" | "drop_database" => {
            GuardVerdict::deny("tool is blocked by policy")
        }
        _ => GuardVerdict::allow(),
    }
}
