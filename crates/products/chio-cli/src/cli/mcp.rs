// Top-level glue for MCP wrapping and native runtime provisioning.

use super::*;

use chio_mcp_adapter::edge::McpTransport as _;

/// Dispatch entry-point for `chio mcp wrap`.
///
/// Wrapper-side of the native MCP adapter surface (`chio-mcp-adapter` and
/// `chio-hosted-mcp`). It runs the verdict gate over `tools/call`,
/// renders an inferred capability-scope manifest scaffold, and (when
/// `--emit-config` is supplied) emits a paste-ready IDE configuration blob
/// for Cursor / Claude Desktop / Continue / Zed.
pub(crate) fn cmd_mcp_wrap(args: &McpWrapArgs) -> Result<(), CliError> {
    if args.self_test_attestation.is_some() {
        return Err(CliError::cli_other_error(
            "mcp wrap --self-test-attestation is unsupported: no receipt-bound verification is available",
        ));
    }

    if let Some(fixture) = args.e2e_fixture.as_ref() {
        return cmd_mcp_wrap_e2e_fixture(args, fixture);
    }

    if let Some(ide) = args.emit_config.as_ref() {
        if args.command.is_empty() {
            return Err(CliError::cli_other_error(
                "chio mcp wrap --emit-config requires a wrapped command after `--`".to_string(),
            ));
        }
        return cmd_mcp_emit_config(args, *ide);
    }

    if args.print_scopes {
        if args.tools_fixture.is_none() && args.command.is_empty() {
            return Err(CliError::cli_other_error(
                "chio mcp wrap --print-scopes requires either --tools-fixture or a wrapped command"
                    .to_string(),
            ));
        }
        return cmd_mcp_print_scopes(args);
    }

    if args.command.is_empty() {
        return Err(CliError::cli_other_error(
            "chio mcp wrap requires a wrapped command after `--`".to_string(),
        ));
    }
    cmd_mcp_wrap_run(args)
}

/// Load a JSON `tools/list` fixture and decode it as a slice of
/// [`chio_mcp_adapter::edge::McpToolInfo`]. The fixture format is the same
/// shape MCP servers return, e.g. `{ "tools": [ ... ] }` or a bare
/// array.
pub(crate) fn load_tools_fixture(
    path: &std::path::Path,
) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, CliError> {
    let raw = crate::input::read_text(path).map_err(|e| {
        CliError::cli_io_error(format!("failed to read tools fixture {path:?}: {e}"))
    })?;
    let value: serde_json::Value = crate::input::text(&raw).map_err(|e| {
        CliError::cli_other_error(format!("failed to parse tools fixture {path:?}: {e}"))
    })?;
    let array = value
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .or_else(|| value.as_array().cloned())
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "tools fixture {path:?} must be a tools array or object with a 'tools' field"
            ))
        })?;
    let tools: Vec<chio_mcp_adapter::edge::McpToolInfo> =
        serde_json::from_value(serde_json::Value::Array(array)).map_err(|e| {
            CliError::cli_other_error(format!("failed to decode tools fixture {path:?}: {e}"))
        })?;
    Ok(tools)
}

// The sibling `mcp/*.rs` files are real submodules wired in with
// `#[path] mod`; each begins with `use super::*;` to inherit the shared
// imports from this parent and `cli/types.rs`/`cli/runtime.rs`. Their
// crate-internal items are re-exported here so the parent (`mcp_cli` in
// `main.rs`) keeps exposing the same surface (e.g. `McpWrapArgs`,
// `cmd_mcp_wrap`).
#[path = "mcp/cage_policy.rs"]
mod cage_policy;
#[path = "mcp/emit_config.rs"]
mod emit_config;
#[path = "mcp/governed_sim.rs"]
mod governed_sim;
#[path = "mcp/ide.rs"]
mod ide;
#[path = "mcp/manifest.rs"]
mod manifest;
#[path = "mcp/payment_config.rs"]
pub mod payment_config;
#[path = "mcp/provision.rs"]
mod provision;
#[path = "mcp/scope.rs"]
mod scope;
#[path = "mcp/wrap.rs"]
mod wrap;

#[cfg(target_os = "linux")]
pub(crate) use cage_policy::{
    export_broker_native_launch_evidence, export_native_launch_evidence,
    export_native_launch_observations,
};
pub(crate) use cage_policy::{load_native_mcp_launch, SignedCagePolicyLaunchFactory};
pub(crate) use cage_policy::{
    verify_broker_native_launch_evidence, verify_native_launch_evidence,
    verify_native_launch_observation, verify_native_start_file, NativeLaunchEvidence,
    NativeLaunchObservation,
};
pub(crate) use emit_config::cmd_mcp_emit_config;
pub(crate) use governed_sim::{cmd_mcp_governed_sim, GovernedSimArgs};
pub(crate) use manifest::cmd_mcp_print_scopes;
pub(crate) use provision::{
    cmd_provision_native_mcp_demo, cmd_provision_reference_runtime, ProvisionReferenceRuntimeArgs,
};
pub(crate) use wrap::{cmd_mcp_wrap_e2e_fixture, cmd_mcp_wrap_run, McpWrapArgs};
