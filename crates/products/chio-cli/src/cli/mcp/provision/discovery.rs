//! Tool discovery runs with the provisioned cage's authority. Legacy demo
//! discovery is explicitly unconfined and is never available to root.

use super::{CliError, ProvisionInputs};

#[cfg(unix)]
#[path = "discovery/launch.rs"]
mod launch;
#[cfg(unix)]
#[path = "discovery/transport.rs"]
mod transport;

pub(super) fn discover_tool_surface(
    inputs: &ProvisionInputs,
) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, CliError> {
    #[cfg(unix)]
    {
        let (child, stdin, stdout, stderr) = launch::start(inputs)?;
        let outcome = transport::exchange(stdin, stdout, stderr);
        // The cage denies clone/fork and owns termination through a pidfd.
        // Legacy discovery owns its process group. I/O never waits for EOF.
        drop(child);
        let tools = outcome.map_err(|reason| {
            CliError::cli_other_error(format!("native MCP tool discovery failed: {reason}"))
        })?;
        serde_json::from_value(tools).map_err(|error| {
            CliError::cli_other_error(format!(
                "the native MCP target advertised an invalid tools/list result: {error}"
            ))
        })
    }
    #[cfg(not(unix))]
    {
        let _ = inputs;
        Err(CliError::cli_other_error(
            "live native discovery requires Unix; supply a reviewed --tools-fixture",
        ))
    }
}
