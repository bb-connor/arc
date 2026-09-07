// Default-deny manifest scaffold renderer for `chio mcp wrap`.
//
// Emits a TOML scaffold that the user reviews before promoting. The
// scaffold lives at `~/.config/chio/mcp/<server-id>.toml` by convention;
// the renderer is pure so tests can compare bytes.

use super::*;

use super::cage_policy::load_native_mcp_launch;
use super::scope::{infer_scopes, InferredCapability, InferredScope};
use super::wrap::{require_unprotected_wrap_compatible, split_wrapped_command, McpWrapArgs};

/// Render the inferred capability scaffold to a TOML string. The output
/// is deterministic: tools are sorted alphabetically, scopes are emitted
/// in a fixed order, and every capability ships with `allow = false`.
pub(crate) fn render_manifest_scaffold(
    server_id: &str,
    capabilities: &[InferredCapability],
) -> String {
    let mut out = String::new();
    out.push_str("# chio mcp wrap -- inferred capability manifest scaffold\n");
    out.push_str("# Review each tool below; flip `allow = true` to promote.\n");
    out.push_str("# Default is deny.\n\n");
    out.push_str(&format!("server_id = \"{}\"\n", escape_toml(server_id)));
    out.push_str("# TODO: review the inferred scopes below before promoting.\n\n");

    for cap in capabilities {
        out.push_str("[[capability]]\n");
        out.push_str(&format!("tool = \"{}\"\n", escape_toml(&cap.tool)));
        out.push_str(&format!("scope = \"{}\"\n", scope_label(cap.scope)));
        out.push_str(&format!("urn = \"{}\"\n", cap.urn));
        if let Some(desc) = cap.description.as_ref() {
            out.push_str(&format!("description = \"{}\"\n", escape_toml(desc)));
        }
        out.push_str(&format!("allow = {}\n", cap.allow));
        out.push_str("# TODO: review and promote\n\n");
    }
    out
}

fn scope_label(scope: InferredScope) -> &'static str {
    match scope {
        InferredScope::Read => "read",
        InferredScope::FileSystem => "filesystem",
        InferredScope::Network => "network",
        InferredScope::Destructive => "destructive",
        InferredScope::Generic => "generic",
    }
}

fn escape_toml(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestScaffold {
    #[serde(default)]
    server_id: Option<String>,
    #[serde(default)]
    capability: Vec<ManifestScaffoldCapability>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestScaffoldCapability {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    urn: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    allow: Option<bool>,
}

/// Read a promoted manifest scaffold and return the set of tool names
/// flagged `allow = true`. The wrap loop's default verdict gate consults
/// this set; tools that are absent or set to `allow = false` deny.
pub(crate) fn load_manifest_allowlist(
    path: &std::path::Path,
    expected_server_id: &str,
) -> Result<std::collections::BTreeSet<String>, CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::cli_io_error(format!("failed to read manifest {path:?}: {e}")))?;

    let scaffold: ManifestScaffold = toml::from_str(&raw).map_err(|e| {
        CliError::cli_other_error(format!("failed to parse manifest TOML at {path:?}: {e}"))
    })?;

    let ManifestScaffold {
        server_id,
        capability: capabilities,
    } = scaffold;
    if server_id.as_deref() != Some(expected_server_id) {
        return Err(CliError::cli_other_error(format!(
            "manifest server_id must exactly match {expected_server_id:?}"
        )));
    }
    let mut out = std::collections::BTreeSet::new();
    for capability in capabilities {
        let ManifestScaffoldCapability {
            tool,
            scope: _scope,
            urn: _urn,
            description: _description,
            allow,
        } = capability;
        let tool = tool.unwrap_or_default();
        if !tool.is_empty() && allow.unwrap_or(false) {
            out.insert(tool);
        }
    }
    Ok(out)
}

/// Print the inferred manifest scaffold to stdout. Used by
/// `chio mcp wrap --print-scopes`.
pub(crate) fn cmd_mcp_print_scopes(args: &McpWrapArgs) -> Result<(), CliError> {
    let tools = if let Some(fixture) = args.tools_fixture.as_ref() {
        load_tools_fixture(fixture)?
    } else {
        let (program, child_args) = split_wrapped_command(&args.command)?;
        let child_args_refs: Vec<&str> = child_args.iter().map(String::as_str).collect();
        let policy_path = args.cage_policy.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "native MCP launch requires a signed, migration-bound cage policy".to_string(),
            )
        })?;
        let trusted_policy_signer = args.cage_policy_signer.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "native MCP launch has no configured policy trust root".to_string(),
            )
        })?;
        let launch = load_native_mcp_launch(
            policy_path,
            trusted_policy_signer,
            &program,
            &child_args_refs,
            None,
        )?;
        if launch.server_id() != args.server_id {
            return Err(CliError::cli_other_error(
                "native MCP launch policy belongs to a different server".to_string(),
            ));
        }
        require_unprotected_wrap_compatible(&launch)?;
        let cage_required = matches!(
            &launch,
            chio_mcp_adapter::transport::NativeMcpLaunch::CageRequired(_)
        );
        let transport = chio_mcp_adapter::transport::StdioMcpTransport::spawn(
            &program,
            &child_args_refs,
            launch,
        )
        .map_err(|e| {
            CliError::cli_other_error(format!(
                "failed to spawn wrapped MCP server '{program}': {e}"
            ))
        })?;
        let operation = if cage_required && transport.enforcement_evidence().is_none() {
            Err(CliError::cli_other_error(
                "cage-required MCP launch returned no fully enforced evidence".to_string(),
            ))
        } else {
            transport
                .list_tools()
                .map_err(|e| CliError::cli_other_error(format!("failed to list tools: {e}")))
        };
        let shutdown = transport.shutdown().map_err(|e| {
            CliError::cli_other_error(format!(
                "MCP scope inference terminal receipt persistence failed: {e}"
            ))
        });
        match (operation, shutdown) {
            (Ok(tools), Ok(())) => tools,
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Err(operation_error), Err(shutdown_error)) => {
                return Err(CliError::cli_other_error(format!(
                    "{operation_error}; shutdown also failed: {shutdown_error}"
                )))
            }
        }
    };

    let inferred = infer_scopes(&tools);
    let scaffold = render_manifest_scaffold(&args.server_id, &inferred);
    print!("{scaffold}");
    Ok(())
}
