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
    out.push_str("# REVIEW REQUIRED: verify inferred scopes before promoting.\n\n");

    for cap in capabilities {
        out.push_str("[[capability]]\n");
        out.push_str(&format!("tool = \"{}\"\n", escape_toml(&cap.tool)));
        out.push_str(&format!("scope = \"{}\"\n", scope_label(cap.scope)));
        out.push_str(&format!("urn = \"{}\"\n", cap.urn));
        if let Some(desc) = cap.description.as_ref() {
            out.push_str(&format!("description = \"{}\"\n", escape_toml(desc)));
        }
        out.push_str(&format!("allow = {}\n", cap.allow));
        out.push_str("# REVIEW REQUIRED: keep denied or explicitly promote\n\n");
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
        )?;
        let operation = if cage_required && transport.enforcement_evidence().is_none() {
            Err(CliError::cli_other_error(
                "cage-required MCP launch returned no fully enforced evidence".to_string(),
            ))
        } else {
            transport
                .list_tools()
                .map_err(|error| CliError::cli_other_error(format!("failed to list tools: {error}")))
        };
        let shutdown = transport.shutdown().map_err(|error| {
            CliError::cli_other_error(format!(
                "MCP scope inference terminal receipt persistence failed: {error}"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create manifest test directory: {error}"));
        let path = directory.path().join("allowlist.toml");
        std::fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("write manifest test fixture: {error}"));
        (directory, path)
    }

    #[test]
    fn promoted_manifest_scaffold_preserves_the_existing_allowlist_syntax() {
        let (_directory, path) = write_manifest(
            r#"
server_id = "filesystem"

[[capability]]
tool = "read_file"
scope = "filesystem"
urn = "urn:chio:scope:filesystem"
description = "Read a file"
allow = true

[[capability]]
tool = "delete_file"
allow = false
"#,
        );

        let allowed = load_manifest_allowlist(&path, "filesystem")
            .unwrap_or_else(|error| panic!("load promoted manifest: {error}"));

        assert_eq!(
            allowed,
            std::collections::BTreeSet::from(["read_file".to_string()])
        );
    }

    #[test]
    fn promoted_manifest_scaffold_rejects_security_and_unknown_fields() {
        for (name, contents) in [
            (
                "flow",
                r#"
[[capability]]
tool = "read_file"
allow = true
flow = { input_classification = "confidential" }
"#,
            ),
            (
                "security",
                r#"
server_id = "filesystem"
[security]
mode = "enforce"
"#,
            ),
            (
                "unknown",
                r#"
[[capability]]
tool = "read_file"
allow = true
future_policy = "allow"
"#,
            ),
        ] {
            let (_directory, path) = write_manifest(contents);
            let error = match load_manifest_allowlist(&path, "filesystem") {
                Ok(_) => panic!("{name} metadata must fail closed"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(
                message.contains("unknown field"),
                "{name} metadata returned a non-schema error: {message}"
            );
        }
    }

    #[test]
    fn promoted_manifest_scaffold_is_bound_to_the_expected_server() {
        let (_directory, path) = write_manifest(
            r#"
server_id = "server-a"

[[capability]]
tool = "read_file"
allow = true
"#,
        );
        let error = load_manifest_allowlist(&path, "server-b")
            .expect_err("cross-server allowlist replay must fail closed");
        assert!(error.to_string().contains("server_id must exactly match"));
    }
}
