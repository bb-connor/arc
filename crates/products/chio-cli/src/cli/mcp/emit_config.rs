// IDE config blob renderer for `chio mcp wrap --emit-config <target>`.
//
// Each IDE has its own schema; the rendered JSON is canonical (sorted
// keys via `serde_json::to_string_pretty`) and the schema version is
// pinned in [`IdeTarget::schema_version`].

use super::*;

use super::ide::IdeTarget;
use super::wrap::McpWrapArgs;

/// Render the paste-ready IDE config blob for the supplied target.
/// Pure function so the test corpus can compare bytes against the
/// pinned `tests/fixtures/ide/<target>.expected.json` files.
pub(crate) fn render_ide_config(
    target: IdeTarget,
    server_id: &str,
    display_name: Option<&str>,
    manifest_path: &std::path::Path,
    cage_policy_path: &std::path::Path,
    cage_policy_signer: &str,
    command: &[String],
) -> Result<String, CliError> {
    let (program, child_args) = command.split_first().ok_or_else(|| {
        CliError::cli_other_error("emit-config requires a wrapped command".to_string())
    })?;
    let child_args_vec: Vec<String> = child_args.to_vec();
    let manifest_path = path_argument(manifest_path, "manifest")?;
    let cage_policy_path = path_argument(cage_policy_path, "cage policy")?;

    let mut chio_argv: Vec<String> = vec![
        "mcp".to_string(),
        "wrap".to_string(),
        "--server-id".to_string(),
        server_id.to_string(),
        "--manifest".to_string(),
        manifest_path,
        "--cage-policy".to_string(),
        cage_policy_path,
        "--cage-policy-signer".to_string(),
        cage_policy_signer.to_string(),
        "--".to_string(),
    ];
    chio_argv.push(program.clone());
    chio_argv.extend(child_args_vec.iter().cloned());

    let display = display_name.unwrap_or(server_id).to_string();

    let blob = match target {
        IdeTarget::Cursor => serde_json::json!({
            "mcpServers": {
                server_id: {
                    "command": "chio",
                    "args": chio_argv,
                    "metadata": {
                        "chioSchema": target.schema_version(),
                        "displayName": display,
                    },
                }
            }
        }),
        IdeTarget::ClaudeDesktop => serde_json::json!({
            "mcpServers": {
                server_id: {
                    "command": "chio",
                    "args": chio_argv,
                    "chio_schema": target.schema_version(),
                }
            }
        }),
        IdeTarget::Continue => serde_json::json!({
            "mcpServers": [{
                "name": display,
                "command": "chio",
                "args": chio_argv,
                "chio": { "schema": target.schema_version() },
            }]
        }),
        IdeTarget::Zed => serde_json::json!({
            "context_servers": {
                server_id: {
                    "command": "chio",
                    "args": chio_argv,
                    "settings": { "chio_schema": target.schema_version() },
                }
            }
        }),
    };

    serde_json::to_string_pretty(&blob)
        .map(|s| format!("{s}\n"))
        .map_err(|e| CliError::cli_other_error(format!("failed to encode IDE config: {e}")))
}

fn path_argument(path: &std::path::Path, label: &str) -> Result<String, CliError> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "emit-config {label} path must be valid UTF-8: {}",
            path.display()
        ))
    })
}

pub(crate) fn cmd_mcp_emit_config(args: &McpWrapArgs, target: IdeTarget) -> Result<(), CliError> {
    let manifest_path = args.manifest.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "chio mcp wrap --emit-config requires --manifest for runtime tool admission"
                .to_string(),
        )
    })?;
    let cage_policy_path = args.cage_policy.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "chio mcp wrap --emit-config requires --cage-policy for native launch admission"
                .to_string(),
        )
    })?;
    let cage_policy_signer = args.cage_policy_signer.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "chio mcp wrap --emit-config requires --cage-policy-signer for policy verification"
                .to_string(),
        )
    })?;
    let blob = render_ide_config(
        target,
        &args.server_id,
        args.display_name.as_deref(),
        manifest_path,
        cage_policy_path,
        cage_policy_signer,
        &args.command,
    )?;
    print!("{blob}");
    Ok(())
}
