//! Apply or restore selected MCP entries after checking their current values.

use super::*;

#[cfg(unix)]
#[path = "activate/file.rs"]
mod file;

#[derive(clap::Args, Debug)]
pub(crate) struct McpActivationArgs {
    /// Adoption directory produced by chio mcp adopt.
    #[arg(long, value_name = "DIR")]
    pub(crate) adoption: PathBuf,
    /// Existing client config to update. Close the client before changing it.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: PathBuf,
    /// Check the proposed changes without writing the client configuration.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

fn invalid(message: impl Into<String>) -> CliError {
    chio_errors::Diagnostic::from_spec(
        &chio_errors::_generated::error_codes::CLI_OTHER,
        message,
    )
    .with_help("Close the client, correct the reported configuration issue, and retry. Use --dry-run to check the proposed changes.")
    .into_error()
    .into()
}

pub(crate) fn cmd_mcp_activate(
    args: &McpActivationArgs,
    json_output: bool,
) -> Result<(), CliError> {
    run(args, false, json_output)
}

pub(crate) fn cmd_mcp_restore(args: &McpActivationArgs, json_output: bool) -> Result<(), CliError> {
    run(args, true, json_output)
}

fn run(args: &McpActivationArgs, restore: bool, json_output: bool) -> Result<(), CliError> {
    #[cfg(not(unix))]
    {
        let _ = (args, restore, json_output);
        Err(invalid(
            "MCP configuration activation currently requires Unix file permissions",
        ))
    }
    #[cfg(unix)]
    {
        use super::adoption_bundle;
        use serde_json::{json, Value};

        let root = std::fs::canonicalize(&args.adoption)?;
        let (adoption, template) = adoption_bundle::load_adoption(&root)?;
        let (original, _) = super::adopt::load_config(&root.join("original.json"))?;
        validate_original(&adoption, &original, &template)?;
        if !restore {
            let policy = load_policy(&adoption.policy_path)?;
            if policy.kernel.durable_admission_mode
                == chio_kernel::admission_operation::DurableAdmissionMode::Off
            {
                return Err(invalid(
                    "activation requires a valid policy with durable admission enabled",
                ));
            }
            for server in &adoption.wrapped_servers {
                if !adoption_bundle::executable_available(&template["mcpServers"][&server.server]) {
                    return Err(invalid(format!(
                        "server '{}': kernel executable is unavailable",
                        server.server
                    )));
                }
            }
        }
        let target = file::ConfigFile::open(&args.config)?;
        if target.path().starts_with(&root) || target.path() == adoption.policy_path {
            return Err(invalid("client configuration must be outside the adoption bundle and distinct from its policy"));
        }
        let mut client = super::adopt::parse_config(target.bytes())?;
        let entries = client
            .get_mut("mcpServers")
            .and_then(Value::as_object_mut)
            .filter(|entries| entries.len() <= 128)
            .ok_or_else(|| {
                invalid("client config must contain an mcpServers object with at most 128 servers")
            })?;
        let (before, after) = if restore {
            (&template, &original)
        } else {
            (&original, &template)
        };
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();
        for server in &adoption.wrapped_servers {
            let name = &server.server;
            let current = entries.get(name).ok_or_else(|| {
                invalid(format!(
                    "server '{name}' is missing; refusing to change the configuration"
                ))
            })?;
            let desired = &after["mcpServers"][name];
            if current == desired {
                unchanged.push(name);
            } else if current == &before["mcpServers"][name] {
                entries.insert(name.clone(), desired.clone());
                changed.push(name);
            } else {
                return Err(invalid(format!("server '{name}' changed since adoption; review the conflict before changing the configuration")));
            }
        }
        if !changed.is_empty() {
            let mut bytes = serde_json::to_vec_pretty(&client)?;
            bytes.push(b'\n');
            if bytes.len() as u64 > super::adopt::MAX_CONFIG_BYTES {
                return Err(invalid("updated MCP config would exceed the 1 MiB limit"));
            }
            if !args.dry_run {
                target.replace(&bytes)?;
            }
        }
        let operation = if restore { "restore" } else { "activate" };
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": "chio.mcp.activation.v1", "operation": operation,
                    "config_path": target.path(), "dry_run": args.dry_run,
                    "configuration_changed": !args.dry_run && !changed.is_empty(),
                    "servers_changed": changed, "servers_already_configured": unchanged,
                    "client_restart_required": !args.dry_run,
                }))?
            );
        } else if args.dry_run {
            println!(
                "Would {operation} {} server entries in {}.",
                changed.len(),
                target.path().display()
            );
        } else {
            println!("MCP {operation}: updated {} server entries in {}. Restart the client to load the configuration.", changed.len(), target.path().display());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_original(
    adoption: &super::adoption_bundle::Adoption,
    original: &serde_json::Value,
    template: &serde_json::Value,
) -> Result<(), CliError> {
    use serde_json::Value;
    for server in &adoption.wrapped_servers {
        let name = &server.server;
        let source = original
            .get("mcpServers")
            .and_then(|entries| entries.get(name))
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("original configuration lacks an adopted server"))?;
        super::adopt::validate_server(name, source)?;
        let expected = &template["mcpServers"][name];
        let mut reconstructed = source.clone();
        reconstructed.insert("command".into(), expected["command"].clone());
        let mut argv = expected["args"]
            .as_array()
            .and_then(|argv| argv.get(..11))
            .ok_or_else(|| invalid("invalid adopted launch arguments"))?
            .to_vec();
        argv.push(source["command"].clone());
        if let Some(args) = source.get("args").and_then(Value::as_array) {
            argv.extend(args.iter().cloned());
        }
        reconstructed.insert("args".into(), Value::Array(argv));
        if &Value::Object(reconstructed) != expected {
            return Err(invalid(format!(
                "server '{name}': adopted launch no longer preserves its original configuration"
            )));
        }
    }
    Ok(())
}
