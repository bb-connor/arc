//! Produce a reviewable MCP configuration using the existing kernel execution path.
//! The importer never launches a server or edits the client's installed config.

use super::*;
use std::collections::BTreeSet;
use std::io::Read;

use chio_control_plane::prepare_private_directory;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::DurableAdmissionMode;
use serde_json::{json, Map, Value};

pub(super) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SERVERS: usize = 128;

#[derive(clap::Args, Debug)]
pub(crate) struct McpAdoptArgs {
    /// Existing JSON configuration containing an mcpServers object.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: PathBuf,

    /// Existing Chio or HushSpec policy, validated before generating config.
    #[arg(long, value_name = "FILE")]
    pub(crate) policy: PathBuf,

    /// New or empty private directory for generated config and runtime state.
    #[arg(long, value_name = "DIR")]
    pub(crate) output: PathBuf,

    /// Server to route through Chio. Repeat to select several; defaults to all.
    #[arg(long = "server", value_name = "NAME")]
    pub(crate) servers: Vec<String>,
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::cli_other_error(message.into())
}

fn path_text(path: &Path) -> Result<String, CliError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("MCP configuration paths must be valid UTF-8"))
}

pub(super) fn load_config(path: &Path) -> Result<(Value, Vec<u8>), CliError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let config = parse_config(&bytes)?;
    Ok((config, bytes))
}

pub(super) fn parse_config(bytes: &[u8]) -> Result<Value, CliError> {
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(invalid("MCP config exceeds the 1 MiB limit"));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| invalid("MCP config must be UTF-8 JSON"))?;
    // Reject ambiguous duplicate members before serde_json's last-wins parsing.
    // Do not include parser diagnostics that might echo credential values.
    let canonical = chio_core::canonical::canonical_json_string_from_str(source)
        .map_err(|_| invalid("MCP config must be strict JSON without duplicate keys"))?;
    let config = serde_json::from_str(&canonical)
        .map_err(|_| invalid("invalid MCP config JSON"))?;
    Ok(config)
}

fn selected_servers(config: &Value, requested: &[String]) -> Result<BTreeSet<String>, CliError> {
    let servers = config
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("MCP config must contain an mcpServers object"))?;
    if servers.is_empty() || servers.len() > MAX_SERVERS {
        return Err(invalid("MCP config must contain between 1 and 128 servers"));
    }
    let selected: BTreeSet<String> = if requested.is_empty() {
        servers.keys().cloned().collect()
    } else {
        requested.iter().cloned().collect()
    };
    for name in &selected {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(invalid("selected server names must use 1-128 ASCII letters, digits, dots, underscores, or hyphens"));
        }
        let server = servers
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(format!("selected server '{name}' is absent or not an object")))?;
        validate_server(name, server)?;
    }
    Ok(selected)
}

pub(super) fn validate_server(name: &str, server: &Map<String, Value>) -> Result<(), CliError> {
    let fail = |reason: &str| invalid(format!("server '{name}': {reason}"));
    if server.contains_key("url")
        || server.get("type").is_some_and(|kind| kind != "stdio")
    {
        return Err(fail("only local stdio servers can be imported; use --server to explicitly select local entries"));
    }
    let program = server
        .get("command")
        .and_then(Value::as_str)
        .filter(|program| !program.trim().is_empty() && !program.contains('\0'))
        .ok_or_else(|| fail("command must be a nonempty string"))?;
    let executable = Path::new(program).file_name().and_then(|name| name.to_str());
    if matches!(executable, Some("chio" | "chio.exe")) {
        return Err(fail("already invokes Chio; refusing to wrap a kernel again"));
    }
    if let Some(arguments) = server.get("args") {
        if !arguments.as_array().is_some_and(|args| {
            args.iter().all(|arg| arg.as_str().is_some_and(|text| !text.contains('\0')))
        }) {
            return Err(fail("args must be an array of strings without NUL bytes"));
        }
    }
    if let Some(environment) = server.get("env") {
        if !environment.as_object().is_some_and(|env| {
            env.iter().all(|(key, value)| {
                !key.is_empty()
                    && !key.contains(['=', '\0'])
                    && value.as_str().is_some_and(|text| !text.contains('\0'))
            })
        }) {
            return Err(fail("env must map valid environment names to string values"));
        }
    }
    Ok(())
}

pub(crate) fn cmd_mcp_adopt(args: &McpAdoptArgs) -> Result<(), CliError> {
    if !cfg!(unix) {
        return Err(invalid("MCP config import currently requires Unix owner-only file permissions"));
    }
    let (mut config, original_bytes) = load_config(&args.config)?;
    let selected = selected_servers(&config, &args.servers)?;
    let policy_path = std::fs::canonicalize(&args.policy)?;
    let policy = load_policy(&policy_path)?;
    if policy.kernel.durable_admission_mode == DurableAdmissionMode::Off {
        return Err(invalid("adopt requires durable admission; select a policy whose durable_admission_mode is not off"));
    }
    let policy_text = path_text(&policy_path)?;
    let executable = path_text(&std::env::current_exe()?)?;
    let output = prepare_private_directory(&args.output)?;
    if !output.is_empty()? {
        return Err(invalid("output directory must be empty; existing configurations and runtime state are never overwritten"));
    }
    let servers = config
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("missing validated mcpServers object"))?;
    let unchanged: Vec<_> = servers.keys().filter(|name| !selected.contains(*name)).cloned().collect();
    let mut wrapped = Vec::new();
    for name in &selected {
        let server = servers.get_mut(name).and_then(Value::as_object_mut)
            .ok_or_else(|| invalid("missing validated server"))?;
        let program = server.get("command").and_then(Value::as_str)
            .ok_or_else(|| invalid("missing validated command"))?.to_owned();
        let original_args = server.get("args").and_then(Value::as_array).cloned().unwrap_or_default();
        // Hash names only for filesystem layout. Policy and receipt server IDs
        // retain the original name, including case, with no wildcard expansion.
        let relative_state = PathBuf::from("state").join(sha256_hex(name.as_bytes()));
        let state = output.path().join(&relative_state);
        let session_db = state.join("session.sqlite");
        let receipt_db = state.join("receipts.sqlite");
        let mut argv = vec![
            json!("--session-db"), json!(path_text(&session_db)?),
            json!("--receipt-db"), json!(path_text(&receipt_db)?),
            json!("mcp"), json!("serve"), json!("--policy"), json!(policy_text),
            json!("--server-id"), json!(name), json!("--"), json!(program),
        ];
        argv.extend(original_args);
        server.insert("command".to_owned(), json!(executable));
        server.insert("args".to_owned(), Value::Array(argv));
        output.create_dir_all(&relative_state)?;
        wrapped.push(json!({
            "server": name,
            "session_db": session_db,
            "receipt_db": receipt_db,
            "kernel_public_key_file": state.join("session.sqlite.kernel.pub"),
        }));
    }
    let report = json!({
        "schema": "chio.mcp.adoption.v1",
        "config_path": output.path().join("mcp.json"),
        "backup_config_path": output.path().join("original.json"),
        "policy_path": policy_path,
        "policy_source_hash": policy.identity.source_hash,
        "policy_runtime_hash": policy.identity.runtime_hash,
        "wrapped_servers": wrapped,
        "unchanged_servers": unchanged,
        "installed": false,
    });
    output.validate_path_identity()?;
    output.write_new_secret(Path::new("original.json"), &original_bytes)?;
    output.write_new_secret(Path::new("mcp.json"), &serde_json::to_vec_pretty(&config)?)?;
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    output.write_new_secret(Path::new("adoption.json"), &report_bytes)?;
    output.validate_path_identity()?;
    println!("{}", String::from_utf8_lossy(&report_bytes));
    Ok(())
}
