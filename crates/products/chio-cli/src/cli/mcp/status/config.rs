use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct Adoption {
    pub schema: String,
    pub config_path: PathBuf,
    pub policy_path: PathBuf,
    pub policy_source_hash: String,
    pub policy_runtime_hash: String,
    pub wrapped_servers: Vec<Server>,
}

#[derive(Deserialize)]
pub(super) struct Server {
    pub server: String,
    pub session_db: PathBuf,
    pub receipt_db: PathBuf,
    pub kernel_public_key_file: PathBuf,
}

pub(super) fn load_adoption(directory: &Path) -> Result<(Adoption, Value), CliError> {
    let root = std::fs::canonicalize(directory)?;
    let (value, _) = super::super::adopt::load_config(&root.join("adoption.json"))?;
    let report: Adoption =
        serde_json::from_value(value).map_err(|_| invalid("invalid adoption report"))?;
    if report.schema != "chio.mcp.adoption.v1"
        || report.config_path != root.join("mcp.json")
        || !report.policy_path.is_absolute()
        || report.wrapped_servers.is_empty()
        || report.wrapped_servers.len() > 128
    {
        return Err(invalid("unsupported adoption report or invalid paths"));
    }
    let (template, _) = super::super::adopt::load_config(&report.config_path)?;
    let mut names = std::collections::BTreeSet::new();
    for server in &report.wrapped_servers {
        let name = &server.server;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !names.insert(name)
        {
            return Err(invalid("invalid or duplicate adopted server name"));
        }
        let state = root
            .join("state")
            .join(chio_core::sha256_hex(name.as_bytes()));
        if server.session_db != state.join("session.sqlite")
            || server.receipt_db != state.join("receipts.sqlite")
            || server.kernel_public_key_file != state.join("session.sqlite.kernel.pub")
        {
            return Err(invalid(
                "adopted server paths do not match its state directory",
            ));
        }
        let entry = template
            .get("mcpServers")
            .and_then(|servers| servers.get(name))
            .ok_or_else(|| invalid("adopted server is missing from generated configuration"))?;
        let command = entry
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("generated configuration has no kernel command"))?;
        let expected = json!([
            "--session-db",
            server.session_db,
            "--receipt-db",
            server.receipt_db,
            "mcp",
            "serve",
            "--policy",
            report.policy_path,
            "--server-id",
            name,
            "--"
        ]);
        let argv = entry
            .get("args")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("generated configuration has no kernel arguments"))?;
        if !Path::new(command).is_absolute()
            || argv.len() < 12
            || argv.get(..11) != expected.as_array().map(Vec::as_slice)
        {
            return Err(invalid(
                "generated configuration no longer matches the adopted kernel launch",
            ));
        }
    }
    Ok((report, template))
}

pub(super) fn executable_available(entry: &Value) -> bool {
    let Some(path) = entry.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
