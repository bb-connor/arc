use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_control_plane::{
    build_kernel, configure_capability_authority, configure_receipt_store, policy,
    DurableAdmissionRuntime,
};
use chio_control_plane::{prepare_private_directory, PreparedPrivateDirectory};
use chio_core_types::capability::attenuation::scope_hash;
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::ChioKernel;
use chio_manifest::ToolManifest;
use chio_mcp_adapter::transport::StdioRequestTimeouts;
use chio_process::mailboxes::{MailboxConfig, SERVER_ID as MAILBOX_SERVER_ID};
use chio_process::{ProcessLimits, ProcessRuntime};
use serde::{Deserialize, Serialize};

use crate::CliError;

pub(super) const SCHEMA: &str = "chio.process.host.v1";
pub(super) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub schema: String,
    pub policy: PathBuf,
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mailboxes: Vec<MailboxConfig>,
    pub limits: ProcessLimits,
    #[serde(default)]
    pub children: Vec<Child>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spawn_templates: Vec<SpawnTemplate>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub supervised_children: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpawnTemplate {
    pub id: String,
    pub tools: Vec<Route>,
    pub max_budget_share_bps: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Server {
    pub id: String,
    /// An absolute executable followed by its literal arguments. No shell.
    pub command: Vec<String>,
    /// Operator-selected MCP request deadline, including service setup and cleanup.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default)]
    pub launch_policy: Option<PathBuf>,
    #[serde(default)]
    pub launch_policy_signer: Option<String>,
}

fn default_request_timeout_seconds() -> u64 {
    StdioRequestTimeouts::default().request_timeout_seconds()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Child {
    pub id: String,
    pub parent: String,
    pub tools: Vec<Route>,
    pub budget_share_bps: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Route {
    pub server_id: String,
    pub tool_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub config: Config,
    pub source_policy_hash: String,
    pub runtime_policy_hash: String,
    pub manifests: Vec<ToolManifest>,
    /// The process ABI this host was initialized under. Hosts initialized
    /// before the field was recorded were written under the first ABI.
    #[serde(default = "first_abi")]
    pub abi: String,
    /// The build that initialized the host, for diagnostics only; the ABI is
    /// the compatibility contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
}

pub(super) fn first_abi() -> String {
    "chio.process.abi.v1".to_owned()
}

/// The build writing host state, recorded for diagnostics.
pub(super) fn code_identity() -> String {
    format!("chio-cli {}", env!("CARGO_PKG_VERSION"))
}

/// Refuse state recorded under another process ABI. State never migrates
/// across ABIs implicitly; export and import carry the ABI and refuse the
/// same way.
pub(super) fn require_abi(recorded: &str, what: &str) -> Result<(), CliError> {
    if recorded == chio_process::PROCESS_ABI {
        return Ok(());
    }
    Err(error(format!(
        "{what} was recorded under process ABI {recorded}; this build speaks {}",
        chio_process::PROCESS_ABI
    )))
}

pub(super) fn error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!("process host: {error}"))
}

pub(super) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(error("configuration exceeds one MiB"));
    }
    serde_json::from_slice(&bytes).map_err(error)
}

pub(super) fn read_current_record(path: &Path) -> Result<Record, CliError> {
    let value: serde_json::Value = read_json(path)?;
    let abi = match value.get("abi") {
        Some(serde_json::Value::String(abi)) => abi.clone(),
        None => first_abi(),
        Some(_) => return Err(error("host ABI must be a string")),
    };
    // Check the version before decoding manifest or configuration fields that
    // changed between ABIs. Legacy state cannot be silently upgraded on open.
    require_abi(&abi, "host state")?;
    serde_json::from_value(value).map_err(error)
}

pub(super) fn identifier(id: &str) -> Result<(), CliError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(error(
            "host ids must contain 1-64 ASCII letters, digits, underscores or hyphens",
        ));
    }
    Ok(())
}

pub(super) fn write_secret(
    directory: &PreparedPrivateDirectory,
    name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<(), CliError> {
    directory.validate_path_identity()?;
    directory.write_new_secret(Path::new(name), bytes)?;
    directory.validate_path_identity()?;
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let source = std::fs::canonicalize(path)?;
        let mut config: Self = read_json(&source)?;
        if config.policy.is_relative() {
            config.policy = source
                .parent()
                .ok_or_else(|| error("configuration has no parent"))?
                .join(&config.policy);
        }
        config.policy = std::fs::canonicalize(&config.policy)?;
        let parent = source
            .parent()
            .ok_or_else(|| error("configuration has no parent"))?;
        for server in &mut config.servers {
            let policy = server.launch_policy.as_mut().ok_or_else(|| {
                error("native MCP servers require launch_policy and launch_policy_signer")
            })?;
            if policy.is_relative() {
                *policy = parent.join(&*policy);
            }
            *policy = std::fs::canonicalize(&*policy)?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        if self.supervised_children && self.spawn_templates.is_empty() {
            return Err(error("supervised children require spawn templates"));
        }
        if self.schema != SCHEMA
            || (self.servers.is_empty()
                && self.mailboxes.is_empty()
                && self.spawn_templates.is_empty())
            || self.servers.len() > 32
            || self.mailboxes.len() > 32
            || self.spawn_templates.len() > 32
        {
            return Err(error("expected chio.process.host.v1 with a configured tool source and at most 32 servers, mailboxes and spawn templates each"));
        }
        if !self.policy.is_absolute()
            || self.children.len() > 1024
            || self.limits.max_calls == 0
            || self.limits.max_depth > 64
            || self.limits.max_processes == 0
            || self.children.len() as u64 + 1 > u64::from(self.limits.max_processes)
        {
            return Err(error("invalid host paths or process tree limits"));
        }
        let mut servers = BTreeSet::new();
        if !self.spawn_templates.is_empty() {
            servers.insert(super::lifecycle::SERVER_ID);
        }
        if !self.mailboxes.is_empty() {
            servers.insert(MAILBOX_SERVER_ID);
        }
        let mut channels = BTreeSet::new();
        for channel in &self.mailboxes {
            channel.validate().map_err(error)?;
            if !channels.insert(channel.id.as_str()) {
                return Err(error("mailbox ids must be unique"));
            }
        }
        for server in &self.servers {
            identifier(&server.id)?;
            StdioRequestTimeouts::with_request_timeout_seconds(server.request_timeout_seconds)
                .map_err(error)?;
            if !server
                .launch_policy
                .as_ref()
                .is_some_and(|path| path.is_absolute())
            {
                return Err(error(
                    "native MCP servers require an absolute launch_policy",
                ));
            }
            let signer = server
                .launch_policy_signer
                .as_deref()
                .ok_or_else(|| error("native MCP servers require launch_policy_signer"))?;
            chio_core_types::crypto::PublicKey::from_hex(signer).map_err(error)?;
            if !servers.insert(server.id.as_str())
                || server.command.is_empty()
                || server.command.len() > 128
                || !Path::new(&server.command[0]).is_absolute()
                || server
                    .command
                    .iter()
                    .any(|arg| arg.contains('\0') || arg.len() > 16_384)
            {
                return Err(error("servers require unique ids and a bounded command starting with an absolute executable"));
            }
        }
        let mut processes = BTreeSet::from(["root"]);
        let mut templates = BTreeSet::new();
        for template in &self.spawn_templates {
            identifier(&template.id)?;
            if template.id.len() > 48
                || !templates.insert(&template.id)
                || template.tools.is_empty()
                || template.tools.len() > 1024
                || template.max_budget_share_bps == 0
                || template.max_budget_share_bps > 10_000
            {
                return Err(error(
                    "invalid spawn template identity, routes or budget share",
                ));
            }
            let mut routes = BTreeSet::new();
            for route in &template.tools {
                if !servers.contains(route.server_id.as_str())
                    || route.tool_name.is_empty()
                    || route.tool_name.contains('*')
                    || !routes.insert((&route.server_id, &route.tool_name))
                {
                    return Err(error(
                        "template routes must be unique concrete tools on configured servers",
                    ));
                }
            }
        }
        for child in &self.children {
            identifier(&child.id)?;
            if !processes.contains(child.parent.as_str())
                || (!self.spawn_templates.is_empty() && child.id.starts_with("dyn_"))
                || !processes.insert(&child.id)
                || child.tools.is_empty()
                || child.tools.len() > 1024
                || child.budget_share_bps == 0
                || child.budget_share_bps > 10_000
            {
                return Err(error(
                    "children need unique ids, an earlier parent, tools and a valid budget share",
                ));
            }
            let mut routes = BTreeSet::new();
            for route in &child.tools {
                if !servers.contains(route.server_id.as_str())
                    || route.tool_name.is_empty()
                    || route.tool_name.contains('*')
                    || !routes.insert((&route.server_id, &route.tool_name))
                {
                    return Err(error(
                        "child tool routes must be unique concrete tools on configured servers",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A single host owns startup reconciliation and serving. Offline management
/// cannot open another kernel and reconcile an active host's in-flight calls.
pub(super) struct Lease {
    pub directory: PreparedPrivateDirectory,
    _file: File,
}

impl Lease {
    pub fn acquire(path: &Path, initializing: bool) -> Result<Self, CliError> {
        if !initializing && !path.is_dir() {
            return Err(error("state directory does not exist"));
        }
        let directory = prepare_private_directory(path)?;
        if std::fs::metadata(directory.path())?.permissions().mode() & 0o077 != 0 {
            return Err(error("state directory must be private (0700)"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.path().join("host.lock"))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(error("invalid host lock file"));
        }
        file.try_lock().map_err(|_| {
            error(
                "host state is already in use; stop the serving host before administrative changes",
            )
        })?;
        directory.validate_path_identity()?;
        if initializing
            && std::fs::read_dir(directory.path())?
                .any(|entry| entry.map_or(true, |entry| entry.file_name() != "host.lock"))
        {
            return Err(error("initialization requires an empty state directory"));
        }
        Ok(Self {
            directory,
            _file: file,
        })
    }
}

pub(super) fn kernel(
    directory: &Path,
    loaded: policy::LoadedPolicy,
) -> Result<(ChioKernel, chio_core_types::crypto::Keypair), CliError> {
    if loaded.default_capabilities.len() != 1 {
        return Err(error(
            "host policy must define one default capability TTL group",
        ));
    }
    if loaded.kernel.durable_admission_mode != DurableAdmissionMode::All
        || loaded.kernel.allow_ephemeral_receipt_log
        || loaded.kernel.allow_ephemeral_revocation_store
    {
        return Err(error("host policy requires durable_admission_mode: all and persistent receipts and revocations"));
    }
    let root_scope = loaded.default_capabilities[0].scope.clone();
    let issuance = loaded.issuance_policy.clone();
    let assurance = loaded.runtime_assurance_policy.clone();
    let authority = DurableAdmissionRuntime::open(&directory.join("authority.db"))?;
    let key = authority.kernel_keypair();
    let mut kernel = build_kernel(loaded, &key);
    kernel.set_capability_trust_root(key.public_key(), scope_hash(&root_scope).map_err(error)?);
    configure_receipt_store(
        &mut kernel,
        Some(&directory.join("receipts.db")),
        None,
        None,
    )?;
    authority.attach(&mut kernel)?;
    configure_capability_authority(
        &mut kernel,
        &key,
        None,
        None,
        Some(&directory.join("receipts.db")),
        None,
        None,
        None,
        issuance,
        assurance,
    )?;
    Ok((kernel, key))
}

pub(super) struct Host {
    pub lease: Lease,
    pub record: Record,
    pub runtime: ProcessRuntime,
    pub kernel: Arc<ChioKernel>,
    #[cfg(target_os = "linux")]
    pub lifecycle: Option<Arc<super::lifecycle::Service>>,
}

impl Host {
    pub fn open(path: &Path, connect: bool) -> Result<Self, CliError> {
        let lease = Lease::acquire(path, false)?;
        let record = read_current_record(&lease.directory.path().join("host.json"))?;
        require_abi(&record.abi, "host state")?;
        record.config.validate()?;
        let policy = policy::load_policy(&record.config.policy)?;
        if policy.identity.source_hash != record.source_policy_hash
            || policy.identity.runtime_hash != record.runtime_policy_hash
        {
            return Err(error("policy changed since initialization; restore the original policy to recover this host"));
        }
        let (mut kernel, issuer) = kernel(lease.directory.path(), policy)?;
        let lifecycle = if connect && !record.config.spawn_templates.is_empty() {
            Some(Arc::new(super::lifecycle::Service::new(
                chio_process::ProcessRegistry::open(
                    lease.directory.path().join("process.db"),
                    &kernel,
                )
                .map_err(error)?,
                record.config.spawn_templates.clone(),
                record.config.supervised_children,
                issuer,
                record.manifests.clone(),
                lease.directory.path().join("runner.db"),
            )))
        } else {
            None
        };
        if connect {
            let (servers, manifests) =
                super::serving::connect(&record.config, &kernel, lease.directory.path())?;
            if chio_core_types::crypto::canonical_json_bytes(&manifests).map_err(error)?
                != chio_core_types::crypto::canonical_json_bytes(&record.manifests)
                    .map_err(error)?
            {
                return Err(error("host tool definitions changed since initialization"));
            }
            for server in servers {
                kernel.register_tool_server(server);
            }
            if let Some(service) = &lifecycle {
                kernel
                    .register_tool_server(Box::new(super::lifecycle::Connection(service.clone())));
            }
        }
        let kernel = Arc::new(kernel);
        let runtime =
            ProcessRuntime::open(lease.directory.path().join("process.db"), kernel.clone())
                .map_err(error)?;
        lease.directory.validate_path_identity()?;
        Ok(Self {
            lease,
            record,
            runtime,
            kernel,
            #[cfg(target_os = "linux")]
            lifecycle,
        })
    }
}

#[cfg(test)]
mod tests {
    use chio_core_types::crypto::Keypair;
    use serde_json::{json, Value};

    use super::{Config, Server, SCHEMA};

    fn server_fixture() -> Value {
        json!({
            "id": "reports",
            "command": ["/usr/bin/python3", "/tools/reports.py"],
            "launch_policy": "/policies/reports.json",
            "launch_policy_signer": Keypair::from_seed(&[73; 32]).public_key().to_hex(),
        })
    }

    #[test]
    fn server_request_timeout_defaults_and_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        let server: Server = serde_json::from_value(server_fixture())?;
        assert_eq!(server.request_timeout_seconds, 60);

        for seconds in [1, 3600] {
            let mut value = server_fixture();
            value["request_timeout_seconds"] = json!(seconds);
            let server: Server = serde_json::from_value(value)?;
            assert_eq!(server.request_timeout_seconds, seconds);
            let restored: Server = serde_json::from_value(serde_json::to_value(server)?)?;
            assert_eq!(restored.request_timeout_seconds, seconds);
        }
        Ok(())
    }

    #[test]
    fn server_request_timeout_rejects_invalid_types_and_unknown_fields() {
        for invalid in [json!(-1), json!(1.5), json!("60"), json!(true), json!(null)] {
            let mut value = server_fixture();
            value["request_timeout_seconds"] = invalid.clone();
            assert!(
                serde_json::from_value::<Server>(value).is_err(),
                "accepted invalid request_timeout_seconds: {invalid}"
            );
        }

        let mut value = server_fixture();
        value["request_timeout_milliseconds"] = json!(1000);
        assert!(serde_json::from_value::<Server>(value).is_err());
    }

    #[test]
    fn config_request_timeout_rejects_out_of_range_values() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config: Config = serde_json::from_value(json!({
            "schema": SCHEMA,
            "policy": "/policies/host.yaml",
            "servers": [server_fixture()],
            "limits": {"max_calls": 1, "max_processes": 1, "max_depth": 0},
        }))?;
        config.validate()?;

        for seconds in [1, 3600] {
            config.servers[0].request_timeout_seconds = seconds;
            config.validate()?;
        }
        for seconds in [0, 3601] {
            config.servers[0].request_timeout_seconds = seconds;
            let failure = config
                .validate()
                .err()
                .ok_or("accepted out-of-range request_timeout_seconds")?;
            assert!(
                failure.to_string().contains("request_timeout_seconds"),
                "unexpected validation error: {failure}"
            );
        }
        Ok(())
    }
}
