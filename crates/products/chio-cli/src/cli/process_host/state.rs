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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Server {
    pub id: String,
    /// An absolute executable followed by its literal arguments. No shell.
    pub command: Vec<String>,
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
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        if self.schema != SCHEMA
            || (self.servers.is_empty() && self.mailboxes.is_empty())
            || self.servers.len() > 32
            || self.mailboxes.len() > 32
        {
            return Err(error("expected chio.process.host.v1, at least one server or mailbox, and at most 32 of each"));
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
        for child in &self.children {
            identifier(&child.id)?;
            if !processes.contains(child.parent.as_str())
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
}

impl Host {
    pub fn open(path: &Path, connect: bool) -> Result<Self, CliError> {
        let lease = Lease::acquire(path, false)?;
        let record: Record = read_json(&lease.directory.path().join("host.json"))?;
        record.config.validate()?;
        let policy = policy::load_policy(&record.config.policy)?;
        if policy.identity.source_hash != record.source_policy_hash
            || policy.identity.runtime_hash != record.runtime_policy_hash
        {
            return Err(error("policy changed since initialization; restore the original policy to recover this host"));
        }
        let (mut kernel, _) = kernel(lease.directory.path(), policy)?;
        if connect {
            let (servers, manifests) =
                super::serving::connect(&record.config, &kernel, lease.directory.path())?;
            if chio_core_types::crypto::canonical_json_bytes(&manifests).map_err(error)?
                != chio_core_types::crypto::canonical_json_bytes(&record.manifests)
                    .map_err(error)?
            {
                return Err(error("MCP tool definitions changed since initialization"));
            }
            for server in servers {
                kernel.register_tool_server(server);
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
        })
    }
}
