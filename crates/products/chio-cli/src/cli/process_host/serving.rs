use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use chio_kernel::{ChioKernel, ToolServerConnection};
use chio_manifest::ToolManifest;
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig};
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::StdioRequestTimeouts;
use chio_process::mailboxes::MailboxServer;
use chio_process::worker::{WorkerServer, WorkerService};

use super::state::{error, Config, Host};
use crate::CliError;

type ConnectedServers = (
    Vec<Box<dyn ToolServerConnection>>,
    Vec<ToolManifest>,
    BTreeMap<String, chio_process::ProcessLaunchReceipt>,
);

pub(super) fn worker_service(runtime: chio_process::ProcessRuntime) -> WorkerService {
    WorkerService::new(runtime).with_error_observer(|error| {
        tracing::warn!(error = %error, "process worker request failed");
    })
}

pub(super) fn connect(
    config: &Config,
    kernel: &ChioKernel,
    directory: &Path,
    require_enforced: bool,
) -> Result<ConnectedServers, CliError> {
    let mut servers: Vec<Box<dyn ToolServerConnection>> = Vec::new();
    let mut manifests = Vec::new();
    let mut launch_receipts = BTreeMap::new();
    for server in &config.servers {
        let arguments: Vec<_> = server.command[1..].iter().map(String::as_str).collect();
        let launch = crate::mcp_cli::load_native_mcp_launch(
            server
                .launch_policy
                .as_deref()
                .ok_or_else(|| error("missing MCP launch policy"))?,
            server
                .launch_policy_signer
                .as_deref()
                .ok_or_else(|| error("missing MCP launch policy signer"))?,
            &server.command[0],
            &arguments,
            None,
        )?;
        if require_enforced
            && !matches!(
                &launch,
                chio_mcp_adapter::transport::NativeMcpLaunch::CageRequired(_)
            )
        {
            return Err(error("governed process tools require Enforced cage launch"));
        }
        if launch.requires_flow_runtime() {
            return Err(error("this process host profile does not install an information-flow runtime; flow-required MCP manifests are refused"));
        }
        let registry = launch.manifest_registry().clone();
        let admitted = registry
            .verified_manifest(&server.id)
            .ok_or_else(|| error("MCP launch policy belongs to another server"))?;
        if require_enforced
            && admitted
                .manifest
                .required_permissions
                .as_ref()
                .is_none_or(|permissions| permissions.network_destinations.is_some())
        {
            return Err(error(
                "this governed route profile requires a manifest with no network destinations",
            ));
        }
        let adapter = McpAdapter::from_command_with_timeouts(
            &server.command[0],
            &arguments,
            McpAdapterConfig {
                server_id: server.id.clone(),
                server_name: admitted.manifest.name.clone(),
                server_version: admitted.manifest.version.clone(),
                public_key: admitted.manifest.public_key.clone(),
            },
            launch,
            StdioRequestTimeouts::with_request_timeout_seconds(server.request_timeout_seconds)
                .map_err(error)?,
        )
        .map_err(error)?;
        let adapter =
            AdaptedMcpServer::new_with_manifest_registry(adapter, &registry).map_err(error)?;
        if require_enforced && adapter.native_enforcement_evidence().is_none() {
            return Err(error(
                "governed process tool has no verified enforcement evidence",
            ));
        }
        if let Some(receipt) = adapter.native_enforcement_receipt() {
            let bytes = chio_core::canonical_json_bytes(receipt).map_err(error)?;
            launch_receipts.insert(
                server.id.clone(),
                chio_process::ProcessLaunchReceipt::new(
                    receipt.id.clone(),
                    chio_core::sha256_hex(&bytes),
                )
                .map_err(error)?,
            );
        } else if require_enforced {
            return Err(error(
                "governed process tool has no persisted enforcement receipt",
            ));
        }
        let mut manifest = adapter.manifest_clone();
        manifest.tools.sort_by(|a, b| a.name.cmp(&b.name));
        manifests.push(manifest);
        servers.push(Box::new(adapter));
    }
    if !config.mailboxes.is_empty() {
        let server = MailboxServer::open(
            directory.join("mailboxes.db"),
            kernel,
            config.mailboxes.clone(),
        )
        .map_err(error)?
        .attest_senders(
            chio_process::ProcessRegistry::open(directory.join("process.db"), kernel)
                .map_err(error)?,
        );
        let manifest = server.manifest();
        chio_manifest::validate_manifest(&manifest).map_err(error)?;
        manifests.push(manifest);
        servers.push(Box::new(server));
    }
    if !config.spawn_templates.is_empty() {
        let manifest = super::lifecycle::manifest(
            &config.spawn_templates,
            config.supervised_children,
            &kernel.public_key().to_hex(),
        );
        chio_manifest::validate_manifest(&manifest).map_err(error)?;
        manifests.push(manifest);
    }
    Ok((servers, manifests, launch_receipts))
}

pub(super) fn serve(state: &Path, socket: &Path) -> Result<(), CliError> {
    let host = Host::open(state, true)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let listener = WorkerServer::bind(socket, worker_service(host.runtime.clone()))?;
        host.lease.directory.validate_path_identity()?;
        println!("{}", serde_json::json!({"ready": true, "protocol": chio_process::worker::PROTOCOL,
            "socket_path": std::fs::canonicalize(socket)?, "kernel_key": host.kernel.public_key().to_hex()}));
        std::io::stdout().flush()?;
        listener.serve(async {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
            }
        }).await?;
        Ok::<_, CliError>(())
    })
}
