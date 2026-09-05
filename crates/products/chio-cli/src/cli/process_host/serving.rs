use std::io::Write;
use std::path::Path;

use chio_kernel::{ChioKernel, ToolServerConnection};
use chio_manifest::ToolManifest;
use chio_mcp_adapter::adapter::McpAdapterConfig;
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_process::mailboxes::MailboxServer;
use chio_process::worker::{WorkerServer, WorkerService};

use super::state::{error, Config, Host};
use crate::CliError;

type ConnectedServers = (Vec<Box<dyn ToolServerConnection>>, Vec<ToolManifest>);

pub(super) fn connect(
    config: &Config,
    kernel: &ChioKernel,
    directory: &Path,
) -> Result<ConnectedServers, CliError> {
    let mut servers: Vec<Box<dyn ToolServerConnection>> = Vec::new();
    let mut manifests = Vec::new();
    for server in &config.servers {
        let arguments: Vec<_> = server.command[1..].iter().map(String::as_str).collect();
        let adapter = AdaptedMcpServer::from_command(
            &server.command[0],
            &arguments,
            McpAdapterConfig {
                server_id: server.id.clone(),
                server_name: server.id.clone(),
                server_version: "1".to_owned(),
                // Local adapter identity, not an attestation of the MCP executable.
                public_key: kernel.public_key().to_hex(),
            },
        )
        .map_err(error)?;
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
        .map_err(error)?;
        let manifest = server.manifest();
        chio_manifest::validate_manifest(&manifest).map_err(error)?;
        manifests.push(manifest);
        servers.push(Box::new(server));
    }
    Ok((servers, manifests))
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
        let listener = WorkerServer::bind(socket, WorkerService::new(host.runtime.clone()))?;
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
