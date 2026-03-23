//! PACT CLI -- command-line interface for the PACT runtime kernel.
//!
//! Provides commands for:
//!
//! - `pact run --policy <path> -- <command> [args...]`
//!   Spawn an agent subprocess, set up the length-prefixed transport over
//!   stdin/stdout pipes, and run the kernel message loop.
//!
//! - `pact check --policy <path> --tool <name> --params <json>`
//!   Load a policy, create a kernel, and evaluate a single tool call.
//!
//! - `pact mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//!   Wrap an MCP server subprocess with the PACT kernel and expose an
//!   MCP-compatible edge over stdio for stock MCP clients.

#![allow(clippy::large_enum_variant, clippy::too_many_arguments)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod policy;
mod remote_mcp;
mod trust_control;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};

use pact_core::capability::PactScope;
use pact_core::crypto::Keypair;
use pact_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use pact_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use pact_kernel::transport::{PactTransport, TransportError};
use pact_kernel::{
    KernelConfig, PactKernel, RevocationStore, SessionOperationResponse, ToolCallOutput,
    ToolCallRequest as KernelToolCallRequest, ToolCallStream,
};
use pact_mcp_adapter::{AdaptedMcpServer, McpAdapterConfig, McpEdgeConfig, PactMcpEdge};

use crate::policy::{load_policy, DefaultCapability, LoadedPolicy};

/// PACT -- Provable Agent Capability Transport.
///
/// Runtime security enforcement for AI agents via capability-based
/// authorization and signed audit receipts.
#[derive(Parser)]
#[command(name = "pact", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: human-readable or JSON.
    #[arg(long, global = true, default_value = "false")]
    json: bool,

    /// Optional SQLite database path for durable receipt persistence.
    #[arg(long, global = true)]
    receipt_db: Option<PathBuf>,

    /// Optional SQLite database path for durable capability revocation persistence.
    #[arg(long, global = true)]
    revocation_db: Option<PathBuf>,

    /// Optional file path for a persistent capability-authority seed.
    #[arg(long, global = true)]
    authority_seed_file: Option<PathBuf>,

    /// Optional SQLite database path for shared capability-authority state.
    #[arg(long, global = true)]
    authority_db: Option<PathBuf>,

    /// Optional SQLite database path for durable shared capability budget state.
    #[arg(long, global = true)]
    budget_db: Option<PathBuf>,

    /// Optional SQLite database path for durable remote MCP session tombstones.
    #[arg(long, global = true)]
    session_db: Option<PathBuf>,

    /// Optional shared trust-control service base URL.
    #[arg(long, global = true)]
    control_url: Option<String>,

    /// Bearer token used to authenticate to the shared trust-control service.
    #[arg(long, global = true)]
    control_token: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Spawn an agent subprocess and enforce policy via the kernel.
    Run {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// The agent command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Evaluate a single tool call against a policy (no subprocess).
    Check {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Tool name to evaluate.
        #[arg(long)]
        tool: String,

        /// Tool parameters as a JSON string.
        #[arg(long, default_value = "{}")]
        params: String,

        /// Server ID to use for the evaluation.
        #[arg(long, default_value = "*")]
        server: String,
    },

    /// Serve an MCP-compatible edge backed by the PACT kernel.
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Manage local trust-plane state such as persisted revocations.
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },

    /// Query and list receipts from the receipt store.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommands,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Wrap an MCP server subprocess and expose a secured MCP edge over stdio.
    Serve {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Server ID to assign to the wrapped MCP server inside PACT.
        #[arg(long)]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Wrap an MCP server subprocess and expose a secured MCP edge over Streamable HTTP.
    ServeHttp {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Server ID to assign to the wrapped MCP server inside PACT.
        #[arg(long)]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// Use one shared wrapped MCP subprocess for all remote sessions.
        #[arg(long, default_value_t = false)]
        shared_hosted_owner: bool,

        /// Socket address to bind the remote MCP edge to.
        #[arg(long, default_value = "127.0.0.1:8931")]
        listen: SocketAddr,

        /// Static bearer token required for remote MCP session admission.
        #[arg(long)]
        auth_token: Option<String>,

        /// Ed25519 public key used to verify OAuth-style JWT bearer tokens.
        #[arg(long)]
        auth_jwt_public_key: Option<String>,

        /// Local auth-server signing seed file. When set, `serve-http` can issue JWTs itself.
        #[arg(long)]
        auth_server_seed_file: Option<PathBuf>,

        /// Expected JWT issuer for remote MCP session admission.
        #[arg(long)]
        auth_jwt_issuer: Option<String>,

        /// Expected JWT audience for remote MCP session admission.
        #[arg(long)]
        auth_jwt_audience: Option<String>,

        /// Optional static bearer token for remote admin APIs.
        #[arg(long)]
        admin_token: Option<String>,

        /// Public base URL used when constructing protected-resource metadata URLs.
        #[arg(long)]
        public_base_url: Option<String>,

        /// Authorization server URL advertised via protected-resource metadata.
        #[arg(long = "auth-server")]
        auth_servers: Vec<String>,

        /// OAuth authorization endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_authorization_endpoint: Option<String>,

        /// OAuth token endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_token_endpoint: Option<String>,

        /// Optional dynamic client registration endpoint advertised in auth-server metadata.
        #[arg(long)]
        auth_registration_endpoint: Option<String>,

        /// Optional JWKS URI advertised in auth-server metadata.
        #[arg(long)]
        auth_jwks_uri: Option<String>,

        /// Scope hint advertised in protected-resource challenges and metadata.
        #[arg(long = "auth-scope")]
        auth_scopes: Vec<String>,

        /// Subject to embed in locally issued auth-server access tokens.
        #[arg(long, default_value = "operator")]
        auth_subject: String,

        /// Authorization-code lifetime for the hosted auth server.
        #[arg(long, default_value_t = 300)]
        auth_code_ttl_secs: u64,

        /// Access-token lifetime for the hosted auth server.
        #[arg(long, default_value_t = 600)]
        auth_access_token_ttl_secs: u64,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TrustCommands {
    /// Serve the shared trust-control plane over HTTP.
    Serve {
        /// Socket address to bind the trust-control service to.
        #[arg(long, default_value = "127.0.0.1:8940")]
        listen: SocketAddr,

        /// Bearer token required for trust-control service requests.
        #[arg(long)]
        service_token: String,

        /// Public base URL this trust-control node advertises to peers and clients.
        #[arg(long)]
        advertise_url: Option<String>,

        /// Peer trust-control base URL. Repeat for multiple peers.
        #[arg(long = "peer-url")]
        peer_urls: Vec<String>,

        /// Background cluster sync interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        cluster_sync_interval_ms: u64,
    },

    /// Persist a capability revocation into the configured revocation database.
    Revoke {
        /// Capability ID to revoke.
        #[arg(long)]
        capability_id: String,
    },

    /// Query whether a capability ID is currently revoked.
    Status {
        /// Capability ID to check.
        #[arg(long)]
        capability_id: String,
    },
}

#[derive(Subcommand)]
enum ReceiptCommands {
    /// List receipts with optional filters. Output: one JSON receipt per line (JSON Lines).
    List {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by tool server ID.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by decision outcome (allow, deny, cancelled, incomplete).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter: receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Filter: receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Filter: minimum cost in minor currency units (only financial receipts).
        #[arg(long)]
        min_cost: Option<u64>,
        /// Filter: maximum cost in minor currency units (only financial receipts).
        #[arg(long)]
        max_cost: Option<u64>,
        /// Maximum number of receipts per page.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Cursor for pagination (seq value to start after).
        #[arg(long)]
        cursor: Option<u64>,
    },
}

fn main() {
    let cli = Cli::parse();
    let receipt_db = cli.receipt_db.clone();
    let revocation_db = cli.revocation_db.clone();
    let authority_seed_file = cli.authority_seed_file.clone();
    let authority_db = cli.authority_db.clone();
    let budget_db = cli.budget_db.clone();
    let session_db = cli.session_db.clone();
    let control_url = cli.control_url.clone();
    let control_token = cli.control_token.clone();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Commands::Run { policy, command } => cmd_run(
            &policy,
            &command,
            cli.json,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Check {
            policy,
            tool,
            params,
            server,
        } => cmd_check(
            &policy,
            &tool,
            &params,
            &server,
            cli.json,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Mcp { command } => match command {
            McpCommands::Serve {
                policy,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                command,
            } => cmd_mcp_serve(
                &policy,
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            McpCommands::ServeHttp {
                policy,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token,
                auth_jwt_public_key,
                auth_server_seed_file,
                auth_jwt_issuer,
                auth_jwt_audience,
                admin_token,
                public_base_url,
                auth_servers,
                auth_authorization_endpoint,
                auth_token_endpoint,
                auth_registration_endpoint,
                auth_jwks_uri,
                auth_scopes,
                auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                command,
            } => cmd_mcp_serve_http(
                &policy,
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token.as_deref(),
                auth_jwt_public_key.as_deref(),
                auth_server_seed_file.as_deref(),
                auth_jwt_issuer.as_deref(),
                auth_jwt_audience.as_deref(),
                admin_token.as_deref(),
                public_base_url.as_deref(),
                &auth_servers,
                auth_authorization_endpoint.as_deref(),
                auth_token_endpoint.as_deref(),
                auth_registration_endpoint.as_deref(),
                auth_jwks_uri.as_deref(),
                &auth_scopes,
                &auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Trust { command } => match command {
            TrustCommands::Serve {
                listen,
                service_token,
                advertise_url,
                peer_urls,
                cluster_sync_interval_ms,
            } => cmd_trust_serve(
                listen,
                &service_token,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                advertise_url.as_deref(),
                &peer_urls,
                cluster_sync_interval_ms,
            ),
            TrustCommands::Revoke { capability_id } => cmd_trust_revoke(
                &capability_id,
                cli.json,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            TrustCommands::Status { capability_id } => cmd_trust_status(
                &capability_id,
                cli.json,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Receipt { command } => match command {
            ReceiptCommands::List {
                capability,
                tool_server,
                tool_name,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                limit,
                cursor,
            } => cmd_receipt_list(
                capability.as_deref(),
                tool_server.as_deref(),
                tool_name.as_deref(),
                outcome.as_deref(),
                since,
                until,
                min_cost,
                max_cost,
                limit,
                cursor,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
    };

    if let Err(e) = result {
        if cli.json {
            let msg = serde_json::json!({ "error": e.to_string() });
            let _ = writeln!(std::io::stderr(), "{msg}");
        } else {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Core(#[from] pact_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] pact_mcp_adapter::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] pact_kernel::KernelError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] pact_kernel::ReceiptStoreError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] pact_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] pact_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] pact_kernel::BudgetStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Other(String),
}

fn cmd_run(
    policy_path: &Path,
    command: &[String],
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        authority_seed_path,
        authority_db_path,
        control_url,
        control_token,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps.clone());

    info!(
        capability_count = initial_caps.len(),
        agent_id = %session_agent_id,
        "issued initial capabilities to agent"
    );

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty command".to_string()))?;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdout".to_string()))?;

    let mut transport = PactTransport::new(child_stdout, child_stdin);

    let init_msg = KernelMessage::CapabilityList {
        capabilities: initial_caps.clone(),
    };
    transport.send(&init_msg)?;
    kernel.activate_session(&session_id)?;

    info!("sent initial capabilities to agent, entering message loop");

    let mut stats = SessionStats::default();

    loop {
        let agent_msg = match transport.recv() {
            Ok(msg) => msg,
            Err(TransportError::ConnectionClosed) => {
                debug!("agent closed connection");
                break;
            }
            Err(e) => {
                warn!(error = %e, "transport read error");
                break;
            }
        };

        let kernel_msgs = handle_agent_message(
            &mut kernel,
            &agent_msg,
            &session_id,
            &session_agent_id,
            &mut stats,
        );

        let mut write_failed = false;
        for kernel_msg in kernel_msgs {
            if let Err(e) = transport.send(&kernel_msg) {
                warn!(error = %e, "transport write error");
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }
    }

    if let Err(e) = kernel.begin_draining_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to mark session draining");
    }

    if let Err(e) = kernel.close_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to close session");
    }

    let status = child.wait()?;
    print_summary(&stats, status.code(), json_output);

    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        Err(CliError::Other(format!("agent exited with code {code}")))
    }
}

fn cmd_check(
    policy_path: &Path,
    tool: &str,
    params_str: &str,
    server: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        authority_seed_path,
        authority_db_path,
        control_url,
        control_token,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    kernel.register_tool_server(Box::new(StubToolServer {
        id: server.to_string(),
    }));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let params: serde_json::Value = serde_json::from_str(params_str)?;
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let cap = match select_capability_for_request(&initial_caps, tool, server, &params) {
        Some(capability) => capability,
        None => kernel
            .issue_capability(&agent_pk, PactScope::default(), 300)
            .map_err(|error| {
                CliError::Other(format!(
                    "failed to issue fallback empty capability: {error}"
                ))
            })?,
    };
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps);
    kernel.activate_session(&session_id)?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("check-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        arguments: params.clone(),
    });

    let response = match kernel.evaluate_session_operation(&context, &operation)? {
        SessionOperationResponse::ToolCall(response) => response,
        SessionOperationResponse::RootList { .. }
        | SessionOperationResponse::ResourceList { .. }
        | SessionOperationResponse::ResourceRead { .. }
        | SessionOperationResponse::ResourceReadDenied { .. }
        | SessionOperationResponse::ResourceTemplateList { .. }
        | SessionOperationResponse::PromptList { .. }
        | SessionOperationResponse::PromptGet { .. }
        | SessionOperationResponse::Completion { .. }
        | SessionOperationResponse::CapabilityList { .. }
        | SessionOperationResponse::Heartbeat => {
            return Err(CliError::Other(
                "unexpected non-tool response while evaluating check command".to_string(),
            ));
        }
    };

    kernel.begin_draining_session(&session_id)?;
    kernel.close_session(&session_id)?;

    if json_output {
        let output = serde_json::json!({
            "verdict": format!("{:?}", response.verdict),
            "tool": tool,
            "server": server,
            "params": params,
            "reason": response.reason,
            "receipt_id": response.receipt.id,
            "policy_hash": policy_identity.runtime_hash,
            "policy_source_hash": policy_identity.source_hash,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        let verdict_str = match response.verdict {
            pact_kernel::Verdict::Allow => "ALLOW",
            pact_kernel::Verdict::Deny => "DENY",
        };
        println!("verdict:    {verdict_str}");
        println!("tool:       {tool}");
        println!("server:     {server}");
        if let Some(reason) = &response.reason {
            println!("reason:     {reason}");
        }
        println!("receipt_id: {}", response.receipt.id);
        println!("policy:     {}", policy_identity.runtime_hash);
        println!("source:     {}", policy_identity.source_hash);
    }

    match response.verdict {
        pact_kernel::Verdict::Allow => Ok(()),
        pact_kernel::Verdict::Deny => {
            std::process::exit(2);
        }
    }
}

fn cmd_mcp_serve(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        server_id = server_id,
        "loaded policy for MCP edge"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        authority_seed_path,
        authority_db_path,
        control_url,
        control_token,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;
    let wrapped_arg_refs = wrapped_args.iter().map(String::as_str).collect::<Vec<_>>();

    let manifest_public_key = manifest_public_key
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
    let adapted_server = AdaptedMcpServer::from_command(
        wrapped_cmd,
        &wrapped_arg_refs,
        McpAdapterConfig {
            server_id: server_id.to_string(),
            server_name: server_name.unwrap_or(server_id).to_string(),
            server_version: server_version
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            public_key: manifest_public_key,
        },
    )?;
    let upstream_notification_source = adapted_server.notification_source();
    let upstream_capabilities = adapted_server.upstream_capabilities();
    let manifest = adapted_server.manifest_clone();
    if let Some(resource_provider) = adapted_server.resource_provider() {
        kernel.register_resource_provider(Box::new(resource_provider));
    }
    if let Some(prompt_provider) = adapted_server.prompt_provider() {
        kernel.register_prompt_provider(Box::new(prompt_provider));
    }
    kernel.register_tool_server(Box::new(adapted_server));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let agent_id = agent_pk.to_hex();
    let capabilities = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;

    info!(
        capability_count = capabilities.len(),
        upstream_resources = upstream_capabilities.resources_supported,
        upstream_prompts = upstream_capabilities.prompts_supported,
        upstream_completions = upstream_capabilities.completions_supported,
        wrapped_command = wrapped_cmd,
        "initialized MCP edge session"
    );

    let mut edge = PactMcpEdge::new(
        McpEdgeConfig {
            server_name: "PACT MCP Edge".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            page_size,
            tools_list_changed: tools_list_changed || upstream_capabilities.tools_list_changed,
            completion_enabled: Some(upstream_capabilities.completions_supported),
            resources_subscribe: upstream_capabilities.resources_subscribe,
            resources_list_changed: upstream_capabilities.resources_list_changed,
            prompts_list_changed: upstream_capabilities.prompts_list_changed,
            logging_enabled: true,
        },
        kernel,
        agent_id,
        capabilities,
        vec![manifest],
    )?;
    edge.attach_upstream_transport(upstream_notification_source);

    edge.serve_stdio(std::io::BufReader::new(std::io::stdin()), std::io::stdout())?;
    Ok(())
}

fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_server_seed_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token: auth_token.map(ToOwned::to_owned),
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token: admin_token.map(ToOwned::to_owned),
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
    })
}

pub(crate) fn build_kernel(loaded_policy: LoadedPolicy, kernel_kp: &Keypair) -> PactKernel {
    let LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        ..
    } = loaded_policy;

    let config = KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: kernel_policy.delegation_depth_limit,
        policy_hash: identity.runtime_hash,
        allow_sampling: kernel_policy.allow_sampling,
        allow_sampling_tool_use: kernel_policy.allow_sampling_tool_use,
        allow_elicitation: kernel_policy.allow_elicitation,
        max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };

    let mut kernel = PactKernel::new(config);

    if !guard_pipeline.is_empty() {
        info!(
            guard_count = guard_pipeline.len(),
            "registering guard pipeline"
        );
        kernel.add_guard(Box::new(guard_pipeline));
    }

    kernel
}

pub(crate) fn configure_receipt_store(
    kernel: &mut PactKernel,
    receipt_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_receipt_store(Box::new(pact_kernel::SqliteReceiptStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_receipt_store(trust_control::build_remote_receipt_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn configure_revocation_store(
    kernel: &mut PactKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(pact_kernel::SqliteRevocationStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(trust_control::build_remote_revocation_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn configure_capability_authority(
    kernel: &mut PactKernel,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::Other(
            "use either local authority flags or --control-url, not both".to_string(),
        ));
    }
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        kernel.set_capability_authority(trust_control::build_remote_capability_authority(
            url, token,
        )?);
        return Ok(());
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            kernel.set_capability_authority(Box::new(pact_kernel::LocalCapabilityAuthority::new(
                keypair,
            )));
        }
        (None, Some(path)) => {
            kernel.set_capability_authority(Box::new(
                pact_kernel::SqliteCapabilityAuthority::open(path)?,
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn configure_budget_store(
    kernel: &mut PactKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(pact_kernel::SqliteBudgetStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(trust_control::build_remote_budget_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::Other(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub(crate) fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<pact_core::PublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(seed_hex) => Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub(crate) fn rotate_authority_keypair(path: &Path) -> Result<pact_core::PublicKey, CliError> {
    let keypair = Keypair::generate();
    write_authority_seed_file(path, &keypair)?;
    Ok(keypair.public_key())
}

pub(crate) fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    match authority_public_key_from_seed_file(path)? {
        Some(_) => {
            let seed_hex = fs::read_to_string(path)?;
            Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
        }
        None => {
            let keypair = Keypair::generate();
            write_authority_seed_file(path, &keypair)?;
            Ok(keypair)
        }
    }
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, format!("{}\n", keypair.seed_hex()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temp_path, path)?;
    Ok(())
}

fn require_revocation_db_path(revocation_db_path: Option<&Path>) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::Other(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

fn cmd_trust_serve(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
) -> Result<(), CliError> {
    trust_control::serve(trust_control::TrustServiceConfig {
        listen,
        service_token: service_token.to_string(),
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(Path::to_path_buf),
        authority_db_path: authority_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        advertise_url: advertise_url.map(ToOwned::to_owned),
        peer_urls: peer_urls.to_vec(),
        cluster_sync_interval: std::time::Duration::from_millis(cluster_sync_interval_ms.max(50)),
    })
}

fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let mut store = pact_kernel::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.list_revocations(
            &trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            },
        )?;
        (response.revoked.unwrap_or(false), url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = pact_kernel::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_receipt_list(
    capability: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    outcome: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    min_cost: Option<u64>,
    max_cost: Option<u64>,
    limit: usize,
    cursor: Option<u64>,
    receipt_db: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let client = trust_control::build_client(url, token)?;
        let query = trust_control::ReceiptQueryHttpQuery {
            capability_id: capability.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            outcome: outcome.map(ToOwned::to_owned),
            since,
            until,
            min_cost,
            max_cost,
            cursor,
            limit: Some(limit),
            agent_subject: None,
        };
        let response = client.query_receipts(&query)?;
        for receipt in &response.receipts {
            println!("{}", serde_json::to_string(receipt)?);
        }
        if let Some(next_cursor) = response.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                response.total_count
            );
        }
    } else {
        let path = receipt_db.ok_or_else(|| {
            CliError::Other(
                "receipt commands require --receipt-db <path> or --control-url".to_string(),
            )
        })?;
        let store = pact_kernel::SqliteReceiptStore::open(path)?;
        let kernel_query = pact_kernel::ReceiptQuery {
            capability_id: capability.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            outcome: outcome.map(ToOwned::to_owned),
            since,
            until,
            min_cost,
            max_cost,
            cursor,
            limit,
            agent_subject: None,
        };
        let result = store.query_receipts(&kernel_query)?;
        for stored in &result.receipts {
            println!("{}", serde_json::to_string(&stored.receipt)?);
        }
        if let Some(next_cursor) = result.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                result.total_count
            );
        }
    }
    Ok(())
}

pub(crate) fn issue_default_capabilities(
    kernel: &PactKernel,
    agent_pk: &pact_core::PublicKey,
    default_capabilities: &[DefaultCapability],
) -> Result<Vec<pact_core::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::Other(format!("failed to issue initial capability: {error}"))
                })
        })
        .collect()
}

fn select_capability_for_request(
    capabilities: &[pact_core::CapabilityToken],
    tool: &str,
    server: &str,
    params: &serde_json::Value,
) -> Option<pact_core::CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_request(capability, tool, server, params)
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| capabilities.first().cloned())
}

fn handle_agent_message(
    kernel: &mut PactKernel,
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
    stats: &mut SessionStats,
) -> Vec<KernelMessage> {
    let is_tool_call = matches!(msg, AgentMessage::ToolCallRequest { .. });
    if is_tool_call {
        stats.requests += 1;
    }

    let (context, operation) = normalize_agent_message(msg, session_id, session_agent_id);
    match kernel.evaluate_session_operation(&context, &operation) {
        Ok(SessionOperationResponse::ToolCall(response)) => {
            match response.verdict {
                pact_kernel::Verdict::Allow => stats.allowed += 1,
                pact_kernel::Verdict::Deny => stats.denied += 1,
            }

            tool_response_messages(context.request_id.to_string(), response)
        }
        Ok(SessionOperationResponse::CapabilityList { capabilities }) => {
            vec![KernelMessage::CapabilityList { capabilities }]
        }
        Ok(
            SessionOperationResponse::RootList { .. }
            | SessionOperationResponse::ResourceList { .. }
            | SessionOperationResponse::ResourceRead { .. }
            | SessionOperationResponse::ResourceReadDenied { .. }
            | SessionOperationResponse::ResourceTemplateList { .. }
            | SessionOperationResponse::PromptList { .. }
            | SessionOperationResponse::PromptGet { .. }
            | SessionOperationResponse::Completion { .. },
        ) => {
            error!(
                request_id = %context.request_id,
                "unexpected non-tool session response on PACT stdio transport"
            );
            vec![KernelMessage::Heartbeat]
        }
        Ok(SessionOperationResponse::Heartbeat) => vec![KernelMessage::Heartbeat],
        Err(e) => match operation {
            SessionOperation::ToolCall(tool_call) => {
                stats.denied += 1;
                error!(
                    request_id = %context.request_id,
                    error = %e,
                    "kernel session evaluation error"
                );

                let request = KernelToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability,
                    tool_name: tool_call.tool_name,
                    server_id: tool_call.server_id,
                    agent_id: session_agent_id.to_string(),
                    arguments: tool_call.arguments,
                    dpop_proof: None,
                };

                vec![KernelMessage::ToolCallResponse {
                    id: context.request_id.to_string(),
                    result: ToolCallResult::Err {
                        error: ToolCallError::InternalError(e.to_string()),
                    },
                    receipt: Box::new(make_error_receipt(kernel, &request)),
                }]
            }
            SessionOperation::ListCapabilities => {
                error!(error = %e, session_id = %session_id, "failed to list capabilities");
                vec![KernelMessage::CapabilityList {
                    capabilities: vec![],
                }]
            }
            SessionOperation::CreateMessage(_)
            | SessionOperation::CreateElicitation(_)
            | SessionOperation::ListRoots
            | SessionOperation::ListResources
            | SessionOperation::ReadResource(_)
            | SessionOperation::ListResourceTemplates
            | SessionOperation::ListPrompts
            | SessionOperation::GetPrompt(_)
            | SessionOperation::Complete(_) => {
                error!(
                    error = %e,
                    request_id = %context.request_id,
                    "unexpected resource/prompt session failure on PACT stdio transport"
                );
                vec![KernelMessage::Heartbeat]
            }
            SessionOperation::Heartbeat => {
                error!(error = %e, session_id = %session_id, "failed to handle heartbeat");
                vec![KernelMessage::Heartbeat]
            }
        },
    }
}

fn tool_response_messages(
    request_id: String,
    response: pact_kernel::ToolCallResponse,
) -> Vec<KernelMessage> {
    let mut messages = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(ToolCallStream { chunks })) => chunks
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk)| KernelMessage::ToolCallChunk {
                id: request_id.clone(),
                chunk_index: chunk_index as u64,
                data: chunk.data.clone(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let chunks_received = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(stream)) => stream.chunk_count(),
        _ => 0,
    };

    let result = match (
        response.verdict,
        response.terminal_state.clone(),
        response.output,
    ) {
        (pact_kernel::Verdict::Allow, _, Some(ToolCallOutput::Value(value))) => {
            ToolCallResult::Ok { value }
        }
        (pact_kernel::Verdict::Allow, _, Some(ToolCallOutput::Stream(_))) => {
            ToolCallResult::StreamComplete {
                total_chunks: chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Cancelled { reason }, _) => {
            ToolCallResult::Cancelled {
                reason,
                chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Incomplete { reason }, _) => {
            ToolCallResult::Incomplete {
                reason,
                chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Completed, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: "kernel".to_string(),
                reason: response
                    .reason
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        },
        (pact_kernel::Verdict::Allow, _, None) => ToolCallResult::Ok {
            value: serde_json::Value::Null,
        },
    };

    messages.push(KernelMessage::ToolCallResponse {
        id: request_id,
        result,
        receipt: Box::new(response.receipt),
    });
    messages
}

fn normalize_agent_message(
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
) -> (OperationContext, SessionOperation) {
    match msg {
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            server_id,
            tool,
            params,
        } => (
            OperationContext::new(
                session_id.clone(),
                RequestId::new(id.clone()),
                session_agent_id.to_string(),
            ),
            SessionOperation::ToolCall(ToolCallOperation {
                capability: *capability_token.clone(),
                server_id: server_id.clone(),
                tool_name: tool.clone(),
                arguments: params.clone(),
            }),
        ),
        AgentMessage::ListCapabilities => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "list_capabilities"),
                session_agent_id.to_string(),
            ),
            SessionOperation::ListCapabilities,
        ),
        AgentMessage::Heartbeat => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "heartbeat"),
                session_agent_id.to_string(),
            ),
            SessionOperation::Heartbeat,
        ),
    }
}

fn control_request_id(session_id: &SessionId, suffix: &str) -> RequestId {
    RequestId::new(format!("{session_id}::{suffix}"))
}

/// Build an error receipt when the kernel fails internally.
fn make_error_receipt(
    _kernel: &mut PactKernel,
    request: &KernelToolCallRequest,
) -> pact_core::PactReceipt {
    // Attempt to build a proper deny receipt through the kernel.
    // If that also fails (unlikely), produce a minimal placeholder.
    let action = pact_core::receipt::ToolCallAction::from_parameters(request.arguments.clone());
    let action = match action {
        Ok(a) => a,
        Err(_) => pact_core::receipt::ToolCallAction::from_parameters(serde_json::json!({}))
            .unwrap_or_else(|_| {
                // This path should never be reached, but if it is, we have a
                // truly minimal fallback.
                pact_core::receipt::ToolCallAction {
                    parameter_hash: "error".to_string(),
                    parameters: serde_json::json!({}),
                }
            }),
    };

    // Sign a receipt with the kernel's key by issuing a capability for this
    // purpose and using the kernel's existing receipt-signing infrastructure.
    // Since we only have pub methods, we use a simplified approach.
    let kp = Keypair::generate();
    let body = pact_core::receipt::PactReceiptBody {
        id: format!("rcpt-error-{}", request.request_id),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        capability_id: request.capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action,
        decision: pact_core::receipt::Decision::Deny {
            reason: "internal kernel error".to_string(),
            guard: "kernel".to_string(),
        },
        content_hash: pact_core::sha256_hex(b"null"),
        policy_hash: "error".to_string(),
        evidence: vec![],
        metadata: None,
        kernel_key: kp.public_key(),
    };

    pact_core::receipt::PactReceipt::sign(body, &kp).unwrap_or_else(|_| {
        // Absolute last resort: this should never happen.
        panic!("failed to sign error receipt");
    })
}

struct StubToolServer {
    id: String,
}

impl pact_kernel::ToolServerConnection for StubToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, pact_kernel::KernelError> {
        Ok(serde_json::json!({
            "stub": true,
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

#[cfg(test)]
struct StubStreamingToolServer {
    id: String,
    incomplete: bool,
}

#[cfg(test)]
impl pact_kernel::ToolServerConnection for StubStreamingToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream_file".to_string()]
    }

    fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, pact_kernel::KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    fn invoke_stream(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<Option<pact_kernel::ToolServerStreamResult>, pact_kernel::KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                pact_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": "hello"}),
                },
                pact_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": arguments}),
                },
            ],
        };

        if self.incomplete {
            Ok(Some(pact_kernel::ToolServerStreamResult::Incomplete {
                stream,
                reason: "stream source ended before final frame".to_string(),
            }))
        } else {
            Ok(Some(pact_kernel::ToolServerStreamResult::Complete(stream)))
        }
    }
}

#[derive(Default)]
struct SessionStats {
    requests: u64,
    allowed: u64,
    denied: u64,
}

fn print_summary(stats: &SessionStats, exit_code: Option<i32>, json_output: bool) {
    if json_output {
        let output = serde_json::json!({
            "summary": {
                "requests": stats.requests,
                "allowed": stats.allowed,
                "denied": stats.denied,
                "exit_code": exit_code,
            }
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        eprintln!();
        eprintln!("--- pact session summary ---");
        eprintln!("requests: {}", stats.requests);
        eprintln!("allowed:  {}", stats.allowed);
        eprintln!("denied:   {}", stats.denied);
        if let Some(code) = exit_code {
            eprintln!("exit:     {code}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn load_test_policy_runtime(policy: &policy::PactPolicy) -> policy::LoadedPolicy {
        let default_capabilities = policy::build_runtime_default_capabilities(policy).unwrap();

        policy::LoadedPolicy {
            format: policy::PolicyFormat::PactYaml,
            identity: policy::PolicyIdentity {
                source_hash: "test-source-hash".to_string(),
                runtime_hash: "test-runtime-hash".to_string(),
            },
            kernel: policy.kernel.clone(),
            default_capabilities,
            guard_pipeline: policy::build_guard_pipeline(&policy.guards),
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/policies")
            .join(name)
    }

    fn unique_db_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn unique_seed_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.seed"))
    }

    fn first_default_capability(
        kernel: &PactKernel,
        policy: &policy::PactPolicy,
        agent_kp: &Keypair,
    ) -> pact_core::CapabilityToken {
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        issue_default_capabilities(kernel, &agent_kp.public_key(), &default_capabilities)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    fn open_ready_session(
        kernel: &mut PactKernel,
        agent_id: &str,
        capabilities: Vec<pact_core::CapabilityToken>,
    ) -> SessionId {
        let session_id = kernel.open_session(agent_id.to_string(), capabilities);
        kernel.activate_session(&session_id).unwrap();
        session_id
    }

    fn only_message(messages: Vec<KernelMessage>) -> KernelMessage {
        assert_eq!(messages.len(), 1, "expected exactly one kernel message");
        messages.into_iter().next().unwrap()
    }

    #[test]
    fn check_builds_kernel_with_guards() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
guards:
  forbidden_path:
    enabled: true
  shell_command:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        assert_eq!(kernel.guard_count(), 1); // pipeline counts as 1
    }

    #[test]
    fn configure_revocation_store_survives_restart() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let revocation_db_path = unique_db_path("pact-cli-revocations");
        let kp = Keypair::generate();

        let agent_kp = Keypair::generate();
        let cap = {
            let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
            configure_revocation_store(&mut kernel, Some(&revocation_db_path), None, None).unwrap();
            kernel.register_tool_server(Box::new(StubToolServer {
                id: "*".to_string(),
            }));

            let cap = first_default_capability(&kernel, &policy, &agent_kp);
            kernel.revoke_capability(&cap.id).unwrap();
            cap
        };

        let mut restarted = build_kernel(load_test_policy_runtime(&policy), &kp);
        configure_revocation_store(&mut restarted, Some(&revocation_db_path), None, None).unwrap();
        restarted.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let request = KernelToolCallRequest {
            request_id: "revoked-after-restart".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
        };

        let response = restarted.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Deny);
        assert!(response.reason.as_deref().unwrap_or("").contains("revoked"));

        let _ = std::fs::remove_file(revocation_db_path);
    }

    #[test]
    fn authority_seed_file_persists_public_key_across_loads_and_rotation() {
        let seed_path = unique_seed_path("pact-cli-authority");
        let original = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        let reloaded = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        assert_eq!(original, reloaded);

        let rotated = rotate_authority_keypair(&seed_path).unwrap();
        assert_ne!(original, rotated);
        assert_eq!(
            authority_public_key_from_seed_file(&seed_path).unwrap(),
            Some(rotated)
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_changes_issued_capability_issuer() {
        let seed_path = unique_seed_path("pact-cli-configure-authority");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        configure_capability_authority(&mut kernel, Some(&seed_path), None, None, None).unwrap();

        let agent_kp = Keypair::generate();
        let capability =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();

        assert_eq!(
            capability.issuer,
            authority_public_key_from_seed_file(&seed_path)
                .unwrap()
                .expect("authority public key")
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_supports_shared_sqlite_backend() {
        let authority_db_path = unique_db_path("pact-cli-authority-db");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let mut first_kernel =
            build_kernel(load_test_policy_runtime(&policy), &Keypair::generate());
        configure_capability_authority(
            &mut first_kernel,
            None,
            Some(&authority_db_path),
            None,
            None,
        )
        .unwrap();

        let first_capability = issue_default_capabilities(
            &first_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let original_issuer = first_capability.issuer.clone();

        let authority = pact_kernel::SqliteCapabilityAuthority::open(&authority_db_path).unwrap();
        let rotated = authority.rotate().unwrap();

        let mut second_kernel =
            build_kernel(load_test_policy_runtime(&policy), &Keypair::generate());
        configure_capability_authority(
            &mut second_kernel,
            None,
            Some(&authority_db_path),
            None,
            None,
        )
        .unwrap();
        let second_capability = issue_default_capabilities(
            &second_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

        assert_ne!(original_issuer, second_capability.issuer);
        assert_eq!(second_capability.issuer, rotated.public_key);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn check_command_allow() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-1".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Allow);
    }

    #[test]
    fn check_command_deny_forbidden_path() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-2".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/home/user/.ssh/id_rsa"}),
            dpop_proof: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Deny);
    }

    #[test]
    fn handle_heartbeat() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::Heartbeat,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        assert!(matches!(response, KernelMessage::Heartbeat));
        assert_eq!(stats.requests, 0);
    }

    #[test]
    fn handle_list_capabilities() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::ListCapabilities,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        match response {
            KernelMessage::CapabilityList { capabilities } => {
                assert_eq!(capabilities.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_uses_explicit_server_id() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
      - server: "srv-b"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-b".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let cap = caps[0].clone();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "srv-b".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/app/src/main.rs"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_uses_session_agent_id_not_presented_subject() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-a".to_string(),
        }));

        let session_agent_kp = Keypair::generate();
        let stolen_agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps = issue_default_capabilities(
            &kernel,
            &session_agent_kp.public_key(),
            &default_capabilities,
        )
        .unwrap();
        let session_agent_id = session_agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &session_agent_id, caps.clone());
        let stolen_capability = first_default_capability(&kernel, &policy, &stolen_agent_kp);

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(stolen_capability),
            server_id: "srv-a".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/app/src/main.rs"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &session_agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hushspec_policy_drives_tool_access_via_session_runtime_path() {
        let loaded_policy = policy::load_policy(&fixture_path("hushspec-tool-allow.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md", "content": "nope"}),
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn yaml_tool_access_drives_tool_access_via_session_runtime_path() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - list_directory
"#,
        )
        .unwrap();

        let loaded_policy = load_test_policy_runtime(&policy);
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md", "content": "nope"}),
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_streams_chunks_before_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: false,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        assert!(matches!(
            &messages[0],
            KernelMessage::ToolCallChunk { chunk_index: 0, .. }
        ));
        assert!(matches!(
            &messages[1],
            KernelMessage::ToolCallChunk { chunk_index: 1, .. }
        ));
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::StreamComplete { total_chunks: 2 }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn handle_tool_call_surfaces_incomplete_stream_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: true,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-2".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::Incomplete {
                        chunks_received: 2,
                        ..
                    }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn hushspec_policy_compiles_shell_guard_into_runtime_path() {
        let loaded_policy =
            policy::load_policy(&fixture_path("hushspec-guard-heavy.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "bash",
            "*",
            &serde_json::json!({"command": "rm -rf /"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "bash".to_string(),
            params: serde_json::json!({"command": "rm -rf /"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }
}
