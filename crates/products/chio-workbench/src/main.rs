#[cfg(unix)]
use chio_workbench::{
    provider::{Claude, ClaudeCode, Provider},
    Workbench, WorkbenchConfig,
};
#[cfg(unix)]
use clap::{Parser, ValueEnum};
#[cfg(unix)]
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

#[cfg(unix)]
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    ClaudeApi,
    ClaudeCode,
}

#[cfg(unix)]
#[derive(Parser)]
#[command(about = "Run a delegated coding task through the Chio kernel")]
struct Args {
    /// Trusted checkout to inspect and edit.
    #[arg(long)]
    workspace: PathBuf,
    /// Private local state directory. Defaults to WORKSPACE/.chio-workbench.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Model ID or CLI model name for the selected provider.
    #[arg(long, env = "ANTHROPIC_MODEL")]
    model: String,
    /// Transport used to obtain model proposals.
    #[arg(long, value_enum, default_value = "claude-api")]
    provider: Backend,
    /// Trusted Claude Code executable, used with --provider claude-code.
    #[arg(long, default_value = "claude")]
    claude_command: PathBuf,
    /// Per-request budget passed to Claude Code's --max-budget-usd flag.
    #[arg(long, default_value_t = 0.25)]
    claude_code_turn_budget_usd: f64,
    /// Loopback port. Set 0 to select an available port.
    #[arg(long, default_value_t = 7392)]
    port: u16,
    /// Project check command and arguments, executed without a shell.
    #[arg(last = true, required = true)]
    check_command: Vec<String>,
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let provider: Arc<dyn Provider> = match args.provider {
        Backend::ClaudeApi => Arc::new(Claude::new(
            std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| "set ANTHROPIC_API_KEY or select --provider claude-code")?,
            args.model,
        )?),
        Backend::ClaudeCode => Arc::new(ClaudeCode::new(
            args.claude_command,
            args.model,
            args.claude_code_turn_budget_usd,
        )?),
    };
    let state_dir = args
        .state_dir
        .unwrap_or_else(|| args.workspace.join(".chio-workbench"));
    let workbench = Workbench::open(
        WorkbenchConfig {
            workspace: args.workspace,
            state_dir,
            check_command: args.check_command,
        },
        provider,
    )?;
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port))
            .await?;
    let address = listener.local_addr()?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let router = chio_workbench::web::router(Arc::clone(&workbench), token.clone(), address);
    println!(
        "Chio Workbench\nWorkspace: {}\nOpen: http://{address}/#access={token}",
        workbench.workspace().display()
    );
    println!("Only share this local URL with the operator. Press Ctrl-C to stop.");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    workbench.shutdown().await;
    Ok(())
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("The local Chio workbench currently requires Linux.");
    std::process::ExitCode::FAILURE
}
