//! Administrative CLI for a local, persistent process host.

use std::path::PathBuf;

use clap::Subcommand;

use crate::CliError;

#[cfg(unix)]
#[path = "process_host/diagnostics.rs"]
mod diagnostics;
#[cfg(unix)]
#[path = "process_host/lifecycle.rs"]
mod lifecycle;
#[cfg(unix)]
#[path = "process_host/provision.rs"]
mod provision;
#[cfg(unix)]
#[path = "process_host/relocation.rs"]
mod relocation;
#[cfg(target_os = "linux")]
#[path = "process_host/runner/mod.rs"]
mod runner;
#[cfg(unix)]
#[path = "process_host/serving.rs"]
mod serving;
#[cfg(unix)]
#[path = "process_host/state.rs"]
mod state;

#[derive(Subcommand)]
pub(crate) enum ProcessCommands {
    /// Read the last native-runner snapshot while the host is running or stopped.
    Status {
        #[arg(long)]
        state: PathBuf,
    },
    /// Read bounded, private stdout/stderr logs from a retained worker attempt.
    Logs {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        process: String,
        #[arg(long)]
        attempt: u32,
    },
    /// Initialize an empty private state directory from a host configuration.
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    /// Serve authenticated workers until SIGINT or SIGTERM, then drain calls.
    Serve {
        #[arg(long)]
        state: PathBuf,
        /// Socket in a separate private directory exposed to worker sandboxes.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Run a declared worker application with persistent, bounded restart attempts (Linux).
    Run {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Issue a private connection descriptor while the host is stopped.
    Credential {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        process: String,
        #[arg(long)]
        socket: PathBuf,
        /// New file in a private directory. Existing files are never replaced.
        #[arg(long)]
        out: PathBuf,
    },
    /// Revoke a process's worker credentials while the host is stopped.
    Revoke {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        process: String,
    },
    /// Permanently cancel a process subtree while the host is stopped.
    Cancel {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        process: String,
    },
    /// Retire the stopped host where it is and write the manifest that lets a copy be imported elsewhere.
    Export {
        #[arg(long)]
        state: PathBuf,
    },
    /// Re-anchor a copied host state directory at its new location and verify it against its manifest.
    Import {
        #[arg(long)]
        state: PathBuf,
    },
}

pub(crate) fn dispatch(command: ProcessCommands) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        match command {
            ProcessCommands::Status { state } => diagnostics::status(&state),
            ProcessCommands::Logs {
                state,
                process,
                attempt,
            } => diagnostics::logs(&state, &process, attempt),
            ProcessCommands::Init { config, state } => provision::init(&config, &state),
            ProcessCommands::Serve { state, socket } => serving::serve(&state, &socket),
            ProcessCommands::Run { state, plan } => {
                #[cfg(target_os = "linux")]
                {
                    runner::run(&state, &plan)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (state, plan);
                    Err(state::error("worker process supervision requires Linux"))
                }
            }
            ProcessCommands::Credential {
                state,
                process,
                socket,
                out,
            } => provision::credential(&state, &process, &socket, &out),
            ProcessCommands::Revoke { state, process } => {
                let host = state::Host::open(&state, false)?;
                let count = chio_process::worker::WorkerService::new(host.runtime.clone())
                    .revoke_credentials(&process)
                    .map_err(state::error)?;
                println!("{}", serde_json::json!({"revoked_credentials": count}));
                Ok(())
            }
            ProcessCommands::Cancel { state, process } => {
                let host = state::Host::open(&state, false)?;
                let count = host.runtime.cancel(&process).map_err(state::error)?;
                println!("{}", serde_json::json!({"cancelled_processes": count}));
                Ok(())
            }
            ProcessCommands::Export { state } => relocation::export(&state),
            ProcessCommands::Import { state } => relocation::import(&state),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = command;
        Err(CliError::cli_other_error(
            "the process host requires Unix sockets".to_owned(),
        ))
    }
}
