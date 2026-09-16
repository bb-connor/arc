//! Administrative CLI for a local, persistent process host.

use std::path::PathBuf;

use clap::Subcommand;

use crate::CliError;

#[cfg(unix)]
#[path = "process_host/call_evidence.rs"]
mod call_evidence;
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
#[cfg(unix)]
#[path = "process_host/run_evidence.rs"]
mod run_evidence;
#[cfg(target_os = "linux")]
#[path = "process_host/runner/mod.rs"]
mod runner;
#[cfg(unix)]
#[path = "process_host/serving.rs"]
mod serving;
#[cfg(unix)]
#[path = "process_host/state.rs"]
mod state;
#[cfg(unix)]
#[path = "process_host/swarm.rs"]
mod swarm;

#[derive(Subcommand)]
pub(crate) enum ProcessCommands {
    /// Observe finished workers, issued graphs, call outcomes and durable family usage (Linux).
    AttestOutcomes {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify worker outcomes and their issued authority without opening host state.
    VerifyOutcomes {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        trusted_kernel_pubkey: PathBuf,
        #[arg(long)]
        runtime_id: String,
    },
    /// Observe one retained call and its continuation custody while stopped (Linux).
    AttestCall {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a retained call observation without opening host state.
    VerifyCall {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        trusted_kernel_pubkey: PathBuf,
        #[arg(long)]
        runtime_id: String,
        /// Original caller request, independently retained by the verifier.
        #[arg(long)]
        request: PathBuf,
        /// Original runtime/process/capability context, independently retained.
        #[arg(long)]
        context: PathBuf,
    },
    /// Attest completed fixed fan-out results and the retained aggregate usage (Linux).
    AttestRun {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Independently verify completed fan-out evidence against operator pins.
    VerifyRun {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        trusted_kernel_pubkey: PathBuf,
        #[arg(long)]
        runtime_id: String,
        /// External operator pin for each native server, repeated as SERVER=PUBLIC_KEY.
        #[arg(long)]
        trusted_launch_policy_signer: Vec<String>,
    },
    /// Read retained application state without launching tools or issuing credentials.
    State {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        process: String,
        /// Read one immutable blob instead of the checkpoint.
        #[arg(long)]
        blob: Option<String>,
    },
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
        /// Signed invocation budget shared by the root and all descendants.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        aggregate_invocations: Option<u32>,
        /// Bind a bounded fan-out plan to this host's actual issued capabilities.
        #[arg(long, requires = "aggregate_invocations")]
        swarm_plan: Option<PathBuf>,
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
    /// Permanently revoke the issued capability and its descendants while stopped.
    RevokeCapability {
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
            ProcessCommands::AttestOutcomes { state, plan, out } => {
                #[cfg(target_os = "linux")]
                {
                    call_evidence::export_outcomes(&state, &plan, &out)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (state, plan, out);
                    Err(state::error("worker outcome attestation requires Linux"))
                }
            }
            ProcessCommands::VerifyOutcomes {
                artifact,
                trusted_kernel_pubkey,
                runtime_id,
            } => call_evidence::verify_outcomes(&artifact, &trusted_kernel_pubkey, &runtime_id),
            ProcessCommands::AttestCall {
                state,
                request,
                context,
                response,
                out,
            } => {
                #[cfg(target_os = "linux")]
                {
                    call_evidence::export(&state, &request, &context, &response, &out)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (state, request, context, response, out);
                    Err(state::error("call custody attestation requires Linux"))
                }
            }
            ProcessCommands::VerifyCall {
                artifact,
                trusted_kernel_pubkey,
                runtime_id,
                request,
                context,
            } => call_evidence::verify_file(
                &artifact,
                &trusted_kernel_pubkey,
                &runtime_id,
                &request,
                &context,
            ),
            ProcessCommands::AttestRun { state, plan, out } => {
                #[cfg(target_os = "linux")]
                {
                    run_evidence::export(&state, &plan, &out)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (state, plan, out);
                    Err(state::error("worker run attestation requires Linux"))
                }
            }
            ProcessCommands::VerifyRun {
                artifact,
                trusted_kernel_pubkey,
                runtime_id,
                trusted_launch_policy_signer,
            } => run_evidence::verify_file(
                &artifact,
                &trusted_kernel_pubkey,
                &runtime_id,
                &trusted_launch_policy_signer,
            ),
            ProcessCommands::State {
                state,
                process,
                blob,
            } => diagnostics::application_state(&state, &process, blob.as_deref()),
            ProcessCommands::Status { state } => diagnostics::status(&state),
            ProcessCommands::Logs {
                state,
                process,
                attempt,
            } => diagnostics::logs(&state, &process, attempt),
            ProcessCommands::Init {
                config,
                state,
                aggregate_invocations,
                swarm_plan,
            } => provision::init(
                &config,
                &state,
                aggregate_invocations,
                swarm_plan.as_deref(),
            ),
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
            ProcessCommands::RevokeCapability { state, process } => {
                let host = state::Host::open(&state, false)?;
                let capability = host
                    .runtime
                    .process(&process)
                    .map_err(state::error)?
                    .capability;
                host.kernel
                    .revoke_capability(&capability.id)
                    .map_err(state::error)?;
                println!(
                    "{}",
                    serde_json::json!({"process": process, "capability_id": capability.id, "capability_revoked": true})
                );
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
