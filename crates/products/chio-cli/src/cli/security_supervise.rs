//! `chio security supervise`: run one service under systemd with its
//! credentials from the credentials directory, readiness on the notify
//! socket and stop signals forwarded to the service.
//!
//! With `--exec` the command only delivers the credentials and replaces
//! itself with the service; that is the form for `ExecStartPre=` checks and
//! for daemons that need no readiness gate.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::supervise::CredentialBinding;
use crate::CliError;

/// Arguments for `chio security supervise`.
#[derive(clap::Args, Debug)]
pub struct SuperviseArgs {
    /// Directory holding the credential files; systemd sets it for every
    /// unit with `LoadCredential=`.
    #[arg(long, value_name = "PATH", env = "CREDENTIALS_DIRECTORY")]
    pub credentials_dir: Option<PathBuf>,

    /// Deliver the credential file CREDENTIAL to the service as VARIABLE.
    /// Repeat for every secret; the variable must not be set already.
    #[arg(long = "credential-env", value_name = "VARIABLE=CREDENTIAL")]
    pub credential_env: Vec<CredentialBinding>,

    /// Report readiness once a GET of this URL answers with a success status.
    #[arg(long, value_name = "URL", conflicts_with = "ready_unix_socket")]
    pub ready_http: Option<String>,

    /// Present this variable's value (a delivered credential, or one already
    /// in the environment) as the bearer on readiness requests.
    #[arg(long, value_name = "VARIABLE", requires = "ready_http")]
    pub ready_http_bearer_env: Option<String>,

    /// Report readiness once this Unix socket accepts a connection.
    #[arg(long, value_name = "PATH")]
    pub ready_unix_socket: Option<PathBuf>,

    /// Seconds the service may take to become ready before it is stopped.
    #[arg(long, value_name = "SECONDS", default_value_t = 60)]
    pub ready_timeout: u64,

    /// Seconds a stopped service may take to drain before SIGKILL.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    pub stop_grace: u64,

    /// Deliver the credentials and replace this process with the service
    /// instead of supervising it.
    #[arg(long, conflicts_with_all = ["ready_http", "ready_unix_socket"])]
    pub exec: bool,

    /// The service command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[cfg(unix)]
pub fn cmd_security_supervise(args: &SuperviseArgs) -> Result<(), CliError> {
    use std::path::Path;
    use std::time::Duration;

    use crate::supervise::{
        exec_with_credentials, load_bindings, supervise, Exit, Notifier, Supervision,
    };

    let Some((program, rest)) = args.command.split_first() else {
        return Err(CliError::cli_other_error(
            "supervise needs the service command after --".to_string(),
        ));
    };
    let credentials = load_bindings(
        args.credentials_dir.as_deref(),
        &args.credential_env,
        |variable| std::env::var_os(variable).is_some(),
    )
    .map_err(|error| CliError::cli_other_error(format!("supervise: {error}")))?;

    if args.exec {
        let error = exec_with_credentials(Path::new(program), rest, credentials);
        return Err(CliError::cli_other_error(format!(
            "supervise: exec {} failed: {error}",
            Path::new(program).display()
        )));
    }

    let readiness = readiness(args, &credentials)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::cli_other_error(format!("supervise: runtime could not start: {error}"))
        })?;
    let outcome = runtime.block_on(supervise(Supervision {
        program: PathBuf::from(program),
        args: rest.to_vec(),
        environment: credentials,
        readiness,
        ready_timeout: Duration::from_secs(args.ready_timeout),
        stop_grace: Duration::from_secs(args.stop_grace),
        notifier: Notifier::from_environment(),
    }));
    drop(runtime);
    match outcome {
        Ok(Exit::Code(0)) => Ok(()),
        Ok(Exit::Code(code)) => std::process::exit(code),
        Ok(Exit::Signal(number)) => end_by_signal(number),
        Err(error) => {
            eprintln!("chio security supervise: {error}");
            std::process::exit(1)
        }
    }
}

#[cfg(unix)]
fn readiness(
    args: &SuperviseArgs,
    credentials: &[(String, String)],
) -> Result<crate::supervise::Readiness, CliError> {
    use crate::supervise::Readiness;

    if let Some(url) = &args.ready_http {
        let bearer = match &args.ready_http_bearer_env {
            Some(variable) => {
                let value = credentials
                    .iter()
                    .find(|(name, _)| name == variable)
                    .map(|(_, value)| value.clone())
                    .or_else(|| std::env::var(variable).ok())
                    .ok_or_else(|| {
                        CliError::cli_other_error(format!(
                            "supervise: --ready-http-bearer-env names {variable}, which is neither a delivered credential nor set in the environment"
                        ))
                    })?;
                Some(value)
            }
            None => None,
        };
        return Ok(Readiness::Http {
            url: url.clone(),
            bearer,
        });
    }
    if let Some(path) = &args.ready_unix_socket {
        return Ok(Readiness::UnixSocket(path.clone()));
    }
    Ok(Readiness::Immediate)
}

/// End this process by the signal that ended the service, so the manager
/// records the same outcome it would have seen from the service itself.
#[cfg(unix)]
fn end_by_signal(number: i32) -> ! {
    // SAFETY: signal(2) and raise(2) are called with a valid signal number
    // after the runtime and every handler it installed have been dropped;
    // restoring the default disposition and raising ends the process.
    unsafe {
        libc::signal(number, libc::SIG_DFL);
        libc::raise(number);
    }
    std::process::exit(128 + number)
}

#[cfg(not(unix))]
pub fn cmd_security_supervise(_args: &SuperviseArgs) -> Result<(), CliError> {
    Err(CliError::cli_other_error(
        "chio security supervise requires a unix platform".to_string(),
    ))
}
