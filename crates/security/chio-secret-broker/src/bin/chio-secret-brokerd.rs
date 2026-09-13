#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use chio_secret_broker::daemon_runtime::harden_broker_process_custody;
use chio_secret_broker::daemon_runtime::{
    secure_inherited_key_file, BrokerDaemonConfig, BrokerDaemonRuntime,
};
use chio_secret_broker::inherited_fd::adopt_inherited_key_file;
use chio_secret_broker::{BrokerError, Result};

struct Args {
    config_path: PathBuf,
    master_key_fd: u32,
    signing_key_fd: u32,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        let mut config_path = None;
        let mut master_key_fd = None;
        let mut signing_key_fd = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or_else(|| {
                BrokerError::InvalidRequest("daemon argument is missing its value".to_string())
            })?;
            match flag.to_str() {
                Some("--config") if config_path.is_none() => {
                    config_path = Some(PathBuf::from(value));
                }
                Some("--master-key-fd") if master_key_fd.is_none() => {
                    master_key_fd = Some(parse_fd(value, "master key")?);
                }
                Some("--signing-key-fd") if signing_key_fd.is_none() => {
                    signing_key_fd = Some(parse_fd(value, "signing key")?);
                }
                _ => {
                    return Err(BrokerError::InvalidRequest(
                        "daemon argument is unknown or repeated".to_string(),
                    ))
                }
            }
        }
        let master_key_fd = master_key_fd.ok_or_else(|| {
            BrokerError::InvalidRequest("master-key descriptor is required".to_string())
        })?;
        let signing_key_fd = signing_key_fd.ok_or_else(|| {
            BrokerError::InvalidRequest("signing-key descriptor is required".to_string())
        })?;
        if master_key_fd == signing_key_fd {
            return Err(BrokerError::Custody(
                "master and signing keys must use distinct inherited descriptors".to_string(),
            ));
        }
        Ok(Self {
            config_path: config_path.ok_or_else(|| {
                BrokerError::InvalidRequest("daemon config path is required".to_string())
            })?,
            master_key_fd,
            signing_key_fd,
        })
    }
}

fn parse_fd(value: std::ffi::OsString, label: &str) -> Result<u32> {
    let value = value.into_string().map_err(|_| {
        BrokerError::InvalidRequest(format!("{label} descriptor is not valid UTF-8"))
    })?;
    value.parse::<u32>().map_err(|_| {
        BrokerError::InvalidRequest(format!("{label} descriptor is not an unsigned integer"))
    })
}

fn run() -> Result<()> {
    #[cfg(target_os = "linux")]
    harden_broker_process_custody()?;
    let args = Args::parse()?;
    let config = BrokerDaemonConfig::load(args.config_path)?;
    // SAFETY: process launch transfers both descriptor numbers exclusively to
    // brokerd, and no Rust value in this process owns either original.
    #[allow(unsafe_code)]
    let master_key = unsafe { adopt_inherited_key_file(args.master_key_fd, "master key") }?;
    // SAFETY: the distinct signing descriptor is transferred by the same
    // launch contract and has no competing Rust owner in this process.
    #[allow(unsafe_code)]
    let signing_key = unsafe { adopt_inherited_key_file(args.signing_key_fd, "signing key") }?;
    let master_key = secure_inherited_key_file(master_key, "master key")?;
    let signing_key = secure_inherited_key_file(signing_key, "signing key")?;
    BrokerDaemonRuntime::build(config, master_key, signing_key)?.serve()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-secret-brokerd failed closed: {}", error_code(&error));
            ExitCode::FAILURE
        }
    }
}

fn error_code(error: &BrokerError) -> &'static str {
    match error {
        BrokerError::InvalidRequest(_) => "invalid_configuration",
        BrokerError::AuthorizationDenied(_) => "authorization_denied",
        BrokerError::AuthorityUnavailable(_) => "authority_unavailable",
        BrokerError::Conflict(_) => "state_conflict",
        BrokerError::Invariant(_) => "runtime_invariant",
        BrokerError::Storage(_) => "storage_unavailable",
        BrokerError::Upstream(_) => "upstream_unavailable",
        BrokerError::ResponseRejected(_) => "response_rejected",
        BrokerError::Custody(_) => "custody_unavailable",
    }
}
