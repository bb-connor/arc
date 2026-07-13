use std::path::PathBuf;
use std::process::ExitCode;

use chio_secret_broker::daemon_runtime::{
    open_inherited_key_fd, BrokerDaemonConfig, BrokerDaemonRuntime,
};
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
        Ok(Self {
            config_path: config_path.ok_or_else(|| {
                BrokerError::InvalidRequest("daemon config path is required".to_string())
            })?,
            master_key_fd: master_key_fd.ok_or_else(|| {
                BrokerError::Custody("master-key descriptor is required".to_string())
            })?,
            signing_key_fd: signing_key_fd.ok_or_else(|| {
                BrokerError::Custody("signing-key descriptor is required".to_string())
            })?,
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
    let args = Args::parse()?;
    let config = BrokerDaemonConfig::load(args.config_path)?;
    let master_key = open_inherited_key_fd(args.master_key_fd, "master key")?;
    let signing_key = open_inherited_key_fd(args.signing_key_fd, "signing key")?;
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
