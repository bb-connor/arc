#![deny(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use chio_active_response_authority::{
    load_runtime_config, AuthorityDaemonRuntime, AuthorityError, Result,
};
use chio_secure_ipc::{harden_process_custody, InheritedSecretFile};

struct Arguments {
    config_path: PathBuf,
    signing_key_fd: u32,
}

impl Arguments {
    fn parse() -> Result<Self> {
        let mut arguments = env::args_os().skip(1);
        let mut config_path = None;
        let mut signing_key_fd = None;
        while let Some(argument) = arguments.next() {
            let value = arguments.next().ok_or_else(|| {
                AuthorityError::InvalidConfig("every argument requires a value".to_string())
            })?;
            match argument.to_str() {
                Some("--config") if config_path.is_none() => {
                    config_path = Some(PathBuf::from(value));
                }
                Some("--signing-key-fd") if signing_key_fd.is_none() => {
                    let value = value.to_str().ok_or_else(|| {
                        AuthorityError::InvalidConfig(
                            "signing key descriptor is not UTF-8".to_string(),
                        )
                    })?;
                    signing_key_fd = Some(value.parse::<u32>().map_err(|_| {
                        AuthorityError::InvalidConfig(
                            "signing key descriptor is invalid".to_string(),
                        )
                    })?);
                }
                _ => {
                    return Err(AuthorityError::InvalidConfig(
                        "accepted arguments are --config and --signing-key-fd".to_string(),
                    ))
                }
            }
        }
        Ok(Self {
            config_path: config_path
                .ok_or_else(|| AuthorityError::InvalidConfig("--config is required".to_string()))?,
            signing_key_fd: signing_key_fd.ok_or_else(|| {
                AuthorityError::InvalidConfig("--signing-key-fd is required".to_string())
            })?,
        })
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse()?;
    harden_process_custody().map_err(|error| AuthorityError::Custody(error.to_string()))?;
    let config = load_runtime_config(&arguments.config_path)?;
    // SAFETY: daemon launch transfers exclusive ownership of this descriptor.
    #[allow(unsafe_code)]
    let signing_key =
        unsafe { InheritedSecretFile::adopt(arguments.signing_key_fd, "authority signing key") }
            .map_err(|error| AuthorityError::Custody(error.to_string()))?;
    AuthorityDaemonRuntime::build(config, signing_key)?.serve()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
