//! Privileged repository endpoint; provider credentials never reach its child.
#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
fn run() -> chio_secret_broker::Result<()> {
    use chio_secret_broker::{
        repository_adapter::{RepositoryHttpsConfig, RepositoryHttpsServer},
        BrokerError,
    };
    chio_secret_broker::daemon_runtime::harden_broker_process_custody()?;
    let mut args = std::env::args_os().skip(1);
    let invalid = || BrokerError::InvalidRequest("expected --config PATH".into());
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(invalid());
    }
    let path = args.next().ok_or_else(invalid)?;
    if args.next().is_some() {
        return Err(invalid());
    }
    RepositoryHttpsServer::bind(RepositoryHttpsConfig::load(std::path::Path::new(&path))?)?.serve()
}
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-repository-adapter: {}", error.diagnostic_code());
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("chio-repository-adapter: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
