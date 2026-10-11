//! Privileged host adapter. Its credential and Docker endpoint never enter cages.
#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
fn run() -> chio_secret_broker::Result<()> {
    use chio_secret_broker::{
        docker_adapter::server::{DockerHttpsConfig, DockerHttpsServer},
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
    DockerHttpsServer::bind(DockerHttpsConfig::load(std::path::Path::new(&path))?)?.serve()
}
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-docker-adapter: {}", error.diagnostic_code());
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("chio-docker-adapter: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
