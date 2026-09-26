//! One brokered MCP invocation over the host's inherited socket at slot 8.
#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
fn run() -> chio_secret_broker::Result<()> {
    use chio_core_types::PublicKey;
    use chio_secret_broker::inherited_fd::adopt_prepared_broker_stream;
    use chio_secret_broker::prepared_mcp::{serve_prepared_broker_mcp, PreparedBrokerMcpConfig};
    use chio_secret_broker::BrokerError;

    let invalid = || BrokerError::InvalidRequest("invalid prepared MCP configuration".into());
    let mut args = std::env::args_os().skip(1);
    let mut tenant = None;
    let mut tool = None;
    let mut signer = None;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(invalid)?
            .into_string()
            .map_err(|_| invalid())?;
        match flag.to_str() {
            Some("--tenant-scope") if tenant.is_none() => tenant = Some(value),
            Some("--tool-name") if tool.is_none() => tool = Some(value),
            Some("--receipt-signer") if signer.is_none() => signer = Some(value),
            _ => return Err(invalid()),
        }
    }
    let config = PreparedBrokerMcpConfig::new(
        tenant.ok_or_else(invalid)?,
        tool.ok_or_else(invalid)?,
        PublicKey::from_hex(&signer.ok_or_else(invalid)?).map_err(|_| invalid())?,
    )?;
    // SAFETY: the native cage launch transfers broker slot 8 exclusively to
    // this executable. No code above opens, adopts or replaces descriptors.
    #[allow(unsafe_code)]
    let broker = unsafe { adopt_prepared_broker_stream() }?;
    serve_prepared_broker_mcp(
        config,
        broker,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-broker-mcp failed closed: {}", error.diagnostic_code());
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("chio-broker-mcp failed closed: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
