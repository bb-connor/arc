//! Hosted execution is available only on its qualified Linux platform.
use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod hosted_canary;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        hosted_canary::main()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("chio-finding-market-canary requires Linux");
        ExitCode::from(2)
    }
}
