//! Hosted execution is available only on its qualified Linux platform.
use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod hosted_worker;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        hosted_worker::main()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("chio-finding-worker requires Linux");
        ExitCode::from(2)
    }
}
