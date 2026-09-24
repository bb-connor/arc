#[cfg(unix)]
mod polyglot_support;
#[cfg(unix)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(unix)]
#[tokio::main]
async fn main() -> support::Result {
    if let Ok(phase) = std::env::var(polyglot_support::PHASE) {
        let directory = std::path::PathBuf::from(std::env::var(polyglot_support::DIRECTORY)?);
        return polyglot_support::run_phase(&directory, phase == "first").await;
    }
    polyglot_support::run_demo(&std::env::current_exe()?, false)
}

#[cfg(not(unix))]
fn main() {
    eprintln!("polyglot_swarm requires Unix sockets, Python 3.11+ and Node 22+");
}
