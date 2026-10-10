#![cfg(all(feature = "worker-server", unix))]

#[path = "../examples/polyglot_support/mod.rs"]
mod polyglot_support;
mod support;

#[test]
fn python_and_javascript_recover_after_host_process_death() -> support::Result {
    polyglot_support::run_demo(&std::env::current_exe()?, true)
}

#[test]
fn polyglot_host_phase() -> support::Result {
    if let Ok(phase) = std::env::var(polyglot_support::PHASE) {
        let directory = std::path::PathBuf::from(std::env::var(polyglot_support::DIRECTORY)?);
        return tokio::runtime::Runtime::new()?
            .block_on(polyglot_support::run_phase(&directory, phase == "first"));
    }
    Ok(())
}
