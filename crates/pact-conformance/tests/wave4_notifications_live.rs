#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use pact_conformance::{default_run_options, run_conformance_harness, unique_run_dir};

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn ensure_pact_binary(repo_root: &PathBuf) {
    let pact_binary = repo_root.join("target/debug/pact");
    if pact_binary.exists() {
        return;
    }

    let status = Command::new("cargo")
        .current_dir(repo_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("pact-cli")
        .status()
        .expect("build pact-cli");
    assert!(status.success(), "cargo build -p pact-cli must succeed");
}

#[test]
fn wave4_notification_harness_runs_against_live_js_and_python_peers() {
    if !command_available("node") || !command_available("python3") {
        return;
    }

    let mut options = default_run_options();
    ensure_pact_binary(&options.repo_root);
    options.scenarios_dir = options.repo_root.join("tests/conformance/scenarios/wave4");
    let run_dir = unique_run_dir("pact-conformance-wave4-notifications");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/wave4-notifications.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let js_results = std::fs::read_to_string(summary.results_dir.join("js-remote-http.json"))
        .expect("js results");
    let python_results =
        std::fs::read_to_string(summary.results_dir.join("python-remote-http.json"))
            .expect("python results");

    assert!(report.contains("## MCP Core"));
    assert!(report.contains("`resources-subscribe-updated-notification`"));
    assert!(report.contains("`catalog-list-changed-notifications`"));
    assert!(report.contains("4/4 pass"));
    assert!(js_results.contains("\"scenarioId\": \"resources-subscribe-updated-notification\""));
    assert!(js_results.contains("\"scenarioId\": \"catalog-list-changed-notifications\""));
    assert!(python_results.contains("\"scenarioId\": \"resources-subscribe-updated-notification\""));
    assert!(python_results.contains("\"scenarioId\": \"catalog-list-changed-notifications\""));
    assert!(python_results.contains("\"status\": \"pass\""));
}
