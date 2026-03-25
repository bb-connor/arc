#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use pact_conformance::{
    default_run_options, run_conformance_harness, unique_run_dir, ConformanceAuthMode, PeerTarget,
};
use serde_json::Value;

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

fn scenario_passed(results_json: &str, scenario_id: &str) -> bool {
    let Ok(results) = serde_json::from_str::<Vec<Value>>(results_json) else {
        return false;
    };
    results.iter().any(|result| {
        result["scenarioId"].as_str() == Some(scenario_id)
            && result["status"].as_str() == Some("pass")
    })
}

#[test]
fn wave3_auth_harness_runs_against_live_go_peer() {
    if !command_available("go") || !command_available("python3") {
        return;
    }

    let mut options = default_run_options();
    ensure_pact_binary(&options.repo_root);
    options.peers = vec![PeerTarget::Go];
    options.auth_mode = ConformanceAuthMode::LocalOAuth;
    options.scenarios_dir = options.repo_root.join("tests/conformance/scenarios/wave3");
    let run_dir = unique_run_dir("pact-conformance-wave3-go");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/wave3-go-live.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let go_results = std::fs::read_to_string(summary.results_dir.join("go-remote-http.json"))
        .expect("go results");

    assert!(report.contains("## MCP Core"));
    assert!(report.contains("`auth-unauthorized-challenge`"));
    assert!(report.contains("`auth-token-exchange-initialize`"));
    assert!(scenario_passed(&go_results, "auth-unauthorized-challenge"));
    assert!(scenario_passed(
        &go_results,
        "auth-protected-resource-metadata"
    ));
    assert!(scenario_passed(
        &go_results,
        "auth-authorization-server-metadata"
    ));
    assert!(scenario_passed(&go_results, "auth-code-initialize"));
    assert!(scenario_passed(
        &go_results,
        "auth-token-exchange-initialize"
    ));
}
