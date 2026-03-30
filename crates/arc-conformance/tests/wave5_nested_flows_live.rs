#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use arc_conformance::{default_run_options, run_conformance_harness, unique_run_dir};

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn ensure_arc_binary(repo_root: &PathBuf) {
    let arc_binary = repo_root.join("target/debug/arc");
    if arc_binary.exists() {
        return;
    }

    let arc_binary = repo_root.join("target/debug/arc");
    if arc_binary.exists() {
        return;
    }

    let status = Command::new("cargo")
        .current_dir(repo_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("arc-cli")
        .status()
        .expect("build arc-cli");
    assert!(status.success(), "cargo build -p arc-cli must succeed");
}

#[test]
fn wave5_nested_flow_harness_runs_against_live_js_and_python_peers() {
    if !command_available("node") || !command_available("python3") {
        return;
    }

    let mut options = default_run_options();
    ensure_arc_binary(&options.repo_root);
    options.scenarios_dir = options.repo_root.join("tests/conformance/scenarios/wave5");
    let run_dir = unique_run_dir("arc-conformance-wave5-nested-flows");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/wave5-nested-flows.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let js_results = std::fs::read_to_string(summary.results_dir.join("js-remote-http.json"))
        .expect("js results");
    let python_results =
        std::fs::read_to_string(summary.results_dir.join("python-remote-http.json"))
            .expect("python results");

    assert!(report.contains("## MCP Core"));
    assert!(report.contains("`nested-sampling-create-message`"));
    assert!(report.contains("`nested-elicitation-form-create`"));
    assert!(report.contains("`nested-elicitation-url-create`"));
    assert!(report.contains("`nested-roots-list`"));
    assert!(report.contains("8/8 pass"));
    assert!(js_results.contains("\"scenarioId\": \"nested-sampling-create-message\""));
    assert!(js_results.contains("\"scenarioId\": \"nested-elicitation-form-create\""));
    assert!(js_results.contains("\"scenarioId\": \"nested-elicitation-url-create\""));
    assert!(js_results.contains("\"scenarioId\": \"nested-roots-list\""));
    assert!(python_results.contains("\"scenarioId\": \"nested-sampling-create-message\""));
    assert!(python_results.contains("\"scenarioId\": \"nested-elicitation-form-create\""));
    assert!(python_results.contains("\"scenarioId\": \"nested-elicitation-url-create\""));
    assert!(python_results.contains("\"scenarioId\": \"nested-roots-list\""));
    assert!(python_results.contains("\"status\": \"pass\""));
}
