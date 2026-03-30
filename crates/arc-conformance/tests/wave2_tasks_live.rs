#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use arc_conformance::{default_run_options, run_conformance_harness, unique_run_dir};
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
fn wave2_task_harness_runs_against_live_js_and_python_peers() {
    if !command_available("node") || !command_available("python3") {
        return;
    }

    let mut options = default_run_options();
    ensure_arc_binary(&options.repo_root);
    options.scenarios_dir = options.repo_root.join("tests/conformance/scenarios/wave2");
    let run_dir = unique_run_dir("arc-conformance-wave2-tasks");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/wave2-tasks.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let js_results = std::fs::read_to_string(summary.results_dir.join("js-remote-http.json"))
        .expect("js results");
    let python_results =
        std::fs::read_to_string(summary.results_dir.join("python-remote-http.json"))
            .expect("python results");

    assert!(report.contains("## MCP Experimental"));
    assert!(report.contains("`tasks-call-get-result`"));
    assert!(report.contains("`tasks-cancel`"));
    assert!(!report.contains("xfail"));
    assert!(scenario_passed(&js_results, "tasks-call-get-result"));
    assert!(scenario_passed(&js_results, "tasks-cancel"));
    assert!(scenario_passed(&python_results, "tasks-call-get-result"));
    assert!(scenario_passed(&python_results, "tasks-cancel"));
}
