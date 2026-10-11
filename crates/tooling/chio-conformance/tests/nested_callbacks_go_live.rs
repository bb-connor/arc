#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Stdio};

use chio_conformance::{default_run_options, run_conformance_harness, unique_run_dir, PeerTarget};
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

fn python3_supports_chio_sdk() -> bool {
    let Ok(output) = Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let mut parts = version.trim().split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (3, 11)
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
fn nested_callbacks_harness_runs_against_live_go_peer() {
    if !command_available("go") || !python3_supports_chio_sdk() {
        return;
    }

    let mut options = default_run_options();
    options.peers = vec![PeerTarget::Go];
    options.scenarios_dir = options
        .repo_root
        .join("tests/conformance/scenarios/nested_callbacks");
    let run_dir = unique_run_dir("chio-conformance-nested-callbacks-go");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/nested-callbacks-go-live.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let go_results = std::fs::read_to_string(summary.results_dir.join("go-remote-http.json"))
        .expect("go results");

    assert!(report.contains("## MCP Core"));
    assert!(report.contains("`nested-sampling-create-message`"));
    assert!(report.contains("`nested-elicitation-form-create`"));
    assert!(report.contains("`nested-elicitation-url-create`"));
    assert!(report.contains("`nested-roots-list`"));
    assert!(scenario_passed(
        &go_results,
        "nested-sampling-create-message"
    ));
    assert!(scenario_passed(
        &go_results,
        "nested-elicitation-form-create"
    ));
    assert!(scenario_passed(
        &go_results,
        "nested-elicitation-url-create"
    ));
    assert!(scenario_passed(&go_results, "nested-roots-list"));
}
