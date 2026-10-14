#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use chio_conformance::{default_run_options, run_conformance_harness, unique_run_dir};
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

fn scenario_statuses(path: &Path) -> BTreeMap<String, String> {
    let results: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read peer results"))
            .expect("decode peer results");
    let mut statuses = BTreeMap::new();
    for result in results {
        let id = result["scenarioId"]
            .as_str()
            .expect("scenario id")
            .to_owned();
        let status = result["status"]
            .as_str()
            .expect("scenario status")
            .to_owned();
        assert!(
            statuses.insert(id.clone(), status).is_none(),
            "duplicate result for {id}"
        );
    }
    statuses
}

#[test]
fn notifications_harness_runs_against_live_js_and_python_peers() {
    if !command_available("node") || !python3_supports_chio_sdk() {
        return;
    }

    let mut options = default_run_options();
    options.scenarios_dir = options
        .repo_root
        .join("tests/conformance/scenarios/notifications");
    let run_dir = unique_run_dir("chio-conformance-notifications");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/notifications.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    assert!(report.contains("## MCP Core"));

    let expected: BTreeMap<String, String> = [
        ("catalog-list-changed-notifications", "pass"),
        ("hosted-replay-across-restart", "unsupported"),
        ("hosted-subscription-across-restart", "unsupported"),
        ("resources-subscribe-updated-notification", "pass"),
    ]
    .into_iter()
    .map(|(scenario, status)| (scenario.to_owned(), status.to_owned()))
    .collect();
    for peer in ["js-remote-http.json", "python-remote-http.json"] {
        assert_eq!(
            scenario_statuses(&summary.results_dir.join(peer)),
            expected,
            "{peer}"
        );
    }
    for scenario in expected.keys() {
        assert!(report.contains(&format!("`{scenario}`")), "{scenario}");
    }
}
