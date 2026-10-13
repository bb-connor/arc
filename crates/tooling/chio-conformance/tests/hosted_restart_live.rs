#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_conformance::{default_run_options, run_conformance_harness, unique_run_dir};
use serde_json::Value;

fn scenario_passed(results_json: &str, scenario_id: &str) -> bool {
    serde_json::from_str::<Vec<Value>>(results_json).is_ok_and(|results| {
        results.iter().any(|result| {
            result["scenarioId"].as_str() == Some(scenario_id)
                && result["status"].as_str() == Some("pass")
        })
    })
}

#[test]
fn hosted_sessions_survive_a_server_restart() {
    if std::env::var_os("CHIO_CAGE_INIT").is_none() {
        eprintln!(
            "skipping hosted restart conformance; it needs a qualified enforcing host (CHIO_CAGE_INIT)"
        );
        return;
    }

    let mut options = default_run_options();
    options.peers = Vec::new();
    options.restart_probe = true;
    options.scenarios_dir = options
        .repo_root
        .join("tests/conformance/scenarios/notifications");
    let run_dir = unique_run_dir("chio-conformance-hosted-restart");
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join("reports/hosted-restart-live.md");

    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let results = std::fs::read_to_string(
        summary
            .results_dir
            .join("chio-restart-probe-remote-http.json"),
    )
    .expect("restart probe results");
    for scenario in [
        "hosted-subscription-across-restart",
        "hosted-replay-across-restart",
    ] {
        assert!(
            scenario_passed(&results, scenario),
            "restart probe must pass `{scenario}`; results: {results}"
        );
    }
}
