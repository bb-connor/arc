#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;
#[path = "mcp_core_cpp_live/public_diagnostics.rs"]
mod public_diagnostics;

use chio_conformance::{run_conformance_harness, ConformanceAuthMode};

#[test]
fn mcp_core_harness_runs_against_live_cpp_peer() {
    if common::skip_cpp_live_conformance_unless_enabled() {
        return;
    }

    if !common::command_available("cmake") || !common::python3_supports_chio_sdk() {
        return;
    }

    let options = common::cpp_options("mcp_core", ConformanceAuthMode::StaticBearer);
    eprintln!("C++ MCP core results: {}", options.results_dir.display());
    eprintln!(
        "C++ MCP core logs: {}",
        options.results_dir.join("artifacts/logs").display()
    );
    let summary = run_conformance_harness(&options).expect("run conformance harness");
    let report = std::fs::read_to_string(&summary.report_output).expect("read report");
    let cpp_results = std::fs::read_to_string(summary.results_dir.join("cpp-remote-http.json"))
        .expect("cpp results");
    let failures = public_diagnostics::failed_scenario_details(&cpp_results);
    std::fs::write(
        summary.results_dir.join("cpp-failed-scenarios-public.json"),
        serde_json::to_vec_pretty(&failures).expect("serialize public diagnostics"),
    )
    .expect("write public diagnostics");
    let diagnostic = format!(
        "failed scenarios: {failures}; retained results: {}; logs: {}",
        summary.results_dir.display(),
        summary.results_dir.join("artifacts/logs").display(),
    );

    assert!(report.contains("## MCP Core"));
    assert!(
        common::scenario_passed(&cpp_results, "initialize"),
        "{diagnostic}"
    );
    assert!(
        common::scenario_passed(&cpp_results, "tools-list"),
        "{diagnostic}"
    );
    assert!(
        common::scenario_passed(&cpp_results, "tools-call-simple-text"),
        "{diagnostic}"
    );
    assert!(
        common::scenario_passed(&cpp_results, "resources-list"),
        "{diagnostic}"
    );
    assert!(
        common::scenario_passed(&cpp_results, "prompts-list"),
        "{diagnostic}"
    );
}
