// Conformance subcommand handlers for the `chio` CLI.
//
// This file is included into `main.rs` via `include!` and reuses the
// shared `use` declarations from `cli/types.rs`. Only the `Run` variant
// is implemented in M01.P4.T2; `fetch-peers` lands in M01.P4.T4.

/// Dispatch entry-point for `chio conformance run`.
///
/// Builds default `ConformanceRunOptions`, applies the `--peer` selector,
/// invokes the harness, then emits a summary in either human or JSON shape.
/// The artifact files written under `tests/conformance/results/generated/`
/// already match the on-disk format consumed by `tests/conformance/reports/`;
/// the JSON report emitted here is the same shape as the `peer_result_files`
/// pointers plus a small envelope describing the run.
fn cmd_conformance_run(
    peer: &str,
    report: Option<&str>,
    scenario: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let mut options = chio_conformance::default_run_options();
    options.peers = parse_peer_selection(peer)?;

    let summary = chio_conformance::run_conformance_harness(&options).map_err(|error| {
        CliError::Other(format!("conformance harness failed: {error}"))
    })?;

    let json_report = matches!(report, Some(value) if value.eq_ignore_ascii_case("json"));
    if let Some(value) = report {
        if !json_report && !value.eq_ignore_ascii_case("human") {
            return Err(CliError::Other(format!(
                "unsupported --report value `{value}`; expected `json` or `human`",
            )));
        }
    }

    let scenarios = chio_conformance::load_scenarios_from_dir(&options.scenarios_dir).map_err(
        |error| CliError::Other(format!("failed to load scenarios: {error}")),
    )?;
    let mut results = chio_conformance::load_results_from_dir(&summary.results_dir).map_err(
        |error| CliError::Other(format!("failed to load peer results: {error}")),
    )?;
    if let Some(filter) = scenario {
        results.retain(|result| result.scenario_id == filter);
    }

    if json_report {
        write_json_report(&summary, &scenarios, &results, scenario, output)
    } else {
        write_human_report(&summary, &results, scenario, output)
    }
}

fn parse_peer_selection(peer: &str) -> Result<Vec<chio_conformance::PeerTarget>, CliError> {
    match peer {
        "all" => Ok(vec![
            chio_conformance::PeerTarget::Js,
            chio_conformance::PeerTarget::Python,
            chio_conformance::PeerTarget::Go,
            chio_conformance::PeerTarget::Cpp,
        ]),
        "js" => Ok(vec![chio_conformance::PeerTarget::Js]),
        "python" => Ok(vec![chio_conformance::PeerTarget::Python]),
        "go" => Ok(vec![chio_conformance::PeerTarget::Go]),
        "cpp" => Ok(vec![chio_conformance::PeerTarget::Cpp]),
        other => Err(CliError::Other(format!(
            "unsupported --peer value `{other}`; expected one of js, python, go, cpp, all",
        ))),
    }
}

fn write_json_report(
    summary: &chio_conformance::ConformanceRunSummary,
    scenarios: &[chio_conformance::ScenarioDescriptor],
    results: &[chio_conformance::ScenarioResult],
    scenario_filter: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let envelope = serde_json::json!({
        "schemaVersion": "chio-conformance-run/v1",
        "listen": summary.listen.to_string(),
        "resultsDir": summary.results_dir.display().to_string(),
        "reportOutput": summary.report_output.display().to_string(),
        "peerResultFiles": summary
            .peer_result_files
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>(),
        "scenarioFilter": scenario_filter,
        "scenarioCount": scenarios.len(),
        "results": results,
    });

    let rendered = serde_json::to_string_pretty(&envelope).map_err(|error| {
        CliError::Other(format!("failed to serialise conformance report: {error}"))
    })?;

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::Other(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &rendered).map_err(|error| {
            CliError::Other(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{rendered}").map_err(|error| {
            CliError::Other(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}

fn write_human_report(
    summary: &chio_conformance::ConformanceRunSummary,
    results: &[chio_conformance::ScenarioResult],
    scenario_filter: Option<&str>,
    output: Option<&Path>,
) -> Result<(), CliError> {
    let mut buffer = String::new();
    buffer.push_str(&format!("listen: {}\n", summary.listen));
    buffer.push_str(&format!(
        "results: {}\n",
        summary.results_dir.display()
    ));
    buffer.push_str(&format!(
        "report:  {}\n",
        summary.report_output.display()
    ));
    for peer_result in &summary.peer_result_files {
        buffer.push_str(&format!("peer:    {}\n", peer_result.display()));
    }
    if let Some(filter) = scenario_filter {
        buffer.push_str(&format!("scenario filter: {filter}\n"));
    }
    buffer.push_str(&format!("\nscenarios reported: {}\n", results.len()));
    for result in results {
        buffer.push_str(&format!(
            "  - {} [{}] peer={} status={} duration_ms={}\n",
            result.scenario_id,
            result.category.heading(),
            result.peer,
            result.status.label(),
            result.duration_ms,
        ));
    }

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    CliError::Other(format!(
                        "failed to create report parent directory `{}`: {error}",
                        parent.display(),
                    ))
                })?;
            }
        }
        fs::write(path, &buffer).map_err(|error| {
            CliError::Other(format!(
                "failed to write report to `{}`: {error}",
                path.display(),
            ))
        })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        write!(stdout, "{buffer}").map_err(|error| {
            CliError::Other(format!("failed to write report to stdout: {error}"))
        })?;
    }
    Ok(())
}
