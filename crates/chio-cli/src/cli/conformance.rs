// Conformance subcommand handlers for the `chio` CLI.
//
// This file is included into `main.rs` via `include!` and reuses the
// shared `use` declarations from `cli/types.rs`. The `Run` variant landed
// in M01.P4.T2; the `FetchPeers` variant landed in M01.P4.T4 and downloads
// pinned peer-language adapter binaries described by
// `crates/chio-conformance/peers.lock.toml`.

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

/// Path of the canonical lockfile shipped inside the chio-conformance crate.
/// Resolved relative to the chio-cli binary's source layout so that the
/// subcommand works from a fresh checkout without extra arguments.
fn default_peers_lock_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is defined at compile time for the chio-cli crate.
    // The lockfile lives in a sibling crate.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("chio-conformance")
        .join("peers.lock.toml")
}

/// Dispatch entry-point for `chio conformance fetch-peers`.
///
/// `--check` parses and validates the lockfile only; it never touches the
/// network. Without `--check`, each entry is downloaded, sha256-verified,
/// and written under `out/`. The `language` filter, when set, restricts
/// the loop to entries matching that adapter (`python`, `js`, `go`, `cpp`).
fn cmd_conformance_fetch_peers(
    check: bool,
    out: &Path,
    language: Option<&str>,
) -> Result<(), CliError> {
    let lock_path = default_peers_lock_path();
    let lock = chio_conformance::PeersLock::load(&lock_path).map_err(|error| {
        CliError::Other(format!(
            "failed to load peers lockfile `{}`: {error}",
            lock_path.display(),
        ))
    })?;
    lock.validate().map_err(|error| {
        CliError::Other(format!("peers lockfile is invalid: {error}"))
    })?;

    if let Some(filter) = language {
        if !chio_conformance::SUPPORTED_LANGUAGES.contains(&filter) {
            return Err(CliError::Other(format!(
                "unsupported --language value `{filter}`; expected one of {:?}",
                chio_conformance::SUPPORTED_LANGUAGES,
            )));
        }
    }

    let entries: Vec<&chio_conformance::PeerEntry> = match language {
        Some(value) => lock.entries_for_language(value),
        None => lock.peers.iter().collect(),
    };

    if check {
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "peers.lock.toml: {} (schema {})",
            lock_path.display(),
            lock.schema,
        )
        .map_err(|error| {
            CliError::Other(format!("failed to write check summary: {error}"))
        })?;
        writeln!(
            stdout,
            "validated {} entries (filter: {})",
            entries.len(),
            language.unwrap_or("<none>"),
        )
        .map_err(|error| {
            CliError::Other(format!("failed to write check summary: {error}"))
        })?;
        for entry in &entries {
            writeln!(
                stdout,
                "  - {} {} -> {}",
                entry.language, entry.target, entry.url,
            )
            .map_err(|error| {
                CliError::Other(format!("failed to write check entry: {error}"))
            })?;
        }
        return Ok(());
    }

    fs::create_dir_all(out).map_err(|error| {
        CliError::Other(format!(
            "failed to create output dir `{}`: {error}",
            out.display(),
        ))
    })?;

    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|error| {
            CliError::Other(format!("failed to build http client: {error}"))
        })?;

    for entry in &entries {
        download_and_verify(&client, entry, out)?;
    }
    Ok(())
}

fn download_and_verify(
    client: &reqwest::blocking::Client,
    entry: &chio_conformance::PeerEntry,
    out: &Path,
) -> Result<(), CliError> {
    let response = client.get(&entry.url).send().map_err(|error| {
        CliError::Other(format!(
            "failed to GET `{}` ({}): {error}",
            entry.url, entry.language,
        ))
    })?;
    if !response.status().is_success() {
        return Err(CliError::Other(format!(
            "non-success status {} fetching `{}`",
            response.status(),
            entry.url,
        )));
    }
    let bytes = response.bytes().map_err(|error| {
        CliError::Other(format!(
            "failed to read body of `{}`: {error}",
            entry.url,
        ))
    })?;
    let actual = chio_conformance::sha256_hex(&bytes);
    if actual != entry.sha256 {
        return Err(CliError::Other(format!(
            "sha256 mismatch for `{}`: expected {}, got {}",
            entry.url, entry.sha256, actual,
        )));
    }

    // Derive a deterministic filename from the URL's last path segment.
    let filename = entry
        .url
        .rsplit('/')
        .next()
        .unwrap_or("peer.bin");
    let target_dir = out.join(&entry.language).join(&entry.target);
    fs::create_dir_all(&target_dir).map_err(|error| {
        CliError::Other(format!(
            "failed to create `{}`: {error}",
            target_dir.display(),
        ))
    })?;
    let target_path = target_dir.join(filename);
    fs::write(&target_path, &bytes).map_err(|error| {
        CliError::Other(format!(
            "failed to write `{}`: {error}",
            target_path.display(),
        ))
    })?;
    Ok(())
}
