//! Workspace task runner.
//!
//! Subcommands so far:
//!
//! ```text
//! cargo xtask trajectory regen-manifest
//! cargo xtask trajectory regen-manifest --check
//! cargo xtask validate-scenarios
//! cargo xtask freeze-vectors
//! cargo xtask freeze-vectors --check
//! ```
//!
//! `trajectory regen-manifest` walks `.planning/trajectory/tickets/M*/P*.yml`,
//! concatenates the per-phase ticket arrays, sorts by id, and writes the
//! result to `.planning/trajectory/tickets/manifest.yml` with the canonical
//! header. With `--check` it exits non-zero on drift instead of writing.
//!
//! `validate-scenarios` walks `tests/conformance/scenarios/**/*.json`, looks
//! up each scenario's declared `$schema` URI (resolved against the
//! `https://chio-protocol.dev/schemas/` prefix to a path under
//! `spec/schemas/`), and validates the scenario via `chio-spec-validate`.
//! Scenarios without a `$schema` field are skipped (so that legacy
//! conformance descriptors continue to load). Prints a per-scenario
//! `PASS|FAIL|SKIP` line and exits non-zero on any FAIL. If the scenarios
//! directory is missing or contains no JSON files, it prints `no scenarios
//! found` and exits 0.
//!
//! `freeze-vectors` walks `tests/bindings/vectors/**/*.json`, computes a
//! sha256 digest per file, and writes
//! `tests/bindings/vectors/MANIFEST.sha256` with one
//! `<sha256>  <relative-path>` line per file (sorted by path, lower-case hex,
//! two-space separator, trailing newline). The format mirrors
//! `shasum -a 256` so the manifest can be verified with that tool. With
//! `--check` it compares the computed manifest against the on-disk file and
//! exits non-zero on drift; CI uses this mode to catch unfrozen vectors.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::de::Error as _;
use serde_yml::Value;
use sha2::{Digest, Sha256};

const MANIFEST_HEADER: &str = "\
# GENERATED from per-phase files under .planning/trajectory/tickets/M{nn}/P{n}.yml
# Do not hand-edit. Regenerate with `cargo xtask trajectory regen-manifest`.
# CI validates manifest.yml against schema.json on every PR.
#
# The per-phase files under tickets/M{nn}/P{n}.yml are the source of truth.
# This manifest is a flat, id-sorted concatenation. Empty manifest is the
# Wave-0 seed state until the Wave 1a phase tickets are authored.
";

#[derive(Debug)]
enum XtaskError {
    Usage(String),
    Io(String, std::io::Error),
    Yaml(String, serde_yml::Error),
    Json(String, serde_json::Error),
    Drift(String),
    Validation(String),
}

impl fmt::Display for XtaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "usage: {msg}"),
            Self::Io(path, err) => write!(f, "io error on {path}: {err}"),
            Self::Yaml(path, err) => write!(f, "yaml error in {path}: {err}"),
            Self::Json(path, err) => write!(f, "json error in {path}: {err}"),
            Self::Drift(detail) => write!(f, "manifest drift: {detail}"),
            Self::Validation(detail) => write!(f, "scenario validation failed: {detail}"),
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "trajectory" => run_trajectory(args.collect()),
        "validate-scenarios" => validate_scenarios(args.collect()),
        "freeze-vectors" => freeze_vectors(args.collect()),
        "" | "help" | "--help" | "-h" => {
            print_help();
            return ExitCode::SUCCESS;
        }
        other => Err(XtaskError::Usage(format!("unknown subcommand: {other}"))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("xtask subcommands:");
    println!("  trajectory regen-manifest [--check]");
    println!("  validate-scenarios");
    println!("  freeze-vectors [--check]");
}

fn run_trajectory(args: Vec<String>) -> Result<(), XtaskError> {
    let mut iter = args.into_iter();
    let sub = iter
        .next()
        .ok_or_else(|| XtaskError::Usage("trajectory <subcommand>".into()))?;
    match sub.as_str() {
        "regen-manifest" => regen_manifest(iter.collect()),
        other => Err(XtaskError::Usage(format!(
            "unknown trajectory subcommand: {other}"
        ))),
    }
}

fn regen_manifest(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "regen-manifest: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let tickets_dir = workspace_root.join(".planning/trajectory/tickets");
    let manifest_path = tickets_dir.join("manifest.yml");

    let mut tickets: Vec<Value> = Vec::new();
    let phase_files = collect_phase_files(&tickets_dir)?;
    for path in &phase_files {
        let raw =
            fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        if raw.trim().is_empty() {
            continue;
        }
        let parsed: Value =
            serde_yml::from_str(&raw).map_err(|err| XtaskError::Yaml(display_path(path), err))?;
        match parsed {
            Value::Sequence(seq) => tickets.extend(seq),
            Value::Null => continue,
            _ => {
                return Err(XtaskError::Yaml(
                    display_path(path),
                    serde_yml::Error::custom(format!(
                        "{}: expected a YAML sequence at the top level",
                        display_path(path)
                    )),
                ));
            }
        }
    }

    tickets.sort_by_key(ticket_id);

    let body = if tickets.is_empty() {
        "[]\n".to_string()
    } else {
        serde_yml::to_string(&Value::Sequence(tickets))
            .map_err(|err| XtaskError::Yaml(display_path(&manifest_path), err))?
    };
    let new_content = format!("{MANIFEST_HEADER}\n{body}");

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        if existing != new_content {
            return Err(XtaskError::Drift(format!(
                "manifest.yml is stale; rerun `cargo xtask trajectory regen-manifest` ({} phase files inspected)",
                phase_files.len()
            )));
        }
        println!(
            "manifest.yml in sync with {} phase files",
            phase_files.len()
        );
    } else {
        fs::write(&manifest_path, new_content)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        println!(
            "wrote {} ({} phase files; {} ticket entries)",
            display_path(&manifest_path),
            phase_files.len(),
            // Recompute count for the message.
            count_top_level_sequence_entries(&manifest_path).unwrap_or(0)
        );
    }
    Ok(())
}

fn collect_phase_files(tickets_dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out: Vec<PathBuf> = Vec::new();
    let entries = match fs::read_dir(tickets_dir) {
        Ok(it) => it,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(err) => return Err(XtaskError::Io(display_path(tickets_dir), err)),
    };
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(tickets_dir), err))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if !is_milestone_dir(name) || !path.is_dir() {
            continue;
        }
        let phase_entries =
            fs::read_dir(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let mut phase_files: Vec<PathBuf> = Vec::new();
        for phase_entry in phase_entries {
            let phase_entry =
                phase_entry.map_err(|err| XtaskError::Io(display_path(&path), err))?;
            let phase_path = phase_entry.path();
            let Some(phase_name) = phase_path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if is_phase_file(phase_name) {
                phase_files.push(phase_path);
            }
        }
        phase_files.sort();
        out.extend(phase_files);
    }
    out.sort();
    Ok(out)
}

fn is_milestone_dir(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 3 && bytes[0] == b'M' && bytes[1].is_ascii_digit() && bytes[2].is_ascii_digit()
}

fn is_phase_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".yml") else {
        return false;
    };
    if !stem.starts_with('P') {
        return false;
    }
    let rest = &stem[1..];
    if rest.is_empty() {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn ticket_id(value: &Value) -> String {
    match value {
        Value::Mapping(map) => map
            .get(Value::String("id".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn count_top_level_sequence_entries(path: &Path) -> Result<usize, XtaskError> {
    let raw = fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    let value: Value =
        serde_yml::from_str(&raw).map_err(|err| XtaskError::Yaml(display_path(path), err))?;
    match value {
        Value::Sequence(seq) => Ok(seq.len()),
        Value::Null => Ok(0),
        _ => Ok(0),
    }
}

const SCHEMA_URI_PREFIX: &str = "https://chio-protocol.dev/schemas/";

fn validate_scenarios(args: Vec<String>) -> Result<(), XtaskError> {
    if let Some(arg) = args.into_iter().next() {
        return Err(XtaskError::Usage(format!(
            "validate-scenarios: unexpected argument: {arg}"
        )));
    }

    let workspace_root = workspace_root()?;
    let scenarios_dir = workspace_root.join("tests/conformance/scenarios");
    let schemas_root = workspace_root.join("spec/schemas");

    let scenarios = collect_scenario_files(&scenarios_dir)?;
    if scenarios.is_empty() {
        println!("no scenarios found under {}", display_path(&scenarios_dir));
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();
    let mut pass_count: usize = 0;
    let mut skip_count: usize = 0;
    for scenario in &scenarios {
        let raw = fs::read_to_string(scenario)
            .map_err(|err| XtaskError::Io(display_path(scenario), err))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|err| XtaskError::Json(display_path(scenario), err))?;
        let schema_uri = value
            .as_object()
            .and_then(|obj| obj.get("$schema"))
            .and_then(|v| v.as_str());
        let Some(uri) = schema_uri else {
            println!("SKIP {} (no $schema field)", display_path(scenario));
            skip_count += 1;
            continue;
        };
        let Some(rel) = uri.strip_prefix(SCHEMA_URI_PREFIX) else {
            println!(
                "SKIP {} (unrecognized $schema URI: {})",
                display_path(scenario),
                uri
            );
            skip_count += 1;
            continue;
        };
        let schema_path = schemas_root.join(rel);
        match chio_spec_validate::validate(&schema_path, scenario) {
            Ok(()) => {
                println!("PASS {}", display_path(scenario));
                pass_count += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", display_path(scenario));
                failures.push(display_path(scenario));
            }
        }
    }

    println!(
        "validate-scenarios: {} pass, {} fail, {} skip ({} scenarios inspected)",
        pass_count,
        failures.len(),
        skip_count,
        scenarios.len()
    );

    if failures.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Validation(format!(
            "{} scenarios failed: {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

fn collect_scenario_files(scenarios_dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out: Vec<PathBuf> = Vec::new();
    if !scenarios_dir.exists() {
        return Ok(out);
    }
    walk_json(scenarios_dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext.eq_ignore_ascii_case("json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

const VECTORS_DIR: &str = "tests/bindings/vectors";
const VECTORS_MANIFEST: &str = "tests/bindings/vectors/MANIFEST.sha256";

fn freeze_vectors(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "freeze-vectors: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let vectors_dir = workspace_root.join(VECTORS_DIR);
    let manifest_path = workspace_root.join(VECTORS_MANIFEST);

    let mut json_files: Vec<PathBuf> = Vec::new();
    if vectors_dir.exists() {
        walk_json(&vectors_dir, &mut json_files)?;
    }
    json_files.sort();

    // Build (relative-path, sha256-hex) pairs sorted by relative path.
    let mut entries: Vec<(String, String)> = Vec::with_capacity(json_files.len());
    for path in &json_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "freeze-vectors: vector file {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hex = digest_to_hex(&digest);
        entries.push((rel_str, hex));
    }
    // Sort lexicographically by relative path; tuples compare by `.0` first.
    entries.sort();

    // Format mirrors `shasum -a 256`: "<hex>  <path>\n" per file (including
    // a trailing newline after the last entry).
    let mut new_content = String::with_capacity(entries.len() * 96);
    for (rel_str, hex) in &entries {
        new_content.push_str(hex);
        new_content.push_str("  ");
        new_content.push_str(rel_str);
        new_content.push('\n');
    }

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        if existing != new_content {
            let drift = describe_manifest_drift(&existing, &new_content);
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask freeze-vectors` ({} vector files inspected)\n{}",
                display_path(&manifest_path),
                entries.len(),
                drift
            )));
        }
        println!(
            "{} in sync with {} vector files",
            display_path(&manifest_path),
            entries.len()
        );
    } else {
        fs::write(&manifest_path, &new_content)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        println!(
            "wrote {} ({} vector files)",
            display_path(&manifest_path),
            entries.len()
        );
    }
    Ok(())
}

fn digest_to_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Lower-case hex, two chars per byte, matches `shasum -a 256` output.
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

fn describe_manifest_drift(existing: &str, computed: &str) -> String {
    let existing_lines: Vec<&str> = existing.lines().collect();
    let computed_lines: Vec<&str> = computed.lines().collect();
    let mut diff = String::new();
    let mut shown = 0usize;
    let limit = 8usize;
    let max_len = existing_lines.len().max(computed_lines.len());
    for idx in 0..max_len {
        let lhs = existing_lines.get(idx).copied().unwrap_or("");
        let rhs = computed_lines.get(idx).copied().unwrap_or("");
        if lhs != rhs {
            if shown < limit {
                diff.push_str(&format!("  - on-disk: {lhs}\n"));
                diff.push_str(&format!("  + computed: {rhs}\n"));
            }
            shown += 1;
        }
    }
    if shown == 0 {
        // Bytes differ but no per-line difference (e.g. trailing newline).
        format!(
            "  on-disk bytes ({}) != computed bytes ({})",
            existing.len(),
            computed.len()
        )
    } else if shown > limit {
        format!("{diff}  ... ({} more differing lines)", shown - limit)
    } else {
        diff
    }
}

fn workspace_root() -> Result<PathBuf, XtaskError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut here = PathBuf::from(manifest_dir);
    if !here.pop() {
        return Err(XtaskError::Usage(format!(
            "could not derive workspace root from CARGO_MANIFEST_DIR={manifest_dir}"
        )));
    }
    Ok(here)
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
