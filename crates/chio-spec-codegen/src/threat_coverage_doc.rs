//! Generator for `docs/security/threat-coverage.md`.
//!
//! Owner: M05.P5.T5.
//!
//! Reads:
//!
//! - `spec/security/chio-threat-model.v1.json` (threats and per-ID
//!   `coverage_state`),
//! - `spec/security/coverage.yaml` (owners, closure refs, deferrals,
//!   and backing evidence),
//! - `crates/chio-adversarial-suite/manifest.json` (corpus
//!   entries with `threat_id` cross-link),
//! - `crates/chio-conformance/tests/threats/<id>.rs` (presence
//!   alone is the test-mapping evidence; the threat-coverage gate
//!   handles the unimplemented! check separately).
//!
//! Emits a markdown report grouping threats by coverage state.
//! Each `## Threat: <id>` heading lists corpus cases and the
//! escape-class fixture pointers. The M05.P5.T4 gate fails closed on
//! `partial`; the doc generator still surfaces partial IDs under a
//! separate Partial heading if a future draft introduces one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{write_if_changed, CodegenError};

/// Default docs output path.
pub const THREAT_COVERAGE_DOC: &str = "docs/security/threat-coverage.md";

/// Default coverage map path.
pub const SECURITY_COVERAGE_MAP: &str = "spec/security/coverage.yaml";

/// Default location of the adversarial-suite manifest.
pub const ADVERSARIAL_MANIFEST: &str = "crates/chio-adversarial-suite/manifest.json";

/// Default location of the threats stub directory.
pub const THREAT_STUBS_DIR: &str = "crates/chio-conformance/tests/threats";

/// Default location of the wasm-guard escape harness directory.
pub const ESCAPE_HARNESS_DIR: &str = "crates/chio-wasm-guards/tests/escape";

/// Coverage state surfaced in the generated doc.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoverageState {
    Covered,
    Partial,
    Pending,
}

impl CoverageState {
    fn parse(raw: Option<&str>, source_path: &Path) -> Result<Self, CodegenError> {
        match raw.unwrap_or("covered") {
            "covered" => Ok(Self::Covered),
            "partial" => Ok(Self::Partial),
            "pending" => Ok(Self::Pending),
            other => Err(CodegenError::Registry(
                source_path.to_path_buf(),
                format!("unknown coverage_state {other:?}"),
            )),
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::Covered => "Covered",
            Self::Partial => "Partial",
            Self::Pending => "Pending",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ThreatModelDoc {
    threats: Vec<ThreatRow>,
}

#[derive(Debug, Deserialize)]
struct ThreatRow {
    id: String,
    name: String,
    surfaces: Vec<String>,
    #[serde(default)]
    coverage_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoverageMapDoc {
    threats: Vec<CoverageMapRow>,
}

#[derive(Debug, Deserialize)]
struct CoverageMapRow {
    id: String,
    #[serde(default)]
    coverage_state: Option<String>,
    #[serde(default)]
    owned_by: Option<String>,
    #[serde(default)]
    closed_by: Option<String>,
    #[serde(default)]
    deferred_to: Option<String>,
    #[serde(default)]
    deferred_reason: Option<String>,
    #[serde(default)]
    backing_evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestDoc {
    cases: Vec<ManifestCase>,
}

#[derive(Debug, Deserialize)]
struct ManifestCase {
    id: String,
    class: String,
    expected_reason: String,
    threat_id: String,
    path: String,
}

/// Inputs the doc generator pulls together. Public so callers can
/// preview without writing to disk.
#[derive(Debug)]
pub struct ThreatCoverageInputs<'a> {
    pub threat_model_path: &'a Path,
    pub coverage_path: &'a Path,
    pub manifest_path: &'a Path,
    pub stubs_dir: &'a Path,
    pub escape_dir: &'a Path,
}

/// Render the `threat-coverage.md` body without touching the file
/// system.
pub fn render_threat_coverage_doc(
    inputs: &ThreatCoverageInputs<'_>,
) -> Result<String, CodegenError> {
    let threat_raw = fs::read_to_string(inputs.threat_model_path)
        .map_err(|err| CodegenError::Io(inputs.threat_model_path.to_path_buf(), err))?;
    let threat_doc: ThreatModelDoc = serde_json::from_str(&threat_raw)
        .map_err(|err| CodegenError::Json(inputs.threat_model_path.to_path_buf(), err))?;

    let coverage_raw = fs::read_to_string(inputs.coverage_path)
        .map_err(|err| CodegenError::Io(inputs.coverage_path.to_path_buf(), err))?;
    let coverage_doc: CoverageMapDoc = serde_yaml::from_str(&coverage_raw).map_err(|err| {
        CodegenError::Registry(
            inputs.coverage_path.to_path_buf(),
            format!("yaml parse error: {err}"),
        )
    })?;
    let coverage_by_id = validate_coverage_map(&threat_doc, &coverage_doc, inputs)?;

    let manifest_doc: ManifestDoc = if inputs.manifest_path.exists() {
        let raw = fs::read_to_string(inputs.manifest_path)
            .map_err(|err| CodegenError::Io(inputs.manifest_path.to_path_buf(), err))?;
        serde_json::from_str(&raw)
            .map_err(|err| CodegenError::Json(inputs.manifest_path.to_path_buf(), err))?
    } else {
        ManifestDoc { cases: Vec::new() }
    };

    // Index manifest cases by threat ID for O(1) lookup.
    let mut by_threat: BTreeMap<String, Vec<&ManifestCase>> = BTreeMap::new();
    for case in &manifest_doc.cases {
        by_threat
            .entry(case.threat_id.clone())
            .or_default()
            .push(case);
    }
    for cases in by_threat.values_mut() {
        cases.sort_by(|a, b| a.id.cmp(&b.id));
    }

    let mut sections: BTreeMap<CoverageState, Vec<&ThreatRow>> = BTreeMap::new();
    for threat in &threat_doc.threats {
        let state =
            CoverageState::parse(threat.coverage_state.as_deref(), inputs.threat_model_path)?;
        sections.entry(state).or_default().push(threat);
    }

    let mut body = String::new();
    body.push_str("# Chio Threat Coverage\n\n");
    body.push_str(
        "Generated by `chio-spec-codegen --threat-model-doc` (M05.P5.T5). \
         Each threat ID is grouped by coverage state and enriched from \
         `spec/security/coverage.yaml`. Re-run the generator after editing \
         `spec/security/chio-threat-model.v1.json`, \
         `spec/security/coverage.yaml`, or the \
         `crates/chio-adversarial-suite/cases/` corpus.\n\n",
    );
    body.push_str(
        "Coverage states:\n\
         - `Covered` - the threat ID has a populated test body at \
           `crates/chio-conformance/tests/threats/<id>.rs`.\n\
         - `Partial` - fail-closed state; the threat-model coverage gate \
           rejects partial coverage after M05.P4.\n\
         - `Pending` - no backing test yet; the threat-model-coverage \
         CI gate accepts the entry because it is explicitly marked \
           `pending` with a non-empty `deferred_to` in the JSON, but \
           a green test must land before the owning milestone closes.\n\n",
    );

    for state in [
        CoverageState::Covered,
        CoverageState::Partial,
        CoverageState::Pending,
    ] {
        let Some(threats) = sections.get(&state) else {
            continue;
        };
        body.push_str(&format!("# {} ({})\n\n", state.heading(), threats.len()));
        for threat in threats {
            render_threat_section(
                &mut body,
                threat,
                state,
                by_threat
                    .get(&threat.id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                coverage_by_id.get(threat.id.as_str()),
                inputs.stubs_dir,
                inputs.escape_dir,
            );
        }
    }

    Ok(body)
}

fn validate_coverage_map<'a>(
    threat_doc: &ThreatModelDoc,
    coverage_doc: &'a CoverageMapDoc,
    inputs: &ThreatCoverageInputs<'_>,
) -> Result<BTreeMap<&'a str, &'a CoverageMapRow>, CodegenError> {
    let threat_ids: BTreeSet<&str> = threat_doc.threats.iter().map(|t| t.id.as_str()).collect();
    let coverage_ids: BTreeSet<&str> = coverage_doc.threats.iter().map(|t| t.id.as_str()).collect();

    let missing: Vec<&str> = threat_ids.difference(&coverage_ids).copied().collect();
    let extra: Vec<&str> = coverage_ids.difference(&threat_ids).copied().collect();
    let mut state_drift = Vec::new();

    let mut by_id = BTreeMap::new();
    for row in &coverage_doc.threats {
        if by_id.insert(row.id.as_str(), row).is_some() {
            return Err(CodegenError::Registry(
                inputs.coverage_path.to_path_buf(),
                format!("coverage map drift: duplicate threat ID {}", row.id),
            ));
        }
    }

    for threat in &threat_doc.threats {
        let threat_state =
            CoverageState::parse(threat.coverage_state.as_deref(), inputs.threat_model_path)?;
        if let Some(row) = by_id.get(threat.id.as_str()) {
            let coverage_state =
                CoverageState::parse(row.coverage_state.as_deref(), inputs.coverage_path)?;
            if coverage_state != threat_state {
                state_drift.push(format!(
                    "{} is {:?} in threat model but {:?} in coverage.yaml",
                    threat.id, threat_state, coverage_state
                ));
            }
        }
    }

    if !missing.is_empty() || !extra.is_empty() || !state_drift.is_empty() {
        let mut parts = Vec::new();
        if !missing.is_empty() {
            parts.push(format!(
                "missing from coverage.yaml: {}",
                missing.join(", ")
            ));
        }
        if !extra.is_empty() {
            parts.push(format!("extra in coverage.yaml: {}", extra.join(", ")));
        }
        parts.extend(state_drift);
        return Err(CodegenError::Registry(
            inputs.coverage_path.to_path_buf(),
            format!("coverage map drift: {}", parts.join("; ")),
        ));
    }

    Ok(by_id)
}

fn render_threat_section(
    out: &mut String,
    threat: &ThreatRow,
    state: CoverageState,
    cases: &[&ManifestCase],
    coverage: Option<&&CoverageMapRow>,
    stubs_dir: &Path,
    escape_dir: &Path,
) {
    out.push_str(&format!("## Threat: {}\n\n", threat.id));
    out.push_str(&format!("- **Name:** {}\n", threat.name));
    out.push_str(&format!("- **State:** {}\n", state.heading()));
    out.push_str(&format!("- **Surfaces:** {}\n", threat.surfaces.join(", ")));
    if let Some(row) = coverage {
        if let Some(owner) = non_empty(row.owned_by.as_deref()) {
            out.push_str(&format!("- **Owner:** {owner}\n"));
        }
        if let Some(closed_by) = non_empty(row.closed_by.as_deref()) {
            out.push_str(&format!("- **Closed by:** {closed_by}\n"));
        }
        if let Some(deferred_to) = non_empty(row.deferred_to.as_deref()) {
            out.push_str(&format!("- **Deferred to:** `{deferred_to}`\n"));
        }
        if let Some(reason) = non_empty(row.deferred_reason.as_deref()) {
            out.push_str(&format!("- **Deferred reason:** {reason}\n"));
        }
    }

    let stub_path = stubs_dir.join(format!("{}.rs", threat.id));
    if stub_path.exists() {
        out.push_str(&format!(
            "- **Test stub:** `crates/chio-conformance/tests/threats/{}.rs`\n",
            threat.id
        ));
    } else {
        out.push_str("- **Test stub:** (not yet emitted)\n");
    }

    // Cite escape-class harness directory for runtime exhaustion threats.
    if matches!(
        threat.id.as_str(),
        "resource_exhaustion_dos" | "tool_server_escape" | "wasm_guard_resource_exhaustion"
    ) && escape_dir.exists()
    {
        out.push_str("- **Escape harness:** `crates/chio-wasm-guards/tests/escape/`\n");
    }

    if cases.is_empty() {
        out.push_str("- **Corpus cases:** (none cite this threat ID)\n\n");
    } else {
        out.push_str("- **Corpus cases:**\n");
        for case in cases {
            out.push_str(&format!(
                "  - `{}` (class `{}`, reason `{}`, path `{}`)\n",
                case.id, case.class, case.expected_reason, case.path
            ));
        }
        out.push('\n');
    }

    if let Some(row) = coverage {
        if !row.backing_evidence.is_empty() {
            out.push_str("- **Backing evidence:**\n");
            for evidence in &row.backing_evidence {
                out.push_str(&format!("  - `{evidence}`\n"));
            }
            out.push('\n');
        }
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

/// Top-level entry point: render the doc and write to `out_path`,
/// returning the rendered body.
pub fn codegen_threat_coverage_doc(
    inputs: &ThreatCoverageInputs<'_>,
    out_path: &Path,
) -> Result<String, CodegenError> {
    let body = render_threat_coverage_doc(inputs)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|err| CodegenError::Io(parent.to_path_buf(), err))?;
    }
    write_if_changed(out_path, body.as_bytes())?;
    Ok(body)
}

/// Convenience wrapper that pulls every input from its canonical
/// repository-relative path. Used by the CLI and tests.
pub fn codegen_threat_coverage_doc_default(repo_root: &Path) -> Result<PathBuf, CodegenError> {
    let inputs = ThreatCoverageInputs {
        threat_model_path: &repo_root.join(crate::THREAT_MODEL_INPUT),
        coverage_path: &repo_root.join(SECURITY_COVERAGE_MAP),
        manifest_path: &repo_root.join(ADVERSARIAL_MANIFEST),
        stubs_dir: &repo_root.join(THREAT_STUBS_DIR),
        escape_dir: &repo_root.join(ESCAPE_HARNESS_DIR),
    };
    let out_path = repo_root.join(THREAT_COVERAGE_DOC);
    codegen_threat_coverage_doc(&inputs, &out_path)?;
    Ok(out_path)
}

/// Check that the checked-in threat coverage doc is byte-for-byte fresh.
pub fn check_threat_coverage_doc_default(repo_root: &Path) -> Result<PathBuf, CodegenError> {
    let inputs = ThreatCoverageInputs {
        threat_model_path: &repo_root.join(crate::THREAT_MODEL_INPUT),
        coverage_path: &repo_root.join(SECURITY_COVERAGE_MAP),
        manifest_path: &repo_root.join(ADVERSARIAL_MANIFEST),
        stubs_dir: &repo_root.join(THREAT_STUBS_DIR),
        escape_dir: &repo_root.join(ESCAPE_HARNESS_DIR),
    };
    let out_path = repo_root.join(THREAT_COVERAGE_DOC);
    let expected = render_threat_coverage_doc(&inputs)?;
    let actual = fs::read_to_string(&out_path)
        .map_err(|err| CodegenError::Io(out_path.to_path_buf(), err))?;
    if actual != expected {
        return Err(CodegenError::Drift(
            out_path,
            "run `cargo run -p chio-spec-codegen -- --threat-model-doc --repo-root .`".to_string(),
        ));
    }
    Ok(out_path)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    #[test]
    fn coverage_state_parses_known_values() {
        assert_eq!(
            CoverageState::parse(Some("covered"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Covered
        );
        assert_eq!(
            CoverageState::parse(Some("partial"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Partial
        );
        assert_eq!(
            CoverageState::parse(Some("pending"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Pending
        );
        assert_eq!(
            CoverageState::parse(None, Path::new("threat-model.json")).unwrap(),
            CoverageState::Covered
        );
    }

    #[test]
    fn coverage_state_rejects_unknown_values() {
        let err = CoverageState::parse(Some("nonsense"), Path::new("threat-model.json"))
            .expect_err("unknown coverage_state must fail closed");
        assert!(err.to_string().contains("unknown coverage_state"));
    }

    #[test]
    fn rendered_doc_contains_six_initial_threat_headings() {
        let root = repo_root();
        let inputs = ThreatCoverageInputs {
            threat_model_path: &root.join(crate::THREAT_MODEL_INPUT),
            coverage_path: &root.join(SECURITY_COVERAGE_MAP),
            manifest_path: &root.join(ADVERSARIAL_MANIFEST),
            stubs_dir: &root.join(THREAT_STUBS_DIR),
            escape_dir: &root.join(ESCAPE_HARNESS_DIR),
        };
        let body = render_threat_coverage_doc(&inputs).expect("render");
        for tid in [
            "capability_token_theft",
            "kernel_impersonation",
            "tool_server_escape",
            "native_channel_replay",
            "resource_exhaustion_dos",
            "delegation_chain_abuse",
        ] {
            assert!(
                body.contains(&format!("## Threat: {tid}\n")),
                "rendered doc must contain heading for {tid}"
            );
        }
    }

    #[test]
    fn rendered_doc_contains_coverage_map_metadata() {
        let root = repo_root();
        let inputs = ThreatCoverageInputs {
            threat_model_path: &root.join(crate::THREAT_MODEL_INPUT),
            coverage_path: &root.join(SECURITY_COVERAGE_MAP),
            manifest_path: &root.join(ADVERSARIAL_MANIFEST),
            stubs_dir: &root.join(THREAT_STUBS_DIR),
            escape_dir: &root.join(ESCAPE_HARNESS_DIR),
        };
        let body = render_threat_coverage_doc(&inputs).expect("render");

        assert!(body.contains("## Threat: mobile_attestation_replay\n"));
        assert!(body.contains("- **Owner:** trajectory-4\n"));
        assert!(
            body.contains("- **Deferred to:** `trajectory-4.M07.real-attestation`\n"),
            "pending threats must surface coverage.yaml deferred_to"
        );
        assert!(
            body.contains("No conformance threat test exists for replayed App Attest assertions"),
            "pending threats must surface coverage.yaml deferred_reason"
        );
        assert!(
            body.contains("- **Closed by:** M05.P5.T3\n"),
            "covered threats must surface coverage.yaml closed_by"
        );
    }

    #[test]
    fn coverage_map_ids_must_match_threat_model_ids() {
        let root = repo_root();
        let tmp = tempfile::tempdir().expect("tempdir");
        let threat_model = tmp.path().join("threat-model.json");
        let coverage = tmp.path().join("coverage.yaml");
        let manifest = tmp.path().join("manifest.json");
        let stubs = tmp.path().join("stubs");
        let escape = tmp.path().join("escape");
        fs::create_dir_all(&stubs).expect("stubs dir");
        fs::write(&manifest, r#"{"cases":[]}"#).expect("manifest");
        fs::write(
            &threat_model,
            r#"{"threats":[{"id":"json_only","name":"JSON only","surfaces":["native_chio"]}]}"#,
        )
        .expect("threat model");
        fs::write(
            &coverage,
            "schema: chio.security.coverage/v1\nthreats:\n  - id: yaml_only\n    coverage_state: covered\n",
        )
        .expect("coverage");

        let inputs = ThreatCoverageInputs {
            threat_model_path: &threat_model,
            coverage_path: &coverage,
            manifest_path: &manifest,
            stubs_dir: &stubs,
            escape_dir: &escape,
        };

        let err = render_threat_coverage_doc(&inputs)
            .expect_err("coverage.yaml and threat-model IDs must match");
        let message = err.to_string();
        assert!(message.contains("coverage map drift"));
        assert!(message.contains("missing from coverage.yaml: json_only"));
        assert!(message.contains("extra in coverage.yaml: yaml_only"));

        let _ = root;
    }
}
