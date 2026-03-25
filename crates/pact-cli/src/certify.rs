use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use pact_conformance::{
    generate_markdown_report, load_results_from_dir, load_scenarios_from_dir, CompatibilityReport,
    ResultStatus, ScenarioDescriptor, ScenarioResult,
};
use pact_core::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};

use crate::{load_or_create_authority_keypair, CliError};

const CERTIFICATION_SCHEMA: &str = "pact.certify.check.v1";
const CERTIFICATION_REGISTRY_VERSION: &str = "pact.certify.registry.v1";
const CRITERIA_PROFILE_ALL_PASS_V1: &str = "conformance-all-pass-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CertificationVerdict {
    Pass,
    Fail,
}

impl CertificationVerdict {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CriterionStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationCriterion {
    id: String,
    description: String,
    status: CriterionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationFinding {
    kind: String,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scenario_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deployment_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<ResultStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationSummary {
    scenario_count: usize,
    result_count: usize,
    evaluated_peer_count: usize,
    pass_count: usize,
    fail_count: usize,
    unsupported_count: usize,
    skipped_count: usize,
    xfail_count: usize,
    missing_scenarios_count: usize,
    unknown_results_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationEvidence {
    scenarios_dir: String,
    results_dir: String,
    normalized_scenarios_sha256: String,
    normalized_results_sha256: String,
    generated_report_sha256: String,
    generated_report_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificationTarget {
    tool_server_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationCheckBody {
    schema: String,
    criteria_profile: String,
    checked_at: u64,
    target: CertificationTarget,
    verdict: CertificationVerdict,
    summary: CertificationSummary,
    criteria: Vec<CertificationCriterion>,
    evidence: CertificationEvidence,
    findings: Vec<CertificationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedCertificationCheck {
    pub(crate) body: CertificationCheckBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CertificationRegistryState {
    Active,
    Superseded,
    Revoked,
}

impl CertificationRegistryState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CertificationResolutionState {
    Active,
    Superseded,
    Revoked,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationRegistryEntry {
    pub(crate) artifact_id: String,
    pub(crate) artifact_sha256: String,
    pub(crate) tool_server_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tool_server_name: Option<String>,
    pub(crate) verdict: CertificationVerdict,
    pub(crate) checked_at: u64,
    pub(crate) published_at: u64,
    pub(crate) status: CertificationRegistryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) superseded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revoked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revoked_reason: Option<String>,
    pub(crate) artifact: SignedCertificationCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationRegistry {
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) artifacts: BTreeMap<String, CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationRegistryListResponse {
    pub(crate) configured: bool,
    pub(crate) count: usize,
    pub(crate) artifacts: Vec<CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationResolutionResponse {
    pub(crate) tool_server_id: String,
    pub(crate) state: CertificationResolutionState,
    pub(crate) total_entries: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) current: Option<CertificationRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificationRevocationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revoked_at: Option<u64>,
}

struct EvaluationArtifacts {
    verdict: CertificationVerdict,
    criteria: Vec<CertificationCriterion>,
    findings: Vec<CertificationFinding>,
    summary: CertificationSummary,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

impl Default for CertificationRegistry {
    fn default() -> Self {
        Self {
            version: CERTIFICATION_REGISTRY_VERSION.to_string(),
            artifacts: BTreeMap::new(),
        }
    }
}

fn require_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::Other(format!(
            "{label} directory does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::Other(format!(
            "{label} path must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn build_certification_body(
    criteria_profile: &str,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    scenarios_dir: &Path,
    results_dir: &Path,
    report_output: Option<&Path>,
    scenarios: Vec<ScenarioDescriptor>,
    results: Vec<ScenarioResult>,
) -> Result<(CertificationCheckBody, Vec<u8>), CliError> {
    if criteria_profile != CRITERIA_PROFILE_ALL_PASS_V1 {
        return Err(CliError::Other(format!(
            "unsupported certification criteria profile: {criteria_profile}"
        )));
    }

    let report = CompatibilityReport {
        scenarios: scenarios.clone(),
        results: results.clone(),
    };
    let report_markdown = generate_markdown_report(&report);
    let report_bytes = report_markdown.as_bytes().to_vec();

    let evaluation = evaluate_all_pass_profile(&scenarios, &results);
    let evidence = CertificationEvidence {
        scenarios_dir: scenarios_dir.display().to_string(),
        results_dir: results_dir.display().to_string(),
        normalized_scenarios_sha256: sha256_hex(&canonical_json_bytes(&scenarios)?),
        normalized_results_sha256: sha256_hex(&canonical_json_bytes(&results)?),
        generated_report_sha256: sha256_hex(&report_bytes),
        generated_report_bytes: report_bytes.len(),
        report_output: report_output.map(|path| path.display().to_string()),
    };

    let body = CertificationCheckBody {
        schema: CERTIFICATION_SCHEMA.to_string(),
        criteria_profile: criteria_profile.to_string(),
        checked_at: unix_now(),
        target: CertificationTarget {
            tool_server_id: tool_server_id.to_string(),
            tool_server_name: tool_server_name.map(ToOwned::to_owned),
        },
        verdict: evaluation.verdict,
        summary: evaluation.summary,
        criteria: evaluation.criteria,
        evidence,
        findings: evaluation.findings,
    };
    Ok((body, report_bytes))
}

fn evaluate_all_pass_profile(
    scenarios: &[ScenarioDescriptor],
    results: &[ScenarioResult],
) -> EvaluationArtifacts {
    let scenario_ids = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut results_by_scenario = BTreeMap::<String, usize>::new();
    let mut findings = Vec::new();

    for result in results {
        if scenario_ids.contains(result.scenario_id.as_str()) {
            *results_by_scenario
                .entry(result.scenario_id.clone())
                .or_insert(0) += 1;
        } else {
            findings.push(CertificationFinding {
                kind: "unknown-scenario-result".to_string(),
                message: format!(
                    "result references unknown scenario `{}`",
                    result.scenario_id
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    for scenario in scenarios {
        if scenario.expected != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "scenario-expectation-not-certifiable".to_string(),
                message: format!(
                    "scenario `{}` has non-pass expected status `{}`",
                    scenario.id,
                    scenario.expected.label()
                ),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: Some(scenario.expected),
            });
        }
        if !results_by_scenario.contains_key(&scenario.id) {
            findings.push(CertificationFinding {
                kind: "missing-scenario-result".to_string(),
                message: format!("scenario `{}` has no result coverage", scenario.id),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: None,
            });
        }
    }

    for result in results {
        if result.status != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "non-pass-result".to_string(),
                message: format!(
                    "scenario `{}` returned `{}`",
                    result.scenario_id,
                    result.status.label()
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    let pass_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Pass)
        .count();
    let fail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Fail)
        .count();
    let unsupported_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Unsupported)
        .count();
    let skipped_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Skipped)
        .count();
    let xfail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Xfail)
        .count();
    let unknown_results_count = findings
        .iter()
        .filter(|finding| finding.kind == "unknown-scenario-result")
        .count();
    let missing_scenarios_count = findings
        .iter()
        .filter(|finding| finding.kind == "missing-scenario-result")
        .count();
    let unsupported_expectation_count = findings
        .iter()
        .filter(|finding| finding.kind == "scenario-expectation-not-certifiable")
        .count();
    let unique_peers = results
        .iter()
        .map(|result| result.peer.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    let criteria = vec![
        CertificationCriterion {
            id: "non-empty-scenario-corpus".to_string(),
            description: "Certification requires at least one declared scenario.".to_string(),
            status: if scenarios.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "non-empty-result-corpus".to_string(),
            description: "Certification requires at least one observed result.".to_string(),
            status: if results.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "scenario-coverage-complete".to_string(),
            description:
                "Every declared scenario must have at least one result and every result must map to a declared scenario."
                    .to_string(),
            status: if missing_scenarios_count == 0 && unknown_results_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "certification-profile-supported".to_string(),
            description:
                "The alpha certification profile only supports scenario sets whose declared expectation is pass."
                    .to_string(),
            status: if unsupported_expectation_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "all-results-pass".to_string(),
            description:
                "Every observed conformance result must be pass; fail, unsupported, skipped, and xfail block certification."
                    .to_string(),
            status: if fail_count == 0
                && unsupported_count == 0
                && skipped_count == 0
                && xfail_count == 0
                && !results.is_empty()
            {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
    ];

    let verdict = if criteria
        .iter()
        .all(|criterion| criterion.status == CriterionStatus::Pass)
    {
        CertificationVerdict::Pass
    } else {
        CertificationVerdict::Fail
    };

    EvaluationArtifacts {
        verdict,
        criteria,
        findings,
        summary: CertificationSummary {
            scenario_count: scenarios.len(),
            result_count: results.len(),
            evaluated_peer_count: unique_peers,
            pass_count,
            fail_count,
            unsupported_count,
            skipped_count,
            xfail_count,
            missing_scenarios_count,
            unknown_results_count,
        },
    }
}

fn sign_artifact(
    body: CertificationCheckBody,
    keypair: &Keypair,
) -> Result<SignedCertificationCheck, CliError> {
    let (signature, _) = keypair.sign_canonical(&body)?;
    Ok(SignedCertificationCheck {
        body,
        signer_public_key: keypair.public_key(),
        signature,
    })
}

pub(crate) fn verify_signed_certification_check(
    artifact: &SignedCertificationCheck,
) -> Result<(), CliError> {
    if artifact.body.schema != CERTIFICATION_SCHEMA {
        return Err(CliError::Other(format!(
            "unsupported certification schema: {}",
            artifact.body.schema
        )));
    }
    let body_bytes = canonical_json_bytes(&artifact.body)?;
    if !artifact
        .signer_public_key
        .verify(&body_bytes, &artifact.signature)
    {
        return Err(CliError::Other(
            "certification artifact signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn certification_artifact_id(
    artifact: &SignedCertificationCheck,
) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(artifact)?))
}

fn load_signed_certification_check(path: &Path) -> Result<SignedCertificationCheck, CliError> {
    let artifact: SignedCertificationCheck = serde_json::from_slice(&fs::read(path)?)?;
    verify_signed_certification_check(&artifact)?;
    Ok(artifact)
}

impl CertificationRegistry {
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != CERTIFICATION_REGISTRY_VERSION {
                    return Err(CliError::Other(format!(
                        "unsupported certification registry version: {}",
                        registry.version
                    )));
                }
                for entry in registry.artifacts.values() {
                    verify_certification_registry_entry(entry)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), CliError> {
        ensure_parent_dir(path)?;
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub(crate) fn get(&self, artifact_id: &str) -> Option<&CertificationRegistryEntry> {
        self.artifacts.get(artifact_id)
    }

    pub(crate) fn publish(
        &mut self,
        artifact: SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        verify_signed_certification_check(&artifact)?;
        let artifact_id = certification_artifact_id(&artifact)?;
        if let Some(existing) = self.artifacts.get(&artifact_id) {
            return Ok(existing.clone());
        }

        for existing in self.artifacts.values_mut() {
            if existing.tool_server_id == artifact.body.target.tool_server_id
                && existing.status == CertificationRegistryState::Active
            {
                existing.status = CertificationRegistryState::Superseded;
                existing.superseded_by = Some(artifact_id.clone());
            }
        }

        let entry = CertificationRegistryEntry {
            artifact_sha256: artifact_id.clone(),
            artifact_id: artifact_id.clone(),
            tool_server_id: artifact.body.target.tool_server_id.clone(),
            tool_server_name: artifact.body.target.tool_server_name.clone(),
            verdict: artifact.body.verdict,
            checked_at: artifact.body.checked_at,
            published_at: unix_now(),
            status: CertificationRegistryState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            artifact,
        };
        self.artifacts.insert(artifact_id, entry.clone());
        Ok(entry)
    }

    pub(crate) fn resolve(
        &self,
        tool_server_id: &str,
    ) -> CertificationResolutionResponse {
        let mut matches = self
            .artifacts
            .values()
            .filter(|entry| entry.tool_server_id == tool_server_id)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.published_at
                .cmp(&right.published_at)
                .then(left.checked_at.cmp(&right.checked_at))
                .then(left.artifact_id.cmp(&right.artifact_id))
        });
        let total_entries = matches.len();
        let current = matches
            .iter()
            .rev()
            .find(|entry| entry.status == CertificationRegistryState::Active)
            .cloned()
            .or_else(|| {
                matches
                    .iter()
                    .rev()
                    .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                    .max_by(|left, right| {
                        left.revoked_at
                            .cmp(&right.revoked_at)
                            .then(left.published_at.cmp(&right.published_at))
                            .then(left.checked_at.cmp(&right.checked_at))
                    })
                    .cloned()
            })
            .or_else(|| matches.last().cloned());
        let state = match current.as_ref().map(|entry| entry.status) {
            Some(CertificationRegistryState::Active) => CertificationResolutionState::Active,
            Some(CertificationRegistryState::Superseded) => {
                CertificationResolutionState::Superseded
            }
            Some(CertificationRegistryState::Revoked) => CertificationResolutionState::Revoked,
            None => CertificationResolutionState::NotFound,
        };
        CertificationResolutionResponse {
            tool_server_id: tool_server_id.to_string(),
            state,
            total_entries,
            current,
        }
    }

    pub(crate) fn revoke(
        &mut self,
        artifact_id: &str,
        reason: Option<&str>,
        revoked_at: Option<u64>,
    ) -> Result<CertificationRegistryEntry, CliError> {
        let Some(entry) = self.artifacts.get_mut(artifact_id) else {
            return Err(CliError::Other(format!(
                "certification artifact `{artifact_id}` was not found"
            )));
        };
        entry.status = CertificationRegistryState::Revoked;
        entry.revoked_at = Some(revoked_at.unwrap_or_else(unix_now));
        entry.revoked_reason = reason.map(str::to_string);
        Ok(entry.clone())
    }
}

fn verify_certification_registry_entry(
    entry: &CertificationRegistryEntry,
) -> Result<(), CliError> {
    verify_signed_certification_check(&entry.artifact)?;
    let expected_artifact_id = certification_artifact_id(&entry.artifact)?;
    if entry.artifact_id != expected_artifact_id {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched artifact_id",
            entry.artifact_id
        )));
    }
    if entry.artifact_sha256 != expected_artifact_id {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched artifact digest",
            entry.artifact_id
        )));
    }
    if entry.tool_server_id != entry.artifact.body.target.tool_server_id {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched tool_server_id",
            entry.artifact_id
        )));
    }
    if entry.tool_server_name != entry.artifact.body.target.tool_server_name {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched tool_server_name",
            entry.artifact_id
        )));
    }
    if entry.checked_at != entry.artifact.body.checked_at {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched checked_at",
            entry.artifact_id
        )));
    }
    if entry.verdict != entry.artifact.body.verdict {
        return Err(CliError::Other(format!(
            "certification registry entry `{}` has mismatched verdict",
            entry.artifact_id
        )));
    }
    Ok(())
}

pub(crate) fn cmd_certify_verify(
    input: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let artifact_id = certification_artifact_id(&artifact)?;
    if json_output {
        let message = serde_json::json!({
            "input": input.display().to_string(),
            "artifactId": artifact_id,
            "toolServerId": artifact.body.target.tool_server_id,
            "toolServerName": artifact.body.target.tool_server_name,
            "verdict": artifact.body.verdict.label(),
            "checkedAt": artifact.body.checked_at,
            "signerPublicKey": artifact.signer_public_key,
            "verified": true,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!("certification verified");
        println!("artifact_id:      {artifact_id}");
        println!("tool_server_id:   {}", artifact.body.target.tool_server_id);
        println!("verdict:          {}", artifact.body.verdict.label());
        println!("checked_at:       {}", artifact.body.checked_at);
    }
    Ok(())
}

pub(crate) fn cmd_certify_check(
    scenarios_dir: &Path,
    results_dir: &Path,
    output: &Path,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    report_output: Option<&Path>,
    criteria_profile: &str,
    signing_seed_file: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    require_existing_dir(scenarios_dir, "scenarios")?;
    require_existing_dir(results_dir, "results")?;

    let scenarios = load_scenarios_from_dir(scenarios_dir)?;
    let results = load_results_from_dir(results_dir)?;
    let (body, report_bytes) = build_certification_body(
        criteria_profile,
        tool_server_id,
        tool_server_name,
        scenarios_dir,
        results_dir,
        report_output,
        scenarios,
        results,
    )?;

    if let Some(report_output) = report_output {
        ensure_parent_dir(report_output)?;
        fs::write(report_output, &report_bytes)?;
    }

    let signing_key = load_or_create_authority_keypair(signing_seed_file)?;
    let artifact = sign_artifact(body, &signing_key)?;
    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&artifact)?)?;

    if json_output {
        let message = serde_json::json!({
            "output": output.display().to_string(),
            "verdict": artifact.body.verdict.label(),
            "criteriaProfile": artifact.body.criteria_profile,
            "summary": artifact.body.summary,
            "signerPublicKey": artifact.signer_public_key,
        });
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{message}")?;
    } else {
        println!(
            "wrote certification artifact to {} ({}, {} result(s))",
            output.display(),
            artifact.body.verdict.label(),
            artifact.body.summary.result_count
        );
        if let Some(report_output) = report_output {
            println!("wrote certification report to {}", report_output.display());
        }
    }

    Ok(())
}

pub(crate) fn cmd_certify_registry_publish_local(
    input: &Path,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.publish(artifact)?;
    registry.save(registry_path)?;
    emit_registry_entry("published certification artifact", &entry, json_output)
}

pub(crate) fn cmd_certify_registry_list_local(
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = CertificationRegistryListResponse {
        configured: true,
        count: registry.artifacts.len(),
        artifacts: registry.artifacts.into_values().collect(),
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("certifications: {}", response.count);
        for artifact in response.artifacts {
            println!(
                "- {} server={} verdict={} status={}",
                artifact.artifact_id,
                artifact.tool_server_id,
                artifact.verdict.label(),
                artifact.status.label()
            );
        }
    }
    Ok(())
}

pub(crate) fn cmd_certify_registry_get_local(
    artifact_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.get(artifact_id).cloned().ok_or_else(|| {
        CliError::Other(format!(
            "certification artifact `{artifact_id}` was not found"
        ))
    })?;
    emit_registry_entry("certification artifact", &entry, json_output)
}

pub(crate) fn cmd_certify_registry_resolve_local(
    tool_server_id: &str,
    registry_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let registry = CertificationRegistry::load(registry_path)?;
    let response = registry.resolve(tool_server_id);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("tool_server_id: {}", response.tool_server_id);
        println!(
            "state:          {}",
            match response.state {
                CertificationResolutionState::Active => "active",
                CertificationResolutionState::Superseded => "superseded",
                CertificationResolutionState::Revoked => "revoked",
                CertificationResolutionState::NotFound => "not-found",
            }
        );
        println!("total_entries:  {}", response.total_entries);
        if let Some(current) = response.current {
            println!("artifact_id:    {}", current.artifact_id);
            println!("verdict:        {}", current.verdict.label());
            println!("status:         {}", current.status.label());
        }
    }
    Ok(())
}

pub(crate) fn cmd_certify_registry_revoke_local(
    artifact_id: &str,
    registry_path: &Path,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let mut registry = CertificationRegistry::load(registry_path)?;
    let entry = registry.revoke(artifact_id, reason, revoked_at)?;
    registry.save(registry_path)?;
    emit_registry_entry("revoked certification artifact", &entry, json_output)
}

fn emit_registry_entry(
    headline: &str,
    entry: &CertificationRegistryEntry,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(entry)?);
    } else {
        println!("{headline}");
        println!("artifact_id:     {}", entry.artifact_id);
        println!("tool_server_id:  {}", entry.tool_server_id);
        println!("verdict:         {}", entry.verdict.label());
        println!("status:          {}", entry.status.label());
        println!("published_at:    {}", entry.published_at);
        if let Some(revoked_at) = entry.revoked_at {
            println!("revoked_at:      {revoked_at}");
        }
        if let Some(reason) = entry.revoked_reason.as_deref() {
            println!("revoked_reason:  {reason}");
        }
        if let Some(superseded_by) = entry.superseded_by.as_deref() {
            println!("superseded_by:   {superseded_by}");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    use pact_conformance::{
        DeploymentMode, PeerRole, RequiredCapabilities, ScenarioCategory, Transport,
    };

    fn scenario(id: &str) -> ScenarioDescriptor {
        ScenarioDescriptor {
            id: id.to_string(),
            title: format!("Scenario {id}"),
            area: "core".to_string(),
            category: ScenarioCategory::McpCore,
            spec_versions: vec!["2025-11-25".to_string()],
            transport: vec![Transport::Stdio],
            peer_roles: vec![PeerRole::ClientToPactServer],
            deployment_modes: vec![DeploymentMode::WrappedStdio],
            required_capabilities: RequiredCapabilities::default(),
            tags: vec!["wave1".to_string()],
            expected: ResultStatus::Pass,
            timeout_ms: None,
            notes: None,
        }
    }

    fn result(id: &str, status: ResultStatus) -> ScenarioResult {
        ScenarioResult {
            scenario_id: id.to_string(),
            peer: "js".to_string(),
            peer_role: PeerRole::ClientToPactServer,
            deployment_mode: DeploymentMode::WrappedStdio,
            transport: Transport::Stdio,
            spec_version: "2025-11-25".to_string(),
            category: ScenarioCategory::McpCore,
            status,
            duration_ms: 25,
            assertions: Vec::new(),
            notes: None,
            artifacts: BTreeMap::new(),
            failure_kind: None,
            failure_message: None,
            expected_failure: None,
        }
    }

    #[test]
    fn all_pass_profile_produces_pass_verdict() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize")],
            &[result("initialize", ResultStatus::Pass)],
        );
        assert_eq!(evaluation.verdict, CertificationVerdict::Pass);
        assert!(evaluation.findings.is_empty());
        assert_eq!(evaluation.summary.pass_count, 1);
    }

    #[test]
    fn all_pass_profile_fails_on_missing_unknown_and_non_pass_results() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize"), scenario("list-tools")],
            &[
                result("initialize", ResultStatus::Pass),
                result("unknown", ResultStatus::Fail),
                result("initialize", ResultStatus::Unsupported),
            ],
        );

        assert_eq!(evaluation.verdict, CertificationVerdict::Fail);
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "missing-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "unknown-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "non-pass-result"));
    }

    #[test]
    fn signed_artifact_verifies_against_body() {
        let (body, _) = build_certification_body(
            CRITERIA_PROFILE_ALL_PASS_V1,
            "demo-server",
            Some("Demo"),
            Path::new("/tmp/scenarios"),
            Path::new("/tmp/results"),
            None,
            vec![scenario("initialize")],
            vec![result("initialize", ResultStatus::Pass)],
        )
        .expect("build body");
        let keypair = Keypair::generate();
        let artifact = sign_artifact(body, &keypair).expect("sign artifact");

        assert!(artifact
            .signer_public_key
            .verify_canonical(&artifact.body, &artifact.signature)
            .expect("verify canonical"));
    }
}
