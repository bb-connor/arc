//! Signed observations of completed fixed fan-out, never new dispatch authority.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{canonical_json_bytes, sha256_hex, PublicKey};
use chio_core::receipt::body::ChioReceipt;
use chio_swarm_authority::SwarmAuthorityBundle;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::state::error;
use crate::CliError;

#[cfg(target_os = "linux")]
#[path = "run_evidence/export.rs"]
mod exporting;
#[cfg(target_os = "linux")]
pub(super) use exporting::export;
#[path = "run_evidence/custody.rs"]
mod custody;
#[path = "run_evidence/native.rs"]
mod native;
#[path = "run_evidence/verify.rs"]
mod verification;

const SCHEMA: &str = "chio.process.completed-fanout.v3";
const LEGACY_SCHEMA: &str = "chio.process.completed-fanout.v2";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    runtime_id: String,
    bootstrap: ChioReceipt,
    host_record: super::state::Record,
    /// Original signed allocation authority, distinct from captured quota below.
    authority: SwarmAuthorityBundle,
    results: BTreeMap<String, CompletedCall>,
    runner: Value,
    aggregate: AggregateUsage,
    confinement: BTreeMap<String, crate::mcp_cli::NativeLaunchEvidence>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedCall {
    request: Value,
    context: Value,
    response: Value,
    custody: custody::Observation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<super::nonce_evidence::Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_log: Option<super::receipt_evidence::Evidence>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateUsage {
    profile: String,
    owner_id: String,
    max_invocations: u32,
    reserved_invocations: u32,
    captured_invocations: u32,
}

fn hash<T: Serialize>(value: &T) -> Result<String, CliError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(error)
}

fn require(condition: bool, message: &str) -> Result<(), CliError> {
    if condition {
        Ok(())
    } else {
        Err(error(message))
    }
}

fn capabilities(evidence: &Evidence) -> Result<BTreeMap<String, CapabilityToken>, CliError> {
    serde_json::from_value(evidence.bootstrap.action.parameters["capabilities"].clone())
        .map_err(error)
}

fn verified_receipt(receipt: &ChioReceipt, key: &PublicKey) -> Result<ChioReceipt, CliError> {
    crate::receipt_verify::verify_original_receipt(
        &serde_json::to_string(receipt).map_err(error)?,
        key,
    )
}

pub(super) fn verify_file(
    path: &Path,
    key_path: &Path,
    runtime_id: &str,
    native_pins: &[String],
) -> Result<(), CliError> {
    let key = crate::load_trusted_kernel_pubkey(key_path).map_err(error)?;
    let file = std::fs::File::open(path)?;
    require(
        file.metadata()?.is_file(),
        "run artifact must be a regular file",
    )?;
    let mut text = String::new();
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_string(&mut text)?;
    require(
        text.len() as u64 <= MAX_ARTIFACT_BYTES,
        "run artifact exceeds 64 MiB",
    )?;
    let signed = crate::receipt_verify::verify_original_receipt(&text, &key)?;
    let evidence: Evidence =
        serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    verification::verify(
        &signed,
        &evidence,
        &key,
        runtime_id,
        &native::pins(native_pins)?,
    )?;
    let mut checks = vec![
        "signer_pin",
        "runtime_pin",
        "issued_capabilities",
        "worker_responses",
        "task_authority",
        "actual_join_parents",
        "terminal_result",
        "runner_completion",
        "aggregate_usage",
        "continuation_custody",
    ];
    if !evidence.confinement.is_empty() {
        checks.push("confinement_receipt_chain");
    }
    let mut unchecked = vec!["scenario_matrix"];
    if evidence.schema == SCHEMA {
        checks.extend(["execution_nonces", "receipt_log_inclusion"]);
    } else {
        unchecked.extend(["execution_nonces", "receipt_log_inclusion"]);
    }
    println!(
        "{}",
        json!({
            "schema": "chio.process.run-verification.v1", "runtime_id": evidence.runtime_id,
            "verified_workers": evidence.results.keys().collect::<Vec<_>>(),
            "captured_invocations": evidence.aggregate.captured_invocations,
            "verified_native_launches": evidence.confinement.len(), "checks": checks,
            "artifact_schema": evidence.schema, "unchecked": unchecked,
            "m5_acceptance_complete": false,
        })
    );
    Ok(())
}
