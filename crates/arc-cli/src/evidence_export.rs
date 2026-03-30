use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use arc_core::receipt::ArcReceipt;
use arc_core::{canonical_json_bytes, sha256_hex, PublicKey, Signature};
use arc_kernel::{
    is_supported_checkpoint_schema, verify_checkpoint_signature, CapabilitySnapshot,
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt, KernelCheckpoint, ReceiptInclusionProof,
};
use arc_store_sqlite::SqliteReceiptStore;

use crate::policy::load_policy;
use crate::{load_or_create_authority_keypair, CliError};

const EVIDENCE_EXPORT_MANIFEST_SCHEMA: &str = "arc.evidence_export_manifest.v1";
const LEGACY_EVIDENCE_EXPORT_MANIFEST_SCHEMA: &str = "arc.evidence_export_manifest.v1";
const FEDERATION_POLICY_SCHEMA: &str = "arc.federation-policy.v1";
const LEGACY_FEDERATION_POLICY_SCHEMA: &str = "arc.federation-policy.v1";
const FEDERATED_EVIDENCE_SHARE_SCHEMA: &str = "arc.federated-evidence-share.v1";
const LEGACY_FEDERATED_EVIDENCE_SHARE_SCHEMA: &str = "arc.federated-evidence-share.v1";

fn is_supported_evidence_export_manifest_schema(schema: &str) -> bool {
    schema == EVIDENCE_EXPORT_MANIFEST_SCHEMA || schema == LEGACY_EVIDENCE_EXPORT_MANIFEST_SCHEMA
}

fn is_supported_federation_policy_schema(schema: &str) -> bool {
    schema == FEDERATION_POLICY_SCHEMA || schema == LEGACY_FEDERATION_POLICY_SCHEMA
}

fn federated_evidence_share_schema_for_manifest(schema: &str) -> &'static str {
    if schema == LEGACY_EVIDENCE_EXPORT_MANIFEST_SCHEMA {
        LEGACY_FEDERATED_EVIDENCE_SHARE_SCHEMA
    } else {
        FEDERATED_EVIDENCE_SHARE_SCHEMA
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportCounts {
    tool_receipts: u64,
    child_receipts: u64,
    checkpoints: u64,
    capability_lineage: u64,
    inclusion_proofs: u64,
    uncheckpointed_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceProofCoverage {
    checkpointed_receipts: u64,
    uncheckpointed_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportFileHash {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PolicyAttachmentMetadata {
    format: String,
    source_hash: String,
    runtime_hash: String,
    source_path: String,
    source_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct FederationPolicyAttachmentMetadata {
    issuer: String,
    partner: String,
    signer_public_key: PublicKey,
    created_at: u64,
    expires_at: u64,
    require_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FederationPolicyBody {
    schema: String,
    issuer: String,
    partner: String,
    signer_public_key: PublicKey,
    created_at: u64,
    expires_at: u64,
    query: EvidenceExportQuery,
    require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederationPolicyDocument {
    body: FederationPolicyBody,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportRequest {
    #[serde(default)]
    pub query: EvidenceExportQuery,
    #[serde(default)]
    pub require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportResponse {
    pub bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceImportPackage {
    manifest: EvidenceExportManifest,
    bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceImportRequest {
    pub package: EvidenceImportPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceImportResponse {
    pub share: arc_kernel::FederatedEvidenceShareSummary,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedEvidenceExport {
    pub query: EvidenceExportQuery,
    pub require_proofs: bool,
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EvidenceExportManifest {
    schema: String,
    exported_at: u64,
    query: EvidenceExportQuery,
    counts: EvidenceExportCounts,
    proof_coverage: EvidenceProofCoverage,
    child_receipt_scope: EvidenceChildReceiptScope,
    files: Vec<EvidenceExportFileHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyAttachmentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    federation_policy: Option<FederationPolicyAttachmentMetadata>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceVerificationResult {
    schema: String,
    verified_at: u64,
    tool_receipts: u64,
    child_receipts: u64,
    checkpoints: u64,
    capability_lineage: u64,
    inclusion_proofs: u64,
    uncheckpointed_receipts: u64,
    verified_files: u64,
    child_receipt_scope: EvidenceChildReceiptScope,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn ensure_clean_output_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "evidence export output path must be a directory: {}",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(CliError::Other(format!(
                "evidence export output directory must be empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn ensure_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
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

fn write_bytes_file(
    output_dir: &Path,
    relative_path: &str,
    bytes: &[u8],
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let path = output_dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    file_hashes.push(EvidenceExportFileHash {
        path: relative_path.to_string(),
        sha256: sha256_hex(bytes),
        bytes: bytes.len() as u64,
    });
    Ok(())
}

fn write_json_file<T: Serialize>(
    output_dir: &Path,
    relative_path: &str,
    value: &T,
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_file(output_dir, relative_path, &bytes, file_hashes)
}

fn write_ndjson_file<T: Serialize>(
    output_dir: &Path,
    relative_path: &str,
    records: &[T],
    file_hashes: &mut Vec<EvidenceExportFileHash>,
) -> Result<(), CliError> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend_from_slice(serde_json::to_string(record)?.as_bytes());
        bytes.push(b'\n');
    }
    write_bytes_file(output_dir, relative_path, &bytes, file_hashes)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(
    input_dir: &Path,
    relative_path: &str,
) -> Result<T, CliError> {
    let path = input_dir.join(relative_path);
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn read_ndjson_file<T: for<'de> Deserialize<'de>>(
    input_dir: &Path,
    relative_path: &str,
) -> Result<Vec<T>, CliError> {
    let path = input_dir.join(relative_path);
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    String::from_utf8(bytes)
        .map_err(|error| CliError::Other(format!("{} is not valid UTF-8: {error}", relative_path)))?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(CliError::from))
        .collect()
}

fn render_readme(bundle: &EvidenceExportBundle) -> String {
    let child_scope = match bundle.child_receipt_scope {
        EvidenceChildReceiptScope::FullQueryWindow => {
            "Child receipts include the full export query window."
        }
        EvidenceChildReceiptScope::TimeWindowContextOnly => {
            "Child receipts are included only as time-window context; capability and agent filters do not apply to them yet."
        }
        EvidenceChildReceiptScope::OmittedNoJoinPath => {
            "Child receipts are omitted because the export was capability/agent scoped without a truthful child-receipt join path."
        }
    };

    format!(
        "\
ARC evidence export

This directory is a local SQLite export assembled by `arc evidence export`.
It contains signed receipts, checkpoints, inclusion proofs, capability lineage,
and retention metadata for offline review.

Tool receipts: {}
Child receipts: {}
Checkpoints: {}
Inclusion proofs: {}
Uncheckpointed receipts: {}

{}
",
        bundle.tool_receipts.len(),
        bundle.child_receipts.len(),
        bundle.checkpoints.len(),
        bundle.inclusion_proofs.len(),
        bundle.uncheckpointed_receipts.len(),
        child_scope
    )
}

fn policy_source_relative_path(policy_file: &Path) -> String {
    let extension = policy_file
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .unwrap_or("txt");
    format!("policy/source.{extension}")
}

fn federation_policy_relative_path() -> &'static str {
    "federation-policy.json"
}

fn policy_metadata(
    policy_file: &Path,
    source_path: &str,
    source_bytes: u64,
) -> Result<PolicyAttachmentMetadata, CliError> {
    let loaded = load_policy(policy_file)?;
    Ok(PolicyAttachmentMetadata {
        format: loaded.format_name().to_string(),
        source_hash: loaded.identity.source_hash,
        runtime_hash: loaded.identity.runtime_hash,
        source_path: source_path.to_string(),
        source_bytes,
    })
}

fn read_federation_policy(path: &Path) -> Result<FederationPolicyDocument, CliError> {
    let policy: FederationPolicyDocument = serde_json::from_slice(&fs::read(path)?)?;
    verify_federation_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn render_missing_proofs_error(records: &[EvidenceUncheckpointedReceipt]) -> CliError {
    let sample = records
        .iter()
        .take(5)
        .map(|record| format!("{}@{}", record.receipt_id, record.seq))
        .collect::<Vec<_>>()
        .join(", ");
    CliError::Other(format!(
        "evidence export requires checkpoint coverage, but {} receipt(s) are uncheckpointed: {}",
        records.len(),
        sample
    ))
}

pub(crate) fn verify_federation_policy(policy: &FederationPolicyDocument) -> Result<(), CliError> {
    if !is_supported_federation_policy_schema(&policy.body.schema) {
        return Err(CliError::Other(format!(
            "unsupported federation policy schema: expected {} or {}, got {}",
            FEDERATION_POLICY_SCHEMA, LEGACY_FEDERATION_POLICY_SCHEMA, policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(CliError::Other(
            "federation policy created_at must be less than or equal to expires_at".to_string(),
        ));
    }
    if !policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)?
    {
        return Err(CliError::Other(
            "federation policy signature verification failed".to_string(),
        ));
    }
    Ok(())
}

fn federation_policy_metadata(
    policy: &FederationPolicyDocument,
) -> FederationPolicyAttachmentMetadata {
    FederationPolicyAttachmentMetadata {
        issuer: policy.body.issuer.clone(),
        partner: policy.body.partner.clone(),
        signer_public_key: policy.body.signer_public_key.clone(),
        created_at: policy.body.created_at,
        expires_at: policy.body.expires_at,
        require_proofs: policy.body.require_proofs,
    }
}

pub(crate) fn merge_export_query(
    policy_query: &EvidenceExportQuery,
    cli_query: &EvidenceExportQuery,
) -> Result<EvidenceExportQuery, CliError> {
    let capability_id = merge_exact_scope(
        policy_query.capability_id.as_deref(),
        cli_query.capability_id.as_deref(),
        "capability_id",
    )?;
    let agent_subject = merge_exact_scope(
        policy_query.agent_subject.as_deref(),
        cli_query.agent_subject.as_deref(),
        "agent_subject",
    )?;
    let since = match (policy_query.since, cli_query.since) {
        (Some(policy), Some(cli)) => Some(max(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    let until = match (policy_query.until, cli_query.until) {
        (Some(policy), Some(cli)) => Some(min(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err(CliError::Other(
                "federation policy scope and requested export window do not overlap".to_string(),
            ));
        }
    }
    Ok(EvidenceExportQuery {
        capability_id,
        agent_subject,
        since,
        until,
    })
}

fn merge_exact_scope(
    policy_value: Option<&str>,
    cli_value: Option<&str>,
    field: &str,
) -> Result<Option<String>, CliError> {
    match (policy_value, cli_value) {
        (Some(policy), Some(cli)) if policy != cli => Err(CliError::Other(format!(
            "requested export {field} falls outside the signed federation policy"
        ))),
        (Some(policy), _) => Ok(Some(policy.to_string())),
        (None, Some(cli)) => Ok(Some(cli.to_string())),
        (None, None) => Ok(None),
    }
}

pub(crate) fn ensure_query_within_federation_policy(
    policy_query: &EvidenceExportQuery,
    export_query: &EvidenceExportQuery,
) -> Result<(), CliError> {
    if policy_query.capability_id.is_some()
        && policy_query.capability_id != export_query.capability_id
    {
        return Err(CliError::Other(
            "evidence package query exceeds federation policy capability scope".to_string(),
        ));
    }
    if policy_query.agent_subject.is_some()
        && policy_query.agent_subject != export_query.agent_subject
    {
        return Err(CliError::Other(
            "evidence package query exceeds federation policy agent scope".to_string(),
        ));
    }
    if let Some(policy_since) = policy_query.since {
        if export_query.since.unwrap_or(0) < policy_since {
            return Err(CliError::Other(
                "evidence package query starts before the federation policy window".to_string(),
            ));
        }
    }
    if let Some(policy_until) = policy_query.until {
        if export_query.until.unwrap_or(u64::MAX) > policy_until {
            return Err(CliError::Other(
                "evidence package query ends after the federation policy window".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn prepare_evidence_export(
    query: EvidenceExportQuery,
    require_proofs: bool,
    federation_policy: Option<FederationPolicyDocument>,
) -> Result<PreparedEvidenceExport, CliError> {
    if let Some(policy) = &federation_policy {
        verify_federation_policy(policy)?;
    }
    let query = if let Some(policy) = &federation_policy {
        merge_export_query(&policy.body.query, &query)?
    } else {
        query
    };
    let require_proofs = require_proofs
        || federation_policy
            .as_ref()
            .is_some_and(|policy| policy.body.require_proofs);
    Ok(PreparedEvidenceExport {
        query,
        require_proofs,
        federation_policy,
    })
}

pub(crate) fn validate_evidence_bundle_requirements(
    bundle: &EvidenceExportBundle,
    require_proofs: bool,
) -> Result<(), CliError> {
    if require_proofs && !bundle.uncheckpointed_receipts.is_empty() {
        return Err(render_missing_proofs_error(&bundle.uncheckpointed_receipts));
    }
    Ok(())
}

fn safe_relative_path(relative_path: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(CliError::Other(format!(
            "evidence package manifest path must be relative: {relative_path}"
        )));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Other(format!(
                    "evidence package manifest path escapes the package root: {relative_path}"
                )))
            }
        }
    }
    Ok(path.to_path_buf())
}

fn verify_manifest_file_hashes(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !seen.insert(file.path.as_str()) {
            return Err(CliError::Other(format!(
                "duplicate file entry in evidence manifest: {}",
                file.path
            )));
        }
        let relative = safe_relative_path(&file.path)?;
        let bytes = fs::read(input_dir.join(relative))?;
        let actual_hash = sha256_hex(&bytes);
        let actual_bytes = bytes.len() as u64;
        if actual_hash != file.sha256 {
            return Err(CliError::Other(format!(
                "evidence package file hash mismatch for {}",
                file.path
            )));
        }
        if actual_bytes != file.bytes {
            return Err(CliError::Other(format!(
                "evidence package byte length mismatch for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn verify_query_scope(
    query: &EvidenceExportQuery,
    tool_receipts: &[EvidenceToolReceiptRecord],
    child_receipts: &[EvidenceChildReceiptRecord],
    child_receipt_scope: EvidenceChildReceiptScope,
    lineage_by_capability: &BTreeMap<String, &CapabilitySnapshot>,
) -> Result<(), CliError> {
    let expected_child_scope = query.child_receipt_scope();
    if child_receipt_scope != expected_child_scope {
        return Err(CliError::Other(format!(
            "child receipt scope mismatch: manifest says {:?}, query implies {:?}",
            child_receipt_scope, expected_child_scope
        )));
    }
    if matches!(
        child_receipt_scope,
        EvidenceChildReceiptScope::OmittedNoJoinPath
    ) && !child_receipts.is_empty()
    {
        return Err(CliError::Other(
            "child receipts were exported despite an omitted child-receipt scope".to_string(),
        ));
    }

    for record in tool_receipts {
        if let Some(capability_id) = &query.capability_id {
            if &record.receipt.capability_id != capability_id {
                return Err(CliError::Other(format!(
                    "tool receipt {} is outside capability filter {}",
                    record.receipt.id, capability_id
                )));
            }
        }
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(CliError::Other(format!(
                    "tool receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(CliError::Other(format!(
                    "tool receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
        if let Some(agent_subject) = &query.agent_subject {
            let snapshot = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .ok_or_else(|| {
                    CliError::Other(format!(
                        "missing capability lineage for receipt capability {}",
                        record.receipt.capability_id
                    ))
                })?;
            if &snapshot.subject_key != agent_subject {
                return Err(CliError::Other(format!(
                    "tool receipt {} lineage subject {} does not match agent filter {}",
                    record.receipt.id, snapshot.subject_key, agent_subject
                )));
            }
        }
    }

    for record in child_receipts {
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(CliError::Other(format!(
                    "child receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(CliError::Other(format!(
                    "child receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
    }

    Ok(())
}

fn verify_tool_receipts(
    tool_receipts: &[EvidenceToolReceiptRecord],
) -> Result<BTreeMap<u64, &ArcReceipt>, CliError> {
    let mut by_seq = BTreeMap::new();
    for record in tool_receipts {
        if by_seq.insert(record.seq, &record.receipt).is_some() {
            return Err(CliError::Other(format!(
                "duplicate tool receipt seq in evidence package: {}",
                record.seq
            )));
        }
        if !record.receipt.verify_signature()? {
            return Err(CliError::Other(format!(
                "tool receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
        if !record.receipt.action.verify_hash()? {
            return Err(CliError::Other(format!(
                "tool receipt action hash verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(by_seq)
}

fn verify_child_receipts(child_receipts: &[EvidenceChildReceiptRecord]) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for record in child_receipts {
        if !seen.insert(record.seq) {
            return Err(CliError::Other(format!(
                "duplicate child receipt seq in evidence package: {}",
                record.seq
            )));
        }
        if !record.receipt.verify_signature()? {
            return Err(CliError::Other(format!(
                "child receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(())
}

fn verify_checkpoints(
    checkpoints: &[KernelCheckpoint],
) -> Result<BTreeMap<u64, &KernelCheckpoint>, CliError> {
    let mut by_seq = BTreeMap::new();
    for checkpoint in checkpoints {
        if !is_supported_checkpoint_schema(&checkpoint.body.schema) {
            return Err(CliError::Other(format!(
                "unsupported checkpoint schema in evidence package: {}",
                checkpoint.body.schema
            )));
        }
        if !verify_checkpoint_signature(checkpoint)? {
            return Err(CliError::Other(format!(
                "checkpoint signature verification failed: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
        if by_seq
            .insert(checkpoint.body.checkpoint_seq, checkpoint)
            .is_some()
        {
            return Err(CliError::Other(format!(
                "duplicate checkpoint_seq in evidence package: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    Ok(by_seq)
}

fn verify_lineage(
    capability_lineage: &[CapabilitySnapshot],
) -> Result<BTreeMap<String, &CapabilitySnapshot>, CliError> {
    let mut by_capability = BTreeMap::new();
    for snapshot in capability_lineage {
        if by_capability
            .insert(snapshot.capability_id.clone(), snapshot)
            .is_some()
        {
            return Err(CliError::Other(format!(
                "duplicate capability lineage snapshot in evidence package: {}",
                snapshot.capability_id
            )));
        }
    }
    Ok(by_capability)
}

fn verify_inclusion_proofs(
    tool_receipts_by_seq: &BTreeMap<u64, &ArcReceipt>,
    checkpoints_by_seq: &BTreeMap<u64, &KernelCheckpoint>,
    inclusion_proofs: &[ReceiptInclusionProof],
    expected_uncheckpointed_receipts: u64,
) -> Result<(), CliError> {
    let mut proved_receipt_seqs = BTreeSet::new();
    for proof in inclusion_proofs {
        let checkpoint = checkpoints_by_seq
            .get(&proof.checkpoint_seq)
            .ok_or_else(|| {
                CliError::Other(format!(
                    "inclusion proof references missing checkpoint {}",
                    proof.checkpoint_seq
                ))
            })?;
        let receipt = tool_receipts_by_seq
            .get(&proof.receipt_seq)
            .ok_or_else(|| {
                CliError::Other(format!(
                    "inclusion proof references missing receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if proof.merkle_root != checkpoint.body.merkle_root {
            return Err(CliError::Other(format!(
                "inclusion proof root mismatch for receipt seq {}",
                proof.receipt_seq
            )));
        }
        if proof.leaf_index >= checkpoint.body.tree_size {
            return Err(CliError::Other(format!(
                "inclusion proof leaf index {} exceeds checkpoint tree size {}",
                proof.leaf_index, checkpoint.body.tree_size
            )));
        }
        if proof.receipt_seq < checkpoint.body.batch_start_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(CliError::Other(format!(
                "inclusion proof receipt seq {} falls outside checkpoint batch {}-{}",
                proof.receipt_seq, checkpoint.body.batch_start_seq, checkpoint.body.batch_end_seq
            )));
        }
        if !proved_receipt_seqs.insert(proof.receipt_seq) {
            return Err(CliError::Other(format!(
                "duplicate inclusion proof for receipt seq {}",
                proof.receipt_seq
            )));
        }
        let canonical = canonical_json_bytes(*receipt)?;
        if !proof.verify(&canonical, &checkpoint.body.merkle_root) {
            return Err(CliError::Other(format!(
                "inclusion proof verification failed for receipt seq {}",
                proof.receipt_seq
            )));
        }
    }

    let derived_uncheckpointed = tool_receipts_by_seq
        .len()
        .saturating_sub(proved_receipt_seqs.len()) as u64;
    if derived_uncheckpointed != expected_uncheckpointed_receipts {
        return Err(CliError::Other(format!(
            "uncheckpointed receipt count mismatch: manifest says {}, derived {}",
            expected_uncheckpointed_receipts, derived_uncheckpointed
        )));
    }

    Ok(())
}

fn verify_manifest_counts(
    manifest: &EvidenceExportManifest,
    tool_receipts: &[EvidenceToolReceiptRecord],
    child_receipts: &[EvidenceChildReceiptRecord],
    checkpoints: &[KernelCheckpoint],
    capability_lineage: &[CapabilitySnapshot],
    inclusion_proofs: &[ReceiptInclusionProof],
) -> Result<(), CliError> {
    let counts = &manifest.counts;
    if counts.tool_receipts != tool_receipts.len() as u64
        || counts.child_receipts != child_receipts.len() as u64
        || counts.checkpoints != checkpoints.len() as u64
        || counts.capability_lineage != capability_lineage.len() as u64
        || counts.inclusion_proofs != inclusion_proofs.len() as u64
    {
        return Err(CliError::Other(
            "evidence package manifest counts do not match exported data".to_string(),
        ));
    }
    let checkpointed_receipts = counts
        .tool_receipts
        .saturating_sub(counts.uncheckpointed_receipts);
    if manifest.proof_coverage.checkpointed_receipts != checkpointed_receipts
        || manifest.proof_coverage.uncheckpointed_receipts != counts.uncheckpointed_receipts
    {
        return Err(CliError::Other(
            "evidence package proof coverage summary does not match receipt counts".to_string(),
        ));
    }
    Ok(())
}

fn verify_policy_attachment(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let Some(expected_policy) = &manifest.policy else {
        return Ok(());
    };
    let metadata: PolicyAttachmentMetadata = read_json_file(input_dir, "policy/metadata.json")?;
    if &metadata != expected_policy {
        return Err(CliError::Other(
            "policy metadata file does not match evidence manifest".to_string(),
        ));
    }
    let relative = safe_relative_path(&expected_policy.source_path)?;
    if !input_dir.join(relative).exists() {
        return Err(CliError::Other(format!(
            "policy source file referenced by manifest is missing: {}",
            expected_policy.source_path
        )));
    }
    Ok(())
}

fn verify_federation_policy_attachment(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let Some(expected_policy) = &manifest.federation_policy else {
        return Ok(());
    };
    let policy = read_federation_policy(&input_dir.join(federation_policy_relative_path()))?;
    let actual_metadata = federation_policy_metadata(&policy);
    if &actual_metadata != expected_policy {
        return Err(CliError::Other(
            "federation policy metadata does not match evidence manifest".to_string(),
        ));
    }
    if manifest.exported_at < policy.body.created_at
        || manifest.exported_at > policy.body.expires_at
    {
        return Err(CliError::Other(
            "evidence package export timestamp falls outside the federation policy validity window"
                .to_string(),
        ));
    }
    ensure_query_within_federation_policy(&policy.body.query, &manifest.query)?;
    if policy.body.require_proofs && manifest.counts.uncheckpointed_receipts != 0 {
        return Err(CliError::Other(
            "federation policy requires full checkpoint coverage, but the evidence package contains uncheckpointed receipts".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_import_package_data(
    package: &EvidenceImportPackage,
) -> Result<(), CliError> {
    if !is_supported_evidence_export_manifest_schema(&package.manifest.schema) {
        return Err(CliError::Other(format!(
            "unsupported evidence manifest schema: expected {} or {}, got {}",
            EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            LEGACY_EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            package.manifest.schema
        )));
    }
    if package.bundle.query != package.manifest.query {
        return Err(CliError::Other(
            "evidence import package query does not match the embedded manifest".to_string(),
        ));
    }
    verify_manifest_counts(
        &package.manifest,
        &package.bundle.tool_receipts,
        &package.bundle.child_receipts,
        &package.bundle.checkpoints,
        &package.bundle.capability_lineage,
        &package.bundle.inclusion_proofs,
    )?;
    let actual_federation_metadata = package
        .federation_policy
        .as_ref()
        .map(federation_policy_metadata);
    if actual_federation_metadata != package.manifest.federation_policy {
        return Err(CliError::Other(
            "evidence import federation policy metadata does not match the embedded manifest"
                .to_string(),
        ));
    }
    if let Some(policy) = package.federation_policy.as_ref() {
        verify_federation_policy(policy)?;
        if package.manifest.exported_at < policy.body.created_at
            || package.manifest.exported_at > policy.body.expires_at
        {
            return Err(CliError::Other(
                "evidence import package export timestamp falls outside the federation policy validity window"
                    .to_string(),
            ));
        }
        ensure_query_within_federation_policy(&policy.body.query, &package.manifest.query)?;
        if policy.body.require_proofs && package.manifest.counts.uncheckpointed_receipts != 0 {
            return Err(CliError::Other(
                "federation policy requires full checkpoint coverage, but the evidence import package contains uncheckpointed receipts".to_string(),
            ));
        }
    }

    let lineage_by_capability = verify_lineage(&package.bundle.capability_lineage)?;
    let tool_receipts_by_seq = verify_tool_receipts(&package.bundle.tool_receipts)?;
    verify_child_receipts(&package.bundle.child_receipts)?;
    let checkpoints_by_seq = verify_checkpoints(&package.bundle.checkpoints)?;
    verify_inclusion_proofs(
        &tool_receipts_by_seq,
        &checkpoints_by_seq,
        &package.bundle.inclusion_proofs,
        package.manifest.counts.uncheckpointed_receipts,
    )?;
    verify_query_scope(
        &package.bundle.query,
        &package.bundle.tool_receipts,
        &package.bundle.child_receipts,
        package.bundle.child_receipt_scope,
        &lineage_by_capability,
    )?;
    Ok(())
}

fn load_verified_evidence_package(input: &Path) -> Result<EvidenceImportPackage, CliError> {
    ensure_existing_dir(input, "evidence package")?;

    let manifest: EvidenceExportManifest = read_json_file(input, "manifest.json")?;
    if !is_supported_evidence_export_manifest_schema(&manifest.schema) {
        return Err(CliError::Other(format!(
            "unsupported evidence manifest schema: expected {} or {}, got {}",
            EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            LEGACY_EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            manifest.schema
        )));
    }

    verify_manifest_file_hashes(input, &manifest)?;
    let query: EvidenceExportQuery = read_json_file(input, "query.json")?;
    if query != manifest.query {
        return Err(CliError::Other(
            "query.json does not match the evidence manifest query".to_string(),
        ));
    }

    let tool_receipts: Vec<EvidenceToolReceiptRecord> = read_ndjson_file(input, "receipts.ndjson")?;
    let child_receipts: Vec<EvidenceChildReceiptRecord> =
        read_ndjson_file(input, "child-receipts.ndjson")?;
    let checkpoints: Vec<KernelCheckpoint> = read_ndjson_file(input, "checkpoints.ndjson")?;
    let capability_lineage: Vec<CapabilitySnapshot> =
        read_ndjson_file(input, "capability-lineage.ndjson")?;
    let inclusion_proofs: Vec<ReceiptInclusionProof> =
        read_ndjson_file(input, "inclusion-proofs.ndjson")?;
    let retention: EvidenceRetentionMetadata = read_json_file(input, "retention.json")?;

    verify_manifest_counts(
        &manifest,
        &tool_receipts,
        &child_receipts,
        &checkpoints,
        &capability_lineage,
        &inclusion_proofs,
    )?;
    verify_policy_attachment(input, &manifest)?;
    verify_federation_policy_attachment(input, &manifest)?;

    let lineage_by_capability = verify_lineage(&capability_lineage)?;
    verify_query_scope(
        &query,
        &tool_receipts,
        &child_receipts,
        manifest.child_receipt_scope,
        &lineage_by_capability,
    )?;
    let tool_receipts_by_seq = verify_tool_receipts(&tool_receipts)?;
    verify_child_receipts(&child_receipts)?;
    let checkpoints_by_seq = verify_checkpoints(&checkpoints)?;
    verify_inclusion_proofs(
        &tool_receipts_by_seq,
        &checkpoints_by_seq,
        &inclusion_proofs,
        manifest.counts.uncheckpointed_receipts,
    )?;

    let federation_policy = if manifest.federation_policy.is_some() {
        Some(read_federation_policy(
            &input.join(federation_policy_relative_path()),
        )?)
    } else {
        None
    };
    let child_receipt_scope = manifest.child_receipt_scope;

    let package = EvidenceImportPackage {
        manifest,
        bundle: EvidenceExportBundle {
            query,
            tool_receipts,
            child_receipts,
            child_receipt_scope,
            checkpoints,
            capability_lineage,
            inclusion_proofs,
            uncheckpointed_receipts: Vec::new(),
            retention,
        },
        federation_policy,
    };
    validate_import_package_data(&package)?;
    Ok(package)
}

pub(crate) fn build_federated_share_import(
    package: &EvidenceImportPackage,
) -> Result<arc_kernel::FederatedEvidenceShareImport, CliError> {
    let federation_policy = package.federation_policy.as_ref().ok_or_else(|| {
        CliError::Other(
            "evidence import requires a signed attached federation policy so remote receipt sharing stays bilateral and explicit".to_string(),
        )
    })?;
    let share_descriptor = serde_json::json!({
        "schema": federated_evidence_share_schema_for_manifest(&package.manifest.schema),
        "manifest": &package.manifest,
        "federationPolicy": federation_policy,
    });
    let share_id = format!(
        "share-{}",
        sha256_hex(&canonical_json_bytes(&share_descriptor)?)
    );
    let manifest_hash = sha256_hex(&canonical_json_bytes(&package.manifest)?);
    Ok(arc_kernel::FederatedEvidenceShareImport {
        share_id,
        manifest_hash,
        exported_at: package.manifest.exported_at,
        issuer: federation_policy.body.issuer.clone(),
        partner: federation_policy.body.partner.clone(),
        signer_public_key: federation_policy.body.signer_public_key.to_hex(),
        require_proofs: federation_policy.body.require_proofs,
        query_json: serde_json::to_string(&package.bundle.query)?,
        tool_receipts: package
            .bundle
            .tool_receipts
            .iter()
            .map(|record| arc_kernel::StoredToolReceipt {
                seq: record.seq,
                receipt: record.receipt.clone(),
            })
            .collect(),
        capability_lineage: package.bundle.capability_lineage.clone(),
    })
}

fn write_evidence_package(
    output: &Path,
    bundle: EvidenceExportBundle,
    policy_file: Option<&Path>,
    federation_policy: Option<&FederationPolicyDocument>,
) -> Result<(), CliError> {
    ensure_clean_output_dir(output)?;

    let mut file_hashes = Vec::new();
    write_json_file(output, "query.json", &bundle.query, &mut file_hashes)?;
    write_ndjson_file(
        output,
        "receipts.ndjson",
        &bundle.tool_receipts,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "child-receipts.ndjson",
        &bundle.child_receipts,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoints.ndjson",
        &bundle.checkpoints,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "capability-lineage.ndjson",
        &bundle.capability_lineage,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "inclusion-proofs.ndjson",
        &bundle.inclusion_proofs,
        &mut file_hashes,
    )?;
    write_json_file(
        output,
        "retention.json",
        &bundle.retention,
        &mut file_hashes,
    )?;
    write_bytes_file(
        output,
        "README.txt",
        render_readme(&bundle).as_bytes(),
        &mut file_hashes,
    )?;

    let policy = if let Some(policy_file) = policy_file {
        let source_bytes = fs::read(policy_file)?;
        let source_path = policy_source_relative_path(policy_file);
        write_bytes_file(output, &source_path, &source_bytes, &mut file_hashes)?;
        let metadata = policy_metadata(policy_file, &source_path, source_bytes.len() as u64)?;
        write_json_file(output, "policy/metadata.json", &metadata, &mut file_hashes)?;
        Some(metadata)
    } else {
        None
    };

    let federation_policy = if let Some(policy) = federation_policy {
        write_json_file(
            output,
            federation_policy_relative_path(),
            policy,
            &mut file_hashes,
        )?;
        Some(federation_policy_metadata(policy))
    } else {
        None
    };

    let counts = EvidenceExportCounts {
        tool_receipts: bundle.tool_receipts.len() as u64,
        child_receipts: bundle.child_receipts.len() as u64,
        checkpoints: bundle.checkpoints.len() as u64,
        capability_lineage: bundle.capability_lineage.len() as u64,
        inclusion_proofs: bundle.inclusion_proofs.len() as u64,
        uncheckpointed_receipts: bundle.uncheckpointed_receipts.len() as u64,
    };
    let proof_coverage = EvidenceProofCoverage {
        checkpointed_receipts: counts
            .tool_receipts
            .saturating_sub(counts.uncheckpointed_receipts),
        uncheckpointed_receipts: counts.uncheckpointed_receipts,
    };
    let manifest = EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at: unix_now(),
        query: bundle.query,
        counts,
        proof_coverage,
        child_receipt_scope: bundle.child_receipt_scope,
        files: file_hashes,
        policy,
        federation_policy,
    };
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_evidence_federation_policy_create(
    output: &Path,
    signing_seed_file: &Path,
    issuer: &str,
    partner: &str,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    expires_at: u64,
    require_proofs: bool,
    purpose: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let keypair = load_or_create_authority_keypair(signing_seed_file)?;
    let created_at = unix_now();
    if created_at > expires_at {
        return Err(CliError::Other(
            "--expires-at must be greater than or equal to the current Unix timestamp".to_string(),
        ));
    }
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err(CliError::Other(
                "federation policy since must be less than or equal to until".to_string(),
            ));
        }
    }

    let body = FederationPolicyBody {
        schema: FEDERATION_POLICY_SCHEMA.to_string(),
        issuer: issuer.to_string(),
        partner: partner.to_string(),
        signer_public_key: keypair.public_key(),
        created_at,
        expires_at,
        query: EvidenceExportQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            since,
            until,
        },
        require_proofs,
        purpose: purpose.map(ToOwned::to_owned),
    };
    let (signature, _) = keypair.sign_canonical(&body)?;
    let policy = FederationPolicyDocument { body, signature };
    verify_federation_policy(&policy)?;
    fs::write(output, serde_json::to_vec_pretty(&policy)?)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else {
        println!("federation policy created");
        println!("output:              {}", output.display());
        println!("issuer:              {}", policy.body.issuer);
        println!("partner:             {}", policy.body.partner);
        println!(
            "signer_public_key:   {}",
            policy.body.signer_public_key.to_hex()
        );
        println!("require_proofs:      {}", policy.body.require_proofs);
    }

    Ok(())
}

pub fn cmd_evidence_export(
    output: &Path,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    policy_file: Option<&Path>,
    federation_policy_file: Option<&Path>,
    require_proofs: bool,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let prepared = prepare_evidence_export(
        EvidenceExportQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            since,
            until,
        },
        require_proofs,
        federation_policy_file
            .map(read_federation_policy)
            .transpose()?,
    )?;

    let response = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --receipt-db or --control-url for evidence export, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let store = SqliteReceiptStore::open(receipt_db)?;
            let bundle = store.build_evidence_export_bundle(&prepared.query)?;
            validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)?;
            RemoteEvidenceExportResponse {
                bundle,
                federation_policy: prepared.federation_policy,
            }
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client = crate::trust_control::build_client(control_url, token)?;
            client.export_evidence(&RemoteEvidenceExportRequest {
                query: prepared.query,
                require_proofs: prepared.require_proofs,
                federation_policy: prepared.federation_policy,
            })?
        }
        (None, None) => {
            return Err(CliError::Other(
                "evidence export requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    write_evidence_package(
        output,
        response.bundle,
        policy_file,
        response.federation_policy.as_ref(),
    )
}

pub fn cmd_evidence_import(
    input: &Path,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let package = load_verified_evidence_package(input)?;
    let share_import = build_federated_share_import(&package)?;

    let share = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --receipt-db or --control-url for evidence import, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let mut store = SqliteReceiptStore::open(receipt_db)?;
            store.import_federated_evidence_share(&share_import)?
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client = crate::trust_control::build_client(control_url, token)?;
            client
                .import_evidence(&RemoteEvidenceImportRequest { package })?
                .share
        }
        (None, None) => {
            return Err(CliError::Other(
                "evidence import requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&share)?);
    } else {
        println!("federated evidence share imported");
        println!("share_id:            {}", share.share_id);
        println!("issuer:              {}", share.issuer);
        println!("partner:             {}", share.partner);
        println!("signer_public_key:   {}", share.signer_public_key);
        println!("tool_receipts:       {}", share.tool_receipts);
        println!("capability_lineage:  {}", share.capability_lineage);
    }

    Ok(())
}

pub fn cmd_evidence_verify(input: &Path, json_output: bool) -> Result<(), CliError> {
    let package = load_verified_evidence_package(input)?;
    let manifest = package.manifest;

    let result = EvidenceVerificationResult {
        schema: manifest.schema,
        verified_at: unix_now(),
        tool_receipts: manifest.counts.tool_receipts,
        child_receipts: manifest.counts.child_receipts,
        checkpoints: manifest.counts.checkpoints,
        capability_lineage: manifest.counts.capability_lineage,
        inclusion_proofs: manifest.counts.inclusion_proofs,
        uncheckpointed_receipts: manifest.counts.uncheckpointed_receipts,
        verified_files: manifest.files.len() as u64,
        child_receipt_scope: manifest.child_receipt_scope,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("evidence package verified");
        println!("tool_receipts:          {}", result.tool_receipts);
        println!("child_receipts:         {}", result.child_receipts);
        println!("checkpoints:            {}", result.checkpoints);
        println!("capability_lineage:     {}", result.capability_lineage);
        println!("inclusion_proofs:       {}", result.inclusion_proofs);
        println!(
            "uncheckpointed_receipts: {}",
            result.uncheckpointed_receipts
        );
        println!("verified_files:         {}", result.verified_files);
        println!("child_receipt_scope:    {:?}", result.child_receipt_scope);
    }

    Ok(())
}
