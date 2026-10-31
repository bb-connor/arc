//! The on-disk evidence package: its file layout, inventory rules, payload
//! commitment and the writer that produces and signs it.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::Keypair;
use chio_core_types::hashing::sha256_hex;
use chio_core_types::receipt::checkpoint::CheckpointTransparencySummary;
use chio_core_types::receipt::evidence::{
    EvidenceDisclosureNotice, EvidenceExportBundle, EvidenceExportCounts, EvidenceExportFileHash,
    EvidenceExportManifest, EvidencePackageEnvelope, EvidencePackagePayload, EvidenceProofCoverage,
    EvidenceTransparencyClaims, ExportCommitment, FederationPolicyDocument,
    PolicyAttachmentMetadata, EVIDENCE_EXPORT_COMMITMENT_SCHEMA, EVIDENCE_EXPORT_MANIFEST_SCHEMA,
};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::Serialize;

use crate::error::BundleVerifyError;
use crate::read::{safe_relative_path, MAX_FILE_BYTES, MAX_PACKAGE_BYTES};
use crate::verify::receipt_semantic_summary;

pub const ENVELOPE_FILE: &str = "export-envelope.json";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const QUERY_FILE: &str = "query.json";
pub const RECEIPTS_FILE: &str = "receipts.ndjson";
pub const CHILD_RECEIPTS_FILE: &str = "child-receipts.ndjson";
pub const CHECKPOINTS_FILE: &str = "checkpoints.ndjson";
pub const PUBLICATIONS_FILE: &str = "checkpoint-publications.ndjson";
pub const WITNESSES_FILE: &str = "checkpoint-witnesses.ndjson";
pub const CONSISTENCY_PROOFS_FILE: &str = "checkpoint-consistency-proofs.ndjson";
pub const EQUIVOCATIONS_FILE: &str = "checkpoint-equivocations.ndjson";
pub const CAPABILITY_LINEAGE_FILE: &str = "capability-lineage.ndjson";
pub const INCLUSION_PROOFS_FILE: &str = "inclusion-proofs.ndjson";
pub const UNCHECKPOINTED_FILE: &str = "uncheckpointed-receipts.ndjson";
pub const RETENTION_FILE: &str = "retention.json";
pub const README_FILE: &str = "README.txt";
pub const POLICY_METADATA_FILE: &str = "policy/metadata.json";
pub const POLICY_SOURCE_PREFIX: &str = "policy/source.";
pub const FEDERATION_POLICY_FILE: &str = "federation-policy.json";

/// Files every package lists, besides the optional policy and federation
/// policy attachments.
pub const REQUIRED_FILES: &[&str] = &[
    QUERY_FILE,
    RECEIPTS_FILE,
    CHILD_RECEIPTS_FILE,
    CHECKPOINTS_FILE,
    PUBLICATIONS_FILE,
    WITNESSES_FILE,
    CONSISTENCY_PROOFS_FILE,
    EQUIVOCATIONS_FILE,
    CAPABILITY_LINEAGE_FILE,
    INCLUSION_PROOFS_FILE,
    UNCHECKPOINTED_FILE,
    RETENTION_FILE,
    README_FILE,
];

/// The manifest lists every package file exactly once, every path is safe,
/// and each file and the total stay inside the byte limits.
pub fn verify_inventory(manifest: &EvidenceExportManifest) -> Result<(), BundleVerifyError> {
    let mut expected: BTreeSet<&str> = REQUIRED_FILES.iter().copied().collect();
    if let Some(policy) = &manifest.policy {
        expected.insert(POLICY_METADATA_FILE);
        if !policy.source_path.starts_with(POLICY_SOURCE_PREFIX) {
            return Err(BundleVerifyError::file(
                "unsupported evidence policy attachment path",
            ));
        }
        expected.insert(&policy.source_path);
    }
    if manifest.federation_policy.is_some() {
        expected.insert(FEDERATION_POLICY_FILE);
    }
    let actual: BTreeSet<&str> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    if actual != expected || actual.len() != manifest.files.len() {
        return Err(BundleVerifyError::file(
            "evidence manifest must declare every package file exactly once",
        ));
    }
    let max_file = u64::try_from(MAX_FILE_BYTES).unwrap_or(u64::MAX);
    let mut total = 0_u64;
    for file in &manifest.files {
        safe_relative_path(&file.path)?;
        total = total
            .checked_add(file.bytes)
            .ok_or_else(|| BundleVerifyError::file("evidence package size overflow"))?;
        if file.bytes > max_file || total > MAX_PACKAGE_BYTES {
            return Err(BundleVerifyError::file(
                "evidence package exceeds file or total byte limit",
            ));
        }
    }
    Ok(())
}

/// The digest `ExportCommitment::payload_sha256` commits to.
pub fn payload_sha256(
    bundle: &EvidenceExportBundle,
    transparency: Option<&CheckpointTransparencySummary>,
    federation_policy: Option<&FederationPolicyDocument>,
) -> Result<String, BundleVerifyError> {
    let bytes = canonical_json_bytes(&EvidencePackagePayload {
        bundle,
        transparency,
        federation_policy,
    })
    .map_err(|error| {
        BundleVerifyError::schema(format!("payload is not canonicalizable: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// The digest `ExportCommitment::manifest_sha256` commits to.
pub fn manifest_sha256(manifest: &EvidenceExportManifest) -> Result<String, BundleVerifyError> {
    let bytes = canonical_json_bytes(manifest).map_err(|error| {
        BundleVerifyError::schema(format!("manifest is not canonicalizable: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// A policy file attached to a package with its precomputed identity.
pub struct PolicyAttachment<'a> {
    pub metadata: PolicyAttachmentMetadata,
    pub source: &'a [u8],
}

/// Everything a package carries besides what the writer derives.
pub struct PackageContents<'a> {
    pub bundle: &'a EvidenceExportBundle,
    /// Transparency records already verified against `bundle.checkpoints`.
    pub transparency: &'a CheckpointTransparencySummary,
    pub claim_boundary: EvidenceTransparencyClaims,
    pub readme: &'a str,
    pub policy: Option<PolicyAttachment<'a>>,
    pub federation_policy: Option<&'a FederationPolicyDocument>,
    pub exported_at: u64,
}

/// Canonical bytes, so file hashes do not vary with serde_json map features.
fn file_bytes<T: Serialize>(relative_path: &str, value: &T) -> Result<Vec<u8>, BundleVerifyError> {
    canonical_json_bytes(value)
        .map_err(|error| BundleVerifyError::schema(format!("{relative_path}: {error}")))
}

struct Writer<'a> {
    output: &'a Path,
    files: Vec<EvidenceExportFileHash>,
}

impl Writer<'_> {
    fn bytes(&mut self, relative_path: &str, bytes: &[u8]) -> Result<(), BundleVerifyError> {
        let path = self.output.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                BundleVerifyError::io(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        fs::write(&path, bytes).map_err(|error| {
            BundleVerifyError::io(format!("cannot write {}: {error}", path.display()))
        })?;
        self.files.push(EvidenceExportFileHash {
            path: relative_path.to_string(),
            sha256: sha256_hex(bytes),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
        Ok(())
    }

    fn json<T: Serialize>(
        &mut self,
        relative_path: &str,
        value: &T,
    ) -> Result<(), BundleVerifyError> {
        let bytes = file_bytes(relative_path, value)?;
        self.bytes(relative_path, &bytes)
    }

    fn ndjson<T: Serialize>(
        &mut self,
        relative_path: &str,
        records: &[T],
    ) -> Result<(), BundleVerifyError> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&file_bytes(relative_path, record)?);
            bytes.push(b'\n');
        }
        self.bytes(relative_path, &bytes)
    }
}

fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Write a package into the empty directory `output` and sign its envelope
/// with `signing_key`.
pub fn write_package(
    output: &Path,
    contents: PackageContents<'_>,
    signing_key: &Keypair,
) -> Result<EvidenceExportManifest, BundleVerifyError> {
    let PackageContents {
        bundle,
        transparency,
        claim_boundary,
        readme,
        policy,
        federation_policy,
        exported_at,
    } = contents;
    let mut writer = Writer {
        output,
        files: Vec::new(),
    };
    writer.ndjson(UNCHECKPOINTED_FILE, &bundle.uncheckpointed_receipts)?;
    writer.json(QUERY_FILE, &bundle.query)?;
    writer.ndjson(RECEIPTS_FILE, &bundle.tool_receipts)?;
    writer.ndjson(CHILD_RECEIPTS_FILE, &bundle.child_receipts)?;
    writer.ndjson(CHECKPOINTS_FILE, &bundle.checkpoints)?;
    writer.ndjson(PUBLICATIONS_FILE, &transparency.publications)?;
    writer.ndjson(WITNESSES_FILE, &transparency.witnesses)?;
    writer.ndjson(CONSISTENCY_PROOFS_FILE, &transparency.consistency_proofs)?;
    writer.ndjson(EQUIVOCATIONS_FILE, &transparency.equivocations)?;
    writer.ndjson(CAPABILITY_LINEAGE_FILE, &bundle.capability_lineage)?;
    writer.ndjson(INCLUSION_PROOFS_FILE, &bundle.inclusion_proofs)?;
    writer.json(RETENTION_FILE, &bundle.retention)?;
    writer.bytes(README_FILE, readme.as_bytes())?;

    let policy = match policy {
        Some(attachment) => {
            writer.bytes(&attachment.metadata.source_path, attachment.source)?;
            writer.json(POLICY_METADATA_FILE, &attachment.metadata)?;
            Some(attachment.metadata)
        }
        None => None,
    };
    let federation_policy_attachment = match federation_policy {
        Some(document) => {
            writer.json(FEDERATION_POLICY_FILE, document)?;
            Some(document.attachment_metadata())
        }
        None => None,
    };

    let counts = EvidenceExportCounts {
        tool_receipts: count(bundle.tool_receipts.len()),
        child_receipts: count(bundle.child_receipts.len()),
        checkpoints: count(bundle.checkpoints.len()),
        capability_lineage: count(bundle.capability_lineage.len()),
        inclusion_proofs: count(bundle.inclusion_proofs.len()),
        uncheckpointed_receipts: count(bundle.uncheckpointed_receipts.len()),
    };
    let proof_coverage = EvidenceProofCoverage {
        checkpointed_receipts: counts
            .tool_receipts
            .saturating_sub(counts.uncheckpointed_receipts),
        uncheckpointed_receipts: counts.uncheckpointed_receipts,
    };
    let manifest = EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at,
        query: bundle.query.clone(),
        counts,
        proof_coverage,
        receipt_semantics: receipt_semantic_summary(&bundle.tool_receipts),
        child_receipt_scope: bundle.child_receipt_scope,
        claim_boundary: Some(claim_boundary),
        files: writer.files,
        policy,
        federation_policy: federation_policy_attachment,
        disclosure_notice: EvidenceDisclosureNotice::for_query(&bundle.query),
    };
    verify_inventory(&manifest)?;
    let envelope = sign_envelope(
        &manifest,
        bundle,
        Some(transparency),
        federation_policy,
        signing_key,
    )?;
    let manifest_bytes = file_bytes(MANIFEST_FILE, &manifest)?;
    fs::write(output.join(MANIFEST_FILE), manifest_bytes)
        .map_err(|error| BundleVerifyError::io(format!("cannot write {MANIFEST_FILE}: {error}")))?;
    let envelope_bytes = file_bytes(ENVELOPE_FILE, &envelope)?;
    fs::write(output.join(ENVELOPE_FILE), envelope_bytes)
        .map_err(|error| BundleVerifyError::io(format!("cannot write {ENVELOPE_FILE}: {error}")))?;
    Ok(manifest)
}

/// Sign the commitment to `manifest` and the decoded payload.
pub fn sign_envelope(
    manifest: &EvidenceExportManifest,
    bundle: &EvidenceExportBundle,
    transparency: Option<&CheckpointTransparencySummary>,
    federation_policy: Option<&FederationPolicyDocument>,
    signing_key: &Keypair,
) -> Result<EvidencePackageEnvelope, BundleVerifyError> {
    SignedExportEnvelope::sign(
        ExportCommitment {
            schema: EVIDENCE_EXPORT_COMMITMENT_SCHEMA.to_string(),
            manifest_sha256: manifest_sha256(manifest)?,
            payload_sha256: payload_sha256(bundle, transparency, federation_policy)?,
        },
        signing_key,
    )
    .map_err(|error| {
        BundleVerifyError::envelope(format!("cannot sign the export envelope: {error}"))
    })
}
