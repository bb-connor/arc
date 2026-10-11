//! Disk transport for the common authenticated package verifier.

use super::verification::*;
use super::*;

pub(super) fn verify_manifest_file_hashes(
    input_dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !seen.insert(file.path.as_str()) {
            return Err(CliError::attest_error(format!(
                "duplicate file entry in evidence manifest: {}",
                file.path
            )));
        }
        let bytes = package_io::read_bytes(input_dir, &file.path)?;
        let actual_hash = sha256_hex(&bytes);
        let actual_bytes = crate::integer::count(bytes.len());
        if actual_hash != file.sha256 {
            return Err(CliError::attest_error(format!(
                "evidence package file hash mismatch for {}",
                file.path
            )));
        }
        if actual_bytes != file.bytes {
            return Err(CliError::attest_error(format!(
                "evidence package byte length mismatch for {}",
                file.path
            )));
        }
    }
    Ok(())
}

pub(super) fn load_verified_evidence_package(
    input: &Path,
    verification: &EvidenceVerificationPolicy,
) -> Result<EvidenceImportPackage, CliError> {
    verification.validate()?;
    ensure_existing_dir(input, "evidence package")?;
    let envelope: envelope::PackageEnvelope = read_json_file(input, "export-envelope.json")
        .map_err(|error| {
            CliError::attest_error(format!(
                "invalid or missing evidence export envelope: {error}"
            ))
        })?;
    let manifest: EvidenceExportManifest = read_json_file(input, "manifest.json")?;
    envelope::verify_manifest(&envelope, &manifest, verification)?;
    package_io::verify_inventory(&manifest)?;
    verify_manifest_file_hashes(input, &manifest)?;
    verify_policy_attachment(input, &manifest)?;
    verify_federation_policy_attachment(input, &manifest)?;
    let bundle = EvidenceExportBundle {
        query: read_json_file(input, "query.json")?,
        tool_receipts: read_ndjson_file(input, "receipts.ndjson")?,
        child_receipts: read_ndjson_file(input, "child-receipts.ndjson")?,
        child_receipt_scope: manifest.child_receipt_scope,
        checkpoints: read_ndjson_file(input, "checkpoints.ndjson")?,
        capability_lineage: read_ndjson_file(input, "capability-lineage.ndjson")?,
        inclusion_proofs: read_ndjson_file(input, "inclusion-proofs.ndjson")?,
        uncheckpointed_receipts: read_ndjson_file(input, "uncheckpointed-receipts.ndjson")?,
        retention: read_json_file(input, "retention.json")?,
    };
    let transparency = Some(CheckpointTransparencySummary {
        publications: read_ndjson_file(input, "checkpoint-publications.ndjson")?,
        witnesses: read_ndjson_file(input, "checkpoint-witnesses.ndjson")?,
        consistency_proofs: read_ndjson_file(input, "checkpoint-consistency-proofs.ndjson")?,
        equivocations: read_ndjson_file(input, "checkpoint-equivocations.ndjson")?,
    });
    let federation_policy = if manifest.federation_policy.is_some() {
        Some(read_json_file(input, federation_policy_relative_path())?)
    } else {
        None
    };
    let package = EvidenceImportPackage {
        envelope,
        manifest,
        bundle,
        transparency,
        federation_policy,
    };
    validate_import_package_data(&package, verification)?;
    Ok(package)
}

pub fn load_verified_evidence_package_summary(
    input: &Path,
    verification: &EvidenceVerificationPolicy,
) -> Result<VerifiedEvidencePackage, CliError> {
    let package = load_verified_evidence_package(input, verification)?;
    let manifest_hash = sha256_hex(&canonical_json_bytes(&package.manifest)?);
    Ok(VerifiedEvidencePackage {
        bundle: package.bundle,
        transparency: package.transparency,
        manifest_schema: package.manifest.schema,
        exported_at: package.manifest.exported_at,
        manifest_hash,
    })
}
