//! Signed package production using an explicitly supplied kernel identity.

use super::*;

pub(super) fn write_evidence_package(
    output: &Path,
    bundle: EvidenceExportBundle,
    transparency: Option<CheckpointTransparencySummary>,
    policy_file: Option<&Path>,
    federation_policy: Option<&FederationPolicyDocument>,
    signing_key: &chio_core::Keypair,
) -> Result<(), CliError> {
    let clock_now = unix_now()?;
    ensure_clean_output_dir(output)?;
    let transparency = match transparency {
        Some(summary) => {
            verify_checkpoint_transparency_records(
                &bundle.checkpoints,
                &summary.publications,
                &summary.witnesses,
                &summary.consistency_proofs,
                &summary.equivocations,
            )?;
            summary
        }
        None => validate_checkpoint_transparency_summary(&bundle.checkpoints)?,
    };
    let claim_boundary = build_evidence_transparency_claims(&bundle, &transparency, None);
    let disclosure_notice = maybe_build_disclosure_notice(&bundle.query);

    let mut file_hashes = Vec::new();
    write_ndjson_file(
        output,
        "uncheckpointed-receipts.ndjson",
        &bundle.uncheckpointed_receipts,
        &mut file_hashes,
    )?;
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
        "checkpoint-publications.ndjson",
        &transparency.publications,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-witnesses.ndjson",
        &transparency.witnesses,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-consistency-proofs.ndjson",
        &transparency.consistency_proofs,
        &mut file_hashes,
    )?;
    write_ndjson_file(
        output,
        "checkpoint-equivocations.ndjson",
        &transparency.equivocations,
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
        render_readme(
            &bundle,
            &transparency,
            &claim_boundary,
            disclosure_notice.as_ref(),
        )
        .as_bytes(),
        &mut file_hashes,
    )?;

    let policy = if let Some(policy_file) = policy_file {
        let source_bytes = fs::read(policy_file)?;
        let source_path = policy_source_relative_path(policy_file);
        write_bytes_file(output, &source_path, &source_bytes, &mut file_hashes)?;
        let metadata = policy_metadata(
            policy_file,
            &source_path,
            crate::integer::count(source_bytes.len()),
        )?;
        write_json_file(output, "policy/metadata.json", &metadata, &mut file_hashes)?;
        Some(metadata)
    } else {
        None
    };

    let federation_policy_attachment = if let Some(policy) = federation_policy {
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
        tool_receipts: crate::integer::count(bundle.tool_receipts.len()),
        child_receipts: crate::integer::count(bundle.child_receipts.len()),
        checkpoints: crate::integer::count(bundle.checkpoints.len()),
        capability_lineage: crate::integer::count(bundle.capability_lineage.len()),
        inclusion_proofs: crate::integer::count(bundle.inclusion_proofs.len()),
        uncheckpointed_receipts: crate::integer::count(bundle.uncheckpointed_receipts.len()),
    };
    let proof_coverage = EvidenceProofCoverage {
        checkpointed_receipts: counts
            .tool_receipts
            .saturating_sub(counts.uncheckpointed_receipts),
        uncheckpointed_receipts: counts.uncheckpointed_receipts,
    };
    let receipt_semantics = evidence_receipt_semantic_summary(&bundle.tool_receipts);
    let manifest = EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at: clock_now,
        query: bundle.query.clone(),
        counts,
        proof_coverage,
        receipt_semantics,
        child_receipt_scope: bundle.child_receipt_scope,
        claim_boundary: Some(claim_boundary),
        files: file_hashes,
        policy,
        federation_policy: federation_policy_attachment,
        disclosure_notice,
    };
    package_io::verify_inventory(&manifest)?;
    let envelope = envelope::sign(
        &manifest,
        &bundle,
        Some(&transparency),
        federation_policy,
        signing_key,
    )?;
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    fs::write(
        output.join("export-envelope.json"),
        serde_json::to_vec_pretty(&envelope)?,
    )?;
    Ok(())
}
