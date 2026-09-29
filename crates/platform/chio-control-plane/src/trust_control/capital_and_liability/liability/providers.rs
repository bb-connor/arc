use super::*;

pub fn issue_signed_liability_provider(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    report: &LiabilityProviderReport,
    supersedes_provider_record_id: Option<&str>,
) -> Result<SignedLiabilityProvider, CliError> {
    let clock_now = unix_timestamp_now()?;
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    report.validate().map_err(CliError::cli_other_error)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_provider_artifact(
        report.clone(),
        issued_at,
        supersedes_provider_record_id.map(ToOwned::to_owned),
    )?;
    let signed = SignedLiabilityProvider::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability provider artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_provider(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

fn build_liability_provider_artifact(
    report: LiabilityProviderReport,
    issued_at: u64,
    supersedes_provider_record_id: Option<String>,
) -> Result<LiabilityProviderArtifact, CliError> {
    report.validate().map_err(CliError::cli_other_error)?;
    let lifecycle_state = report.lifecycle_state;
    let provider_record_id_input = canonical_json_bytes(&(
        LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
        issued_at,
        lifecycle_state,
        &supersedes_provider_record_id,
        &report,
    ))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let provider_record_id = format!("lpr-{}", sha256_hex(&provider_record_id_input));
    Ok(LiabilityProviderArtifact {
        schema: LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_record_id,
        issued_at,
        lifecycle_state,
        supersedes_provider_record_id,
        report,
    })
}
