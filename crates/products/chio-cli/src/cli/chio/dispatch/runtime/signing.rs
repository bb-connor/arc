use std::path::Path;

use crate::CliError;

use super::super::{read_utf8_json_file, write_json_string, write_pretty_json};

pub(crate) fn cmd_chio_runtime_sign_trust_input(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimeVerifierTrustBundleV4 =
        crate::input::text(&read_utf8_json_file(body, "Chio runtime trust input body")?)?;
    let keypair = crate::load_existing_authority_keypair(signing_seed_file)?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio runtime trust input signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio runtime trust input")
}

pub(crate) fn cmd_chio_runtime_sign_policy(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePheromonePolicy = crate::input::text(&read_utf8_json_file(
        body,
        "Chio runtime pheromone policy body",
    )?)?;
    let keypair = crate::load_existing_authority_keypair(signing_seed_file)?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| {
            CliError::cli_other_error(format!("Chio runtime pheromone policy signing: {error}"))
        },
    )?;
    write_pretty_json(out, &signed, "Chio runtime pheromone policy")
}

pub(crate) fn cmd_chio_runtime_sign_peer_weights(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePeerWeights = crate::input::text(&read_utf8_json_file(
        body,
        "Chio runtime peer weights body",
    )?)?;
    let keypair = crate::load_existing_authority_keypair(signing_seed_file)?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio runtime peer weights signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio runtime peer weights")
}

pub(crate) fn cmd_chio_runtime_sign_pheromone_query_report(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: serde_json::Value = crate::input::text(&read_utf8_json_file(
        body,
        "Chio pheromone query report body",
    )?)?;
    chio_runtime::runtime_pheromone_advisory_from_query_report_json(
        &serde_json::to_string(&body).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone query report validation: {error}"))
        })?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone query report validation: {error}"))
    })?;
    let keypair = crate::load_existing_authority_keypair(signing_seed_file)?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio pheromone query report signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio pheromone query report")
}

pub(crate) fn cmd_chio_runtime_peer_weights_hash(body: &Path, out: &Path) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePeerWeights = crate::input::text(&read_utf8_json_file(
        body,
        "Chio runtime peer weights body",
    )?)?;
    let hash = chio_runtime::runtime_peer_weights_sha256(&body).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights hash: {error}"))
    })?;
    write_json_string(out, &format!("{hash}\n"))
}
