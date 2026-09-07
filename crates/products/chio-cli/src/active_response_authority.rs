use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(unix)]
use chio_active_response_authority::{
    build_authority_store, compute_authority_store_digest, AuthorityStoreBundle,
};
use chio_active_response_authority::ActiveDefenseDeploymentConfig;
use chio_core::canonical_json_bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::CliError;

const MAX_AUTHORITY_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(unix)]
pub(crate) fn cmd_authority_store_build(
    input_path: &Path,
    output_path: &Path,
    manifest_path: &Path,
) -> Result<(), CliError> {
    let bundle: AuthorityStoreBundle = read_canonical(input_path, "authority bundle")?;
    let manifest = build_authority_store(&bundle, output_path, manifest_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let rendered = String::from_utf8(canonical_json_bytes(&manifest).map_err(|error| {
        CliError::cli_other_error(format!("authority manifest rendering failed: {error}"))
    })?)
    .map_err(|error| {
        CliError::cli_other_error(format!("authority manifest was not UTF-8: {error}"))
    })?;
    println!("{rendered}");
    Ok(())
}

#[cfg(unix)]
pub(crate) fn cmd_authority_store_digest(input_path: &Path) -> Result<(), CliError> {
    let bundle: AuthorityStoreBundle = read_canonical(input_path, "authority bundle")?;
    let digest = compute_authority_store_digest(&bundle)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    println!("{}", hex::encode(digest.as_bytes()));
    Ok(())
}

pub(crate) fn cmd_authority_deployment_digest(input_path: &Path) -> Result<(), CliError> {
    let deployment: ActiveDefenseDeploymentConfig =
        read_canonical(input_path, "authority deployment")?;
    let digest = deployment
        .compute_deployment_digest()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    println!("{}", hex::encode(digest.as_bytes()));
    Ok(())
}

pub(crate) fn cmd_authority_deployment_validate(input_path: &Path) -> Result<(), CliError> {
    let deployment: ActiveDefenseDeploymentConfig =
        read_canonical(input_path, "authority deployment")?;
    deployment
        .validate()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    println!("{}", hex::encode(deployment.deployment_digest.as_bytes()));
    Ok(())
}

fn read_canonical<T>(input_path: &Path, label: &str) -> Result<T, CliError>
where
    T: DeserializeOwned + Serialize,
{
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(input_path)
        .map_err(|error| CliError::cli_io_error(format!("{label} open failed: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| CliError::cli_io_error(format!("{label} metadata failed: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_AUTHORITY_BUNDLE_BYTES
    {
        return Err(CliError::cli_other_error(format!(
            "{label} must be a bounded regular file"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::cli_other_error(format!("{label} size is invalid")))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_AUTHORITY_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::cli_io_error(format!("{label} read failed: {error}")))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(CliError::cli_other_error(format!(
            "{label} changed while it was read"
        )));
    }
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::cli_other_error(format!("{label} decode failed: {error}")))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| CliError::cli_other_error(format!("{label} encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} must be canonical JSON"
        )));
    }
    Ok(value)
}
