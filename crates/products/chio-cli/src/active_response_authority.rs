use std::path::Path;

use chio_active_response_authority::ActiveDefenseDeploymentConfig;
#[cfg(unix)]
use chio_active_response_authority::{
    build_authority_store, compute_authority_store_digest, AuthorityStoreBundle,
};
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
    let _ = label;
    let bytes = crate::input::read_regular(input_path, MAX_AUTHORITY_BUNDLE_BYTES as usize)?;
    Ok(chio_core::canonical::UntrustedJsonText::from_wire(
        &bytes,
        MAX_AUTHORITY_BUNDLE_BYTES as usize,
    )?
    .decode_canonical()?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn authority_documents_require_exact_canonical_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        std::fs::write(&path, br#"{"a":1}"#).unwrap();
        assert_eq!(
            read_canonical::<serde_json::Value>(&path, "test").unwrap()["a"],
            1
        );
        for bytes in [
            br#"{"a": 1}"#.as_slice(),
            br#"{"private-marker":1,"private-marker":2}"#,
        ] {
            std::fs::write(&path, bytes).unwrap();
            let error = read_canonical::<serde_json::Value>(&path, "test").unwrap_err();
            assert!(matches!(
                error,
                CliError::SignedJson(chio_core::canonical::UntrustedJsonError::NonCanonical)
            ));
            assert!(!error.to_string().contains("private-marker"));
        }
    }
}
