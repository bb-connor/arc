use std::fs;
use std::path::Path;

use crate::CliError;

use super::types::SignedCertificationCheck;
use super::verify::verify_signed_certification_check;

pub(crate) fn unix_now() -> Result<u64, chio_security_types::clock::ClockError> {
    use chio_security_types::clock::{Clock, SystemClock};
    SystemClock.unix_millis().map(|now| now.as_secs())
}

pub(crate) fn normalize_registry_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub(crate) fn require_certification_discovery_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::attest_error(
            "certification discovery requires --certification-discovery-file when not using --control-url"
                .to_string(),
        )
    })
}

pub(crate) fn require_existing_dir(path: &Path, label: &str) -> Result<(), CliError> {
    if !path.exists() {
        return Err(CliError::attest_error(format!(
            "{label} directory does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::attest_error(format!(
            "{label} path must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub(crate) fn load_signed_certification_check(
    path: &Path,
) -> Result<SignedCertificationCheck, CliError> {
    let artifact: SignedCertificationCheck = crate::signed_input::read(path)?;
    verify_signed_certification_check(&artifact)?;
    Ok(artifact)
}
