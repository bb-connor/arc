//! Private provisioning artifacts. Permissions are set and checked through
//! the descriptor that was opened without following symlinks, never by
//! re-resolving a path that may since name another file.
use super::*;

pub(super) fn validate_private_handle(
    file: &File,
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<(), CliError> {
    let metadata = file.metadata().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be a regular file"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
            return Err(CliError::cli_other_error(format!(
                "{label} must be singly linked with mode 0600"
            )));
        }
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} is empty or exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

/// Sets mode 0600 through the descriptor and validates that descriptor. The
/// path only labels errors, so an entry replaced after open is not touched.
pub(super) fn restrict_private_file(file: &File, path: &Path, label: &str) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = file.metadata().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect {label} {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(CliError::cli_other_error(format!(
                "{label} must be a singly linked regular file"
            )));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to set private permissions on {}: {error}",
                    path.display()
                ))
            })?;
    }
    validate_private_handle(file, path, MAX_MIGRATION_DATABASE_BYTES, label)
}

#[cfg(unix)]
pub(super) fn require_private_directory_metadata(
    metadata: &std::fs::Metadata,
    operator: u32,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != operator {
        return Err(tampered(
            "demo output directory is not owned by the provisioning user",
        ));
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(tampered("demo output directory mode is not 0700"));
    }
    Ok(())
}
