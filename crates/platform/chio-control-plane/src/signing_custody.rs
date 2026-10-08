//! Existing private signing custody with bounded reads and zeroizing ownership.
use crate::{CliError, Keypair};
use std::path::Path;
#[cfg(not(unix))]
use std::{
    fs::{self, OpenOptions},
    io::Read,
};

/// Load existing seed-file signing custody without creating or repairing it.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed_bytes = read_private_signing_custody(path, 256)?;
    let seed_hex = std::str::from_utf8(&seed_bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8"))?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

/// Signing custody is a regular file owned by the effective user, singly
/// linked, with mode 0600 or stricter.
#[cfg(unix)]
const SIGNING_CUSTODY_POLICY: chio_secure_fs::OwnerPolicy = chio_secure_fs::OwnerPolicy {
    owner: chio_secure_fs::Owner::EffectiveUser,
    forbidden_mode: 0o177,
    require_single_link: true,
    reject_acl: false,
};

/// Read existing private signing custody, bounded and wiped on every exit path.
#[cfg(unix)]
pub fn read_private_signing_custody(
    path: &Path,
    maximum_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    chio_secure_fs::read_private_file(path, &SIGNING_CUSTODY_POLICY, maximum_bytes)
        .map(|(bytes, _)| bytes)
        .map_err(signing_custody_error)
}

#[cfg(unix)]
fn signing_custody_error(error: std::io::Error) -> CliError {
    use chio_secure_fs::Refusal;

    let message = match chio_secure_fs::refusal(&error) {
        Some(Refusal::NotRegularFile) => "authority seed must be a regular file",
        Some(Refusal::Owner | Refusal::Mode | Refusal::LinkCount) => {
            "authority seed must be singly linked with mode 0600 or stricter"
        }
        Some(Refusal::ChangedWhileOpening) => "authority seed changed while it was opened",
        Some(Refusal::TooLarge) => "authority seed exceeds its byte limit",
        Some(Refusal::ChangedWhileReading) => "authority seed identity changed while it was read",
        _ => return CliError::Io(error),
    };
    CliError::cli_io_error(message)
}

/// Read existing private signing custody, bounded and wiped on every exit path.
#[cfg(not(unix))]
pub fn read_private_signing_custody(
    path: &Path,
    maximum_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let expected_length = regular_seed_length(&fs::symlink_metadata(path)?)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    if regular_seed_length(&file.metadata()?)? != expected_length {
        return Err(CliError::cli_io_error(
            "authority seed changed while it was opened",
        ));
    }

    let capacity = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| CliError::cli_io_error("invalid signing custody byte limit"))?;
    // Fixed storage never releases secret-bearing allocations during growth.
    let mut bytes = zeroize::Zeroizing::new(vec![0; capacity]);
    let mut filled = 0;
    while filled < bytes.len() {
        let remaining = bytes
            .get_mut(filled..)
            .ok_or_else(|| CliError::cli_io_error("signing custody read exceeds its byte limit"))?;
        match file.read(remaining) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bytes.truncate(filled);
    if bytes.len() > maximum_bytes {
        bytes.fill(0);
        return Err(CliError::cli_io_error(
            "authority seed exceeds its byte limit",
        ));
    }

    if regular_seed_length(&fs::symlink_metadata(path)?)? != expected_length
        || regular_seed_length(&file.metadata()?)? != expected_length
    {
        bytes.fill(0);
        return Err(CliError::cli_io_error(
            "authority seed identity changed while it was read",
        ));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn regular_seed_length(metadata: &fs::Metadata) -> Result<u64, CliError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_io_error(
            "authority seed must be a regular file",
        ));
    }
    Ok(metadata.len())
}
