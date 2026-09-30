//! Existing private signing custody with bounded reads and zeroizing ownership.
use crate::{CliError, Keypair};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

/// Load existing seed-file signing custody without creating or repairing it.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed_bytes = read_private_signing_custody(path, 256)?;
    let seed_hex = std::str::from_utf8(&seed_bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8"))?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthoritySeedFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

/// Read existing private signing custody, bounded and wiped on every exit path.
pub fn read_private_signing_custody(
    path: &Path,
    maximum_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_authority_seed_metadata(&path_metadata)?;
    let expected_identity = authority_seed_file_identity(&path_metadata);

    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path)?;

    let opened_metadata = file.metadata()?;
    validate_authority_seed_metadata(&opened_metadata)?;
    if authority_seed_file_identity(&opened_metadata) != expected_identity {
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
        match file.read(&mut bytes[filled..]) {
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

    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_authority_seed_metadata(&final_path_metadata)?;
    if authority_seed_file_identity(&final_path_metadata) != expected_identity
        || authority_seed_file_identity(&file.metadata()?) != expected_identity
    {
        bytes.fill(0);
        return Err(CliError::cli_io_error(
            "authority seed identity changed while it was read",
        ));
    }
    Ok(bytes)
}

fn validate_authority_seed_metadata(metadata: &fs::Metadata) -> Result<(), CliError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_io_error(
            "authority seed must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.nlink() != 1
            || metadata.mode() & 0o177 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(CliError::cli_io_error(
                "authority seed must be singly linked with mode 0600 or stricter",
            ));
        }
    }
    Ok(())
}

fn authority_seed_file_identity(metadata: &fs::Metadata) -> AuthoritySeedFileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    AuthoritySeedFileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
    }
}
