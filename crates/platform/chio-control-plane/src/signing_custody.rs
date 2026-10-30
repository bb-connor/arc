//! Existing private signing custody with bounded reads and zeroizing ownership.
use crate::{CliError, Keypair};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

/// Custody policy variable: `required` refuses plaintext seed files, while
/// `development` or unset allows them. Any other value is a configuration error.
pub const KEY_CUSTODY_ENV: &str = "CHIO_KEY_CUSTODY";
/// Directory systemd fills from `LoadCredential=` and `LoadCredentialEncrypted=`.
const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
const CREDENTIAL_PREFIX: &[u8] = b"credential:";
const CREDENTIAL_NAME_MAX_BYTES: usize = 255;
const AUTHORITY_SEED_MAX_BYTES: usize = 256;

/// Where an authority seed is held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyRef {
    /// Plaintext seed file private to this user.
    File(PathBuf),
    /// systemd credential `<name>` under `$CREDENTIALS_DIRECTORY`.
    SystemdCredential { name: String },
}

impl KeyRef {
    /// `credential:<name>` names a systemd credential; every other path is a seed file.
    pub fn parse(raw: &Path) -> Result<Self, KeyCustodyError> {
        let Some(name) = raw
            .as_os_str()
            .as_encoded_bytes()
            .strip_prefix(CREDENTIAL_PREFIX)
        else {
            return Ok(Self::File(raw.to_path_buf()));
        };
        if name.is_empty()
            || name.len() > CREDENTIAL_NAME_MAX_BYTES
            || name == b"."
            || name == b".."
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(KeyCustodyError::InvalidCredentialName);
        }
        let name = std::str::from_utf8(name).map_err(|_| KeyCustodyError::InvalidCredentialName)?;
        Ok(Self::SystemdCredential {
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub fn is_os_custody(&self) -> bool {
        !matches!(self, Self::File(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPolicy {
    AllowFiles,
    RequireOsCustody,
}

impl CustodyPolicy {
    /// Unset is the development default; every other value must match
    /// exactly, so a malformed policy never weakens custody.
    pub fn from_value(value: Option<&OsStr>) -> Result<Self, KeyCustodyError> {
        match value.map(OsStr::to_str) {
            None | Some(Some("development")) => Ok(Self::AllowFiles),
            Some(Some("required")) => Ok(Self::RequireOsCustody),
            Some(_) => Err(KeyCustodyError::InvalidPolicy),
        }
    }

    pub fn from_env() -> Result<Self, KeyCustodyError> {
        Self::from_value(std::env::var_os(KEY_CUSTODY_ENV).as_deref())
    }

    pub fn check(self, key: &KeyRef) -> Result<(), KeyCustodyError> {
        if self == Self::RequireOsCustody && !key.is_os_custody() {
            return Err(KeyCustodyError::NotOsCustody);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KeyCustodyError {
    #[error("credential reference must be credential:<name> with a name of [A-Za-z0-9._-]")]
    InvalidCredentialName,
    #[error("CHIO_KEY_CUSTODY must be unset, `development` or `required`")]
    InvalidPolicy,
    #[error("key custody policy requires OS custody; refusing a plaintext seed file")]
    NotOsCustody,
    #[error("CREDENTIALS_DIRECTORY is not set; deliver the seed with LoadCredential= or LoadCredentialEncrypted=")]
    CredentialsDirectoryUnset,
    #[error("CREDENTIALS_DIRECTORY must be an absolute path")]
    CredentialsDirectoryNotAbsolute,
    #[error("systemd credential must be a singly linked regular file in systemd custody or private to this user")]
    CredentialCustodyRefused,
}

/// Load existing signing custody without creating or repairing it.
/// `path` is a key reference: `credential:<name>` or a seed file path.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    let key = KeyRef::parse(path)?;
    let policy = CustodyPolicy::from_env()?;
    load_authority_keypair(
        &key,
        policy,
        std::env::var_os(CREDENTIALS_DIRECTORY_ENV).as_deref(),
    )
}

fn load_authority_keypair(
    key: &KeyRef,
    policy: CustodyPolicy,
    credentials_directory: Option<&OsStr>,
) -> Result<Keypair, CliError> {
    let seed_bytes =
        read_key_custody(key, policy, credentials_directory, AUTHORITY_SEED_MAX_BYTES)?;
    let seed_hex = std::str::from_utf8(&seed_bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8"))?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

fn read_key_custody(
    key: &KeyRef,
    policy: CustodyPolicy,
    credentials_directory: Option<&OsStr>,
    maximum_bytes: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    policy.check(key)?;
    match key {
        KeyRef::File(path) => read_custody(path, maximum_bytes, Custody::PrivateFile),
        KeyRef::SystemdCredential { name } => {
            let directory =
                Path::new(credentials_directory.ok_or(KeyCustodyError::CredentialsDirectoryUnset)?);
            if !directory.is_absolute() {
                return Err(KeyCustodyError::CredentialsDirectoryNotAbsolute.into());
            }
            read_custody(
                &directory.join(name),
                maximum_bytes,
                Custody::SystemdCredential,
            )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Custody {
    PrivateFile,
    SystemdCredential,
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
    read_custody(path, maximum_bytes, Custody::PrivateFile)
}

fn read_custody(
    path: &Path,
    maximum_bytes: usize,
    custody: Custody,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_path_metadata(&path_metadata, custody)?;
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
    validate_opened_custody(&file, &opened_metadata, custody)?;
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

    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_path_metadata(&final_path_metadata, custody)?;
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

fn validate_path_metadata(metadata: &fs::Metadata, custody: Custody) -> Result<(), CliError> {
    match custody {
        Custody::PrivateFile => validate_authority_seed_metadata(metadata),
        Custody::SystemdCredential if is_single_regular_file(metadata) => Ok(()),
        Custody::SystemdCredential => Err(KeyCustodyError::CredentialCustodyRefused.into()),
    }
}

/// A credential is either private to this user or held by systemd: root-owned,
/// read-only and granted to this user through its ACL.
fn validate_opened_custody(
    file: &File,
    metadata: &fs::Metadata,
    custody: Custody,
) -> Result<(), CliError> {
    match custody {
        Custody::PrivateFile => validate_authority_seed_metadata(metadata),
        Custody::SystemdCredential => {
            if validate_authority_seed_metadata(metadata).is_ok() {
                return Ok(());
            }
            #[cfg(unix)]
            if chio_secure_ipc::credentials::is_systemd_credential(
                file,
                rustix::process::geteuid().as_raw(),
            )? {
                return Ok(());
            }
            #[cfg(not(unix))]
            let _ = file;
            Err(KeyCustodyError::CredentialCustodyRefused.into())
        }
    }
}

fn is_single_regular_file(metadata: &fs::Metadata) -> bool {
    let regular = metadata.file_type().is_file() && !metadata.file_type().is_symlink();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        regular && metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    regular
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

#[cfg(test)]
#[path = "signing_custody_tests.rs"]
mod tests;
