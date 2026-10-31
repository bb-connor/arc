//! Bounded, zeroizing reads of private signing seeds held in a seed file or a
//! systemd credential.

use std::ffi::{OsStr, OsString};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Custody policy variable: `required` refuses plaintext seed files, while
/// `development` or unset allows them. Any other value is a configuration error.
pub const KEY_CUSTODY_ENV: &str = "CHIO_KEY_CUSTODY";
/// Directory systemd fills from `LoadCredential=` and `LoadCredentialEncrypted=`.
pub const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
const CREDENTIAL_PREFIX: &[u8] = b"credential:";
const CREDENTIAL_NAME_MAX_BYTES: usize = 255;

/// Where a signing seed is held.
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
    #[error("credential references are read-only; provision the seed with systemd-creds and LoadCredentialEncrypted=")]
    ReadOnlyCustody,
}

#[derive(Debug, thiserror::Error)]
pub enum SeedReadError {
    #[error(transparent)]
    Custody(#[from] KeyCustodyError),
    /// A seed file outside private custody; the message names the violated rule.
    #[error("{0}")]
    UnsafeFile(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Resolves key references under a custody policy and reads the seeds they name.
pub trait SeedSource {
    /// Parse `reference` and refuse it when the custody policy forbids it.
    fn resolve(&self, reference: &Path) -> Result<KeyRef, KeyCustodyError>;

    /// Read the seed `key` names, bounded and wiped on every exit path.
    fn read_seed(
        &self,
        key: &KeyRef,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SeedReadError>;
}

/// Seeds held in private files and systemd credentials of this process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsSeedSource {
    policy: CustodyPolicy,
    credentials_directory: Option<OsString>,
}

impl OsSeedSource {
    #[must_use]
    pub fn new(policy: CustodyPolicy, credentials_directory: Option<OsString>) -> Self {
        Self {
            policy,
            credentials_directory,
        }
    }

    /// Policy from `CHIO_KEY_CUSTODY` and credentials from `CREDENTIALS_DIRECTORY`.
    pub fn from_env() -> Result<Self, KeyCustodyError> {
        Ok(Self::new(
            CustodyPolicy::from_value(std::env::var_os(KEY_CUSTODY_ENV).as_deref())?,
            std::env::var_os(CREDENTIALS_DIRECTORY_ENV),
        ))
    }
}

impl SeedSource for OsSeedSource {
    fn resolve(&self, reference: &Path) -> Result<KeyRef, KeyCustodyError> {
        let key = KeyRef::parse(reference)?;
        self.policy.check(&key)?;
        Ok(key)
    }

    fn read_seed(
        &self,
        key: &KeyRef,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SeedReadError> {
        self.policy.check(key)?;
        match key {
            KeyRef::File(path) => read_custody(path, maximum_bytes, Custody::PrivateFile),
            KeyRef::SystemdCredential { name } => {
                let directory = Path::new(
                    self.credentials_directory
                        .as_deref()
                        .ok_or(KeyCustodyError::CredentialsDirectoryUnset)?,
                );
                if !directory.is_absolute() {
                    return Err(KeyCustodyError::CredentialsDirectoryNotAbsolute.into());
                }
                let custody = match self.policy {
                    CustodyPolicy::AllowFiles => Custody::Credential,
                    CustodyPolicy::RequireOsCustody => Custody::SystemdCredential,
                };
                read_custody(&directory.join(name), maximum_bytes, custody)
            }
        }
    }
}

/// Read a seed file private to this user, bounded and wiped on every exit path.
pub fn read_private_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SeedReadError> {
    read_custody(path, maximum_bytes, Custody::PrivateFile)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Custody {
    /// Seed file private to this user.
    PrivateFile,
    /// Credential private to this user or held by systemd.
    Credential,
    /// Credential on systemd's read-only credential mount.
    SystemdCredential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeedFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

fn read_custody(
    path: &Path,
    maximum_bytes: usize,
    custody: Custody,
) -> Result<Zeroizing<Vec<u8>>, SeedReadError> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_path_metadata(&path_metadata, custody)?;
    let expected_identity = seed_file_identity(&path_metadata);

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
    if seed_file_identity(&opened_metadata) != expected_identity {
        return Err(SeedReadError::UnsafeFile(
            "authority seed changed while it was opened",
        ));
    }

    let capacity = maximum_bytes
        .checked_add(1)
        .ok_or(SeedReadError::UnsafeFile(
            "invalid signing custody byte limit",
        ))?;
    // Fixed storage never releases secret-bearing allocations during growth.
    let mut bytes = Zeroizing::new(vec![0; capacity]);
    let mut filled = 0;
    while filled < bytes.len() {
        let remaining = bytes.get_mut(filled..).ok_or(SeedReadError::UnsafeFile(
            "signing custody read exceeds its byte limit",
        ))?;
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
        return Err(SeedReadError::UnsafeFile(
            "authority seed exceeds its byte limit",
        ));
    }

    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_path_metadata(&final_path_metadata, custody)?;
    if seed_file_identity(&final_path_metadata) != expected_identity
        || seed_file_identity(&file.metadata()?) != expected_identity
    {
        bytes.fill(0);
        return Err(SeedReadError::UnsafeFile(
            "authority seed identity changed while it was read",
        ));
    }
    Ok(bytes)
}

fn validate_path_metadata(metadata: &fs::Metadata, custody: Custody) -> Result<(), SeedReadError> {
    match custody {
        Custody::PrivateFile => validate_private_metadata(metadata),
        Custody::Credential | Custody::SystemdCredential if is_single_regular_file(metadata) => {
            Ok(())
        }
        Custody::Credential | Custody::SystemdCredential => {
            Err(KeyCustodyError::CredentialCustodyRefused.into())
        }
    }
}

/// A credential held by systemd is root-owned, read-only and granted to this
/// user through its ACL, or, without ACL support, private to this user on the
/// read-only credential mount. Development custody also accepts a private file.
fn validate_opened_custody(
    file: &File,
    metadata: &fs::Metadata,
    custody: Custody,
) -> Result<(), SeedReadError> {
    let private = validate_private_metadata(metadata);
    let held = match custody {
        Custody::PrivateFile => return private,
        Custody::Credential => private.is_ok(),
        Custody::SystemdCredential => {
            private.is_ok() && crate::credentials::is_on_credential_mount(file)?
        }
    };
    #[cfg(unix)]
    let held = held
        || crate::credentials::is_systemd_credential(file, rustix::process::geteuid().as_raw())?;
    if held {
        Ok(())
    } else {
        Err(KeyCustodyError::CredentialCustodyRefused.into())
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

fn validate_private_metadata(metadata: &fs::Metadata) -> Result<(), SeedReadError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SeedReadError::UnsafeFile(
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
            return Err(SeedReadError::UnsafeFile(
                "authority seed must be singly linked with mode 0600 or stricter",
            ));
        }
    }
    Ok(())
}

fn seed_file_identity(metadata: &fs::Metadata) -> SeedFileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    SeedFileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

#[cfg(test)]
#[path = "seed_custody_tests.rs"]
mod tests;
