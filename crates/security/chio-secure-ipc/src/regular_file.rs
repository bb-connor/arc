//! Bounded reads of operator files under an owner and mode policy.

use std::fs::{File, Metadata};
use std::path::Path;

/// Who may own and write a file before its bytes are used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilePolicy {
    /// Secrets and keys: owned by this user, with no group or other access.
    Private,
    /// Authority-granting configuration: owned by this user or root, and
    /// neither group nor world writable (sshd `StrictModes`).
    Trusted,
}

#[derive(Debug, thiserror::Error)]
pub enum RegularFileError {
    #[error("file is a symbolic link")]
    Symlink,
    #[error("file is not a regular file")]
    NotRegular,
    #[error("file is owned by a user its policy does not accept")]
    ForeignOwner,
    #[error("file is group or world writable")]
    Writable,
    #[error("file grants group or other access")]
    Exposed,
    /// The path named a different file at open than at the check.
    #[error("file was replaced while it was opened")]
    Replaced,
    #[error("file is larger than {max_bytes} bytes")]
    TooLarge { max_bytes: usize },
    #[error("file could not be read: {0}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for RegularFileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// Opens the regular file at `path` under `policy`.
///
/// The path is checked with `lstat`, opened with `O_NOFOLLOW` and
/// `O_NONBLOCK` (a FIFO never blocks the open), and the opened descriptor is
/// checked again: it must be the same regular file the path named, and its
/// owner and mode must satisfy `policy`. A missing file is
/// `Io(ErrorKind::NotFound)`.
#[cfg(unix)]
pub fn open_regular(path: &Path, policy: FilePolicy) -> Result<(File, Metadata), RegularFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let named = std::fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() {
        return Err(RegularFileError::Symlink);
    }
    if !named.file_type().is_file() {
        return Err(RegularFileError::NotRegular);
    }
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| RegularFileError::Io(std::io::ErrorKind::InvalidInput))?;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            return Err(RegularFileError::Symlink);
        }
        Err(error) => return Err(error.into()),
    };
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(RegularFileError::NotRegular);
    }
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(RegularFileError::Replaced);
    }
    check_policy(
        policy,
        opened.uid(),
        opened.mode(),
        rustix::process::geteuid().as_raw(),
    )?;
    #[cfg(feature = "test-support")]
    test_support::before_read(&opened);
    Ok((file, opened))
}

#[cfg(not(unix))]
pub fn open_regular(
    _path: &Path,
    _policy: FilePolicy,
) -> Result<(File, Metadata), RegularFileError> {
    Err(RegularFileError::Io(std::io::ErrorKind::Unsupported))
}

/// Reads the regular file [`open_regular`] opens at `path` under `policy`,
/// refusing it as [`RegularFileError::TooLarge`] once it holds more than
/// `max_bytes` bytes. At most `max_bytes + 1` bytes are read.
pub fn read_regular(
    path: &Path,
    policy: FilePolicy,
    max_bytes: usize,
) -> Result<Vec<u8>, RegularFileError> {
    use std::io::Read;

    let (file, _) = open_regular(path, policy)?;
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(RegularFileError::TooLarge { max_bytes });
    }
    Ok(bytes)
}

/// The owner and mode rule of `policy`, for a file owned by `uid` with
/// `mode`, read by `euid`.
fn check_policy(
    policy: FilePolicy,
    uid: u32,
    mode: u32,
    euid: u32,
) -> Result<(), RegularFileError> {
    match policy {
        FilePolicy::Private if uid != euid => Err(RegularFileError::ForeignOwner),
        FilePolicy::Private if mode & 0o077 != 0 => Err(RegularFileError::Exposed),
        FilePolicy::Trusted if uid != euid && uid != 0 => Err(RegularFileError::ForeignOwner),
        FilePolicy::Trusted if mode & 0o022 != 0 => Err(RegularFileError::Writable),
        FilePolicy::Private | FilePolicy::Trusted => Ok(()),
    }
}

/// A hook run with the device and inode of each file [`open_regular`]
/// accepts, before any read, so tests can hold a read open at a chosen file.
#[cfg(all(unix, feature = "test-support"))]
pub mod test_support {
    use std::os::unix::fs::MetadataExt;
    use std::sync::OnceLock;

    static HOOK: OnceLock<fn(u64, u64)> = OnceLock::new();

    /// Installs `hook` for the process. The first installed hook stays.
    pub fn set_read_hook(hook: fn(u64, u64)) {
        let _ = HOOK.set(hook);
    }

    pub(super) fn before_read(metadata: &std::fs::Metadata) {
        if let Some(hook) = HOOK.get() {
            hook(metadata.dev(), metadata.ino());
        }
    }
}

#[cfg(all(test, unix))]
#[path = "regular_file/tests.rs"]
mod tests;
