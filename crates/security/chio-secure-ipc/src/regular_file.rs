//! Bounded reads of operator files under an owner and mode policy.

use std::fs::{File, Metadata};
use std::path::Path;

use zeroize::Zeroizing;

/// Who may own an operator file and which permission bits it may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPolicy {
    /// The content is verified after the read (signed input), so any owner
    /// and mode is accepted.
    Authenticated,
    /// Authority-granting configuration: owned by this user or root, and
    /// neither group nor world writable (sshd `StrictModes`).
    Trusted,
    /// A secret: owned by this user, with no mode bit outside owner read and
    /// write, and no second hard link.
    Private,
}

/// Why [`open_regular`] or [`read_regular_file`] refused a path.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegularFileError {
    #[error("file does not exist")]
    Missing,
    #[error("path is a symbolic link")]
    SymbolicLink,
    #[error("path is not a regular file")]
    NotRegular,
    #[error("file is owned by uid {uid}, which the policy does not allow")]
    ForeignOwner { uid: u32 },
    #[error("file is writable by group or other (mode {mode:o})")]
    Writable { mode: u32 },
    #[error("file mode {mode:o} grants more than owner read and write")]
    Exposed { mode: u32 },
    #[error("file has {links} hard links")]
    MultiplyLinked { links: u64 },
    #[error("file exceeds {max_bytes} bytes")]
    TooLarge { max_bytes: usize },
    #[error("file cannot be read: {0}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for RegularFileError {
    fn from(error: std::io::Error) -> Self {
        #[cfg(unix)]
        if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
            return Self::SymbolicLink;
        }
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::Missing,
            kind => Self::Io(kind),
        }
    }
}

/// Opens the regular file at `path` if it satisfies `policy`.
///
/// The open refuses a final-component symbolic link and never blocks on a
/// FIFO or device. The type, owner and mode checks run on the opened
/// descriptor, so a path replaced after the open cannot change what is
/// checked or read.
#[cfg(unix)]
pub fn open_regular(path: &Path, policy: OpenPolicy) -> Result<(File, Metadata), RegularFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(RegularFileError::NotRegular);
    }
    check_ownership(
        policy,
        metadata.uid(),
        metadata.mode(),
        metadata.nlink(),
        rustix::process::geteuid().as_raw(),
    )?;
    #[cfg(feature = "test-support")]
    test_support::before_read(&metadata);
    Ok((file, metadata))
}

#[cfg(not(unix))]
pub fn open_regular(
    _path: &Path,
    _policy: OpenPolicy,
) -> Result<(File, Metadata), RegularFileError> {
    Err(RegularFileError::Io(std::io::ErrorKind::Unsupported))
}

/// Reads the regular file [`open_regular`] opens at `path` under `policy`.
/// See [`read_opened`].
pub fn read_regular_file(
    path: &Path,
    max_bytes: usize,
    policy: OpenPolicy,
) -> Result<Zeroizing<Vec<u8>>, RegularFileError> {
    let (file, _) = open_regular(path, policy)?;
    read_opened(file, max_bytes)
}

/// Reads `file` from its current offset, refusing it as
/// [`RegularFileError::TooLarge`] once it holds more than `max_bytes` bytes.
/// At most `max_bytes + 1` bytes are read. Every buffer that held file bytes
/// is wiped when it is dropped, on success and on every refusal, and a buffer
/// that must grow is copied into a larger one rather than reallocated.
pub(crate) fn read_opened(
    file: File,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, RegularFileError> {
    use std::io::Read;

    let ceiling = max_bytes.saturating_add(1);
    let expected = usize::try_from(file.metadata()?.len()).unwrap_or(usize::MAX);
    let mut buffer = Zeroizing::new(Vec::with_capacity(
        expected.min(max_bytes).saturating_add(1),
    ));
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    let mut reader = file.take(u64::try_from(ceiling).unwrap_or(u64::MAX));
    loop {
        let read = match reader.read(chunk.as_mut_slice()) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let bytes = chunk.get(..read).unwrap_or_default();
        if buffer.capacity().saturating_sub(buffer.len()) < bytes.len() {
            let needed = buffer.len().saturating_add(bytes.len());
            let mut grown = Zeroizing::new(Vec::with_capacity(
                buffer
                    .capacity()
                    .saturating_mul(2)
                    .max(needed)
                    .min(ceiling.max(needed)),
            ));
            grown.extend_from_slice(&buffer);
            buffer = grown;
        }
        buffer.extend_from_slice(bytes);
    }
    if buffer.len() > max_bytes {
        return Err(RegularFileError::TooLarge { max_bytes });
    }
    Ok(buffer)
}

/// The owner, mode and link rule of `policy` for a file owned by `uid` with
/// `st_mode` `mode` and `links` hard links, read by `euid`.
pub(crate) fn check_ownership(
    policy: OpenPolicy,
    uid: u32,
    mode: u32,
    links: u64,
    euid: u32,
) -> Result<(), RegularFileError> {
    let permissions = mode & 0o7777;
    match policy {
        OpenPolicy::Authenticated => Ok(()),
        OpenPolicy::Trusted if uid != euid && uid != 0 => {
            Err(RegularFileError::ForeignOwner { uid })
        }
        OpenPolicy::Private if uid != euid => Err(RegularFileError::ForeignOwner { uid }),
        OpenPolicy::Trusted if permissions & 0o022 != 0 => {
            Err(RegularFileError::Writable { mode: permissions })
        }
        OpenPolicy::Private if permissions & !0o600 != 0 => {
            Err(RegularFileError::Exposed { mode: permissions })
        }
        OpenPolicy::Private if links > 1 => Err(RegularFileError::MultiplyLinked { links }),
        OpenPolicy::Trusted | OpenPolicy::Private => Ok(()),
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
