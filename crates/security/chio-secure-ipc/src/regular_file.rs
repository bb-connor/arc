//! Bounded reads of operator files that refuse anything but a regular file.

/// Who may own and write a file before its bytes are trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPolicy {
    /// The content is verified after the read (signed input), so any owner
    /// and mode is accepted.
    Authenticated,
    /// Authority configuration: owned by this user or root, and neither group
    /// nor world writable.
    Trusted,
    /// Secret material: owned by this user, with no group or world access.
    Private,
}

/// Opens the regular file at `path` under `policy`.
///
/// The open refuses a final-component symbolic link (`ELOOP`) and never
/// blocks on a FIFO or device; anything but a regular file is refused with
/// [`std::io::ErrorKind::InvalidInput`], and an owner or mode `policy` does
/// not accept with [`std::io::ErrorKind::PermissionDenied`]. A missing file
/// keeps [`std::io::ErrorKind::NotFound`].
#[cfg(unix)]
pub fn open_regular(path: &std::path::Path, policy: OpenPolicy) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
    let flags = i32::try_from(flags.bits()).map_err(std::io::Error::other)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    let accepted = match policy {
        OpenPolicy::Authenticated => true,
        OpenPolicy::Trusted => {
            (metadata.uid() == euid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0
        }
        OpenPolicy::Private => metadata.uid() == euid && metadata.mode() & 0o077 == 0,
    };
    if !accepted {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "input owner or mode is not accepted by its open policy",
        ));
    }
    #[cfg(feature = "test-support")]
    test_support::before_read(&metadata);
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_regular(
    _path: &std::path::Path,
    _policy: OpenPolicy,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "regular file reads require nonblocking no-follow opens",
    ))
}

/// Reads at most `max_bytes + 1` bytes of the regular file [`open_regular`]
/// opens at `path` under `policy`, so a decoder bounded at `max_bytes` sees an
/// oversized file as too large.
pub fn read_regular_file(
    path: &std::path::Path,
    policy: OpenPolicy,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    open_regular(path, policy)?
        .take(limit)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// A hook run with the device and inode of each regular file
/// [`open_regular`] accepts, before any read, so
/// tests can hold a read open at a chosen file.
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
