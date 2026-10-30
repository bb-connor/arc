//! Bounded reads of operator files that refuse anything but a regular file.

/// Reads at most `max_bytes + 1` bytes of the regular file at `path`, so a
/// decoder bounded at `max_bytes` sees an oversized file as too large.
///
/// The open refuses a final-component symbolic link (`ELOOP`) and never
/// blocks on a FIFO or device; anything but a regular file is refused with
/// [`std::io::ErrorKind::InvalidInput`] before a byte is read. A missing file
/// keeps [`std::io::ErrorKind::NotFound`].
#[cfg(unix)]
pub fn read_regular_file(path: &std::path::Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
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
    #[cfg(feature = "test-support")]
    test_support::before_read(&metadata);
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(not(unix))]
pub fn read_regular_file(_path: &std::path::Path, _max_bytes: usize) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "regular file reads require nonblocking no-follow opens",
    ))
}

/// A hook run with the device and inode of each regular file
/// [`read_regular_file`] opens, after the type check and before the read, so
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
