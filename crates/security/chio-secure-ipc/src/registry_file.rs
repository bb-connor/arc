//! Single-writer registry files replaced atomically under an exclusive lock.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use crate::LifecycleLock;

#[derive(Debug, thiserror::Error)]
pub enum RegistryFileError {
    #[error("the registry file is being written by another writer; nothing was changed, retry")]
    Busy,
    #[error("registry files can be written only where an exclusive writer lock is available")]
    Unsupported,
    #[error("registry path has no file name")]
    NoFileName,
    #[error(
        "registry file `{}` is a symbolic link; registries are written only at their own path",
        .0.display()
    )]
    SymlinkDestination(PathBuf),
    #[error(
        "registry lock `{}` is not a private regular file of this user with one link",
        .0.display()
    )]
    LockNotPrivate(PathBuf),
    /// Nothing was replaced; a temporary this write created is removed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The new file is in place, but the directory sync after the rename
    /// failed, so the rename may not survive a crash.
    #[error("registry file was replaced but not made durable: {0}")]
    PersistedWithoutDurability(#[source] std::io::Error),
}

/// Exclusive writer lock for one registry file, and the only way to replace it.
///
/// The lock is a `flock` on `.<file name>.lock` in the registry's canonical
/// directory. That file is never replaced, so every path naming the registry
/// through that directory contends on one inode. Writers on other hosts
/// sharing a network filesystem are not excluded.
#[must_use = "dropping the lock releases the registry"]
pub struct RegistryFile {
    #[cfg(unix)]
    _lock: LifecycleLock,
    destination: PathBuf,
}

impl RegistryFile {
    /// Takes the writer lock of the registry at `path`, creating its parent
    /// directory. A destination that is a symbolic link is refused, because a
    /// replace would swap the link rather than the file it names. Without the
    /// lock this returns [`RegistryFileError::Busy`] at once, never waiting.
    #[cfg(unix)]
    pub fn lock(path: &Path) -> Result<Self, RegistryFileError> {
        use std::os::unix::fs::OpenOptionsExt;
        let file_name = path.file_name().ok_or(RegistryFileError::NoFileName)?;
        std::fs::create_dir_all(parent_of(path))?;
        let directory = std::fs::canonicalize(parent_of(path))?;
        let destination = directory.join(file_name);
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RegistryFileError::SymlinkDestination(destination));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let lock_path = directory.join(format!(".{}.lock", file_name.to_string_lossy()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)?;
        check_lock_identity(&lock_path, &file)?;
        let lock = match LifecycleLock::try_exclusive(file) {
            Ok(lock) => lock,
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(RegistryFileError::Busy),
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        check_lock_identity(&lock_path, lock.file())?;
        Ok(Self {
            _lock: lock,
            destination,
        })
    }

    #[cfg(not(unix))]
    pub fn lock(_path: &Path) -> Result<Self, RegistryFileError> {
        Err(RegistryFileError::Unsupported)
    }

    /// The canonical path of the registry this lock guards; every read and
    /// write under the lock uses it.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Replaces the registry with `bytes`: an exclusively created sibling, no
    /// more permissive than the file it replaces, is synced and renamed into
    /// place, then the directory is synced. A failure before the rename
    /// removes only that sibling and leaves the prior file intact.
    pub fn replace(&self, bytes: &[u8]) -> Result<(), RegistryFileError> {
        replace_with(&self.destination, bytes, &temporary_nonce(), &|_| Ok(()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplaceStage {
    BeforeRename,
    DirectorySync,
}

/// `nonce` names the temporary sibling; `inject` can fail a stage.
fn replace_with(
    path: &Path,
    bytes: &[u8],
    nonce: &str,
    inject: &dyn Fn(ReplaceStage) -> std::io::Result<()>,
) -> Result<(), RegistryFileError> {
    let directory = parent_of(path);
    let file_name = path
        .file_name()
        .ok_or(RegistryFileError::NoFileName)?
        .to_string_lossy();
    let temporary = directory.join(format!(".{file_name}.{nonce}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mode = match std::fs::symlink_metadata(path) {
            Ok(existing) => existing.mode() & 0o600,
            Err(_) => 0o600,
        };
        options.mode(mode);
    }
    let mut file = options.open(&temporary)?;
    let committed = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        inject(ReplaceStage::BeforeRename)?;
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = committed {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    inject(ReplaceStage::DirectorySync)
        .and_then(|()| sync_directory(directory))
        .map_err(RegistryFileError::PersistedWithoutDurability)
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn temporary_nonce() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// The lock file is a private regular file of this user with one link, and
/// `file` is that file.
#[cfg(unix)]
fn check_lock_identity(lock_path: &Path, file: &std::fs::File) -> Result<(), RegistryFileError> {
    use std::os::unix::fs::MetadataExt;
    let at_path = std::fs::symlink_metadata(lock_path)?;
    let held = file.metadata()?;
    let private = crate::regular_file::check_ownership(
        crate::regular_file::OpenPolicy::Private,
        held.uid(),
        held.mode(),
        held.nlink(),
        rustix::process::geteuid().as_raw(),
    );
    if !at_path.file_type().is_file()
        || !held.file_type().is_file()
        || (at_path.dev(), at_path.ino()) != (held.dev(), held.ino())
        || private.is_err()
    {
        return Err(RegistryFileError::LockNotPrivate(lock_path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?
        .sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "registry_file/tests.rs"]
mod tests;
