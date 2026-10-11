use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    flock, mkdirat, openat, statat, unlinkat, AtFlags, FileType, FlockOperation, Mode, OFlags,
};

use super::{SnapshotBackingError, SnapshotCustodyRefusal, SnapshotLocationRefusal};

/// Ownership and permission rule a held directory must keep satisfying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Policy {
    /// Owned by the effective user or root; writable by others only when
    /// sticky.
    Ancestor,
    /// The receipt store's own data directory: the ancestor rule, or also
    /// group-writable when not writable by others. It holds only the private
    /// snapshot parent, whose identity is held and rechecked.
    DataDirectory,
    /// Owned by the effective user with mode 0700.
    Private,
}

pub(super) struct DirectoryCustody {
    pub(super) path: PathBuf,
    pub(super) handle: File,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) owner: u32,
    policy: Policy,
}

impl DirectoryCustody {
    fn from_handle(
        path: PathBuf,
        handle: File,
        owner: u32,
        policy: Policy,
    ) -> Result<Self, SnapshotBackingError> {
        let metadata = handle.metadata()?;
        validate_metadata(&metadata, owner, policy)?;
        let directory = Self {
            path,
            handle,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner,
            policy,
        };
        directory.validate()?;
        Ok(directory)
    }

    pub(super) fn validate(&self) -> Result<(), SnapshotBackingError> {
        for metadata in [self.handle.metadata()?, fs::symlink_metadata(&self.path)?] {
            validate_metadata(&metadata, self.owner, self.policy)?;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(SnapshotBackingError::Refused(
                    SnapshotCustodyRefusal::DirectoryIdentity,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn validate_entry(
        &self,
        parent: &DirectoryCustody,
    ) -> Result<(), SnapshotBackingError> {
        parent.validate()?;
        self.validate()?;
        let name = self.path.file_name().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingDirectoryName,
        ))?;
        let metadata = statat(&parent.handle, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        if metadata.st_dev != self.device || metadata.st_ino != self.inode {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::DirectoryEntryIdentity,
            ));
        }
        Ok(())
    }

    /// Create one snapshot directory in the locked snapshot parent and take
    /// its lifetime lock. The caller holds the parent lock, so no reclaimer
    /// can observe the new entry before its lock is held.
    pub(super) fn create_private(parent: &DirectoryCustody) -> Result<Self, SnapshotBackingError> {
        parent.validate()?;
        let name = uuid::Uuid::now_v7().hyphenated().to_string();
        mkdirat(&parent.handle, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(std::io::Error::from)?;
        // Capture the new no-follow entry before allocating another descriptor.
        // The guard can remove it under EMFILE with only the held parent.
        let mut staged = StagedPrivateDirectory::capture(parent, &name)?;
        #[cfg(test)]
        pause::reached(&parent.path.join(&name));
        let handle = openat(&parent.handle, &name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(std::io::Error::from)?;
        let directory = Self::from_handle(
            parent.path.join(&name),
            handle,
            parent.owner,
            Policy::Private,
        )?;
        directory.validate_entry(parent)?;
        staged.validate_opened(&directory.handle)?;
        // Held by this handle for the custody's lifetime; the kernel releases
        // it when the process dies, however it dies.
        flock(&directory.handle, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        staged.active = false;
        Ok(directory)
    }

    /// A set-group-ID data directory passes that bit to the parent this
    /// process just created; reset the new parent to exactly 0700. Anything
    /// else at that name is left for validation to refuse.
    fn clear_inherited_mode(
        base: &DirectoryCustody,
        name: &str,
    ) -> Result<(), SnapshotBackingError> {
        let handle = openat(&base.handle, name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(std::io::Error::from)?;
        let metadata = rustix::fs::fstat(&handle).map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == base.owner
        {
            rustix::fs::fchmod(&handle, Mode::RWXU).map_err(std::io::Error::from)?;
        }
        Ok(())
    }

    /// Open, or create, the versioned private parent that holds every
    /// snapshot directory. An existing entry that is not a private directory
    /// of the effective user is left untouched and refused as unusable.
    /// Without `create`, a missing parent is `None`.
    pub(super) fn open_snapshot_parent(
        base: &DirectoryCustody,
        name: &str,
        create: bool,
    ) -> Result<Option<Self>, SnapshotBackingError> {
        base.validate()?;
        match statat(&base.handle, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT && !create => return Ok(None),
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(&base.handle, name, Mode::RWXU) {
                    Ok(()) => Self::clear_inherited_mode(base, name)?,
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
            Ok(_) => {}
        }
        let metadata =
            statat(&base.handle, name, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != base.owner
            || metadata.st_mode & 0o7777 != 0o700
        {
            return Err(SnapshotBackingError::Unusable(
                SnapshotLocationRefusal::ForeignParent,
            ));
        }
        let handle = openat(&base.handle, name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(std::io::Error::from)?;
        let parent = Self::from_handle(base.path.join(name), handle, base.owner, Policy::Private)?;
        parent.validate_entry(base)?;
        if parent.device != metadata.st_dev || parent.inode != metadata.st_ino {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::DirectoryEntryIdentity,
            ));
        }
        Ok(Some(parent))
    }

    pub(super) fn remove_empty(
        &self,
        parent: &DirectoryCustody,
    ) -> Result<(), SnapshotBackingError> {
        self.validate_entry(parent)?;
        let name = self.path.file_name().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingDirectoryName,
        ))?;
        unlinkat(&parent.handle, name, AtFlags::REMOVEDIR).map_err(std::io::Error::from)?;
        Ok(())
    }
}

/// Cleanup of an exclusively created directory before its handle is open.
/// Capturing its identity uses statat, which needs no additional descriptor.
/// Failure to capture an identity leaves the entry conservatively untouched.
pub(super) struct StagedPrivateDirectory<'a> {
    parent: &'a DirectoryCustody,
    name: &'a str,
    device: u64,
    inode: u64,
    active: bool,
}

impl<'a> StagedPrivateDirectory<'a> {
    pub(super) fn validate_opened(&self, handle: &File) -> Result<(), SnapshotBackingError> {
        let metadata = handle.metadata()?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::DirectoryEntryIdentity,
            ));
        }
        Ok(())
    }

    pub(super) fn capture(
        parent: &'a DirectoryCustody,
        name: &'a str,
    ) -> Result<Self, SnapshotBackingError> {
        parent.validate()?;
        let metadata = statat(&parent.handle, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != parent.owner
            || metadata.st_mode & 0o7777 != 0o700
        {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::PrivateDirectory,
            ));
        }
        Ok(Self {
            parent,
            name,
            device: metadata.st_dev,
            inode: metadata.st_ino,
            active: true,
        })
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SnapshotBackingError> {
        if !self.active {
            return Ok(());
        }
        self.parent.validate()?;
        let metadata = statat(&self.parent.handle, self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        if metadata.st_dev != self.device || metadata.st_ino != self.inode {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::DirectoryEntryIdentity,
            ));
        }
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != self.parent.owner
            || metadata.st_mode & 0o7777 != 0o700
        {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::PrivateDirectory,
            ));
        }
        unlinkat(&self.parent.handle, self.name, AtFlags::REMOVEDIR)
            .map_err(std::io::Error::from)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for StagedPrivateDirectory<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Hold every directory from `/` to `parent` under the strict ancestor rule.
pub(super) fn open_parents(parent: &Path) -> Result<Vec<DirectoryCustody>, SnapshotBackingError> {
    open_held(parent, Policy::Ancestor)
}

/// Hold every directory from `/` to the receipt store's own data directory.
/// Ancestors keep the strict rule; only the data directory itself may also be
/// group-writable.
pub(super) fn open_data_directory(
    directory: &Path,
) -> Result<Vec<DirectoryCustody>, SnapshotBackingError> {
    open_held(directory, Policy::DataDirectory)
}

fn open_held(parent: &Path, last: Policy) -> Result<Vec<DirectoryCustody>, SnapshotBackingError> {
    if !parent.is_absolute() {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::AbsoluteParent,
        ));
    }
    let owner = rustix::process::geteuid().as_raw();
    let handle = openat(rustix::fs::CWD, "/", directory_flags(), Mode::empty())
        .map(File::from)
        .map_err(std::io::Error::from)?;
    let mut directories = vec![DirectoryCustody::from_handle(
        PathBuf::from("/"),
        handle,
        owner,
        Policy::Ancestor,
    )?];
    let mut components = parent.components().peekable();
    while let Some(component) = components.next() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(SnapshotBackingError::Refused(
                    SnapshotCustodyRefusal::NormalizedParent,
                ))
            }
        };
        let ancestor = directories.last().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingParent,
        ))?;
        ancestor.validate()?;
        let handle = openat(&ancestor.handle, name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(std::io::Error::from)?;
        let policy = if components.peek().is_none() {
            last
        } else {
            Policy::Ancestor
        };
        let directory =
            DirectoryCustody::from_handle(ancestor.path.join(name), handle, owner, policy)?;
        directory.validate_entry(ancestor)?;
        directories.push(directory);
    }
    validate_parents(&directories)?;
    Ok(directories)
}

pub(super) fn validate_parents(parents: &[DirectoryCustody]) -> Result<(), SnapshotBackingError> {
    let mut previous = None;
    for directory in parents {
        directory.validate()?;
        if let Some(parent) = previous {
            directory.validate_entry(parent)?;
        }
        previous = Some(directory);
    }
    Ok(())
}

pub(super) fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn validate_metadata(
    metadata: &fs::Metadata,
    owner: u32,
    policy: Policy,
) -> Result<(), SnapshotBackingError> {
    if !metadata.is_dir() {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::NotDirectory,
        ));
    }
    let mode = metadata.mode();
    let sticky = mode & 0o1000 != 0;
    let owned = metadata.uid() == owner || metadata.uid() == 0;
    let refusal = match policy {
        Policy::Private => (metadata.uid() != owner || mode & 0o7777 != 0o700)
            .then_some(SnapshotCustodyRefusal::PrivateDirectory),
        Policy::Ancestor => (!owned || (mode & 0o022 != 0 && !sticky))
            .then_some(SnapshotCustodyRefusal::UnsafeAncestor),
        Policy::DataDirectory => (!owned || (mode & 0o002 != 0 && !sticky))
            .then_some(SnapshotCustodyRefusal::UnsafeAncestor),
    };
    match refusal {
        Some(refusal) => Err(SnapshotBackingError::Refused(refusal)),
        None => Ok(()),
    }
}

/// A test-only pause between publishing a snapshot directory and taking its
/// lifetime lock, scoped to the provisioning thread.
#[cfg(test)]
pub(super) mod pause {
    use std::cell::RefCell;
    use std::path::Path;

    type Hook = Box<dyn FnMut(&Path)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Run `hook` with the new directory's path whenever this thread has
    /// created a snapshot directory and not yet locked it.
    pub(in super::super) fn on_this_thread(hook: impl FnMut(&Path) + 'static) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn reached(path: &Path) {
        HOOK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }
}
