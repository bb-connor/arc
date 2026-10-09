use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags};

use super::{SnapshotBackingError, SnapshotCustodyRefusal};

pub(super) struct DirectoryCustody {
    pub(super) path: PathBuf,
    pub(super) handle: File,
    device: u64,
    inode: u64,
    owner: u32,
    private: bool,
}

impl DirectoryCustody {
    fn from_handle(
        path: PathBuf,
        handle: File,
        owner: u32,
        private: bool,
    ) -> Result<Self, SnapshotBackingError> {
        let metadata = handle.metadata()?;
        validate_metadata(&metadata, owner, private)?;
        let directory = Self {
            path,
            handle,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner,
            private,
        };
        directory.validate()?;
        Ok(directory)
    }

    pub(super) fn validate(&self) -> Result<(), SnapshotBackingError> {
        for metadata in [self.handle.metadata()?, fs::symlink_metadata(&self.path)?] {
            validate_metadata(&metadata, self.owner, self.private)?;
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

    pub(super) fn create_private(parent: &DirectoryCustody) -> Result<Self, SnapshotBackingError> {
        parent.validate()?;
        let name = format!("chio-receipt-snapshot-{}", uuid::Uuid::now_v7());
        mkdirat(&parent.handle, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(std::io::Error::from)?;
        // Capture the new no-follow entry before allocating another descriptor.
        // The guard can remove it under EMFILE with only the held parent.
        let mut staged = StagedPrivateDirectory::capture(parent, &name)?;
        let handle = openat(&parent.handle, &name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(std::io::Error::from)?;
        let directory = Self::from_handle(parent.path.join(&name), handle, parent.owner, true)?;
        directory.validate_entry(parent)?;
        staged.validate_opened(&directory.handle)?;
        staged.active = false;
        Ok(directory)
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

pub(super) fn open_parents(parent: &Path) -> Result<Vec<DirectoryCustody>, SnapshotBackingError> {
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
        false,
    )?];
    for component in parent.components() {
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
        let directory =
            DirectoryCustody::from_handle(ancestor.path.join(name), handle, owner, false)?;
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

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn validate_metadata(
    metadata: &fs::Metadata,
    owner: u32,
    private: bool,
) -> Result<(), SnapshotBackingError> {
    if !metadata.is_dir() {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::NotDirectory,
        ));
    }
    if private {
        if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::PrivateDirectory,
            ));
        }
    } else if (metadata.uid() != owner && metadata.uid() != 0)
        || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
    {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::UnsafeAncestor,
        ));
    }
    Ok(())
}
