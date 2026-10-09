use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use chio_sqlite_file_identity::{inspect_main_database_file_identity, SqliteFileIdentity};
use rusqlite::Connection;
use rustix::fs::{openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags};

use super::directory::{open_parents, validate_parents, DirectoryCustody};
use super::{SnapshotBackingError, SnapshotCustodyRefusal};

const DATABASE_NAME: &str = "snapshot.sqlite3";

pub(super) struct FileCustody {
    parents: Vec<DirectoryCustody>,
    pub(super) directory: DirectoryCustody,
    pub(super) database_path: PathBuf,
    // This descriptor must outlive the owned SQLite connection, including any
    // failed open/configuration path, to preserve SQLite's process-wide locks.
    file: File,
    identity: SqliteFileIdentity,
    owner: u32,
    cleaned: bool,
}

impl FileCustody {
    pub(super) fn create_in(parent: &Path) -> Result<Self, SnapshotBackingError> {
        let parents = open_parents(parent)?;
        let parent = parents.last().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingParent,
        ))?;
        let directory = DirectoryCustody::create_private(parent)?;
        let descriptor = match openat(
            &directory.handle,
            DATABASE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let _ = directory.remove_empty(parent);
                return Err(std::io::Error::from(error).into());
            }
        };
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        let custody = Self {
            database_path: directory.path.join(DATABASE_NAME),
            parents,
            directory,
            file,
            identity: file_identity(&metadata),
            owner: rustix::process::geteuid().as_raw(),
            cleaned: false,
        };
        custody.validate_filesystem()?;
        Ok(custody)
    }

    pub(super) fn validate_filesystem(&self) -> Result<(), SnapshotBackingError> {
        self.validate_directories()?;
        for metadata in [
            self.file.metadata()?,
            fs::symlink_metadata(&self.database_path)?,
        ] {
            validate_file(&metadata, self.owner)?;
            if file_identity(&metadata) != self.identity {
                return Err(SnapshotBackingError::Refused(
                    SnapshotCustodyRefusal::FileIdentity,
                ));
            }
        }
        let metadata = statat(
            &self.directory.handle,
            DATABASE_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != self.owner
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
            || metadata.st_dev != self.identity.device
            || metadata.st_ino != self.identity.inode
        {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::LeafIdentity,
            ));
        }
        self.validate_sidecars()
    }

    pub(super) fn validate_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), SnapshotBackingError> {
        self.validate_filesystem()?;
        let actual = inspect_main_database_file_identity(connection)?;
        if actual != self.identity {
            return Err(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::DescriptorIdentity,
            ));
        }
        // Recheck parents and entries after descriptor inspection, without
        // claiming the checks form an atomic filesystem operation.
        self.validate_filesystem()
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SnapshotBackingError> {
        if self.cleaned {
            return Ok(());
        }
        self.validate_filesystem()?;
        // Never recurse or delete by the configured absolute path. Both
        // unlink operations are relative to held directory descriptors.
        unlinkat(&self.directory.handle, DATABASE_NAME, AtFlags::empty())
            .map_err(std::io::Error::from)?;
        self.validate_directories()?;
        let parent = self.parents.last().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingParent,
        ))?;
        self.directory.remove_empty(parent)?;
        self.cleaned = true;
        Ok(())
    }

    fn validate_directories(&self) -> Result<(), SnapshotBackingError> {
        validate_parents(&self.parents)?;
        let parent = self.parents.last().ok_or(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MissingParent,
        ))?;
        self.directory.validate_entry(parent)
    }

    fn validate_sidecars(&self) -> Result<(), SnapshotBackingError> {
        for name in [
            "snapshot.sqlite3-wal",
            "snapshot.sqlite3-shm",
            "snapshot.sqlite3-journal",
        ] {
            match statat(&self.directory.handle, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
                Ok(_) => {
                    return Err(SnapshotBackingError::Refused(
                        SnapshotCustodyRefusal::UnexpectedSidecar,
                    ))
                }
            }
        }
        Ok(())
    }
}

impl Drop for FileCustody {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn validate_file(metadata: &fs::Metadata, owner: u32) -> Result<(), SnapshotBackingError> {
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::PrivateFile,
        ));
    }
    Ok(())
}

fn file_identity(metadata: &fs::Metadata) -> SqliteFileIdentity {
    SqliteFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
    }
}
