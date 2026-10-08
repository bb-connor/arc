use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{mkdirat, openat, unlinkat, AtFlags, Dir, Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::error::{refuse, Refusal};
use crate::file::{changed_while_reading, entry_metadata, FileIdentity, PrivateFile};
use crate::policy::OwnerPolicy;
use crate::publish::{open_lock_at, publish_at, Expect};
use crate::walk::{self, Existing};

/// A private directory pinned by a descriptor.
///
/// Preparation validates the whole path from `/` without following symlinks.
/// Afterwards, relative operations stay anchored to the validated directory
/// even if its pathname is renamed or replaced; [`Self::revalidate`] reports
/// whether the pathname still names it.
#[derive(Debug)]
pub struct PrivateDirectory {
    path: PathBuf,
    directory: File,
    policy: OwnerPolicy,
}

impl PrivateDirectory {
    /// Creates a missing directory, and any missing ancestors, at 0700, or
    /// checks an existing one against `policy` without changing its mode.
    ///
    /// `policy` also governs every child directory later walked through this
    /// handle.
    pub fn prepare(path: &Path, policy: &OwnerPolicy) -> io::Result<Self> {
        Self::open(path, policy, Existing::Validate)
    }

    /// Like [`Self::prepare`], but resets an existing target's mode to 0700
    /// instead of checking it.
    pub fn prepare_hardened(path: &Path, policy: &OwnerPolicy) -> io::Result<Self> {
        Self::open(path, policy, Existing::Harden)
    }

    fn open(path: &Path, policy: &OwnerPolicy, existing: Existing) -> io::Result<Self> {
        let absolute = walk::absolute_path(path)?;
        let (directory, path) = walk::prepare(&absolute, policy, existing)?;
        Ok(Self {
            path,
            directory,
            policy: *policy,
        })
    }

    /// The resolved absolute path used for preparation. Custody-sensitive
    /// operations use the pinned descriptor, never this pathname.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The policy this directory and its child directories satisfy.
    #[must_use]
    pub fn policy(&self) -> &OwnerPolicy {
        &self.policy
    }

    /// Metadata of the pinned directory.
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.directory.metadata()
    }

    /// Refuses when the prepared pathname no longer names the pinned
    /// directory. Relative operations remain safe either way, but a caller
    /// must check this before reporting that the pathname holds their results.
    pub fn revalidate(&self) -> io::Result<()> {
        let pinned = self.directory.metadata()?;
        let current = fs::symlink_metadata(&self.path)?;
        if !current.is_dir() || pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err(refuse(
                io::ErrorKind::InvalidData,
                Refusal::PathReplaced,
                format!(
                    "prepared private directory path `{}` no longer identifies the pinned directory",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    /// Reports whether the pinned directory has no entries.
    pub fn is_empty(&self) -> io::Result<bool> {
        let descriptor = openat(
            &self.directory,
            Path::new("."),
            walk::read_flags(),
            Mode::empty(),
        )?;
        for entry in Dir::new(descriptor)? {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Creates every missing directory in `relative` with `mode`, subject to
    /// the process umask. Existing and created directories must satisfy this
    /// directory's policy.
    pub fn create_dir_all(&self, relative: &Path, mode: u32) -> io::Result<()> {
        let components = walk::relative_components(relative)?;
        let mode = walk::permission_mode(mode)?;
        let mut directory = self.directory.try_clone()?;
        for component in components {
            let child = match walk::open_child_directory(&directory, component, &self.policy) {
                Ok(child) => child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let created = match mkdirat(&directory, component, mode) {
                        Ok(()) => true,
                        Err(Errno::EXIST) => false,
                        Err(error) => return Err(error.into()),
                    };
                    let child = walk::open_child_directory(&directory, component, &self.policy)?;
                    if created {
                        walk::sync_directory(&directory)?;
                    }
                    child
                }
                Err(error) => return Err(error),
            };
            directory = child;
        }
        walk::sync_directory(&directory)
    }

    /// Creates a new empty file with `mode`, subject to the process umask.
    ///
    /// Creation is exclusive and never follows a symlink. The file and its
    /// directory entry are flushed before the writable file is returned; on
    /// any failure the new entry is removed.
    pub fn create_new(&self, relative: &Path, mode: u32) -> io::Result<File> {
        self.create_and_write(relative, None, mode)
    }

    /// Creates a new file with `mode` and durably writes `contents`, under the
    /// same rules as [`Self::create_new`].
    pub fn write_new(&self, relative: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
        self.create_and_write(relative, Some(contents), mode).map(drop)
    }

    fn create_and_write(
        &self,
        relative: &Path,
        contents: Option<&[u8]>,
        mode: u32,
    ) -> io::Result<File> {
        let mode = walk::permission_mode(mode)?;
        let (directory, name) = self.parent_of(relative)?;
        let mut file = File::from(openat(
            &directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            mode,
        )?);
        let operation = contents
            .map_or(Ok(()), |contents| file.write_all(contents))
            .and_then(|()| file.sync_all())
            .and_then(|()| walk::sync_directory(&directory));
        if let Err(error) = operation {
            drop(file);
            let _ = unlinkat(&directory, name, AtFlags::empty());
            return Err(error);
        }
        Ok(file)
    }

    /// Opens an existing regular file read-only, without following a symlink
    /// or blocking on a special file, and checks it against `policy`.
    pub fn open_private(&self, relative: &Path, policy: &OwnerPolicy) -> io::Result<PrivateFile> {
        let (directory, name) = self.parent_of(relative)?;
        PrivateFile::open_at(&directory, name, policy)
    }

    /// Refuses unless `relative` still names the object `file` was opened
    /// from, with the length observed at open.
    pub fn confirm(&self, relative: &Path, file: &PrivateFile) -> io::Result<()> {
        let (directory, name) = self.parent_of(relative)?;
        let current = entry_metadata(&directory, name)?.ok_or_else(changed_while_reading)?;
        if FileIdentity::of(&current) != file.identity() {
            return Err(changed_while_reading());
        }
        Ok(())
    }

    /// Reads an existing private file within `max_len` bytes into wiped
    /// storage, refusing if the entry changes between the open and the end of
    /// the read.
    pub fn read_private(
        &self,
        relative: &Path,
        policy: &OwnerPolicy,
        max_len: usize,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut file = self.open_private(relative, policy)?;
        let bytes = file.read_bounded(max_len)?;
        self.confirm(relative, &file)?;
        Ok(bytes)
    }

    /// Opens a lock file read-write, creating it with `mode` when missing,
    /// without following a symlink, and checks it against `policy`.
    ///
    /// The file is never truncated, so an existing lock keeps its contents.
    pub fn open_lock(&self, name: &OsStr, mode: u32, policy: &OwnerPolicy) -> io::Result<File> {
        open_lock_at(&self.directory, name, mode, policy)
    }

    /// Atomically replaces `name` with a new file holding `contents`.
    ///
    /// The contents are staged in a new exclusive temporary file created with
    /// `mode`, flushed, checked against `policy`, and renamed over `name`
    /// only if the destination still matches `expect`; the directory is then
    /// flushed. Returns the identity of the published file.
    pub fn atomic_publish(
        &self,
        name: &OsStr,
        contents: &[u8],
        mode: u32,
        expect: Expect,
        policy: &OwnerPolicy,
    ) -> io::Result<FileIdentity> {
        publish_at(&self.directory, name, contents, mode, expect, policy)
    }

    /// Opens the directory that holds `relative`, walking and checking each
    /// intermediate directory, and returns it with the final entry name.
    fn parent_of<'a>(&self, relative: &'a Path) -> io::Result<(File, &'a OsStr)> {
        let components = walk::relative_components(relative)?;
        let (name, parents) = components
            .split_last()
            .ok_or_else(|| io::Error::other("private relative path must name a file"))?;
        let mut directory = self.directory.try_clone()?;
        for component in parents {
            directory = walk::open_child_directory(&directory, component, &self.policy)?;
        }
        Ok((directory, *name))
    }
}
