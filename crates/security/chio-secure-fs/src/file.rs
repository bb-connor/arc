use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{openat, Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::error::{refuse, Refusal};
use crate::policy::OwnerPolicy;

/// The device, inode and length that identify one version of a file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
}

impl FileIdentity {
    /// The identity recorded in `metadata`.
    #[must_use]
    pub fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
        }
    }

    #[must_use]
    pub fn device(&self) -> u64 {
        self.device
    }

    #[must_use]
    pub fn inode(&self) -> u64 {
        self.inode
    }

    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// A regular file opened read-only without following symlinks and checked
/// against a policy.
#[derive(Debug)]
pub struct PrivateFile {
    file: File,
    identity: FileIdentity,
}

impl PrivateFile {
    pub(crate) fn open_at(
        directory: &File,
        name: &OsStr,
        policy: &OwnerPolicy,
    ) -> io::Result<Self> {
        let file = File::from(openat(directory, name, read_file_flags(), Mode::empty())?);
        let metadata = file.metadata()?;
        policy.check_file(&metadata, &file)?;
        Ok(Self {
            file,
            identity: FileIdentity::of(&metadata),
        })
    }

    /// The identity observed when the file was opened.
    #[must_use]
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }

    /// Reads at most `max_len` bytes into wiped storage and refuses a file
    /// that is longer or whose identity changed while it was read.
    pub fn read_bounded(&mut self, max_len: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        let bytes = read_bounded(&mut self.file, max_len)?;
        if FileIdentity::of(&self.file.metadata()?) != self.identity {
            return Err(changed_while_reading());
        }
        Ok(bytes)
    }
}

/// Reads an existing private file by path.
///
/// The path is checked without following a final symlink, opened without
/// following one, checked again through the descriptor, read within
/// `max_len` bytes into wiped storage, and checked once more by path and by
/// descriptor. Any identity change between those observations refuses.
pub fn read_private_file(
    path: &Path,
    policy: &OwnerPolicy,
    max_len: usize,
) -> io::Result<(Zeroizing<Vec<u8>>, FileIdentity)> {
    let path_metadata = fs::symlink_metadata(path)?;
    policy.check_file_metadata(&path_metadata)?;
    let expected = FileIdentity::of(&path_metadata);

    let mut file = File::from(rustix::fs::open(path, read_file_flags(), Mode::empty())?);
    let opened = file.metadata()?;
    policy.check_file(&opened, &file)?;
    if FileIdentity::of(&opened) != expected {
        return Err(refuse(
            io::ErrorKind::InvalidData,
            Refusal::ChangedWhileOpening,
            "private file changed while it was opened",
        ));
    }

    let bytes = read_bounded(&mut file, max_len)?;

    let final_metadata = fs::symlink_metadata(path)?;
    policy.check_file_metadata(&final_metadata)?;
    if FileIdentity::of(&final_metadata) != expected
        || FileIdentity::of(&file.metadata()?) != expected
    {
        return Err(changed_while_reading());
    }
    Ok((bytes, expected))
}

/// The identity of an existing private file, checked by path without
/// following a final symlink. A policy that rejects ACLs is refused, since an
/// ACL can only be read through an open descriptor.
pub fn private_file_identity(path: &Path, policy: &OwnerPolicy) -> io::Result<FileIdentity> {
    policy.require_no_acl_rule()?;
    let metadata = fs::symlink_metadata(path)?;
    policy.check_file_metadata(&metadata)?;
    Ok(FileIdentity::of(&metadata))
}

/// The metadata of one directory entry without following a symlink, or
/// `None` when the entry is absent.
///
/// Linux and Android observe any entry type through a path-only descriptor.
/// Elsewhere the entry is opened for reading, so an entry that cannot be
/// opened that way, such as a symlink or a socket, is reported as an error.
pub fn entry_metadata(directory: &File, name: &OsStr) -> io::Result<Option<Metadata>> {
    match openat(directory, name, entry_flags(), Mode::empty()) {
        Ok(descriptor) => File::from(descriptor).metadata().map(Some),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn read_bounded(file: &mut File, max_len: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let capacity = max_len
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid private file limit"))?;
    // Fixed storage never releases secret-bearing allocations during growth.
    let mut bytes = Zeroizing::new(vec![0; capacity]);
    let mut filled = 0;
    while filled < bytes.len() {
        let remaining = bytes
            .get_mut(filled..)
            .ok_or_else(|| io::Error::other("private file read exceeds its buffer"))?;
        match file.read(remaining) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    bytes.truncate(filled);
    if bytes.len() > max_len {
        return Err(refuse(
            io::ErrorKind::InvalidData,
            Refusal::TooLarge,
            "private file exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn changed_while_reading() -> io::Error {
    refuse(
        io::ErrorKind::InvalidData,
        Refusal::ChangedWhileReading,
        "private file identity changed while it was read",
    )
}

/// Nonblocking, so a FIFO swapped in for the file cannot stall the open.
fn read_file_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn entry_flags() -> OFlags {
    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn entry_flags() -> OFlags {
    read_file_flags()
}
