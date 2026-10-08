use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::error::{invalid_path, refuse, Refusal};
use crate::file::{entry_metadata, FileIdentity};
use crate::policy::OwnerPolicy;
use crate::walk;

const TEMPORARY_ATTEMPTS: usize = 128;

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The destination state a publish requires immediately before staging and
/// again immediately before its rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expect {
    /// No entry exists under the destination name.
    Absent,
    /// The destination is a regular file satisfying the publish policy with
    /// exactly this identity.
    Identity(FileIdentity),
    /// Any destination entry is replaced; a missing one is created.
    Replace,
}

/// Opens a directory for descriptor-relative publishing without following a
/// final symlink.
pub fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        walk::read_flags(),
        Mode::empty(),
    )?))
}

/// Opens a lock file in `directory` read-write, creating it with `mode`
/// (subject to the process umask) when missing, without following a symlink
/// or truncating it, and checks it against `policy`.
pub fn open_lock_at(
    directory: &File,
    name: &OsStr,
    mode: u32,
    policy: &OwnerPolicy,
) -> io::Result<File> {
    single_component(name)?;
    let mode = walk::permission_mode(mode)?;
    let file = File::from(openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        mode,
    )?);
    let metadata = file.metadata()?;
    policy.check_file(&metadata, &file)?;
    Ok(file)
}

/// Atomically replaces `name` in `directory` with a new file holding
/// `contents`.
///
/// `directory` must be a directory opened for reading. The contents are staged
/// in a new exclusive temporary file created with `mode` (subject to the
/// process umask), flushed, checked against `policy`, and renamed over `name`
/// only if the destination still matches `expect`. The directory is flushed
/// and the published entry must be the staged file. On failure the temporary
/// file is removed.
pub fn publish_at(
    directory: &File,
    name: &OsStr,
    contents: &[u8],
    mode: u32,
    expect: Expect,
    policy: &OwnerPolicy,
) -> io::Result<FileIdentity> {
    single_component(name)?;
    let mode = walk::permission_mode(mode)?;
    check_destination(directory, name, expect, policy)?;
    let (temporary, mut file) = create_temporary(directory, name, mode)?;
    let result = stage_and_rename(
        directory, name, &temporary, &mut file, contents, expect, policy,
    );
    if result.is_err() {
        drop(file);
        let _ = unlinkat(directory, temporary.as_os_str(), AtFlags::empty());
    }
    result
}

fn stage_and_rename(
    directory: &File,
    name: &OsStr,
    temporary: &OsStr,
    file: &mut File,
    contents: &[u8],
    expect: Expect,
    policy: &OwnerPolicy,
) -> io::Result<FileIdentity> {
    file.write_all(contents)?;
    file.sync_all()?;
    let staged = file.metadata()?;
    policy.check_file(&staged, file)?;
    check_destination(directory, name, expect, policy)?;
    renameat(directory, temporary, directory, name)?;
    walk::sync_directory(directory)?;
    let published = entry_metadata(directory, name)?.ok_or_else(destination_changed)?;
    let identity = FileIdentity::of(&published);
    if !identity.same_object(&FileIdentity::of(&staged)) {
        return Err(destination_changed());
    }
    Ok(identity)
}

fn check_destination(
    directory: &File,
    name: &OsStr,
    expect: Expect,
    policy: &OwnerPolicy,
) -> io::Result<()> {
    if expect == Expect::Replace {
        return Ok(());
    }
    match (expect, entry_metadata(directory, name)?) {
        (Expect::Absent, None) | (Expect::Replace, _) => Ok(()),
        (Expect::Absent, Some(_)) => Err(refuse(
            io::ErrorKind::AlreadyExists,
            Refusal::DestinationExists,
            "private file destination already exists",
        )),
        (Expect::Identity(_), None) => Err(refuse(
            io::ErrorKind::NotFound,
            Refusal::DestinationChanged,
            "private file destination is missing",
        )),
        (Expect::Identity(expected), Some(metadata)) => {
            policy.check_file_metadata(&metadata)?;
            if FileIdentity::of(&metadata) != expected {
                return Err(destination_changed());
            }
            Ok(())
        }
    }
}

fn create_temporary(directory: &File, name: &OsStr, mode: Mode) -> io::Result<(OsString, File)> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut candidate = OsString::from(".");
        candidate.push(name);
        candidate.push(format!(".{}.{counter}.tmp", std::process::id()));
        match openat(
            directory,
            candidate.as_os_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            mode,
        ) {
            Ok(descriptor) => return Ok((candidate, File::from(descriptor))),
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate a unique private temporary file",
    ))
}

/// Refuses anything but one normal path component.
pub(crate) fn single_component(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == name => Ok(()),
        _ => Err(invalid_path(
            "private entry name must be one normal path component",
        )),
    }
}

fn destination_changed() -> io::Error {
    refuse(
        io::ErrorKind::InvalidData,
        Refusal::DestinationChanged,
        "private file destination identity changed",
    )
}
