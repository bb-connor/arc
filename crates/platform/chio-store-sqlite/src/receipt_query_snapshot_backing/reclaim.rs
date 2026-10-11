//! Bounded reclamation of snapshot directories whose owners died without
//! unwinding.
//!
//! Every snapshot directory lives in one versioned private parent, and its
//! owner holds an exclusive `flock` on it for the custody's lifetime. The
//! kernel releases that lock when the owner dies, however it dies, so an
//! unlocked directory in the parent belongs to no live owner. Creation takes
//! the parent lock before it publishes a directory and keeps it until the
//! directory's own lock is held; every reclaimer takes the same parent lock.
//! A reclaimer therefore never observes a live directory unlocked.
//!
//! One attempt reads at most `SCAN_ENTRIES` entries and examines at most
//! `EXAMINE_DIRECTORIES` snapshot directories, with fixed memory. The next
//! attempt resumes where this one stopped, from a cursor persisted in the
//! parent, so live or foreign entries ahead of an abandoned directory cannot
//! hide it from every later attempt, across restarts included. The cursor is
//! an opaque kernel directory position: a value the kernel does not accept
//! restarts the scan from the beginning.
//!
//! Every check is relative to a held descriptor and never follows a link.
//! Only the known snapshot leaves are unlinked, and only after they validate;
//! nothing is removed recursively. Snapshot directories of earlier builds use
//! other names, have no liveness lock and are never examined.

use std::fs::File;
use std::mem::MaybeUninit;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

use rustix::fs::{
    flock, openat, seek, statat, unlinkat, AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir,
    SeekFrom,
};
use rustix::io::Errno;

use super::directory::{directory_flags, DirectoryCustody};
use super::{SnapshotBackingError, SnapshotLocationRefusal};

/// Versioned name of the private parent of every snapshot directory.
pub(super) const PARENT_NAME: &str = "chio-receipt-snapshots-v2";
const CURSOR_NAME: &str = "reclaim-cursor";
/// Directory entries one attempt reads.
const SCAN_ENTRIES: usize = 256;
/// Snapshot directories one attempt examines.
const EXAMINE_DIRECTORIES: usize = 16;
const LEAVES: [&str; 4] = [
    "snapshot.sqlite3",
    "snapshot.sqlite3-wal",
    "snapshot.sqlite3-shm",
    "snapshot.sqlite3-journal",
];

/// The exclusive parent lock, taken without waiting and released on drop.
pub(super) struct ParentLock<'a> {
    parent: &'a DirectoryCustody,
}

impl<'a> ParentLock<'a> {
    /// Contention is an operational refusal for the caller to retry.
    pub(super) fn acquire(parent: &'a DirectoryCustody) -> Result<Self, SnapshotBackingError> {
        parent.validate()?;
        match flock(&parent.handle, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { parent }),
            Err(error) if error == Errno::WOULDBLOCK => Err(SnapshotBackingError::Unusable(
                SnapshotLocationRefusal::Contended,
            )),
            Err(error) => Err(std::io::Error::from(error).into()),
        }
    }
}

impl Drop for ParentLock<'_> {
    fn drop(&mut self) {
        let _ = flock(&self.parent.handle, FlockOperation::Unlock);
    }
}

/// Counts from one attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReclaimReport {
    /// Abandoned directories removed.
    pub(crate) reclaimed: u64,
    /// Directories whose owner still holds the lifetime lock.
    pub(crate) live: u64,
    /// Snapshot-named entries left in place because they did not validate.
    pub(crate) skipped: u64,
}

/// A completed scan whose resume position is not yet persisted.
pub(super) struct Pending {
    cursor: Cursor,
    next: u64,
    report: ReclaimReport,
}

/// Scan one bounded window of the locked parent and reclaim what it finds.
/// The cursor is opened, or created, before anything is examined, so it
/// exists before any snapshot directory of this parent is created; an
/// unusable cursor is refused first.
pub(super) fn begin(
    parent: &DirectoryCustody,
    _lock: &ParentLock<'_>,
) -> Result<Pending, SnapshotBackingError> {
    let cursor = Cursor::open(parent)?;
    let (report, next) = scan(parent, cursor.cookie)?;
    Ok(Pending {
        cursor,
        next,
        report,
    })
}

/// A persisted attempt. Its cursor stays open while the caller provisions.
pub(super) struct Persisted {
    pub(super) report: ReclaimReport,
    _cursor: Cursor,
}

impl Pending {
    /// Persist where the next attempt resumes. The caller still holds the
    /// parent lock. Directories this attempt reclaimed are already gone when
    /// a failure here refuses the attempt.
    pub(super) fn finish(
        mut self,
        parent: &DirectoryCustody,
    ) -> Result<Persisted, SnapshotBackingError> {
        if self.report.reclaimed > 0 || self.report.skipped > 0 {
            tracing::warn!(
                reclaimed = self.report.reclaimed,
                live = self.report.live,
                skipped = self.report.skipped,
                parent = %parent.path.display(),
                "reclaimed receipt query snapshot directories of exited owners"
            );
        }
        self.cursor.store(parent, self.next)?;
        Ok(Persisted {
            report: self.report,
            _cursor: self.cursor,
        })
    }
}

/// The persisted resume position: one private, single-link, 8-byte file.
///
/// Every provisioning persists a whole cursor before it creates a snapshot
/// directory, and the cursor is never removed or shortened, so every
/// snapshot directory, abandoned or not, was created after a whole cursor
/// existed. Each update rewrites its 8 bytes in place, which changes no size
/// and, on a filesystem that overwrites in place, needs no new block; on a
/// copy-on-write filesystem (btrfs, ZFS) it can still need one. Either way,
/// reclamation unlinks before it updates the cursor, and a failed update is
/// an explicit refusal of that attempt.
struct Cursor {
    file: File,
    cookie: u64,
    /// Whether the file holds exactly one position.
    whole: bool,
}

impl Cursor {
    /// A cursor holding anything but a whole position (for example after a
    /// crash during its creation) starts from the beginning and is restored.
    /// A cursor entry that is not a private regular file is left untouched
    /// and refused, because no progress could be persisted through it.
    fn open(parent: &DirectoryCustody) -> Result<Self, SnapshotBackingError> {
        parent.validate()?;
        match statat(&parent.handle, CURSOR_NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == Errno::NOENT => return Self::create(parent),
            Err(error) => return Err(std::io::Error::from(error).into()),
            Ok(_) => {}
        }
        let file = match openat(&parent.handle, CURSOR_NAME, cursor_flags(), Mode::empty()) {
            Ok(descriptor) => File::from(descriptor),
            Err(error) if unusable_entry(error) => {
                return Err(SnapshotBackingError::Unusable(
                    SnapshotLocationRefusal::UnusableCursor,
                ))
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        validate_cursor(&file, parent.owner)?;
        let mut bytes = [0_u8; 9];
        let mut filled = 0;
        while filled < bytes.len() {
            let Some(rest) = bytes.get_mut(filled..) else {
                break;
            };
            let offset = u64::try_from(filled).unwrap_or(u64::MAX);
            match file.read_at(rest, offset)? {
                0 => break,
                read => filled += read,
            }
        }
        let (cookie, whole) = match (filled, bytes.first_chunk::<8>()) {
            (8, Some(position)) => (u64::from_le_bytes(*position), true),
            _ => (0, false),
        };
        Ok(Self {
            file,
            cookie,
            whole,
        })
    }

    fn create(parent: &DirectoryCustody) -> Result<Self, SnapshotBackingError> {
        let file = openat(
            &parent.handle,
            CURSOR_NAME,
            cursor_flags() | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|error| match error {
            Errno::EXIST => SnapshotBackingError::Unusable(SnapshotLocationRefusal::UnusableCursor),
            error => std::io::Error::from(error).into(),
        })?;
        // Exact mode regardless of the process umask, then the whole position.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        validate_cursor(&file, parent.owner)?;
        file.write_all_at(&0_u64.to_le_bytes(), 0)?;
        Ok(Self {
            file,
            cookie: 0,
            whole: true,
        })
    }

    fn store(
        &mut self,
        parent: &DirectoryCustody,
        cookie: u64,
    ) -> Result<(), SnapshotBackingError> {
        parent.validate()?;
        validate_cursor(&self.file, parent.owner)?;
        #[cfg(test)]
        fault::cursor_write()?;
        if !self.whole {
            self.file.set_len(8)?;
            self.whole = true;
        }
        self.file.write_all_at(&cookie.to_le_bytes(), 0)?;
        Ok(())
    }
}

fn cursor_flags() -> OFlags {
    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
}

/// Open failures that describe the entry itself rather than a resource.
fn unusable_entry(error: Errno) -> bool {
    matches!(
        error,
        Errno::LOOP | Errno::ISDIR | Errno::NXIO | Errno::ACCESS | Errno::PERM | Errno::TXTBSY
    )
}

fn validate_cursor(file: &File, owner: u32) -> Result<(), SnapshotBackingError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SnapshotBackingError::Unusable(
            SnapshotLocationRefusal::UnusableCursor,
        ));
    }
    Ok(())
}

enum ScanFailure {
    /// The kernel did not accept the resume position.
    Rewind,
    Failed(SnapshotBackingError),
}

fn scan(
    parent: &DirectoryCustody,
    start: u64,
) -> Result<(ReclaimReport, u64), SnapshotBackingError> {
    parent.validate()?;
    if start != 0 {
        match scan_from(parent, start) {
            Ok(done) => return Ok(done),
            Err(ScanFailure::Rewind) => {}
            Err(ScanFailure::Failed(error)) => return Err(error),
        }
    }
    match scan_from(parent, 0) {
        Ok(done) => Ok(done),
        Err(ScanFailure::Rewind) => Err(std::io::Error::from(Errno::INVAL).into()),
        Err(ScanFailure::Failed(error)) => Err(error),
    }
}

/// Read the parent from `start` through the held descriptor, whose file
/// position nothing else uses. Returns the counts and the position after the
/// last entry read, or 0 at the end of the directory.
fn scan_from(parent: &DirectoryCustody, start: u64) -> Result<(ReclaimReport, u64), ScanFailure> {
    if i64::try_from(start).is_err() || seek(&parent.handle, SeekFrom::Start(start)).is_err() {
        return Err(ScanFailure::Rewind);
    }
    let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
    let mut entries = RawDir::new(&parent.handle, &mut buffer);
    let mut report = ReclaimReport::default();
    let mut scanned = 0_usize;
    let mut examined = 0_usize;
    loop {
        let entry = match entries.next() {
            None => return Ok((report, 0)),
            Some(Ok(entry)) => entry,
            Some(Err(_)) if scanned == 0 && start != 0 => return Err(ScanFailure::Rewind),
            Some(Err(error)) => {
                return Err(ScanFailure::Failed(std::io::Error::from(error).into()))
            }
        };
        scanned += 1;
        if let Some(name) = snapshot_name(entry.file_name()) {
            examined += 1;
            match examine(parent, name) {
                Examined::Reclaimed => report.reclaimed += 1,
                Examined::Live => report.live += 1,
                Examined::Skipped => report.skipped += 1,
            }
        }
        if scanned >= SCAN_ENTRIES || examined >= EXAMINE_DIRECTORIES {
            return Ok((report, entry.next_entry_cookie()));
        }
    }
}

/// The name, when it is the canonical text of a version 7 UUID, as every
/// snapshot directory is named.
fn snapshot_name(name: &std::ffi::CStr) -> Option<&str> {
    let name = name.to_str().ok()?;
    let parsed = uuid::Uuid::try_parse(name).ok()?;
    let mut canonical = [0_u8; uuid::fmt::Hyphenated::LENGTH];
    let canonical = parsed.hyphenated().encode_lower(&mut canonical);
    (parsed.get_version_num() == 7 && *canonical == *name).then_some(name)
}

enum Examined {
    Reclaimed,
    Live,
    Skipped,
}

fn examine(parent: &DirectoryCustody, name: &str) -> Examined {
    match reclaim_directory(parent, name) {
        Ok(outcome) => outcome,
        Err(_) => Examined::Skipped,
    }
}

fn reclaim_directory(parent: &DirectoryCustody, name: &str) -> Result<Examined, Errno> {
    let entry = statat(&parent.handle, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(entry.st_mode) != FileType::Directory
        || entry.st_uid != parent.owner
        || entry.st_mode & 0o7777 != 0o700
    {
        return Ok(Examined::Skipped);
    }
    let directory = File::from(openat(
        &parent.handle,
        name,
        directory_flags(),
        Mode::empty(),
    )?);
    let held = rustix::fs::fstat(&directory)?;
    if (held.st_dev, held.st_ino) != (entry.st_dev, entry.st_ino) {
        return Ok(Examined::Skipped);
    }
    match flock(&directory, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(error) if error == Errno::WOULDBLOCK => return Ok(Examined::Live),
        Err(error) => return Err(error),
    }
    for leaf in LEAVES {
        match statat(&directory, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == Errno::NOENT => continue,
            Err(error) => return Err(error),
            Ok(metadata)
                if FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
                    && metadata.st_uid == parent.owner
                    && metadata.st_nlink == 1 =>
            {
                unlinkat(&directory, leaf, AtFlags::empty())?;
            }
            Ok(_) => return Ok(Examined::Skipped),
        }
    }
    let current = statat(&parent.handle, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino) {
        return Ok(Examined::Skipped);
    }
    // Anything else inside makes this fail with ENOTEMPTY and stay in place.
    unlinkat(&parent.handle, name, AtFlags::REMOVEDIR)?;
    Ok(Examined::Reclaimed)
}

/// A test-only failure of the next cursor update on this thread.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT_CURSOR_WRITE: Cell<Option<i32>> = const { Cell::new(None) };
    }

    pub(in super::super) fn fail_next_cursor_write(errno: i32) {
        FAIL_NEXT_CURSOR_WRITE.with(|slot| slot.set(Some(errno)));
    }

    pub(super) fn cursor_write() -> std::io::Result<()> {
        match FAIL_NEXT_CURSOR_WRITE.with(Cell::take) {
            Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
            None => Ok(()),
        }
    }
}
