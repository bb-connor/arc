//! Bounded original-byte readers for operator files carrying authenticated data.

use std::io::Read;
use std::path::Path;

use chio_core::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::passport_verifier::{RegistryTransactionError, RegistryUpdateError};
use crate::CliError;

pub(crate) const MAX_SIGNED_FILE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn read_bounded(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(crate::integer::count(MAX_SIGNED_FILE_BYTES + 1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    Ok(UntrustedJsonText::from_wire(bytes, MAX_SIGNED_FILE_BYTES)?.decode_signed()?)
}

/// Space kept free below the read cap so redemptions of live records, which
/// only add small fields to existing entries, can still be persisted after
/// issuance has been refused.
pub(crate) const ISSUANCE_RESERVE_BYTES: usize = 1024 * 1024;

/// Writes `value` as compact JSON, refusing any file the bounded reader could
/// not load back. The destination is untouched when the write is refused.
#[cfg(test)]
pub(crate) fn write_bounded_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    write_bounded_json_with_limit(path, value, MAX_SIGNED_FILE_BYTES)
}

/// Collects serializer output and refuses to grow past `limit` bytes, so an
/// oversized value never materializes beyond the cap.
struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl std::io::Write for LimitedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::other("registry size limit exceeded"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Persists bounded JSON only through the lock that owns its destination.
pub(crate) fn write_bounded_registry<T: Serialize>(
    lock: &RegistryLock,
    value: &T,
    limit: usize,
) -> Result<(), CliError> {
    write_bounded_at(lock.destination(), value, limit)
}

#[cfg(test)]
pub(crate) fn write_bounded_json_with_limit<T: Serialize>(
    path: &Path,
    value: &T,
    limit: usize,
) -> Result<(), CliError> {
    write_bounded_at(path, value, limit)
}

fn write_bounded_at<T: Serialize>(path: &Path, value: &T, limit: usize) -> Result<(), CliError> {
    match encode_within(value, limit)? {
        Some(bytes) => replace_file(path, &bytes),
        None => Err(CliError::policy_constraint_error(format!(
            "registry file would exceed the {limit} byte limit; the existing file was left unchanged"
        ))),
    }
}

/// Compact JSON of `value`, or `None` when it is longer than `limit` bytes.
fn encode_within<T: Serialize>(value: &T, limit: usize) -> Result<Option<Vec<u8>>, CliError> {
    let mut buffer = LimitedBuffer {
        bytes: Vec::new(),
        limit,
        overflowed: false,
    };
    match serde_json::to_writer(&mut buffer, value) {
        Ok(()) => Ok(Some(buffer.bytes)),
        Err(_) if buffer.overflowed => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Largest JSON-escaped length of operator text a revocation stores: a
/// revocation reason, or a dispute note that becomes one. For text without
/// quotes, backslashes or control characters it is the byte length.
pub(crate) const REVOCATION_REASON_LIMIT_BYTES: usize = 256;

/// Refuses operator text stored by a revocation whose JSON-escaped length
/// exceeds [`REVOCATION_REASON_LIMIT_BYTES`]; `field` names it in the error.
pub(crate) fn check_revocation_text(field: &str, text: &str) -> Result<(), CliError> {
    if escaped_len(text)? > REVOCATION_REASON_LIMIT_BYTES {
        return Err(CliError::policy_error(format!(
            "{field} must be at most {REVOCATION_REASON_LIMIT_BYTES} bytes once JSON-escaped"
        )));
    }
    Ok(())
}

/// The larger, by JSON encoding, of `current` and a reason of exactly
/// [`REVOCATION_REASON_LIMIT_BYTES`]: the longest reason a revocation can
/// leave on a record that holds `current`.
pub(crate) fn largest_revocation_reason(current: Option<&str>) -> Result<String, CliError> {
    match current {
        Some(current) if escaped_len(current)? > REVOCATION_REASON_LIMIT_BYTES => {
            Ok(current.to_string())
        }
        _ => Ok("x".repeat(REVOCATION_REASON_LIMIT_BYTES)),
    }
}

/// Bytes `record` grows by when it takes `largest`, its largest revoked form.
pub(crate) fn revocation_headroom<T: Serialize>(
    record: &T,
    largest: &T,
) -> Result<usize, CliError> {
    Ok(encoded_len(largest)?.saturating_sub(encoded_len(record)?))
}

/// A registry whose records keep room in its file for their own revocation.
///
/// Its reserved size is its compact encoding plus [`Self::revocation_reserve`].
/// Revoking a record never raises the reserved size.
pub(crate) trait RevocationReserve: Serialize + DeserializeOwned {
    /// Bytes the records may still grow by through revocation: the sum of
    /// each record's growth to its largest revoked form.
    fn revocation_reserve(&self) -> Result<usize, CliError>;
}

/// Exclusive writer lock for one registry file.
///
/// The lock is an advisory `flock` on a sibling file in the registry's
/// canonical directory. That file is never renamed, replaced or removed, so
/// every writer that names the registry by any path through that directory
/// contends on the same inode, in this process or another on the same host.
/// The registry file itself is replaced by rename on every write and is
/// therefore never the lock target. Writers on other hosts sharing the
/// directory over a network filesystem are not excluded.
pub(crate) struct RegistryLock {
    _file: std::fs::File,
    destination: std::path::PathBuf,
}

impl RegistryLock {
    /// The canonical path of the registry this lock guards; every read and
    /// write under the lock uses it.
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }
}

/// Loads the registry at `path` under its writer lock, applies `change`, and
/// persists the result before the lock is released.
///
/// This is the only writer of a registry: the copy it persists is always the
/// one it loaded under the same lock, so no copy loaded earlier can replace a
/// later write. Without the lock the update is refused as busy, never queued.
pub(crate) fn update_registry<T: RevocationReserve, R>(
    path: &Path,
    load: impl FnOnce(&Path) -> Result<T, CliError>,
    change: impl FnOnce(&mut T) -> Result<R, CliError>,
) -> Result<R, RegistryUpdateError> {
    let lock = lock_registry(path)?;
    let mut registry = load(lock.destination()).map_err(RegistryUpdateError::Load)?;
    let outcome = change(&mut registry).map_err(RegistryUpdateError::Refused)?;
    write_reserving_registry(&lock, &registry).map_err(RegistryUpdateError::Persist)?;
    Ok(outcome)
}

/// Runs an ordinary bounded registry mutation using the same stable lock as
/// revocation registries. A typed operation refusal never reaches persistence.
pub(crate) fn update_bounded_registry<T: Serialize, R, E>(
    path: &Path,
    load: impl FnOnce(&Path) -> Result<T, CliError>,
    limit: usize,
    change: impl FnOnce(&mut T) -> Result<R, E>,
) -> Result<R, RegistryTransactionError<E>> {
    let lock = lock_registry(path).map_err(RegistryTransactionError::Registry)?;
    let mut registry = load(lock.destination())
        .map_err(|error| RegistryTransactionError::Registry(RegistryUpdateError::Load(error)))?;
    let outcome = change(&mut registry).map_err(RegistryTransactionError::Refused)?;
    write_bounded_registry(&lock, &registry, limit)
        .map_err(|error| RegistryTransactionError::Registry(RegistryUpdateError::Persist(error)))?;
    Ok(outcome)
}

/// Takes the writer lock of the registry at `path`.
///
/// The lock lives at `.<file name>.lock` in the canonicalized parent
/// directory, so directory aliases of one registry share it. A hard link to
/// the registry under another name is a different registry entry with its own
/// lock; a write through it replaces only that entry. A registry path that is
/// a symbolic link is refused, because a write would replace the link rather
/// than the file it names.
#[cfg(unix)]
pub(crate) fn lock_registry(path: &Path) -> Result<RegistryLock, RegistryUpdateError> {
    use std::os::unix::fs::OpenOptionsExt;
    let load = |error: CliError| RegistryUpdateError::Load(error);
    let file_name = path
        .file_name()
        .ok_or_else(|| load(CliError::cli_io_error("registry path has no file name")))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent).map_err(|error| load(CliError::Io(error)))?;
    let directory = std::fs::canonicalize(parent).map_err(|error| load(CliError::Io(error)))?;
    let destination = directory.join(file_name);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(load(CliError::policy_constraint_error(format!(
                "registry file `{}` is a symbolic link; registries are written only at their own path",
                destination.display()
            ))));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(load(CliError::Io(error))),
    }
    let lock_path = directory.join(format!(".{}.lock", file_name.to_string_lossy()));
    let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let flags = i32::try_from(flags.bits())
        .map_err(|_| load(CliError::cli_io_error("registry lock flags are invalid")))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(flags)
        .open(&lock_path)
        .map_err(|error| load(CliError::Io(error)))?;
    check_lock_identity(&lock_path, &file).map_err(load)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => return Err(RegistryUpdateError::Busy),
        Err(error) => return Err(load(CliError::Io(error.into()))),
    }
    // The inode locked must still be the one at the lock path, or two writers
    // could hold locks on different inodes.
    check_lock_identity(&lock_path, &file).map_err(load)?;
    Ok(RegistryLock {
        _file: file,
        destination,
    })
}

#[cfg(not(unix))]
pub(crate) fn lock_registry(_path: &Path) -> Result<RegistryLock, RegistryUpdateError> {
    Err(RegistryUpdateError::Unsupported)
}

/// The lock file is a private regular file of this user with one link, and
/// `file` is that file.
#[cfg(unix)]
fn check_lock_identity(lock_path: &Path, file: &std::fs::File) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;
    let at_path = std::fs::symlink_metadata(lock_path)?;
    let held = file.metadata()?;
    if !at_path.file_type().is_file()
        || !held.file_type().is_file()
        || at_path.dev() != held.dev()
        || at_path.ino() != held.ino()
        || held.nlink() != 1
        || held.mode() & 0o077 != 0
        || held.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(CliError::policy_constraint_error(format!(
            "registry lock `{}` is not a private regular file of this user with one link",
            lock_path.display()
        )));
    }
    Ok(())
}

/// Writes `registry` as compact JSON to the destination `lock` guards.
///
/// A write whose reserved size fits the read cap is admitted. From such a
/// file every sequence of revocations of its records persists, because a
/// revocation never raises the reserved size.
///
/// A file whose reserved size is already over the cap, because it was written
/// without the reserve, admits only writes that fit the read cap and do not
/// raise the reserved size of the file they replace: revocations persist
/// whenever the rewritten file fits, and nothing that adds records does.
///
/// The destination is untouched when the write is refused.
pub(crate) fn write_reserving_registry<T: RevocationReserve>(
    lock: &RegistryLock,
    registry: &T,
) -> Result<(), CliError> {
    let path = lock.destination();
    let reserved = registry.revocation_reserve()?;
    if let Some(limit) = MAX_SIGNED_FILE_BYTES.checked_sub(reserved) {
        if let Some(bytes) = encode_within(registry, limit)? {
            return replace_file(path, &bytes);
        }
    }
    let replaced = reserved_size_on_disk::<T>(path)?;
    if let Some(bytes) = encode_within(registry, MAX_SIGNED_FILE_BYTES)? {
        let reserved_size = bytes.len().saturating_add(reserved);
        if replaced.is_some_and(|replaced| reserved_size <= replaced) {
            return replace_file(path, &bytes);
        }
    }
    if replaced.is_some_and(|replaced| replaced > MAX_SIGNED_FILE_BYTES) {
        return Err(CliError::policy_constraint_error(format!(
            "registry file is over its revocation reserve: it was written without room to revoke every record within the {MAX_SIGNED_FILE_BYTES} byte limit, so it admits only a write that fits that limit without raising the reserve; this write does not, and the existing file was left unchanged"
        )));
    }
    Err(CliError::policy_constraint_error(format!(
        "registry file would exceed the {MAX_SIGNED_FILE_BYTES} byte limit once {reserved} bytes are kept for revoking its records; the existing file was left unchanged"
    )))
}

/// Reserved size of the registry stored at `path`, or `None` when there is no
/// file there.
fn reserved_size_on_disk<T: RevocationReserve>(path: &Path) -> Result<Option<usize>, CliError> {
    let bytes = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CliError::Io(error)),
    };
    let replaced: T = decode(&bytes)?;
    Ok(Some(
        encoded_len(&replaced)?.saturating_add(replaced.revocation_reserve()?),
    ))
}

/// Counts serializer output without retaining it.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Length of the compact JSON encoding of `value`.
pub(crate) fn encoded_len<T: Serialize + ?Sized>(value: &T) -> Result<usize, CliError> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

/// JSON-escaped length of `text`, without the enclosing quotes.
fn escaped_len(text: &str) -> Result<usize, CliError> {
    Ok(encoded_len(text)?.saturating_sub(2))
}

/// Points in `replace_file_with` where a failure can be injected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplaceStage {
    /// After the temporary is fully written and synced, before the rename.
    BeforeRename,
    /// After the rename, at the parent directory sync.
    DirectorySync,
}

/// Replaces `path` through a freshly created, randomly named sibling that is
/// opened exclusively with owner-only permissions (never more permissive than
/// the file it replaces), synced, and renamed into place.
///
/// A failure before the rename removes only the temporary this call created
/// and leaves the prior file intact. A failure of the parent directory sync
/// happens after the rename: the new file is already in place, and the result
/// is `CliError::PersistedWithoutDurability`. The directory sync is performed
/// on Unix only; other platforms rely on the file sync and the atomic rename.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let random = chio_core::Keypair::generate().public_key().to_hex();
    replace_file_via(path, bytes, &random)
}

pub(crate) fn replace_file_via(path: &Path, bytes: &[u8], nonce: &str) -> Result<(), CliError> {
    replace_file_with(path, bytes, nonce, &|_| Ok(()))
}

/// `nonce` names the temporary sibling; `inject` can fail a stage.
pub(crate) fn replace_file_with(
    path: &Path,
    bytes: &[u8],
    nonce: &str,
    inject: &dyn Fn(ReplaceStage) -> std::io::Result<()>,
) -> Result<(), CliError> {
    use std::io::Write;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_io_error("registry path has no file name"))?
        .to_string_lossy();
    let temporary = directory.join(format!(".{file_name}.{nonce}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mode = match std::fs::metadata(path) {
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
        return Err(CliError::Io(error));
    }
    let durable = inject(ReplaceStage::DirectorySync).and_then(|()| sync_directory(directory));
    durable.map_err(CliError::PersistedWithoutDurability)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    decode(&read_bounded(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_input_keeps_full_width_integers_and_rejects_nested_aliases() {
        let value: serde_json::Value =
            decode(br#"{"amount":18446744073709551615,"nested":{"limit":1}}"#)
                .unwrap_or_else(|error| panic!("valid signed input: {error}"));
        assert_eq!(value["amount"].as_u64(), Some(u64::MAX));
        for bytes in [
            br#"{"nested":{"limit":0,"limit":1}}"#.as_slice(),
            br#"{"nested":{"limit":1.0000000000000001}}"#.as_slice(),
        ] {
            assert!(matches!(
                decode::<serde_json::Value>(bytes),
                Err(CliError::SignedJson(
                    chio_core::canonical::UntrustedJsonError::SignedInput(_)
                ))
            ));
        }
    }
}
