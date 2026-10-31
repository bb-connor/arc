//! Bounded original-byte readers for operator files carrying authenticated data.

use std::path::Path;

use chio_core::canonical::UntrustedJsonText;
use chio_secure_ipc::registry_file::{RegistryFile, RegistryFileError};
use chio_secure_ipc::regular_file::{read_regular_file, OpenPolicy, RegularFileError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::passport_verifier::{RegistryTransactionError, RegistryUpdateError};
use crate::CliError;

pub(crate) const MAX_SIGNED_FILE_BYTES: usize = 16 * 1024 * 1024;

#[cfg(all(test, unix))]
#[path = "signed_input/read_pause.rs"]
pub(crate) mod read_pause;

pub(crate) fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>, RegularFileError> {
    read_bounded_with_limit(path, MAX_SIGNED_FILE_BYTES)
}

/// Reads an operator file of at most `max_bytes` bytes. Its content is
/// verified after the read, so any owner and mode is accepted.
pub(crate) fn read_bounded_with_limit(
    path: &Path,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, RegularFileError> {
    read_regular_file(path, max_bytes, OpenPolicy::Authenticated)
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

#[cfg(test)]
pub(crate) fn write_bounded_json_with_limit<T: Serialize>(
    path: &Path,
    value: &T,
    limit: usize,
) -> Result<(), CliError> {
    write_bounded_registry(&RegistryFile::lock(path)?, value, limit)
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
    lock: &RegistryFile,
    value: &T,
    limit: usize,
) -> Result<(), CliError> {
    match encode_within(value, limit)? {
        Some(bytes) => Ok(lock.replace(&bytes)?),
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
    let lock = RegistryFile::lock(path)?;
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
    let lock = RegistryFile::lock(path)
        .map_err(|error| RegistryTransactionError::Registry(error.into()))?;
    let mut registry = load(lock.destination())
        .map_err(|error| RegistryTransactionError::Registry(RegistryUpdateError::Load(error)))?;
    let outcome = change(&mut registry).map_err(RegistryTransactionError::Refused)?;
    write_bounded_registry(&lock, &registry, limit)
        .map_err(|error| RegistryTransactionError::Registry(RegistryUpdateError::Persist(error)))?;
    Ok(outcome)
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
    lock: &RegistryFile,
    registry: &T,
) -> Result<(), CliError> {
    let path = lock.destination();
    let reserved = registry.revocation_reserve()?;
    if let Some(limit) = MAX_SIGNED_FILE_BYTES.checked_sub(reserved) {
        if let Some(bytes) = encode_within(registry, limit)? {
            return Ok(lock.replace(&bytes)?);
        }
    }
    let replaced = reserved_size_on_disk::<T>(path)?;
    if let Some(bytes) = encode_within(registry, MAX_SIGNED_FILE_BYTES)? {
        let reserved_size = bytes.len().saturating_add(reserved);
        if replaced.is_some_and(|replaced| reserved_size <= replaced) {
            return Ok(lock.replace(&bytes)?);
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
        Err(RegularFileError::Missing) => return Ok(None),
        Err(error) => return Err(error.into()),
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

impl From<RegistryFileError> for CliError {
    fn from(error: RegistryFileError) -> Self {
        match error {
            RegistryFileError::Io(error) => CliError::Io(error),
            RegistryFileError::PersistedWithoutDurability(error) => {
                CliError::PersistedWithoutDurability(error)
            }
            RegistryFileError::NoFileName => CliError::cli_io_error(error.to_string()),
            RegistryFileError::SymlinkDestination(_) | RegistryFileError::LockNotPrivate(_) => {
                CliError::policy_constraint_error(error.to_string())
            }
            RegistryFileError::Busy | RegistryFileError::Unsupported => {
                CliError::cli_other_error(error.to_string())
            }
        }
    }
}

impl From<RegistryFileError> for RegistryUpdateError {
    fn from(error: RegistryFileError) -> Self {
        match error {
            RegistryFileError::Busy => RegistryUpdateError::Busy,
            RegistryFileError::Unsupported => RegistryUpdateError::Unsupported,
            RegistryFileError::Io(_)
            | RegistryFileError::PersistedWithoutDurability(_)
            | RegistryFileError::NoFileName
            | RegistryFileError::SymlinkDestination(_)
            | RegistryFileError::LockNotPrivate(_) => RegistryUpdateError::Load(error.into()),
        }
    }
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
