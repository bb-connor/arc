//! Filesystem space observed through SQLite's borrowed main-database
//! descriptor. The result is data: it reserves no space and grants no custody.

use crate::SqliteFileIdentityInspectionError;

#[cfg(unix)]
use std::ffi::c_int;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;

/// Available-space inspection failure.
#[derive(Debug)]
pub enum SqliteAvailableSpaceError {
    /// The validated main-database descriptor is unavailable.
    Identity(SqliteFileIdentityInspectionError),
    /// `fstatvfs` on the borrowed descriptor failed.
    Io(std::io::Error),
    /// The filesystem reported a zero fragment size.
    ZeroFragmentSize,
    /// Available blocks times fragment size exceeds `u64`.
    CapacityOverflow,
}

impl std::fmt::Display for SqliteAvailableSpaceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(source) => std::fmt::Display::fmt(source, formatter),
            Self::Io(source) => write!(
                formatter,
                "SQLite main database filesystem capacity failed: {source}"
            ),
            Self::ZeroFragmentSize => {
                formatter.write_str("SQLite main database filesystem fragment size is zero")
            }
            Self::CapacityOverflow => {
                formatter.write_str("SQLite main database filesystem capacity overflow")
            }
        }
    }
}

impl std::error::Error for SqliteAvailableSpaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::ZeroFragmentSize | Self::CapacityOverflow => None,
        }
    }
}

/// Bytes available to unprivileged writers on the filesystem holding the
/// exact main-database file SQLite has open for `connection`.
///
/// The descriptor is found and validated exactly as by
/// `inspect_main_database_file_identity`, then passed to `fstatvfs`. It is
/// never reopened by path, duplicated, closed, or retained, so a renamed,
/// replaced, or unlinked path still reports the held file's filesystem and
/// SQLite's locks are unchanged.
#[cfg(unix)]
pub fn main_database_available_bytes(
    connection: &rusqlite::Connection,
) -> Result<u64, SqliteAvailableSpaceError> {
    let descriptor =
        crate::main_database_descriptor(connection).map_err(SqliteAvailableSpaceError::Identity)?;
    descriptor_available_bytes(descriptor.as_raw_fd())
}

/// Non-Unix platforms have no audited SQLite descriptor and always refuse.
#[cfg(not(unix))]
pub fn main_database_available_bytes(
    _connection: &rusqlite::Connection,
) -> Result<u64, SqliteAvailableSpaceError> {
    Err(SqliteAvailableSpaceError::Identity(
        SqliteFileIdentityInspectionError::Validation(
            "qualified SQLite file identity requires Unix".to_owned(),
        ),
    ))
}

#[cfg(unix)]
fn descriptor_available_bytes(descriptor: c_int) -> Result<u64, SqliteAvailableSpaceError> {
    let mut capacity = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs only inspects the descriptor and writes statvfs on
    // success; an invalid descriptor is refused by the syscall. Callers pass a
    // descriptor borrowed for this call. It is neither closed nor duplicated,
    // and the call takes no file lock.
    if unsafe { libc::fstatvfs(descriptor, capacity.as_mut_ptr()) } != 0 {
        return Err(SqliteAvailableSpaceError::Io(
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fstatvfs returned success and initialized capacity above.
    let capacity = unsafe { capacity.assume_init() };
    available_bytes(u128::from(capacity.f_bavail), u128::from(capacity.f_frsize))
}

/// `available_blocks * fragment_size`, refusing a zero fragment size and any
/// product beyond `u64`. Zero available blocks is a valid empty filesystem.
#[cfg(any(unix, test))]
fn available_bytes(
    available_blocks: u128,
    fragment_size: u128,
) -> Result<u64, SqliteAvailableSpaceError> {
    if fragment_size == 0 {
        return Err(SqliteAvailableSpaceError::ZeroFragmentSize);
    }
    available_blocks
        .checked_mul(fragment_size)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(SqliteAvailableSpaceError::CapacityOverflow)
}

#[cfg(test)]
mod tests;
