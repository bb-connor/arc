//! Narrow audited boundary for binding a `rusqlite` connection to the exact
//! main-database file borrowed by SQLite.
//!
//! The workspace uses rusqlite's pinned `bundled` SQLite build. Qualified
//! stores require a bundled Unix VFS, whose `unixFile` prefix is stable and
//! contains the database descriptor after SQLite's public `sqlite3_file` base.

#![deny(unsafe_op_in_unsafe_fn)]

mod write_capacity;
pub use write_capacity::{
    require_physical_write_capacity, write_capacity_policy_descriptor,
    SqlitePhysicalDebtAmountData, SqliteWriteCapacityStageData,
};

mod write_liability;
pub use write_liability::{
    price_transaction_write_shape, write_price_algorithm_descriptor, SqliteFramePriceProfileData,
    SqliteTransactionWritePriceData, SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData,
};

mod write_geometry;
pub use write_geometry::{main_database_write_geometry, SqliteWriteGeometryData};

#[cfg(unix)]
use std::ffi::{c_int, c_void, CStr};

#[cfg(unix)]
use rusqlite::ffi;

/// Filesystem identity of the exact main-database descriptor held by SQLite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub link_count: u64,
}

/// Ephemeral identity of a live SQLite connection, distinct from its file.
///
/// The identity survives Rust moves through a connection pool. It must not be
/// persisted or used after the connection closes, when SQLite may reuse the
/// allocation. It conveys no authority over the connection or database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteConnectionIdentity(usize);

impl SqliteConnectionIdentity {
    /// Observe an identity without exposing or dereferencing SQLite's handle.
    #[must_use]
    pub fn of(connection: &rusqlite::Connection) -> Self {
        // SAFETY: the borrowed connection is alive; only compare its handle's
        // address. No SQLite operation or dereference uses the raw pointer.
        Self(unsafe { connection.handle() as usize })
    }
}

#[cfg(unix)]
#[repr(C)]
#[derive(Clone, Copy)]
struct BundledUnixFilePrefix {
    methods: *const ffi::sqlite3_io_methods,
    vfs: *mut ffi::sqlite3_vfs,
    inode_info: *mut c_void,
    descriptor: c_int,
}

/// Read the device, inode, and link count from the actual descriptor backing
/// `connection`'s main database.
///
/// This deliberately fails closed for non-Unix or non-bundled-Unix VFSes.
#[cfg(unix)]
pub fn main_database_file_identity(
    connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, String> {
    let descriptor = main_database_descriptor(connection)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the borrowed connection owns this descriptor. fstat neither
    // closes nor duplicates it, preserving SQLite's process-owned locks.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(format!(
            "SQLite main database descriptor metadata failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat returned success and initialized metadata above.
    let metadata = unsafe { metadata.assume_init() };
    // The stat field widths differ between supported Unix targets.
    #[allow(clippy::unnecessary_cast)]
    let identity = SqliteFileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
        link_count: metadata.st_nlink as u64,
    };
    Ok(identity)
}

/// Available filesystem bytes observed through SQLite's actual held main file.
/// This is capacity data, not a reservation or permission to spend owed debt.
#[cfg(unix)]
pub fn main_database_available_bytes(connection: &rusqlite::Connection) -> Result<u64, String> {
    let descriptor = main_database_descriptor(connection)?;
    let mut capacity = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the connection retains the descriptor for this synchronous call.
    // fstatvfs initializes capacity on success and does not change file locks.
    if unsafe { libc::fstatvfs(descriptor, capacity.as_mut_ptr()) } != 0 {
        return Err(format!(
            "SQLite main database filesystem capacity failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstatvfs succeeded and initialized every field.
    let capacity = unsafe { capacity.assume_init() };
    if capacity.f_frsize == 0 {
        return Err("SQLite main database filesystem fragment size is zero".to_owned());
    }
    u64::try_from(u128::from(capacity.f_bavail) * u128::from(capacity.f_frsize))
        .map_err(|_| "SQLite main database filesystem capacity overflow".to_owned())
}

#[cfg(unix)]
fn main_database_descriptor(connection: &rusqlite::Connection) -> Result<c_int, String> {
    let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
    let mut vfs = std::ptr::null_mut::<ffi::sqlite3_vfs>();
    // SAFETY: `connection` keeps its sqlite3 handle alive for this call. Both
    // opcodes are public SQLite APIs and receive correctly typed out-pointers.
    let (file_result, vfs_result) = unsafe {
        let handle = connection.handle();
        (
            ffi::sqlite3_file_control(
                handle,
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                std::ptr::addr_of_mut!(file).cast(),
            ),
            ffi::sqlite3_file_control(
                handle,
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_VFS_POINTER,
                std::ptr::addr_of_mut!(vfs).cast(),
            ),
        )
    };
    if file_result != ffi::SQLITE_OK || file.is_null() {
        return Err(format!(
            "SQLite main file pointer is unavailable (result {file_result})"
        ));
    }
    if vfs_result != ffi::SQLITE_OK || vfs.is_null() {
        return Err(format!(
            "SQLite main VFS pointer is unavailable (result {vfs_result})"
        ));
    }

    // SAFETY: SQLite returned `vfs` from the live connection. Its public
    // sqlite3_vfs fields remain valid while the connection is borrowed.
    let (vfs_name, vfs_file_size) = unsafe {
        let vfs = &*vfs;
        let name = if vfs.zName.is_null() {
            return Err("SQLite main VFS has no name".to_owned());
        } else {
            CStr::from_ptr(vfs.zName)
                .to_str()
                .map_err(|_| "SQLite main VFS name is not UTF-8".to_owned())?
                .to_owned()
        };
        (name, vfs.szOsFile)
    };
    if !vfs_name.starts_with("unix") {
        return Err(format!(
            "qualified SQLite file identity requires a bundled Unix VFS, got {vfs_name}"
        ));
    }
    if vfs_file_size < std::mem::size_of::<BundledUnixFilePrefix>() as c_int {
        return Err("SQLite Unix VFS file object is smaller than its audited prefix".to_owned());
    }

    // SAFETY: the public FILE_POINTER opcode returned an allocation whose VFS
    // reports enough bytes for the pinned bundled Unix prefix checked above.
    // `read_unaligned` avoids imposing a stronger alignment than SQLite gave.
    let prefix = unsafe { std::ptr::read_unaligned(file.cast::<BundledUnixFilePrefix>()) };
    if prefix.vfs != vfs {
        return Err("SQLite main file is not owned by the reported Unix VFS".to_owned());
    }
    if prefix.methods.is_null() || prefix.descriptor < 0 {
        return Err("SQLite main database descriptor is unavailable".to_owned());
    }

    Ok(prefix.descriptor)
}

#[cfg(not(unix))]
pub fn main_database_file_identity(
    _connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, String> {
    Err("qualified SQLite file identity requires Unix".to_owned())
}

#[cfg(not(unix))]
pub fn main_database_available_bytes(_connection: &rusqlite::Connection) -> Result<u64, String> {
    Err("qualified SQLite filesystem capacity requires Unix".to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pooled_connection_identity_survives_a_move_and_distinguishes_the_same_file(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = tempfile::NamedTempFile::new()?;
        let first = rusqlite::Connection::open(file.path())?;
        let second = rusqlite::Connection::open(file.path())?;
        let identity = super::SqliteConnectionIdentity::of(&first);
        assert_ne!(identity, super::SqliteConnectionIdentity::of(&second));
        let moved = Box::new(first);
        assert_eq!(identity, super::SqliteConnectionIdentity::of(&moved));
        Ok(())
    }
    use super::*;

    #[test]
    fn filesystem_capacity_refuses_an_in_memory_database() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = rusqlite::Connection::open_in_memory()?;
        assert!(main_database_available_bytes(&connection).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_capacity_uses_the_held_file_after_rename(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let original = directory.path().join("capacity.sqlite3");
        let retained = directory.path().join("retained.sqlite3");
        let connection = rusqlite::Connection::open(&original)?;
        connection.execute_batch("CREATE TABLE capacity_probe (value INTEGER NOT NULL);")?;
        let before = main_database_file_identity(&connection)?;
        std::fs::rename(&original, &retained)?;
        assert!(!original.exists());
        main_database_available_bytes(&connection)?;
        assert_eq!(main_database_file_identity(&connection)?, before);
        Ok(())
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_platform_rejects_file_identity() -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        assert_eq!(
            main_database_file_identity(&connection),
            Err("qualified SQLite file identity requires Unix".to_owned())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reports_the_borrowed_main_database_file() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir()?;
        let database = directory.path().join("identity.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch("CREATE TABLE identity_probe (value INTEGER NOT NULL);")?;

        let expected = std::fs::metadata(&database)?;
        let actual = main_database_file_identity(&connection)?;
        assert_eq!(actual.device, expected.dev());
        assert_eq!(actual.inode, expected.ino());
        assert_eq!(actual.link_count, expected.nlink());
        connection.execute("INSERT INTO identity_probe VALUES (1)", [])?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn follows_the_borrowed_file_after_path_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir()?;
        let database = directory.path().join("identity.sqlite3");
        let moved = directory.path().join("original.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch("CREATE TABLE identity_probe (value INTEGER NOT NULL);")?;
        let original = main_database_file_identity(&connection)?;
        std::fs::rename(&database, &moved)?;
        std::fs::write(&database, b"replacement file")?;

        assert_eq!(main_database_file_identity(&connection)?, original);
        assert_ne!(std::fs::metadata(&database)?.ino(), original.inode);
        std::fs::remove_file(&moved)?;
        let unlinked = main_database_file_identity(&connection)?;
        assert_eq!(unlinked.device, original.device);
        assert_eq!(unlinked.inode, original.inode);
        assert_eq!(unlinked.link_count, 0);
        Ok(())
    }

    #[test]
    fn rejects_a_database_without_a_main_file() -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        assert!(main_database_file_identity(&connection).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "invoked in a separate process by preserves_transaction_locks"]
    fn transaction_lock_probe() -> Result<(), Box<dyn std::error::Error>> {
        let database = std::env::var("CHIO_IDENTITY_LOCK_PROBE_DATABASE")?;
        let connection = rusqlite::Connection::open(database)?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        let result = connection.execute_batch("BEGIN IMMEDIATE;");
        assert!(
            matches!(result, Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy),
            "competing process acquired a locked database: {result:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preserves_transaction_locks() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("locked.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE; CREATE TABLE probe (value INTEGER); BEGIN EXCLUSIVE;",
        )?;
        for inspect in [false, true] {
            if inspect {
                main_database_file_identity(&connection)?;
                main_database_available_bytes(&connection)?;
            }
            let result = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "tests::transaction_lock_probe",
                    "--nocapture",
                ])
                .env("CHIO_IDENTITY_LOCK_PROBE_DATABASE", &database)
                .output()?;
            assert!(
                result.status.success(),
                "lock probe failed after inspect={inspect}: {}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        connection.execute_batch("ROLLBACK;")?;
        Ok(())
    }
}
