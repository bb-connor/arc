//! Narrow audited boundary for binding a `rusqlite` connection to the exact
//! main-database file borrowed by SQLite.
//!
//! The workspace uses rusqlite's pinned `bundled` SQLite build. Qualified
//! stores require a bundled Unix VFS, whose `unixFile` prefix is stable and
//! contains the database descriptor after SQLite's public `sqlite3_file` base.

#![deny(unsafe_op_in_unsafe_fn)]

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

/// Narrow inspection failure. Validation does not grant file or VFS trust.
/// The legacy String shim preserves the original diagnostic text.
#[derive(Debug)]
pub enum SqliteFileIdentityInspectionError {
    Io(std::io::Error),
    Validation(String),
}

impl std::fmt::Display for SqliteFileIdentityInspectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(
                formatter,
                "SQLite main database descriptor metadata failed: {source}"
            ),
            Self::Validation(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SqliteFileIdentityInspectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Validation(_) => None,
        }
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

/// Compatibility wrapper preserving the existing String error contract.
/// Inspection never closes or duplicates the descriptor held by SQLite.
pub fn main_database_file_identity(
    connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, String> {
    inspect_main_database_file_identity(connection).map_err(|error| error.to_string())
}

/// Read the device, inode, and link count from the actual descriptor backing
/// `connection`'s main database.
///
/// This deliberately fails closed for non-Unix or non-bundled-Unix VFSes.
#[cfg(unix)]
pub fn inspect_main_database_file_identity(
    connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, SqliteFileIdentityInspectionError> {
    let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
    let mut vfs = std::ptr::null_mut::<ffi::sqlite3_vfs>();
    // SAFETY: the borrowed connection keeps the handle alive throughout both calls.
    let handle = unsafe { connection.handle() };
    // SAFETY: FILE_POINTER receives a live handle and a correctly typed out-pointer.
    let file_result = unsafe {
        ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            std::ptr::addr_of_mut!(file).cast(),
        )
    };
    // SAFETY: VFS_POINTER receives the same live handle and its typed out-pointer.
    let vfs_result = unsafe {
        ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_VFS_POINTER,
            std::ptr::addr_of_mut!(vfs).cast(),
        )
    };
    if file_result != ffi::SQLITE_OK || file.is_null() {
        return Err(SqliteFileIdentityInspectionError::Validation(format!(
            "SQLite main file pointer is unavailable (result {file_result})"
        )));
    }
    if vfs_result != ffi::SQLITE_OK || vfs.is_null() {
        return Err(SqliteFileIdentityInspectionError::Validation(format!(
            "SQLite main VFS pointer is unavailable (result {vfs_result})"
        )));
    }

    // SAFETY: SQLite returned `vfs` from the live connection. Its public
    // sqlite3_vfs fields remain valid while the connection is borrowed.
    let vfs_header = unsafe { &*vfs };
    let (vfs_name, vfs_file_size) = {
        let name = if vfs_header.zName.is_null() {
            return Err(SqliteFileIdentityInspectionError::Validation(
                "SQLite main VFS has no name".to_owned(),
            ));
        } else {
            // SAFETY: SQLite's live VFS supplies a non-null NUL-terminated name.
            unsafe { CStr::from_ptr(vfs_header.zName) }
                .to_str()
                .map_err(|_| {
                    SqliteFileIdentityInspectionError::Validation(
                        "SQLite main VFS name is not UTF-8".to_owned(),
                    )
                })?
                .to_owned()
        };
        (name, vfs_header.szOsFile)
    };
    if !vfs_name.starts_with("unix") {
        return Err(SqliteFileIdentityInspectionError::Validation(format!(
            "qualified SQLite file identity requires a bundled Unix VFS, got {vfs_name}"
        )));
    }
    if vfs_file_size < std::mem::size_of::<BundledUnixFilePrefix>() as c_int {
        return Err(SqliteFileIdentityInspectionError::Validation(
            "SQLite Unix VFS file object is smaller than its audited prefix".to_owned(),
        ));
    }

    // SAFETY: the public FILE_POINTER opcode returned an allocation whose VFS
    // reports enough bytes for the pinned bundled Unix prefix checked above.
    // `read_unaligned` avoids imposing a stronger alignment than SQLite gave.
    let prefix = unsafe { std::ptr::read_unaligned(file.cast::<BundledUnixFilePrefix>()) };
    if prefix.vfs != vfs {
        return Err(SqliteFileIdentityInspectionError::Validation(
            "SQLite main file is not owned by the reported Unix VFS".to_owned(),
        ));
    }
    if prefix.methods.is_null() || prefix.descriptor < 0 {
        return Err(SqliteFileIdentityInspectionError::Validation(
            "SQLite main database descriptor is unavailable".to_owned(),
        ));
    }

    descriptor_file_identity(prefix.descriptor)
}

#[cfg(not(unix))]
pub fn inspect_main_database_file_identity(
    _connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, SqliteFileIdentityInspectionError> {
    Err(SqliteFileIdentityInspectionError::Validation(
        "qualified SQLite file identity requires Unix".to_owned(),
    ))
}

#[cfg(unix)]
fn descriptor_file_identity(
    descriptor: c_int,
) -> Result<SqliteFileIdentity, SqliteFileIdentityInspectionError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat only inspects the descriptor and writes stat on success.
    // The production caller keeps its borrowed SQLite descriptor alive; an
    // invalid test descriptor is rejected by the real syscall. It never closes nor
    // duplicates the descriptor. Closing even a duplicate would release the
    // process's POSIX locks on this inode, invalidating SQLite's lock state.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(SqliteFileIdentityInspectionError::Io(
            std::io::Error::last_os_error(),
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
    #[test]
    fn invalid_descriptor_syscall_preserves_actual_ebadf_source(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::error::Error;
        // A real fstat(-1) returns EBADF. No SQLite descriptor is closed or
        // duplicated, no stat record is fabricated, and no fake IO error is made.
        let error = descriptor_file_identity(-1)
            .err()
            .ok_or("actual fstat must refuse invalid descriptor")?;
        assert!(
            matches!(&error, SqliteFileIdentityInspectionError::Io(_)),
            "native fstat refusal must retain Io ownership"
        );
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .ok_or("actual native IO cause must remain inspectable")?;
        assert_eq!(source.raw_os_error(), Some(libc::EBADF));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_identity_matches_healthy_borrowed_file_and_legacy_shim(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("typed.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch("CREATE TABLE typed_probe(value INTEGER);")?;
        let metadata = std::fs::metadata(&database)?;
        let actual = inspect_main_database_file_identity(&connection)?;
        assert_eq!(actual, main_database_file_identity(&connection)?);
        assert_eq!(
            (actual.device, actual.inode, actual.link_count),
            (metadata.dev(), metadata.ino(), metadata.nlink())
        );
        connection.execute("INSERT INTO typed_probe VALUES(1)", [])?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_identity_keeps_unsupported_main_as_validation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        let error = inspect_main_database_file_identity(&connection)
            .err()
            .ok_or("missing main file must refuse")?;
        assert!(matches!(
            &error,
            SqliteFileIdentityInspectionError::Validation(_)
        ));
        assert_eq!(
            main_database_file_identity(&connection).err(),
            Some(error.to_string())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_inspection_preserves_transaction_locks() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("typed-locked.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE; CREATE TABLE probe(value INTEGER); BEGIN EXCLUSIVE;",
        )?;
        inspect_main_database_file_identity(&connection)?;
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
            "actual competing process must retain SQLite lock refusal"
        );
        connection.execute_batch("ROLLBACK;")?;
        Ok(())
    }
}
