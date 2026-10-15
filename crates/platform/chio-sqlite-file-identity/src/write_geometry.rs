//! Physical write layout SQLite uses for the main database, observed without
//! changing page, reserve, or VFS state. The result is data: it reserves no
//! space and grants no writer authority.

use crate::SqliteFileIdentityInspectionError;

#[cfg(any(unix, test))]
/// Largest sector size SQLite's pager uses unclamped (`MAX_SECTOR_SIZE`).
const MAX_SECTOR_BYTES: i32 = 0x10000;
#[cfg(any(unix, test))]
/// Smallest sector size SQLite's pager uses unclamped.
const MIN_SECTOR_BYTES: i32 = 32;
#[cfg(any(unix, test))]
/// Largest reserved-byte count a SQLite page can carry.
const MAX_RESERVED_BYTES: i32 = 255;
const POWERSAFE_OVERWRITE: u32 = rusqlite::ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE as u32;

/// Observed main-database write geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteWriteGeometryData {
    reserved_bytes: u64,
    sector_bytes: u64,
    device_characteristics: u32,
    vfs_name: String,
}

impl SqliteWriteGeometryData {
    /// The current or pending reserved bytes per page, `0..=255`.
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// The main file's `xSectorSize`, a power of two in `32..=65536`.
    pub fn sector_bytes(&self) -> u64 {
        self.sector_bytes
    }

    /// The main file's `xDeviceCharacteristics` flags.
    pub fn device_characteristics(&self) -> u32 {
        self.device_characteristics
    }

    /// Whether `SQLITE_IOCAP_POWERSAFE_OVERWRITE` is set.
    pub fn powersafe_overwrite(&self) -> bool {
        self.device_characteristics & POWERSAFE_OVERWRITE != 0
    }

    /// The name of the VFS owning the main file.
    pub fn vfs_name(&self) -> &str {
        &self.vfs_name
    }
}

/// A `sqlite3_file_control` operation the observation issues on `main`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteGeometryFileControl {
    ReserveBytes,
    FilePointer,
    VfsPointer,
}

/// A public SQLite I/O method the observation calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteGeometryMethod {
    IoMethods,
    SectorSize,
    DeviceCharacteristics,
}

/// Write-geometry observation failure.
#[derive(Debug)]
pub enum SqliteWriteGeometryError {
    /// The canonical main-database identity guard refused.
    Identity(SqliteFileIdentityInspectionError),
    /// A file control returned this non-`SQLITE_OK` status.
    FileControl {
        control: SqliteGeometryFileControl,
        status: i32,
    },
    /// A pointer file control succeeded but returned null.
    NullPointer(SqliteGeometryFileControl),
    /// The main file lacks a public I/O method.
    MissingMethod(SqliteGeometryMethod),
    /// The reserve query returned a value outside `0..=255`.
    ReservedBytes(i32),
    /// `xSectorSize` returned a value that is not a power of two in `32..=65536`.
    SectorSize(i32),
    /// `xDeviceCharacteristics` returned a negative value.
    DeviceCharacteristics(i32),
    /// The VFS has no name.
    MissingVfsName,
    /// The VFS name is not UTF-8.
    VfsNameNotUtf8,
}

impl std::fmt::Display for SqliteWriteGeometryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(source) => std::fmt::Display::fmt(source, formatter),
            Self::FileControl { control, status } => write!(
                formatter,
                "SQLite main {control:?} file control failed (result {status})"
            ),
            Self::NullPointer(control) => write!(
                formatter,
                "SQLite main {control:?} file control returned no pointer"
            ),
            Self::MissingMethod(method) => {
                write!(formatter, "SQLite main file has no {method:?} method")
            }
            Self::ReservedBytes(value) => {
                write!(formatter, "SQLite main reserved bytes are invalid: {value}")
            }
            Self::SectorSize(value) => {
                write!(formatter, "SQLite main sector size is unsupported: {value}")
            }
            Self::DeviceCharacteristics(value) => write!(
                formatter,
                "SQLite main device characteristics are invalid: {value}"
            ),
            Self::MissingVfsName => formatter.write_str("SQLite main VFS has no name"),
            Self::VfsNameNotUtf8 => formatter.write_str("SQLite main VFS name is not UTF-8"),
        }
    }
}

impl std::error::Error for SqliteWriteGeometryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            _ => None,
        }
    }
}

/// Observe the main database's reserved bytes, sector size, device
/// characteristics, and VFS name.
///
/// The canonical identity guard first requires a supported, live, bundled
/// Unix main descriptor. The reserve control is then queried with -1, which
/// reports the current or pending reserve without changing it. The VFS
/// pointer is taken next and then the file pointer, which is used for the
/// public `xSectorSize` and `xDeviceCharacteristics` reads with no SQLite call
/// in between. Neither pointer is retained. Nothing is reopened by path,
/// duplicated, or closed.
#[cfg(unix)]
pub fn main_database_write_geometry(
    connection: &rusqlite::Connection,
) -> Result<SqliteWriteGeometryData, SqliteWriteGeometryError> {
    use rusqlite::ffi;
    use std::ffi::CStr;

    crate::inspect_main_database_file_identity(connection)
        .map_err(SqliteWriteGeometryError::Identity)?;

    // SAFETY: the borrowed connection keeps its sqlite3 handle open for the
    // file controls below, which all run before this function returns.
    let handle = unsafe { connection.handle() };
    let mut reserved: std::ffi::c_int = -1;
    // SAFETY: RESERVE_BYTES takes a typed int. The value -1 is outside
    // 0..=255, so SQLite only reports the requested or actual reserve.
    let reserve_status = unsafe {
        ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_RESERVE_BYTES,
            std::ptr::addr_of_mut!(reserved).cast(),
        )
    };
    if reserve_status != ffi::SQLITE_OK {
        return Err(SqliteWriteGeometryError::FileControl {
            control: SqliteGeometryFileControl::ReserveBytes,
            status: reserve_status,
        });
    }
    let reserved_bytes = reserved_bytes(reserved)?;

    let mut vfs = std::ptr::null_mut::<ffi::sqlite3_vfs>();
    // SAFETY: VFS_POINTER receives the live handle and a typed out-pointer.
    let vfs_status = unsafe {
        ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_VFS_POINTER,
            std::ptr::addr_of_mut!(vfs).cast(),
        )
    };
    let vfs = control_pointer(SqliteGeometryFileControl::VfsPointer, vfs_status, vfs)?;
    let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
    // SAFETY: FILE_POINTER receives the live handle and a typed out-pointer.
    let file_status = unsafe {
        ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            std::ptr::addr_of_mut!(file).cast(),
        )
    };
    let file = control_pointer(SqliteGeometryFileControl::FilePointer, file_status, file)?;

    // SAFETY: `file` is the non-null main file SQLite just returned. SQLite
    // can replace it only while running an operation on this connection, and
    // no SQLite call runs between FILE_POINTER and these reads.
    let methods = unsafe { (*file).pMethods };
    // SAFETY: a non-null pMethods points at the VFS's static method table,
    // which stays valid while the main file is open, as established above.
    let methods = unsafe { methods.as_ref() }.ok_or(SqliteWriteGeometryError::MissingMethod(
        SqliteGeometryMethod::IoMethods,
    ))?;
    let sector_size = methods
        .xSectorSize
        .ok_or(SqliteWriteGeometryError::MissingMethod(
            SqliteGeometryMethod::SectorSize,
        ))?;
    let device_characteristics =
        methods
            .xDeviceCharacteristics
            .ok_or(SqliteWriteGeometryError::MissingMethod(
                SqliteGeometryMethod::DeviceCharacteristics,
            ))?;
    // SAFETY: the public xSectorSize method receives its own live main file.
    // The unix implementation only reads or lazily fills that file's fields.
    let sector = unsafe { sector_size(file) };
    // SAFETY: the public xDeviceCharacteristics method receives its own live
    // main file and only reads or lazily fills that file's fields.
    let device = unsafe { device_characteristics(file) };

    // SAFETY: `vfs` is the non-null VFS SQLite just returned for the open main
    // file; registered VFS objects outlive the files they own.
    let name = unsafe { (*vfs).zName };
    if name.is_null() {
        return Err(SqliteWriteGeometryError::MissingVfsName);
    }
    // SAFETY: a non-null zName is the VFS's NUL-terminated name, valid while
    // the VFS stays registered, which it does while it owns the main file.
    let vfs_name = unsafe { CStr::from_ptr(name) }
        .to_str()
        .map_err(|_| SqliteWriteGeometryError::VfsNameNotUtf8)?
        .to_owned();

    Ok(SqliteWriteGeometryData {
        reserved_bytes,
        sector_bytes: sector_bytes(sector)?,
        device_characteristics: device_characteristics_flags(device)?,
        vfs_name,
    })
}

/// Non-Unix platforms have no audited SQLite descriptor and always refuse.
#[cfg(not(unix))]
pub fn main_database_write_geometry(
    _connection: &rusqlite::Connection,
) -> Result<SqliteWriteGeometryData, SqliteWriteGeometryError> {
    Err(SqliteWriteGeometryError::Identity(
        SqliteFileIdentityInspectionError::Validation(
            "qualified SQLite file identity requires Unix".to_owned(),
        ),
    ))
}

#[cfg(unix)]
fn control_pointer<T>(
    control: SqliteGeometryFileControl,
    status: std::ffi::c_int,
    pointer: *mut T,
) -> Result<*mut T, SqliteWriteGeometryError> {
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(SqliteWriteGeometryError::FileControl { control, status });
    }
    if pointer.is_null() {
        return Err(SqliteWriteGeometryError::NullPointer(control));
    }
    Ok(pointer)
}

#[cfg(any(unix, test))]
fn reserved_bytes(value: i32) -> Result<u64, SqliteWriteGeometryError> {
    if !(0..=MAX_RESERVED_BYTES).contains(&value) {
        return Err(SqliteWriteGeometryError::ReservedBytes(value));
    }
    u64::try_from(value).map_err(|_| SqliteWriteGeometryError::ReservedBytes(value))
}

#[cfg(any(unix, test))]
fn sector_bytes(value: i32) -> Result<u64, SqliteWriteGeometryError> {
    if !(MIN_SECTOR_BYTES..=MAX_SECTOR_BYTES).contains(&value) {
        return Err(SqliteWriteGeometryError::SectorSize(value));
    }
    u64::try_from(value)
        .ok()
        .filter(|bytes| bytes.is_power_of_two())
        .ok_or(SqliteWriteGeometryError::SectorSize(value))
}

#[cfg(any(unix, test))]
fn device_characteristics_flags(value: i32) -> Result<u32, SqliteWriteGeometryError> {
    u32::try_from(value).map_err(|_| SqliteWriteGeometryError::DeviceCharacteristics(value))
}

#[cfg(test)]
mod tests;
