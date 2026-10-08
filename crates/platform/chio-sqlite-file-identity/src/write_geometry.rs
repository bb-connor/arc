//! Read the layout SQLite actually uses without changing its page or VFS state.

/// Observed physical layout DATA. It is not a reservation or writer authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteWriteGeometryData {
    reserved_bytes: u64,
    sector_bytes: u64,
    device_characteristics: u32,
    vfs_name: String,
}

impl SqliteWriteGeometryData {
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    pub fn sector_bytes(&self) -> u64 {
        self.sector_bytes
    }

    pub fn device_characteristics(&self) -> u32 {
        self.device_characteristics
    }

    pub fn powersafe_overwrite(&self) -> bool {
        self.device_characteristics & 0x1000 != 0
    }

    pub fn vfs_name(&self) -> &str {
        &self.vfs_name
    }
}

/// Borrow the actual main file and its public I/O methods. Passing -1 to the
/// reserve-byte file control queries the current or pending maximum without
/// changing either. No descriptor is opened, closed or duplicated here.
#[cfg(unix)]
pub fn main_database_write_geometry(
    connection: &rusqlite::Connection,
) -> Result<SqliteWriteGeometryData, String> {
    use rusqlite::ffi;
    use std::ffi::CStr;

    // Reuse the existing exact-descriptor and bundled Unix VFS boundary.
    super::main_database_file_identity(connection)?;
    let mut reserved = -1_i32;
    let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
    let mut vfs = std::ptr::null_mut::<ffi::sqlite3_vfs>();
    // SAFETY: the connection keeps its sqlite3 handle and file objects alive.
    // These public controls take an int and correctly typed output pointers.
    let (reserved_result, file_result, vfs_result) = unsafe {
        let handle = connection.handle();
        (
            ffi::sqlite3_file_control(
                handle,
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_RESERVE_BYTES,
                std::ptr::addr_of_mut!(reserved).cast(),
            ),
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
    if reserved_result != ffi::SQLITE_OK || !(0..=255).contains(&reserved) {
        return Err("SQLite main reserved bytes are unavailable".to_owned());
    }
    if file_result != ffi::SQLITE_OK || file.is_null() {
        return Err("SQLite main geometry file is unavailable".to_owned());
    }
    if vfs_result != ffi::SQLITE_OK || vfs.is_null() {
        return Err("SQLite main geometry VFS is unavailable".to_owned());
    }
    // SAFETY: these public file/VFS fields belong to the borrowed connection.
    let (sector, device, name) = unsafe {
        let methods = (*file)
            .pMethods
            .as_ref()
            .ok_or_else(|| "SQLite main geometry has no public I/O methods".to_owned())?;
        let sector = methods
            .xSectorSize
            .ok_or_else(|| "SQLite main geometry has no sector-size method".to_owned())?(
            file
        );
        let device = methods.xDeviceCharacteristics.ok_or_else(|| {
            "SQLite main geometry has no device-characteristics method".to_owned()
        })?(file);
        let name = (*vfs).zName;
        if name.is_null() {
            return Err("SQLite main geometry VFS has no name".to_owned());
        }
        let name = CStr::from_ptr(name)
            .to_str()
            .map_err(|_| "SQLite main geometry VFS name is invalid".to_owned())?
            .to_owned();
        (sector, device, name)
    };
    let sector_bytes = u64::try_from(sector)
        .map_err(|_| "SQLite main geometry sector size is invalid".to_owned())?;
    if sector_bytes == 0 || !sector_bytes.is_power_of_two() || sector_bytes > 65_536 {
        return Err("SQLite main geometry sector size is unsupported".to_owned());
    }
    let device_characteristics = u32::try_from(device)
        .map_err(|_| "SQLite main device characteristics are invalid".to_owned())?;
    Ok(SqliteWriteGeometryData {
        reserved_bytes: u64::try_from(reserved)
            .map_err(|_| "SQLite main reserved bytes are invalid".to_owned())?,
        sector_bytes,
        device_characteristics,
        vfs_name: name,
    })
}

#[cfg(not(unix))]
pub fn main_database_write_geometry(
    _connection: &rusqlite::Connection,
) -> Result<SqliteWriteGeometryData, String> {
    Err("qualified SQLite write geometry requires Unix".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn geometry_queries_preserve_the_existing_file_and_transaction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("geometry.sqlite3");
        let connection = rusqlite::Connection::open(database)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE probe(value INTEGER); BEGIN IMMEDIATE;",
        )?;
        let identity = crate::main_database_file_identity(&connection)?;
        let before = main_database_write_geometry(&connection)?;
        assert_eq!(before.reserved_bytes(), 0);
        assert!(before.vfs_name().starts_with("unix"));
        assert_eq!(main_database_write_geometry(&connection)?, before);
        assert_eq!(crate::main_database_file_identity(&connection)?, identity);
        connection.execute("INSERT INTO probe VALUES (1)", [])?;
        connection.execute_batch("COMMIT")?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn geometry_reports_pending_reserved_bytes_without_changing_them(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use rusqlite::ffi;
        let directory = tempfile::tempdir()?;
        let connection = rusqlite::Connection::open(directory.path().join("reserved.sqlite3"))?;
        connection.execute_batch("PRAGMA page_size=512; CREATE TABLE probe(value INTEGER);")?;
        let mut reserved = 32_i32;
        // SAFETY: this test supplies the documented typed int to the live
        // connection. The production geometry API only performs a -1 query.
        let result = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_RESERVE_BYTES,
                std::ptr::addr_of_mut!(reserved).cast(),
            )
        };
        assert_eq!(result, ffi::SQLITE_OK);
        assert_eq!(
            main_database_write_geometry(&connection)?.reserved_bytes(),
            32
        );
        assert_eq!(
            main_database_write_geometry(&connection)?.reserved_bytes(),
            32
        );
        connection.execute("INSERT INTO probe VALUES (1)", [])?;
        Ok(())
    }

    #[test]
    fn geometry_requires_an_actual_supported_main_file() -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_in_memory()?;
        assert!(main_database_write_geometry(&connection).is_err());
        Ok(())
    }
}
