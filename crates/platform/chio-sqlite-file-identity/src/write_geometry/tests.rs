use super::*;
use std::error::Error as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(unix)]
fn reserve_bytes_control(
    connection: &rusqlite::Connection,
    value: std::ffi::c_int,
) -> Result<std::ffi::c_int, Box<dyn std::error::Error>> {
    let mut reserved = value;
    // SAFETY: the borrowed connection keeps its handle open for this call.
    let handle = unsafe { connection.handle() };
    // SAFETY: RESERVE_BYTES receives the live handle and a typed int.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            handle,
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
            std::ptr::addr_of_mut!(reserved).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(format!("RESERVE_BYTES failed with {status}").into());
    }
    Ok(reserved)
}

#[cfg(unix)]
#[test]
fn geometry_queries_preserve_the_current_file_and_transaction() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("geometry.sqlite3");
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL; CREATE TABLE probe(value INTEGER); BEGIN IMMEDIATE;",
    )?;
    let identity = crate::inspect_main_database_file_identity(&connection)?;
    let before = main_database_write_geometry(&connection)?;
    assert_eq!(before.reserved_bytes(), 0);
    assert!(before.vfs_name().starts_with("unix"));
    assert_eq!(before.sector_bytes(), 4096);
    assert!(before.powersafe_overwrite());
    assert_eq!(main_database_write_geometry(&connection)?, before);
    assert_eq!(
        crate::inspect_main_database_file_identity(&connection)?,
        identity
    );
    assert_eq!(crate::main_database_file_identity(&connection)?, identity);
    assert!(!connection.is_autocommit());
    connection.execute("INSERT INTO probe VALUES (1)", [])?;
    connection.execute_batch("COMMIT")?;
    let committed: i64 =
        connection.query_row("SELECT count(*) FROM probe WHERE value = 1", [], |row| {
            row.get(0)
        })?;
    assert_eq!(committed, 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn geometry_reports_pending_reserved_bytes_without_changing_them() -> TestResult {
    let directory = tempfile::tempdir()?;
    let connection = rusqlite::Connection::open(directory.path().join("reserved.sqlite3"))?;
    connection.execute_batch("PRAGMA page_size=512; CREATE TABLE probe(value INTEGER);")?;
    assert_eq!(reserve_bytes_control(&connection, 32)?, 0);
    for _ in 0..2 {
        assert_eq!(
            main_database_write_geometry(&connection)?.reserved_bytes(),
            32
        );
    }
    // A further -1 query still reports the same pending reserve.
    assert_eq!(reserve_bytes_control(&connection, -1)?, 32);
    let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    assert_eq!(page_size, 512);
    connection.execute("INSERT INTO probe VALUES (1)", [])?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn geometry_refuses_a_memory_database_through_the_identity_guard() -> TestResult {
    let connection = rusqlite::Connection::open_in_memory()?;
    let error = main_database_write_geometry(&connection)
        .err()
        .ok_or("a memory database has no supported main file")?;
    let SqliteWriteGeometryError::Identity(SqliteFileIdentityInspectionError::Validation(message)) =
        &error
    else {
        return Err(format!("expected identity validation, got {error:?}").into());
    };
    assert_eq!(
        message,
        "SQLite main file is not owned by the reported Unix VFS"
    );
    assert_eq!(error.to_string(), *message);
    let identity = crate::inspect_main_database_file_identity(&connection)
        .err()
        .ok_or("identity inspection must refuse the same connection")?;
    assert_eq!(identity.to_string(), *message);
    assert!(error
        .source()
        .and_then(|source| source.downcast_ref::<SqliteFileIdentityInspectionError>())
        .is_some());
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_refuses_write_geometry() -> TestResult {
    let connection = rusqlite::Connection::open_in_memory()?;
    let error = main_database_write_geometry(&connection)
        .err()
        .ok_or("non-Unix observation must refuse")?;
    assert!(matches!(
        &error,
        SqliteWriteGeometryError::Identity(SqliteFileIdentityInspectionError::Validation(_))
    ));
    assert_eq!(
        error.to_string(),
        "qualified SQLite file identity requires Unix"
    );
    Ok(())
}

#[test]
fn reserved_bytes_accept_exactly_zero_through_255() -> TestResult {
    assert_eq!(reserved_bytes(0)?, 0);
    assert_eq!(reserved_bytes(32)?, 32);
    assert_eq!(reserved_bytes(255)?, 255);
    for value in [-1, 256, i32::MIN, i32::MAX] {
        assert!(
            matches!(
                reserved_bytes(value),
                Err(SqliteWriteGeometryError::ReservedBytes(refused)) if refused == value
            ),
            "{value} reserved bytes must refuse"
        );
    }
    Ok(())
}

#[test]
fn sector_bytes_accept_only_unclamped_powers_of_two() -> TestResult {
    for value in [32, 512, 4096, 65_536] {
        assert_eq!(sector_bytes(value)?, u64::try_from(value)?);
    }
    for value in [i32::MIN, -1, 0, 1, 16, 31, 48, 4097, 65_537, 131_072] {
        assert!(
            matches!(
                sector_bytes(value),
                Err(SqliteWriteGeometryError::SectorSize(refused)) if refused == value
            ),
            "{value} sector bytes must refuse"
        );
    }
    Ok(())
}

#[test]
fn device_characteristics_refuse_negative_flags() -> TestResult {
    assert_eq!(device_characteristics_flags(0)?, 0);
    assert_eq!(
        device_characteristics_flags(rusqlite::ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE)?,
        POWERSAFE_OVERWRITE
    );
    assert_eq!(device_characteristics_flags(i32::MAX)?, 0x7fff_ffff);
    for value in [-1, i32::MIN] {
        assert!(
            matches!(
                device_characteristics_flags(value),
                Err(SqliteWriteGeometryError::DeviceCharacteristics(refused)) if refused == value
            ),
            "{value} device characteristics must refuse"
        );
    }
    Ok(())
}

#[test]
fn powersafe_overwrite_reads_the_sqlite_flag() {
    let geometry = |device_characteristics| SqliteWriteGeometryData {
        reserved_bytes: 0,
        sector_bytes: 4096,
        device_characteristics,
        vfs_name: "unix".to_owned(),
    };
    assert!(geometry(POWERSAFE_OVERWRITE).powersafe_overwrite());
    assert!(geometry(POWERSAFE_OVERWRITE | 0x8000).powersafe_overwrite());
    assert!(!geometry(0x8000).powersafe_overwrite());
    assert!(!geometry(0).powersafe_overwrite());
}
