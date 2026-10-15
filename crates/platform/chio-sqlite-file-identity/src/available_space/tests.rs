use super::*;
use std::error::Error as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn available_bytes_multiplies_blocks_by_fragment_size() -> TestResult {
    assert_eq!(available_bytes(0, 4096)?, 0);
    assert_eq!(available_bytes(3, 4096)?, 12_288);
    assert_eq!(available_bytes(u128::from(u64::MAX), 1)?, u64::MAX);
    assert_eq!(available_bytes(1, u128::from(u64::MAX))?, u64::MAX);
    Ok(())
}

#[test]
fn available_bytes_refuses_zero_fragment_size_and_overflow() {
    for (blocks, fragment) in [(1, 0), (0, 0), (u128::from(u64::MAX), 0)] {
        assert!(
            matches!(
                available_bytes(blocks, fragment),
                Err(SqliteAvailableSpaceError::ZeroFragmentSize)
            ),
            "{blocks} blocks of fragment size {fragment} must refuse"
        );
    }
    for (blocks, fragment) in [
        (u128::from(u64::MAX), 2),
        (2, u128::from(u64::MAX)),
        (u128::from(u64::MAX), u128::from(u64::MAX)),
        (u128::MAX, 2),
    ] {
        assert!(
            matches!(
                available_bytes(blocks, fragment),
                Err(SqliteAvailableSpaceError::CapacityOverflow)
            ),
            "{blocks} blocks of fragment size {fragment} must overflow"
        );
    }
}

#[test]
fn arithmetic_refusals_have_exact_messages_and_no_source() {
    for (error, message) in [
        (
            SqliteAvailableSpaceError::ZeroFragmentSize,
            "SQLite main database filesystem fragment size is zero",
        ),
        (
            SqliteAvailableSpaceError::CapacityOverflow,
            "SQLite main database filesystem capacity overflow",
        ),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}

#[cfg(unix)]
#[test]
fn reports_space_of_the_held_file_after_rename_replacement_and_unlink() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("space.sqlite3");
    let moved = directory.path().join("moved.sqlite3");
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("CREATE TABLE space_probe(value INTEGER);")?;
    connection.execute("INSERT INTO space_probe VALUES(1)", [])?;
    main_database_available_bytes(&connection)?;
    let original = crate::inspect_main_database_file_identity(&connection)?;

    std::fs::rename(&database, &moved)?;
    std::fs::write(&database, b"replacement file")?;
    main_database_available_bytes(&connection)?;

    // With both paths gone, a path-based observation could not succeed.
    std::fs::remove_file(&database)?;
    std::fs::remove_file(&moved)?;
    assert!(!database.exists() && !moved.exists());
    main_database_available_bytes(&connection)?;
    let unlinked = crate::inspect_main_database_file_identity(&connection)?;
    assert_eq!(
        (unlinked.device, unlinked.inode, unlinked.link_count),
        (original.device, original.inode, 0)
    );

    // Observing capacity grants no writer authority: SQLite refuses to write
    // a database whose path no longer names the held file.
    let retained = |connection: &rusqlite::Connection| {
        connection.query_row(
            "SELECT count(*) FROM space_probe WHERE value = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
    };
    assert_eq!(retained(&connection)?, 1);
    match connection.execute("INSERT INTO space_probe VALUES(2)", []) {
        Err(rusqlite::Error::SqliteFailure(error, _)) => {
            assert_eq!(error.code, rusqlite::ErrorCode::ReadOnly);
            assert_eq!(error.extended_code, rusqlite::ffi::SQLITE_READONLY_DBMOVED);
        }
        other => {
            return Err(format!("expected SQLITE_READONLY_DBMOVED, got {other:?}").into());
        }
    }
    assert_eq!(retained(&connection)?, 1);
    main_database_available_bytes(&connection)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn memory_database_refuses_with_the_identity_validation() -> TestResult {
    let connection = rusqlite::Connection::open_in_memory()?;
    let error = main_database_available_bytes(&connection)
        .err()
        .ok_or("a memory database has no main file descriptor")?;
    let SqliteAvailableSpaceError::Identity(SqliteFileIdentityInspectionError::Validation(message)) =
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
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<SqliteFileIdentityInspectionError>())
        .ok_or("the identity refusal must remain the source")?;
    assert!(matches!(
        source,
        SqliteFileIdentityInspectionError::Validation(_)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn invalid_descriptor_fstatvfs_preserves_actual_ebadf_source() -> TestResult {
    // fstatvfs(-1) returns EBADF without touching any SQLite descriptor.
    let error = descriptor_available_bytes(-1)
        .err()
        .ok_or("actual fstatvfs must refuse an invalid descriptor")?;
    assert!(
        matches!(&error, SqliteAvailableSpaceError::Io(_)),
        "native fstatvfs refusal must retain Io ownership: {error:?}"
    );
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .ok_or("actual native IO cause must remain inspectable")?;
    assert_eq!(source.raw_os_error(), Some(libc::EBADF));
    assert!(error
        .to_string()
        .starts_with("SQLite main database filesystem capacity failed: "));
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_refuses_available_space() -> TestResult {
    let connection = rusqlite::Connection::open_in_memory()?;
    let error = main_database_available_bytes(&connection)
        .err()
        .ok_or("non-Unix inspection must refuse")?;
    assert!(matches!(
        &error,
        SqliteAvailableSpaceError::Identity(SqliteFileIdentityInspectionError::Validation(_))
    ));
    assert_eq!(
        error.to_string(),
        "qualified SQLite file identity requires Unix"
    );
    Ok(())
}
