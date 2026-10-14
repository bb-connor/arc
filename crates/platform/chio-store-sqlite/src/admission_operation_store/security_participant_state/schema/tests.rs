use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn stamp(connection: &Connection, version: i32) -> rusqlite::Result<usize> {
    connection.execute(
        "UPDATE chio_store_schema_versions SET version=?1 WHERE store_key='admission_operation'",
        [version],
    )
}

#[test]
fn recorded_admission_versions_select_their_genuine_native_catalog_and_refuse_others() -> TestResult
{
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE chio_store_schema_versions (store_key TEXT PRIMARY KEY, version INTEGER NOT NULL);
         INSERT INTO chio_store_schema_versions VALUES ('admission_operation', 28);",
    )?;
    assert_eq!(recorded_version(&connection)?, 28);
    connection.execute_batch(&sql_version(29)?)?;
    let predecessor_catalog = catalog(&connection)?;
    for version in 29..=34 {
        stamp(&connection, version)?;
        assert_eq!(
            recorded_version(&connection)?,
            29,
            "admission schema{version}"
        );
        assert!(verify(&connection)?);
        verify_predecessor_catalog(&connection, version)?;
    }
    assert!(verify_predecessor_catalog(&connection, 27).is_err());
    stamp(&connection, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    assert_eq!(recorded_version(&connection)?, CURRENT_VERSION);
    assert!(verify(&connection).is_err());
    connection.execute_batch(&sql()?)?;
    assert!(verify(&connection)?);
    assert_ne!(catalog(&connection)?, predecessor_catalog);
    for version in 29..=34 {
        assert!(verify_predecessor_catalog(&connection, version).is_err());
    }
    for version in [
        -1,
        0,
        27,
        35,
        40,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION - 1,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION + 1,
        i32::MAX,
    ] {
        stamp(&connection, version)?;
        assert!(
            recorded_version(&connection).is_err(),
            "admission schema{version}"
        );
    }
    Ok(())
}

#[test]
fn compiled_catalog_digest_preserves_each_version_and_rejects_unsupported_versions() -> TestResult {
    for version in [28, 29, CURRENT_VERSION] {
        let mut bytes = b"chio.security-participant-state.catalog.v1\0".to_vec();
        bytes.extend(canonical_json_bytes(&expected(version)?)?);
        let expected_digest = sha256_hex(&bytes);
        for _ in 0..3 {
            assert_eq!(digest_version(version)?, expected_digest);
        }
    }
    assert_ne!(digest_version(28)?, digest_version(29)?);
    assert_ne!(digest_version(29)?, digest_version(CURRENT_VERSION)?);
    assert_eq!(digest()?, digest_version(CURRENT_VERSION)?);
    for version in [-1, 0, 27, 31, 32, i32::MAX] {
        assert!(digest_version(version).is_err());
    }
    Ok(())
}

#[test]
fn cached_compiled_digest_never_replaces_live_catalog_verification() -> TestResult {
    for version in [28, 29, CURRENT_VERSION] {
        let expected_digest = digest_version(version)?;
        let connection = Connection::open_in_memory()?;
        assert!(!verify_version(&connection, version)?);
        connection.execute_batch(&sql_version(version)?)?;
        assert!(verify_version(&connection, version)?);
        connection.execute_batch(
            "CREATE TABLE security_participant_state_untrusted_extra (value TEXT)",
        )?;
        assert_eq!(digest_version(version)?, expected_digest);
        assert!(verify_version(&connection, version).is_err());
    }
    Ok(())
}

#[test]
fn current_catalog_adds_only_the_imported_scope_index_to_v29() -> TestResult {
    let predecessor = expected(29)?;
    let current = expected(CURRENT_VERSION)?;
    assert!(predecessor.iter().all(|entry| current.contains(entry)));
    let added = current
        .iter()
        .filter(|entry| !predecessor.contains(entry))
        .collect::<Vec<_>>();
    assert!(!added.is_empty());
    assert!(added.iter().all(
        |(_, _, table, _)| table.as_str() == "security_participant_state_imported_scope_index"
    ));
    Ok(())
}

#[test]
fn imported_scope_index_requires_an_initialization_and_is_immutable() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&sql()?)?;
    // This catalog test seeds only the index's immediate parent; the actual
    // serving lease and migration chain are exercised by the public upgrade
    // tests. Foreign keys are enabled before testing any index insertion.
    connection.pragma_update(None, "foreign_keys", false)?;
    let digest = "a".repeat(64);
    connection.execute(
        "INSERT INTO security_participant_state_initializations
         VALUES (?1, ?2, ?2, ?2, 1, 'store', 'lease', 1, ?2)",
        params!["authority", digest],
    )?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    let insert = |authority: &str, scope: &str, leaf: i64| {
        connection.execute(
            "INSERT INTO security_participant_state_imported_scope_index
             VALUES (?1, ?2, ?3, 1, ?4, X'7B7D', X'5B5D')",
            params![authority, scope, leaf, digest],
        )
    };
    let (scope, other) = ("b".repeat(64), "c".repeat(64));
    assert!(insert("foreign", &scope, 0).is_err());
    insert("authority", &scope, 0)?;
    assert!(insert("authority", &scope, 1).is_err());
    assert!(insert("authority", &other, 0).is_err());
    assert!(insert("authority", &other, 131_072).is_err());
    insert("authority", &other, 1)?;
    assert!(connection
        .execute(
            "UPDATE security_participant_state_imported_scope_index SET member_count = 2",
            [],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM security_participant_state_imported_scope_index",
            []
        )
        .is_err());
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM security_participant_state_imported_scope_index",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}
