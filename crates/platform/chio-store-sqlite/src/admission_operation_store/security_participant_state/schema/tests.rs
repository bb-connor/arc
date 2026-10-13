use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn recorded_admission_versions_preserve_native_catalog_and_refuse_future() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE chio_store_schema_versions (store_key TEXT PRIMARY KEY, version INTEGER NOT NULL);
         INSERT INTO chio_store_schema_versions VALUES ('admission_operation', 28);",
    )?;
    assert_eq!(recorded_version(&connection)?, 28);
    connection.execute_batch(&sql()?)?;
    let native_catalog = catalog(&connection)?;
    let native_digest = digest_version(29)?;
    for version in 29..=40 {
        connection.execute(
            "UPDATE chio_store_schema_versions SET version=?1 WHERE store_key='admission_operation'",
            [version],
        )?;
        let selected = recorded_version(&connection)?;
        assert_eq!(
            selected, 29,
            "changed native catalog at admission schema{version}"
        );
        assert_eq!(digest_version(selected)?, native_digest);
        assert!(verify_version(&connection, selected)?);
        assert_eq!(catalog(&connection)?, native_catalog);
    }
    for version in [-1, 0, 27, 41, i32::MAX] {
        connection.execute(
            "UPDATE chio_store_schema_versions SET version=?1 WHERE store_key='admission_operation'",
            [version],
        )?;
        assert!(recorded_version(&connection).is_err());
        assert_eq!(catalog(&connection)?, native_catalog);
        assert_eq!(digest_version(29)?, native_digest);
    }
    Ok(())
}

#[test]
fn compiled_catalog_digest_preserves_each_version_and_rejects_unsupported_versions() -> TestResult {
    for version in [28, 29] {
        let mut bytes = b"chio.security-participant-state.catalog.v1\0".to_vec();
        bytes.extend(canonical_json_bytes(&expected(version)?)?);
        let expected_digest = sha256_hex(&bytes);
        for _ in 0..3 {
            assert_eq!(digest_version(version)?, expected_digest);
        }
    }
    assert_ne!(digest_version(28)?, digest_version(29)?);
    assert_eq!(digest()?, digest_version(29)?);
    for version in [-1, 0, 27, 30, 32, i32::MAX] {
        assert!(digest_version(version).is_err());
    }
    Ok(())
}

#[test]
fn cached_compiled_digest_never_replaces_live_catalog_verification() -> TestResult {
    for version in [28, 29] {
        let expected_digest = digest_version(version)?;
        let connection = Connection::open_in_memory()?;
        assert!(!verify_version(&connection, version)?);
        connection.execute_batch(&if version == 28 {
            predecessor_sql()
        } else {
            sql()?
        })?;
        assert!(verify_version(&connection, version)?);
        connection.execute_batch(
            "CREATE TABLE security_participant_state_untrusted_extra (value TEXT)",
        )?;
        assert_eq!(digest_version(version)?, expected_digest);
        assert!(verify_version(&connection, version).is_err());
    }
    Ok(())
}
