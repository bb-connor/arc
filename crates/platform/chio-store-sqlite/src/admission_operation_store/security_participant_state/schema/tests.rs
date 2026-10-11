use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
