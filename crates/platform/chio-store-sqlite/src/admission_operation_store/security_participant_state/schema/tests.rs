use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn compiled_catalog_digest_is_stable() -> TestResult {
    let mut bytes = b"chio.security-participant-state.catalog.v1\0".to_vec();
    bytes.extend(canonical_json_bytes(&expected()?)?);
    let expected_digest = sha256_hex(&bytes);
    for _ in 0..3 {
        assert_eq!(digest()?, expected_digest);
    }
    Ok(())
}

#[test]
fn cached_compiled_digest_never_replaces_live_catalog_verification() -> TestResult {
    let expected_digest = digest()?;
    let connection = Connection::open_in_memory()?;
    assert!(!verify(&connection)?);
    connection.execute_batch(&sql()?)?;
    assert!(verify(&connection)?);
    connection
        .execute_batch("CREATE TABLE security_participant_state_untrusted_extra (value TEXT)")?;
    assert_eq!(digest()?, expected_digest);
    assert!(verify(&connection).is_err());
    Ok(())
}
