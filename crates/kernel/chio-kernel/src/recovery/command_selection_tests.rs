use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn physical_source_keys_obey_the_store_character_and_byte_bounds() -> TestResult {
    for key in [
        "a".repeat(512),
        "\u{1f642}".repeat(512),
        "key\nwith-control".into(),
    ] {
        let source = RecoveryProtectedRecordKey::new(key.clone())?;
        assert_eq!(source.as_str(), key);
    }
    for key in [
        String::new(),
        "a".repeat(513),
        "\u{1f642}".repeat(513),
        "key\0suffix".into(),
    ] {
        assert!(matches!(
            RecoveryProtectedRecordKey::new(key),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message == "recovery physical source key refused"
        ));
    }
    Ok(())
}

#[test]
fn generation_ordinals_are_positive_safe_integers() -> TestResult {
    for value in [1, SafeInteger::MAX] {
        assert_eq!(RecoveryGenerationOrdinal::new(value)?.get(), value);
    }
    for value in [0, SafeInteger::MAX + 1, u64::MAX] {
        assert!(matches!(
            RecoveryGenerationOrdinal::new(value),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message == "recovery generation identity refused"
        ));
    }
    Ok(())
}
