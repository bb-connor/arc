use super::*;

#[test]
fn nonce_issuer_readers_refuse_noncanonical_and_oversized_keys() -> TestResult {
    for table in [
        "admission_execution_nonce_issuances",
        "admission_execution_nonce_reservations",
    ] {
        for variant in ["uppercase", "prefix", "oversized"] {
            let mut fixture = nonce_fixture()?;
            fixture.operation = fixture
                .fixture
                .store
                .reserve_execution_nonce_and_commit_admission(
                    &reserve_command(&fixture)?,
                    &fixture.reservation,
                    now_ms(),
                )?
                .into_operation();
            let operation_id = fixture.operation.binding().operation_id();
            assert!(fixture
                .fixture
                .store
                .load_execution_nonce_issuance(operation_id, &fixture.fixture.fence, now_ms(),)?
                .is_some());
            assert!(fixture
                .fixture
                .store
                .load_execution_nonce_reservation(operation_id, &fixture.fixture.fence, now_ms(),)?
                .is_some());
            let canonical = fixture.key.public_key().to_hex();
            let (changed, expected) = match variant {
                "uppercase" => (
                    canonical.to_uppercase(),
                    "durable nonce issuer is not canonical",
                ),
                "prefix" => (
                    format!("0x{canonical}"),
                    "durable nonce issuer is not canonical",
                ),
                _ => (
                    "a".repeat(chio_core::crypto::MAX_KEY_WIRE_BYTES + 1),
                    if table.ends_with("issuances") {
                        "durable nonce issuance exceeds its storage bound"
                    } else {
                        "durable nonce reservation exceeds its storage bound"
                    },
                ),
            };
            if variant != "oversized" {
                assert_ne!(changed, canonical);
                assert_eq!(
                    chio_core::PublicKey::from_hex(&changed)?,
                    fixture.key.public_key()
                );
            }
            fixture.fixture.store.connection()?.execute_batch(&format!(
                "DROP TRIGGER {table}_immutable; PRAGMA ignore_check_constraints = ON;"
            ))?;
            fixture
                .fixture
                .store
                .connection()?
                .execute(&format!("UPDATE {table} SET issuer = ?1"), [&changed])?;
            let result = if table.ends_with("issuances") {
                fixture.fixture.store.load_execution_nonce_issuance(
                    operation_id,
                    &fixture.fixture.fence,
                    now_ms(),
                )
            } else {
                fixture.fixture.store.load_execution_nonce_reservation(
                    operation_id,
                    &fixture.fixture.fence,
                    now_ms(),
                )
            };
            let error = result
                .err()
                .ok_or("alternate issuer entered durable history")?;
            assert!(
                matches!(error, AdmissionOperationStoreError::Invariant(ref detail) if detail == expected),
                "{error}"
            );
        }
    }
    Ok(())
}

#[test]
fn nonce_issuer_storage_bounds_match_the_public_key_wire_bound() {
    let predicate = format!(
        "octet_length(issuer) BETWEEN 1 AND {}",
        chio_core::crypto::MAX_KEY_WIRE_BYTES
    );
    for (source, count) in [
        (include_str!("../../admission_operation_nonce.sql"), 2),
        (
            include_str!("../../admission_operation_store/execution_nonce.rs"),
            1,
        ),
        (
            include_str!("../../admission_operation_store/execution_nonce/issuance/record.rs"),
            1,
        ),
    ] {
        assert_eq!(source.matches(predicate.as_str()).count(), count);
    }
}
