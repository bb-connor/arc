use super::*;

#[test]
fn observed_clock_is_authenticated_and_cannot_be_forged() -> AnchoredTestResult {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "tamper-clock",
        "tamper-cap",
    );
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
    connection.execute_batch(
        "UPDATE admission_operation_commits SET observed_at_unix_ms = observed_at_unix_ms + 1;",
    )?;
    match verify_admission_commit_chain(&connection).expect_err("reject changed observed clock") {
        AdmissionOperationStoreError::Invariant(message) => {
            assert_eq!(
                message,
                "admission operation commit chain digest is invalid"
            );
        }
        other => panic!("expected commit digest refusal, got {other:?}"),
    }
    Ok(())
}

#[test]
fn current_version_cannot_silently_regenerate_a_missing_observation_column() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = fixture.store.connection()?;
    connection.execute_batch(
        "ALTER TABLE admission_operation_commits DROP COLUMN observed_at_unix_ms;",
    )?;
    assert!(matches!(crate::test_schema::apply(
        &mut connection,
        crate::serving_owner::SERVING_NAMESPACES,
        initialize_admission_operation_schema,
        |error| invariant(error.to_string())
    ), Err(AdmissionOperationStoreError::Invariant(message))
        if message == "admission operation schema differs from the canonical definition"));
    Ok(())
}

#[test]
fn commit_chain_requires_v1_with_an_observed_clock() -> AnchoredTestResult {
    for omit_observed_clock in [false, true] {
        let fixture = fixture();
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "commit-format",
            "commit-format-capability",
        );
        fixture.store.begin(&operation, &fixture.fence, now_ms())?;
        let connection = fixture.store.connection()?;
        let head = verify_admission_commit_chain(&connection)?;
        assert_eq!(head.head_sequence, 1);
        let mut entry = connection.query_row(
            "SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                    operation_digest, recovery_claim_digest, participant_digest,
                    previous_chain_digest, store_uuid, store_lease_id, store_owner_epoch,
                    recorded_at_unix_ms, observed_at_unix_ms
             FROM admission_operation_commits WHERE commit_sequence = 1",
            [],
            |row| {
                let mut entry = serde_json::json!({
                    "format": "chio.admission-operation-commit-chain.v1",
                    "commit_sequence": row.get::<_, i64>(0)?,
                    "operation_id": row.get::<_, String>(1)?,
                    "operation_version": row.get::<_, i64>(2)?,
                    "mutation_kind": row.get::<_, String>(3)?,
                    "operation_digest": row.get::<_, String>(4)?,
                    "recovery_claim_digest": row.get::<_, Option<String>>(5)?,
                    "previous_chain_digest": row.get::<_, String>(7)?,
                    "store_uuid": row.get::<_, String>(8)?,
                    "store_lease_id": row.get::<_, String>(9)?,
                    "store_owner_epoch": row.get::<_, i64>(10)?,
                    "recorded_at_unix_ms": row.get::<_, i64>(11)?,
                    "observed_at_unix_ms": row.get::<_, i64>(12)?,
                });
                if let Some(digest) = row.get::<_, Option<String>>(6)? {
                    entry["participant_digest"] = serde_json::Value::String(digest);
                }
                Ok(entry)
            },
        )?;
        assert_eq!(
            sha256_hex(&chio_core::canonical::canonical_json_bytes(&entry)?),
            head.chain_digest
        );
        if omit_observed_clock {
            entry
                .as_object_mut()
                .ok_or("commit entry must be an object")?
                .remove("observed_at_unix_ms");
        } else {
            entry["format"] =
                serde_json::Value::String("chio.admission-operation-commit-chain.v2".to_owned());
        }
        let invalid_digest = sha256_hex(&chio_core::canonical::canonical_json_bytes(&entry)?);
        assert_ne!(invalid_digest, head.chain_digest);
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_commits_immutable'",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable")?;
        assert_eq!(
            connection.execute(
                "UPDATE admission_operation_commits SET chain_digest = ?1 WHERE commit_sequence = 1",
                [&invalid_digest],
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
        let error = verify_admission_commit_chain(&connection).expect_err("reject digest");
        match error {
            AdmissionOperationStoreError::Invariant(message) => {
                assert_eq!(
                    message,
                    "admission operation commit chain digest is invalid"
                );
            }
            other => panic!("expected commit digest refusal, got {other:?}"),
        }
        assert_eq!(load_admission_commit_head(&connection)?, head);
        let retained: String = connection.query_row(
            "SELECT chain_digest FROM admission_operation_commits WHERE commit_sequence = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(retained, invalid_digest);
    }
    Ok(())
}
