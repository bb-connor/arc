use super::*;

fn assert_integrity_failure(error: AdmissionOperationStoreError) {
    assert!(
        matches!(error, AdmissionOperationStoreError::Invariant(ref message)
        if message.contains("runtime replay migration integrity:")),
        "{error:?}"
    );
}

fn tamper_with_triggers_restored(fixture: &Fixture, table: &str, sql: &str) -> AnchoredTestResult {
    let connection = fixture.store.connection()?;
    let triggers: Vec<(String, String)> = connection.prepare(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = ?1 ORDER BY name",
    )?.query_map([table], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<_, _>>()?;
    assert!(
        !triggers.is_empty(),
        "fixture must actually disable the production barriers"
    );
    for (name, _) in &triggers {
        connection.execute_batch(&format!("DROP TRIGGER {name};"))?;
    }
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    connection.execute_batch(sql)?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    for (_, ddl) in triggers {
        connection.execute_batch(&ddl)?;
    }
    Ok(())
}

#[test]
fn destination_inventory_event_and_tombstone_corruption_is_never_repaired() -> AnchoredTestResult {
    for (table, sql) in [
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET canonical_source = X'7b7d'"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET source_id = 'substituted-source'"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET runtime_authority_id = 'substituted-runtime'"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET destination_store_uuid = 'substituted-destination'"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET expectation_id = 'substituted-expectation'"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET inventory_sha256 = printf('%064d', 1)"),
        ("runtime_replay_migration_expectations", "UPDATE runtime_replay_migration_expectations SET expectation_digest = printf('%064d', 2)"),
        ("runtime_replay_migration_events", "UPDATE runtime_replay_migration_events SET event_digest = printf('%064d', 3) WHERE sequence = 2"),
        ("runtime_replay_migration_events", "UPDATE runtime_replay_migration_events SET observed_at_unix_ms = observed_at_unix_ms + 1 WHERE sequence = 2"),
        ("runtime_replay_migration_events", "UPDATE runtime_replay_migration_events SET store_lease_id = 'forged-lease' WHERE sequence = 2"),
        ("runtime_replay_migration_events", "DELETE FROM runtime_replay_migration_events WHERE sequence = 2"),
        ("runtime_replay_migration_events", "DELETE FROM runtime_replay_migration_events WHERE sequence = 1"),
        ("runtime_replay_legacy_tombstones", "UPDATE runtime_replay_legacy_tombstones SET historical_admission_id = 'fabricated-owner' WHERE participant_kind = 'destructive_lease'"),
        ("runtime_replay_legacy_tombstones", "UPDATE runtime_replay_legacy_tombstones SET resource_id = 'different-resource' WHERE participant_kind = 'destructive_lease'"),
        ("runtime_replay_legacy_tombstones", "UPDATE runtime_replay_legacy_tombstones SET source_id = 'different-source' WHERE participant_kind = 'destructive_lease'"),
        ("runtime_replay_legacy_tombstones", "UPDATE runtime_replay_legacy_tombstones SET expectation_id = 'different-expectation' WHERE participant_kind = 'destructive_lease'"),
        ("runtime_replay_legacy_tombstones", "DELETE FROM runtime_replay_legacy_tombstones WHERE participant_kind = 'destructive_lease'"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false);
        let expected = pin(&fixture, &source)?;
        import(&fixture, &source, &expected)?;
        let callbacks_before = source.calls();
        let commits_before = global_count(&fixture.store);
        // Mutate through the owner's own connection so its data_version fence
        // cannot masquerade as evidence that the row verifier caught tampering.
        tamper_with_triggers_restored(&fixture, table, sql)?;
        assert_integrity_failure(load(&fixture).expect_err(sql));
        assert_integrity_failure(pin(&fixture, &source).expect_err(sql));
        assert_integrity_failure(import(&fixture, &source, &expected).expect_err(sql));
        assert_eq!(source.calls(), callbacks_before, "corrupt destination must reject before callbacks: {sql}");
        assert_eq!(global_count(&fixture.store), commits_before, "corrupt destination must never be repaired: {sql}");
    }
    Ok(())
}

#[test]
fn tombstones_without_an_import_event_are_not_inferred_as_success() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    fixture.store.connection()?.execute(
        "INSERT INTO runtime_replay_legacy_tombstones
         (runtime_authority_id, participant_kind, resource_id, source_id, expectation_id, historical_admission_id)
         VALUES (?1, 'destructive_lease', 'same-resource', ?2, ?3, 'historical-admission-0')",
        params![RUNTIME_ID, SOURCE_ID, expected.expectation_id().as_str()],
    )?;
    assert_integrity_failure(
        load(&fixture).expect_err("partial import is not a recoverable success"),
    );
    assert_integrity_failure(
        import(&fixture, &source, &expected).expect_err("partial rows cannot be backfilled"),
    );
    assert_eq!(source.calls(), ["preview"]);
    Ok(())
}

#[test]
fn imported_rows_reject_updates_deletes_and_replacement() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let expected = pin(&fixture, &source)?;
    let imported = import(&fixture, &source, &expected)?;
    for table in [
        "runtime_replay_migration_expectations",
        "runtime_replay_migration_events",
        "runtime_replay_legacy_tombstones",
    ] {
        for sql in [
            format!("UPDATE {table} SET runtime_authority_id = runtime_authority_id"),
            format!("DELETE FROM {table}"),
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
            format!("REPLACE INTO {table} SELECT * FROM {table}"),
        ] {
            let connection = fixture.store.connection()?;
            // Replacement must be guarded even under SQLite's normal default.
            connection.execute_batch("PRAGMA recursive_triggers = OFF;")?;
            let error = connection
                .execute_batch(&sql)
                .expect_err("migration history is immutable");
            assert!(
                matches!(error, rusqlite::Error::SqliteFailure(ref failure, _)
                if failure.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER),
                "{sql}: {error:?}"
            );
        }
    }
    assert_record_equal(&load(&fixture)?.expect("same immutable import"), &imported);
    Ok(())
}

#[test]
fn pinned_source_decoder_rejects_noncanonical_corrupt_and_oversized_evidence() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let original = source.snapshot(SOURCE_ID, RUNTIME_ID, &fixture.fence.store_uuid)?;
    let mut bad_values = Vec::new();
    let value: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
    for pointer in [
        "/body/binding/sourceId",
        "/body/binding/runtimeAuthorityId",
        "/body/binding/destinationAuthorityId",
        "/body/device",
        "/body/inode",
        "/body/barrierSha256",
        "/inventorySha256",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).expect("fixture field") = serde_json::json!("0".repeat(64));
        bad_values.push(canonical_json_bytes(&changed)?);
    }
    for (pointer, replacement) in [
        ("/body/linkCount", serde_json::json!(2)),
        ("/body/markerCounts/0", serde_json::json!(2)),
        ("/body/markers/0/resourceId", serde_json::json!(" ")),
        (
            "/body/markers/0/admissionId",
            serde_json::json!("x".repeat(513)),
        ),
        ("/body/schema", serde_json::json!("other-schema")),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).expect("fixture field") = replacement;
        bad_values.push(canonical_json_bytes(&changed)?);
    }
    let mut changed = value;
    changed["unknownField"] = serde_json::json!(true);
    bad_values.push(canonical_json_bytes(&changed)?);
    let mut noncanonical = original.canonical_bytes().to_vec();
    noncanonical.push(b'\n');
    bad_values.push(noncanonical);
    bad_values.push(Vec::new());
    bad_values.push(vec![
        b' ';
        chio_kernel::admission_operation::MAX_RUNTIME_REPLAY_SOURCE_BYTES
            + 1
    ]);
    for bytes in bad_values {
        let error = RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&bytes)
            .expect_err("untrusted evidence must reject");
        assert!(
            matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.starts_with("runtime replay source:")),
            "{error:?}"
        );
    }
    assert!(!format!("{original:?}").contains("historical-admission"));
    Ok(())
}

#[test]
fn decoder_rejects_self_consistent_duplicate_unsorted_and_excessive_markers() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = Source::new(&fixture, false);
    let original = source.snapshot(SOURCE_ID, RUNTIME_ID, &fixture.fence.store_uuid)?;
    let value: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
    for case in ["duplicate", "unsorted", "too-many", "counts", "nondecimal"] {
        let mut body = value["body"].clone();
        match case {
            "duplicate" => {
                let mut marker = body["markers"][0].clone();
                marker["admissionId"] = serde_json::json!("different-historical-owner");
                body["markers"] = serde_json::json!([body["markers"][0], marker]);
                body["markerCounts"] = serde_json::json!([2, 0, 0]);
            }
            "unsorted" => {
                body["markers"] = serde_json::json!([body["markers"][1], body["markers"][0]]);
                body["markerCounts"] = serde_json::json!([1, 1, 0]);
            }
            "too-many" => {
                let count = chio_kernel::admission_operation::MAX_RUNTIME_REPLAY_SOURCE_MARKERS + 1;
                let markers: Vec<_> = (0..count).map(|index| serde_json::json!({
                    "kind":"destructive_lease", "resourceId":format!("resource-{index:05}"), "admissionId":"historical"
                })).collect();
                body["markers"] = serde_json::json!(markers);
                body["markerCounts"] = serde_json::json!([count, 0, 0]);
            }
            "counts" => body["markerCounts"] = serde_json::json!([3, 0, 0]),
            "nondecimal" => body["device"] = serde_json::json!("01"),
            _ => unreachable!("fixed test cases"),
        }
        let mut preimage = b"chio.runtime-replay-source-seal.v1\0".to_vec();
        preimage.extend_from_slice(&canonical_json_bytes(&body)?);
        let encoded = canonical_json_bytes(
            &serde_json::json!({"body":body,"inventorySha256":sha256_hex(&preimage)}),
        )?;
        let error = RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&encoded).expect_err(case);
        let wanted = match case {
            "duplicate" | "unsorted" => "source markers are not sorted and unique",
            "too-many" => "source snapshot marker limit exceeded",
            "counts" => "source marker counts disagree",
            "nondecimal" => "source file identity is not canonical decimal",
            _ => unreachable!("fixed test cases"),
        };
        assert!(
            matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains(wanted)),
            "{case}: {error:?}"
        );
    }
    Ok(())
}

struct MisboundSource<'a> {
    inner: &'a Source,
    changed_binding: usize,
}

impl RuntimeReplaySourcePort for MisboundSource<'_> {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        self.inner.observe("preview")?;
        let mut binding = [
            source_id.as_str(),
            runtime_authority_id.as_str(),
            destination_authority_id.as_str(),
        ];
        binding[self.changed_binding] = "substituted-binding";
        self.inner.snapshot(binding[0], binding[1], binding[2])
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.inner.seal_exact(expected)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.inner.verify_exact(expected)
    }
}

#[test]
fn configured_source_must_echo_the_exact_destination_and_authority_binding() -> AnchoredTestResult {
    for changed_binding in 0..3 {
        let fixture = fixture();
        let source = Source::new(&fixture, false);
        let before = global_count(&fixture.store);
        let error = fixture
            .store
            .expect_runtime_replay_source(
                &identifier("source_id", SOURCE_ID),
                &identifier("runtime_authority_id", RUNTIME_ID),
                &MisboundSource {
                    inner: &source,
                    changed_binding,
                },
                &fixture.fence,
                now_ms(),
            )
            .expect_err("misbound source cannot be pinned");
        assert!(
            matches!(error, AdmissionOperationStoreError::Invariant(ref message) if message.contains("runtime replay migration source binding mismatch")),
            "{error:?}"
        );
        assert_eq!(source.calls(), ["preview"]);
        assert!(load(&fixture)?.is_none());
        assert_eq!(global_count(&fixture.store), before);
    }
    Ok(())
}
