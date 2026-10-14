//! The retained Input fate is closed data: prior bytes stay prior, current
//! bytes stay classified, and tampered fate shapes never reopen as eligible.
use super::*;
use chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1;

fn mutation_bytes(fixture: &Fixture, operation: &str) -> TestResult<Vec<u8>> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations WHERE operation_id = ?1",
        [operation],
        |row| row.get(0),
    )?)
}

#[test]
fn prior_writer_bytes_stay_v2_current_retains_fate_and_raw_keeps_v1() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let binding = initialized.admission_binding()?;
    let (context, raw) = request("raw")?;

    // The prior-writer fixture emits genuine prior bytes through the real
    // writer: v2 schema, no retained fate, cold-valid structural record.
    let (prior_operation, prior_lease) = setup(&fixture, "prior-input", &context)?;
    let prior_input = NativeSecurityInputJoinRequestV1::new(
        prior_operation.binding().operation_id().clone(),
        raw.key.clone(),
        InformationLabel::bottom(),
    )?;
    let guard = fixture.store.retained_prior_input_writer_for_test()?;
    let prior = fixture.store.join_native_security_input(
        &prior_operation,
        &prior_lease,
        &binding,
        &context,
        &prior_input,
        now_ms(),
    )?;
    drop(guard);
    let prior_generation = prior.join.snapshot.context_generation;
    let bytes = mutation_bytes(&fixture, prior_operation.binding().operation_id().as_str())?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record["schema"], "chio.native-security-flow-join.v2");
    assert!(
        record.get("input_fate").is_none(),
        "a prior writer Input record retains no fate"
    );
    assert_eq!(record["input"], serde_json::to_value(&prior_input)?);
    assert_eq!(canonical_json_bytes(&record)?, bytes);
    // A same-identity retry returns the recorded history with zero writes.
    let before = global_count(&*fixture.store.connection()?)?;
    assert_eq!(
        fixture.store.join_native_security_input(
            &prior_operation,
            &prior_lease,
            &binding,
            &context,
            &prior_input,
            now_ms(),
        )?,
        prior
    );
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert_eq!(count(&fixture)?, 1);
    // The prior record is Unproved history, never a raw or eligible upgrade:
    // it cannot adopt the raw command family or a fresh Input intent.
    assert!(fixture
        .store
        .join_native_security_flow(
            &prior_operation,
            &prior_lease,
            &binding,
            &context,
            &prior.join.command,
            now_ms(),
        )
        .is_err());
    // The retained prior bytes cold-validate and read back unchanged.
    let (_, readback) = fixture
        .store
        .load_native_security_input_join(
            prior_operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("prior input operation")?;
    assert_eq!(readback, Some(prior));

    // After the guard drops, the same store retains the classified fate. Each
    // new operation observes the flow generation its predecessor's join left.
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(prior_generation),
    );
    let (current_operation, current_lease) = setup(&fixture, "current-input", &context)?;
    let current_input = NativeSecurityInputJoinRequestV1::new(
        current_operation.binding().operation_id().clone(),
        raw.key.clone(),
        InformationLabel::bottom(),
    )?;
    let current = fixture.store.join_native_security_input(
        &current_operation,
        &current_lease,
        &binding,
        &context,
        &current_input,
        now_ms(),
    )?;
    let bytes = mutation_bytes(
        &fixture,
        current_operation.binding().operation_id().as_str(),
    )?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record["schema"], "chio.native-security-flow-join.v3");
    assert_eq!(
        record["input_fate"],
        serde_json::json!({"fate": "eligible"})
    );
    assert_eq!(record["input"], serde_json::to_value(&current_input)?);
    assert_eq!(canonical_json_bytes(&record)?, bytes);

    // Raw joins keep byte-identical v1 without input intent or fate.
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(current.join.snapshot.context_generation),
    );
    let (raw_operation, raw_lease) = setup(&fixture, "native-raw", &context)?;
    let (_, raw_command) = request("raw-join")?;
    fixture.store.join_security_participant_flow(
        &raw_operation,
        &raw_lease,
        &initialized,
        &context,
        &raw_command,
        now_ms(),
    )?;
    let bytes = mutation_bytes(&fixture, raw_operation.binding().operation_id().as_str())?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record["schema"], "chio.native-security-flow-join.v1");
    assert!(record.get("input").is_none());
    assert!(record.get("input_fate").is_none());
    assert_eq!(canonical_json_bytes(&record)?, bytes);
    assert_eq!(count(&fixture)?, 3);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn tampered_fate_shapes_fail_recovery_with_recomputed_local_hashes() -> TestResult {
    for damage in [
        // A v3 record without its fate never reads as eligible.
        "missing-fate",
        // The prior schema cannot carry a retained fate either.
        "prior-schema-with-fate",
        // Only the two closed fate variants deserialize.
        "unknown-fate-tag",
        "refused-without-origin",
        // The retained fate bytes are canonical or they are not the record.
        "noncanonical-fate",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let (context, raw) = request("raw")?;
        let (operation, lease) = setup(&fixture, "native-input", &context)?;
        let input = NativeSecurityInputJoinRequestV1::new(
            operation.binding().operation_id().clone(),
            raw.key,
            InformationLabel::bottom(),
        )?;
        fixture.store.join_native_security_input(
            &operation,
            &lease,
            &initialized.admission_binding()?,
            &context,
            &input,
            now_ms(),
        )?;
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        let bytes: Vec<u8> = connection.query_row(
            "SELECT canonical_record FROM security_participant_state_mutations",
            [],
            |row| row.get(0),
        )?;
        let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
        match damage {
            "missing-fate" => {
                record
                    .as_object_mut()
                    .ok_or("record object")?
                    .remove("input_fate");
            }
            "prior-schema-with-fate" => {
                record["schema"] = "chio.native-security-flow-join.v2".into();
            }
            "unknown-fate-tag" => {
                record["input_fate"] = serde_json::json!({"fate": "other"});
            }
            "refused-without-origin" => {
                record["input_fate"] = serde_json::json!({"fate": "refused"});
            }
            "noncanonical-fate" => {
                // Applied against the canonical bytes below; this record is not
                // re-canonicalized so the stored bytes keep the widened fate.
            }
            _ => return Err("unknown fate damage".into()),
        }
        let bytes = match damage {
            "noncanonical-fate" => {
                let canonical = String::from_utf8(canonical_json_bytes(&record)?)?;
                let exact = r#"{"fate":"eligible"}"#;
                let widened = r#"{ "fate":"eligible" }"#;
                let tampered = canonical.replace(exact, widened);
                if tampered == canonical {
                    return Err("canonical record lost its fate object".into());
                }
                // Still valid JSON, no longer the canonical encoding the
                // reader recomputes from the decoded record.
                tampered.into_bytes()
            }
            _ => canonical_json_bytes(&record)?,
        };
        let mut preimage = b"chio.native-security-mutation.commit.v1\0".to_vec();
        preimage.extend_from_slice(&bytes);
        connection.execute_batch("DROP TRIGGER security_participant_state_mutations_no_update")?;
        connection.execute("UPDATE security_participant_state_mutations SET canonical_record = ?1, mutation_digest = ?2", params![bytes, sha256_hex(&preimage)])?;
        connection.execute_batch(&native::schema::sql()?)?;
        assert!(native::verify_coverage(&connection).is_err(), "{damage}");
        drop(connection);
        assert!(
            SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
            "{damage}"
        );
    }
    Ok(())
}
