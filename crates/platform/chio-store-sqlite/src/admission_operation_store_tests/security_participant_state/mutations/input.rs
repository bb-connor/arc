//! Input intent is durable, single-operation and distinct from raw joins.
use super::*;
use chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1;

pub(super) fn label() -> TestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        Default::default(),
        std::collections::BTreeSet::from([chio_security_types::Compartment::new(
            "classified-input",
        )?]),
    )?)
}

#[test]
fn input_join_records_original_intent_and_one_complete_resolved_command() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, raw) = request("unused-raw-command")?;
    let (operation, lease) = setup(&fixture, "native-input", &context)?;
    let input = NativeSecurityInputJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key,
        label()?,
    )?;
    let binding = initialized.admission_binding()?;
    let result = fixture.store.join_native_security_input(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    result.validate()?;
    assert_eq!(result.input, input);
    assert_eq!(result.join.command.principal_join, label()?);
    assert_eq!(result.join.snapshot.principal_label, label()?);
    let (_, readback) = fixture
        .store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("input operation")?;
    assert_eq!(readback, Some(result.clone()));
    let (_, generic) = fixture
        .store
        .load_native_security_flow_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("generic operation")?;
    assert_eq!(generic, Some(result.join.clone()));
    let before = global_count(&*fixture.store.connection()?)?;
    assert_eq!(
        fixture.store.join_native_security_input(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms()
        )?,
        result
    );
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    assert_eq!(count(&fixture)?, 1);
    let bytes: Vec<u8> = fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record["schema"], "chio.native-security-flow-join.v2");
    assert_eq!(record["input"], serde_json::to_value(&input)?);
    assert_eq!(canonical_json_bytes(&record)?, bytes);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn input_retry_cannot_change_input_or_adopt_the_raw_command_family() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, raw) = request("raw")?;
    let (operation, lease) = setup(&fixture, "native-input", &context)?;
    let binding = initialized.admission_binding()?;
    let input = NativeSecurityInputJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key.clone(),
        InformationLabel::bottom(),
    )?;
    let result = fixture.store.join_native_security_input(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    let changed = NativeSecurityInputJoinRequestV1::new(
        input.operation_id().clone(),
        input.key().clone(),
        label()?,
    )?;
    let before = global_count(&*fixture.store.connection()?)?;
    assert!(fixture
        .store
        .join_native_security_input(&operation, &lease, &binding, &context, &changed, now_ms())
        .is_err());
    assert!(fixture
        .store
        .join_native_security_flow(
            &operation,
            &lease,
            &binding,
            &context,
            &result.join.command,
            now_ms()
        )
        .is_err());
    assert_eq!(count(&fixture)?, 1);
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn raw_history_preserves_v1_bytes_and_cannot_be_inferred_as_input_history() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, mut raw) = request("raw")?;
    let (operation, lease) = setup(&fixture, "native-raw", &context)?;
    let binding = initialized.admission_binding()?;
    let input = NativeSecurityInputJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key.clone(),
        InformationLabel::bottom(),
    )?;
    // Even a byte-identical resolved command and the generated prefix cannot
    // turn an original raw command into classified-input intent.
    raw.transition_id = input.transition_id().clone();
    let result = fixture.store.join_native_security_flow(
        &operation,
        &lease,
        &binding,
        &context,
        &raw,
        now_ms(),
    )?;
    let bytes: Vec<u8> = fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(record["schema"], "chio.native-security-flow-join.v1");
    assert!(record.get("input").is_none());
    assert_eq!(canonical_json_bytes(&record)?, bytes);
    assert!(fixture
        .store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert!(fixture
        .store
        .join_native_security_input(&operation, &lease, &binding, &context, &input, now_ms())
        .is_err());
    assert_eq!(
        fixture.store.join_native_security_flow(
            &operation,
            &lease,
            &binding,
            &context,
            &raw,
            now_ms()
        )?,
        result
    );
    let after: Vec<u8> = fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bytes, after);
    assert_eq!(count(&fixture)?, 1);
    Ok(())
}

#[test]
fn input_resolution_uses_current_inherited_state_but_retry_returns_original_history() -> TestResult
{
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let binding = initialized.admission_binding()?;
    let (context, raw) = request("raw-seed")?;
    let (operation, lease) = setup(&fixture, "native-input", &context)?;
    let input = NativeSecurityInputJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key.clone(),
        InformationLabel::bottom(),
    )?;
    let original = fixture.store.join_native_security_input(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    let current = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(original.join.snapshot.context_generation),
    );
    let (second, second_lease) = setup(&fixture, "raw-advance", &current)?;
    let mut raw = raw;
    raw.session_join = label()?;
    let advanced = fixture.store.join_native_security_flow(
        &second,
        &second_lease,
        &binding,
        &current,
        &raw,
        now_ms(),
    )?;
    assert!(advanced.context_generation > original.join.snapshot.context_generation);
    assert_eq!(
        fixture.store.join_native_security_input(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms()
        )?,
        original
    );
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(advanced.context_generation),
    );
    let (third, third_lease) = setup(&fixture, "input-after-raw", &context)?;
    let next = NativeSecurityInputJoinRequestV1::new(
        third.binding().operation_id().clone(),
        raw.key,
        InformationLabel::bottom(),
    )?;
    let result = fixture.store.join_native_security_input(
        &third,
        &third_lease,
        &binding,
        &context,
        &next,
        now_ms(),
    )?;
    result.validate()?;
    assert_eq!(result.input.input_label(), &InformationLabel::bottom());
    assert_eq!(result.join.command.principal_join, label()?);
    assert_eq!(result.join.snapshot.principal_label, label()?);
    assert_eq!(count(&fixture)?, 3);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn input_join_preserves_actual_lease_and_original_context_checks() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, raw) = request("raw")?;
    let (operation, lease, stale) = setup_with_stale_lease(&fixture, "native-input", &context)?;
    let binding = initialized.admission_binding()?;
    let input = NativeSecurityInputJoinRequestV1::new(
        operation.binding().operation_id().clone(),
        raw.key,
        label()?,
    )?;
    assert!(fixture
        .store
        .join_native_security_input(&operation, &stale, &binding, &context, &input, now_ms())
        .is_err());
    let stale_context =
        SecurityInvocationContext::v1(context.as_v1().clone().with_flow_state_generation(19));
    assert!(fixture
        .store
        .join_native_security_input(
            &operation,
            &lease,
            &binding,
            &stale_context,
            &input,
            now_ms()
        )
        .is_err());
    let mut wrong = serde_json::to_value(&input)?;
    wrong["transition_id"] = "forged-transition".into();
    let wrong = serde_json::from_value(wrong)?;
    assert!(fixture
        .store
        .join_native_security_input(&operation, &lease, &binding, &context, &wrong, now_ms())
        .is_err());
    assert_eq!(count(&fixture)?, 0);
    fixture.store.join_native_security_input(
        &operation,
        &lease,
        &binding,
        &context,
        &input,
        now_ms(),
    )?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn input_join_cutpoints_recover_exactly_one_intent_without_downgrading_to_raw() -> TestResult {
    let _reset = ResetCutpoint;
    for stage in 7..=11 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let (context, raw) = request("raw")?;
        let (operation, lease) = setup(&fixture, "native-input", &context)?;
        let binding = initialized.admission_binding()?;
        let input = NativeSecurityInputJoinRequestV1::new(
            operation.binding().operation_id().clone(),
            raw.key,
            label()?,
        )?;
        FAIL_AFTER.set(stage);
        let result = fixture.store.join_native_security_input(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms(),
        );
        FAIL_AFTER.set(0);
        assert!(result.is_err(), "stage {stage}");
        assert_eq!(count(&fixture)?, i64::from(stage >= 10));
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
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            _temp,
            database,
            lock_root,
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
        };
        let operation = fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("operation")?;
        let lease = claim(&fixture, &operation, "new-owner", now_ms());
        let record = fixture.store.join_native_security_input(
            &operation,
            &lease,
            &binding,
            &context,
            &input,
            now_ms(),
        )?;
        record.validate()?;
        assert_eq!(record.input, input);
        assert_eq!(count(&fixture)?, 1);
        assert!(fixture
            .store
            .join_native_security_flow(
                &operation,
                &lease,
                &binding,
                &context,
                &record.join.command,
                now_ms()
            )
            .is_err());
        native::verify_coverage(&*fixture.store.connection()?)?;
    }
    Ok(())
}

#[test]
fn input_intent_schema_and_resolution_tampering_fail_recovery_with_recomputed_local_hashes(
) -> TestResult {
    for damage in [
        "v1-with-input",
        "v2-without-input",
        "null",
        "unknown",
        "input",
        "resolution",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let (context, raw) = request("raw")?;
        let (operation, lease) = setup(&fixture, "native-input", &context)?;
        let input = NativeSecurityInputJoinRequestV1::new(
            operation.binding().operation_id().clone(),
            raw.key,
            label()?,
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
            "v1-with-input" => record["schema"] = "chio.native-security-flow-join.v1".into(),
            "v2-without-input" => {
                record
                    .as_object_mut()
                    .ok_or("record object")?
                    .remove("input");
            }
            "null" => record["input"] = serde_json::Value::Null,
            "unknown" => record["schema"] = "chio.native-security-flow-join.v3".into(),
            "input" => {
                record["input"]["input_label"] = serde_json::to_value(InformationLabel::bottom())?
            }
            "resolution" => {
                record["request"]["session_join"] =
                    serde_json::to_value(InformationLabel::bottom())?
            }
            _ => return Err("unknown input damage".into()),
        }
        let bytes = canonical_json_bytes(&record)?;
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
