//! A nested SQL effect must not turn a monotone join into declassification.
use super::*;

#[test]
fn a_nested_label_downgrade_cannot_commit_as_a_monotone_join() -> TestResult {
    for table in [
        "security_participant_state_principal_flow_state",
        "security_participant_state_lineage_flow_state",
        "security_participant_state_session_flow_state",
    ] {
        let bottom = canonical_json_bytes(&InformationLabel::bottom())?;
        reject_nested_change(&format!(
            "UPDATE {table} SET label_json = X'{}', label_hash = X'{}'
             WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;",
            hex::encode(&bottom), sha256_hex(&bottom),
        ))?;
    }
    Ok(())
}

fn reject_nested_change(statement: &str) -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, mut request) = request("native-join")?;
    request.principal_join = InformationLabel::Top;
    request.lineage_join = InformationLabel::Top;
    request.session_join = InformationLabel::Top;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    let before = global_count(&*fixture.store.connection()?)?;
    fixture.store.connection()?.execute_batch(&format!(
        "CREATE TEMP TRIGGER native_test_lower_label AFTER INSERT ON main.security_participant_state_transitions
         WHEN NEW.tenant_id = 'native-tenant' AND NEW.transition_id = 'native-join' BEGIN
         {statement} END;",
    ))?;
    let result = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    );
    assert!(
        result.is_err(),
        "a native join committed an unauthorized nested change: {result:?}; {statement}"
    );
    assert_eq!(count(&fixture)?, 0);
    assert_eq!(global_count(&*fixture.store.connection()?)?, before);
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER temp.native_test_lower_label")?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    assert_eq!(joined.principal_label, InformationLabel::Top);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn nested_generation_identity_tenant_and_transition_changes_roll_back() -> TestResult {
    for statement in [
        "UPDATE security_participant_state_flow_sequences SET last_generation = 0 WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;",
        "UPDATE security_participant_state_flow_contexts SET session_id = 'other-session' WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;",
        "INSERT INTO security_participant_state_flow_sequences (security_authority_id, tenant_id, last_generation) VALUES (NEW.security_authority_id, 'other-tenant', 1);",
        "UPDATE security_participant_state_transitions SET transition_kind = 'isolation_epoch' WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id AND transition_id = NEW.transition_id;",
        "UPDATE security_participant_state_principal_flow_state SET label_hash = zeroblob(32) WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;",
    ] {
        reject_nested_change(statement)?;
    }
    Ok(())
}

#[test]
fn returned_join_snapshot_must_match_actual_rows_after_nested_effects() -> TestResult {
    reject_nested_change("UPDATE security_participant_state_flow_contexts SET generation = generation + 1 WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;")
}

#[test]
fn historical_rows_cannot_downgrade_when_the_requested_join_is_bottom() -> TestResult {
    use crate::security_state::{
        decode_retained_security_row, encode_retained_security_values, retained_security_columns,
        NativeRowChange,
    };
    use rusqlite::types::{Value, ValueRef};
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, mut request) = request("native-join")?;
    request.principal_join = InformationLabel::Top;
    request.lineage_join = InformationLabel::Top;
    request.session_join = InformationLabel::Top;
    let (operation, lease) = setup(&fixture, "native-operation", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let bytes: Vec<u8> = fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    let changes: Vec<NativeRowChange> = serde_json::from_value(record["changes"].clone())?;
    request.principal_join = InformationLabel::bottom();
    request.lineage_join = InformationLabel::bottom();
    request.session_join = InformationLabel::bottom();
    let bottom = canonical_json_bytes(&InformationLabel::bottom())?;
    for table in [
        "security_principal_flow_state",
        "security_lineage_flow_state",
        "security_session_flow_state",
    ] {
        let image = changes
            .iter()
            .find(|change| change.table == table)
            .and_then(|change| change.after.as_ref())
            .ok_or("captured label image")?;
        let mut candidate = NativeRowChange {
            table: table.into(),
            before: Some(image.clone()),
            after: Some(image.clone()),
        };
        // Equal labels remain a valid monotone history entry.
        candidate.validate_flow_join(&request)?;
        let columns = retained_security_columns(table)?;
        let mut values = decode_retained_security_row(table, image.as_bytes())?;
        for (column, value) in columns.iter().zip(&mut values) {
            if *column == "label_json" {
                *value = Value::Blob(bottom.clone());
            }
            if *column == "label_hash" {
                *value = Value::Blob(hex::decode(sha256_hex(&bottom))?);
            }
        }
        candidate.after = Some(String::from_utf8(encode_retained_security_values(
            table,
            &values.iter().map(ValueRef::from).collect::<Vec<_>>(),
        )?)?);
        // Well-typed canonical images and correct hashes do not authorize
        // historical declassification. This is the validator used at readback.
        assert!(candidate.validate_flow_join(&request).is_err(), "{table}");
    }
    Ok(())
}
