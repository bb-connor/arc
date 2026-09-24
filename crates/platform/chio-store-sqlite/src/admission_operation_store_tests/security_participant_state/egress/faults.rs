use super::*;

#[test]
fn nested_label_write_is_rejected_and_rollback_disables_egress_callback() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-nested-write", None)?;
    let before = counts(&fixture)?;
    let original_joins = joins(&fixture)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_egress_label AFTER INSERT ON main.security_participant_state_egress_fences
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1
         WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id;
         END;",
    )?;
    assert!(pending.acquire(&fixture).is_err());
    assert_eq!(counts(&fixture)?, before);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    connection.execute_batch("DROP TRIGGER temp.native_test_egress_label")?;
    assert!(connection.execute("UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1 WHERE security_authority_id = 'source'", []).is_err());
    native::verify_coverage(&connection)?;
    drop(connection);
    let acquired = pending.acquire(&fixture)?;
    pending.commit(&fixture, &commitment(&acquired)?)?;
    assert_eq!(joins(&fixture)?, original_joins);
    Ok(())
}

#[test]
fn acquisition_and_commit_errors_recover_exactly_one_event_per_phase() -> AnchoredTestResult {
    let _reset = ResetCutpoint;
    for commit_phase in [false, true] {
        for stage in 12..=16 {
            let fixture = fixture();
            hydrate(&fixture, &imported(&fixture, "source")?)?;
            let mut pending = pending(&fixture, "egress-cutpoint", None)?;
            let acquired = if commit_phase {
                Some(pending.acquire(&fixture)?)
            } else {
                None
            };
            let commitment = acquired.as_ref().map(commitment).transpose()?;
            let before = counts(&fixture)?;
            FAIL_AFTER.set(stage);
            let failed = match &commitment {
                Some(commitment) => pending.commit(&fixture, commitment).is_err(),
                None => pending.acquire(&fixture).is_err(),
            };
            FAIL_AFTER.set(0);
            assert!(failed, "commit {commit_phase}, stage {stage}");
            assert_eq!(counts(&fixture)?.0, before.0 + i64::from(stage >= 15));
            let fixture = reopen(fixture)?;
            pending.operation = fixture
                .store
                .load_by_operation_id(pending.operation.binding().operation_id())?
                .ok_or("operation absent")?;
            pending.lease = renew(&fixture, &pending.operation, &pending.lease)?;
            match &commitment {
                Some(commitment) => {
                    pending.commit(&fixture, commitment)?;
                }
                None => {
                    pending.acquire(&fixture)?;
                }
            }
            assert_eq!(counts(&fixture)?.0, before.0 + 1);
            native::verify_coverage(&*fixture.store.connection()?)?;
        }
    }
    Ok(())
}

#[test]
fn nested_commitment_field_substitution_rolls_back_the_whole_commit() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-nested-commit", None)?;
    let acquired = pending.acquire(&fixture)?;
    let commitment = commitment(&acquired)?;
    let before = counts(&fixture)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_egress_expiry AFTER UPDATE ON main.security_participant_state_egress_fences
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         UPDATE security_participant_state_egress_fences SET expires_at = expires_at + 1
         WHERE security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id AND fence_id = NEW.fence_id;
         END;",
    )?;
    assert!(pending.commit(&fixture, &commitment).is_err());
    assert_eq!(counts(&fixture)?, before);
    let connection = fixture.store.connection()?;
    assert!(connection.is_autocommit());
    connection.execute_batch("DROP TRIGGER temp.native_test_egress_expiry")?;
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM security_participant_state_egress_fences WHERE tenant_id = 'native-tenant' AND dispatch_commitment_id IS NOT NULL", [], |row| row.get::<_, i64>(0))?, 0);
    native::verify_coverage(&connection)?;
    drop(connection);
    pending.commit(&fixture, &commitment)?;
    Ok(())
}

#[test]
fn nested_operation_claim_change_cannot_commit_egress_under_stale_custody() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-lease-escape", None)?;
    let before = counts(&fixture)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_egress_claim AFTER INSERT ON main.security_participant_state_egress_fences
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         UPDATE admission_operations SET recovery_expires_at_unix_ms = recovery_expires_at_unix_ms + 1
         WHERE request_id = 'egress-lease-escape';
         END;",
    )?;
    assert!(pending.acquire(&fixture).is_err());
    assert_eq!(
        counts(&fixture)?,
        before,
        "changed operation custody must roll back before commit"
    );
    let connection = fixture.store.connection()?;
    assert_eq!(connection.query_row("SELECT recovery_expires_at_unix_ms FROM admission_operations WHERE request_id = 'egress-lease-escape'", [], |row| row.get::<_, i64>(0))?, i64::try_from(pending.lease.expires_at_unix_ms())?);
    connection.execute_batch("DROP TRIGGER temp.native_test_egress_claim")?;
    native::verify_coverage(&connection)?;
    drop(connection);
    pending.acquire(&fixture)?;
    Ok(())
}

#[test]
fn nested_unrelated_operation_claim_change_is_denied_by_sql_scope() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-isolated-owner", None)?;
    let (_, other_lease) = mutations::setup(&fixture, "egress-unrelated-owner", &pending.context)?;
    let before = counts(&fixture)?;
    fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER native_test_egress_other_claim AFTER INSERT ON main.security_participant_state_egress_fences
         WHEN NEW.tenant_id = 'native-tenant' BEGIN
         UPDATE admission_operations SET recovery_expires_at_unix_ms = recovery_expires_at_unix_ms + 1
         WHERE request_id = 'egress-unrelated-owner';
         END;",
    )?;
    // Rechecking only the selected operation cannot detect this other-row
    // mutation. The SQL authorizer must reject it before execution.
    assert!(pending.acquire(&fixture).is_err());
    assert_eq!(counts(&fixture)?, before);
    let connection = fixture.store.connection()?;
    assert_eq!(connection.query_row("SELECT recovery_expires_at_unix_ms FROM admission_operations WHERE request_id = 'egress-unrelated-owner'", [], |row| row.get::<_, i64>(0))?, i64::try_from(other_lease.expires_at_unix_ms())?);
    connection.execute_batch("DROP TRIGGER temp.native_test_egress_other_claim")?;
    native::verify_coverage(&connection)?;
    drop(connection);
    pending.acquire(&fixture)?;
    Ok(())
}
