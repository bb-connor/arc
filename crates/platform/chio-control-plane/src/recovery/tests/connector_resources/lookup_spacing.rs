//! Lookup cooldown survives rollback, expiry and a new native serving owner.
use super::*;

fn workflow_bytes(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    let key = format!(
        "workflow:{}:{}",
        chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?),
        workflow.as_str(),
    );
    let connection = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
    Ok(connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [key],
        |row| row.get(0),
    )?)
}

fn selected_time() -> TestResult<u64> {
    Ok(now_ms()?.checked_add(999).ok_or("fixture clock overflow")? / 1000)
}

#[tokio::test]
async fn lookup_clock_rollback_cannot_spend_another_attempt() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Settle,
    )?;
    let selected = selected_time()?;
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected);
    let first = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(first.workflow().provider_lookups.get(), 1);
    let retained = workflow_bytes(&fixture, &workflow)?;
    drop(clock);
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        selected.checked_sub(1).ok_or("fixture clock underflow")?,
    );
    assert!(fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)
        .is_err());
    assert_eq!(workflow_bytes(&fixture, &workflow)?, retained);
    assert_eq!(external_count(&fixture.path)?, 1);
    drop(clock);
    // The refusal itself used the regressed clock. Restore its prior trusted
    // time before asking a separate authenticated reader to verify custody.
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected);
    assert_eq!(native_original(&fixture, &workflow)?, original);
    drop(clock);
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        selected.checked_add(1).ok_or("fixture clock overflow")?,
    );
    let spaced = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(spaced.workflow().provider_lookups.get(), 2);
    assert_eq!(native_original(&fixture, &workflow)?, original);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn lookup_spacing_does_not_extend_expired_control() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Settle,
    )?;
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected_time()?);
    let first = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(first.workflow().provider_lookups.get(), 1);
    let retained = workflow_bytes(&fixture, &workflow)?;
    let expiry = fixture.control.expires_at;
    drop(clock);
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(expiry);
    assert!(fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)
        .is_err());
    // Direct physical comparison grants no control or disclosure. Current
    // actor-facing reads correctly refuse this expired token as well.
    assert_eq!(workflow_bytes(&fixture, &workflow)?, retained);
    assert!(fixture
        .kernel
        .authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Settle,
        )
        .is_err());
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn lookup_spacing_survives_serving_owner_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_path_buf();
    let fixture = RecoveryFixture::open(path.clone(), None, false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Settle,
    )?;
    let original_epoch = fixture.authority.mutation_fence().owner_epoch;
    let selected = selected_time()?;
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected);
    let first = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(first.workflow().provider_lookups.get(), 1);
    let retained = workflow_bytes(&fixture, &workflow)?;
    drop(first);
    drop(actor);
    drop(fixture);
    let reopened = RecoveryFixture::open(path, None, false)?;
    assert!(reopened.authority.mutation_fence().owner_epoch > original_epoch);
    let actor = reopened.kernel.authenticate_recovery_actor(
        reopened.runtime.scope(),
        &reopened.control,
        RecoveryPermission::Settle,
    )?;
    assert!(reopened
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)
        .is_err());
    assert_eq!(workflow_bytes(&reopened, &workflow)?, retained);
    assert_eq!(native_original(&reopened, &workflow)?, original);
    assert_eq!(external_count(&reopened.path)?, 1);
    drop(clock);
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        selected.checked_add(1).ok_or("fixture clock overflow")?,
    );
    let spaced = reopened
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(spaced.workflow().provider_lookups.get(), 2);
    assert_eq!(native_original(&reopened, &workflow)?, original);
    assert_eq!(external_count(&reopened.path)?, 1);
    Ok(())
}
