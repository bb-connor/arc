//! Actual captured effects keep their physical workflow at the native ceiling.
//! The allowance ceiling is modeled by the typed owner writer, never resealed.
use super::*;

async fn captured_at_native_ceiling() -> TestResult<(tempfile::TempDir, RecoveryWorkflowRecordV1)> {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let original = retained_workflow(directory.path())?;
    let native_before = native_original_bytes(directory.path(), &original)?;
    let return_before = captured_return_bytes(directory.path(), &original)?;
    let authority = SqliteAuthorityStore::open_serving(
        directory.path().join("admission.db"),
        directory.path().join("locks"),
    )?;
    authority
        .admission_operation_store()
        .exhaust_captured_finalizing_native_allowance_for_test(
            &original.scope,
            &original.workflow_id,
        )?;
    drop(authority);
    let physical = retained_workflow(directory.path())?;
    let quota: Value =
        serde_json::from_slice(&retained_workflow_quota_bytes(directory.path(), &physical)?.1)?;
    assert_eq!(quota["native"].as_u64(), Some(128));
    assert!(quota.get("native_terminal").is_none());
    assert!(quota.get("native_release").is_none());
    assert!(quota.get("native_hold").is_none());
    assert_eq!(
        native_original_bytes(directory.path(), &physical)?,
        native_before
    );
    assert_eq!(
        captured_return_bytes(directory.path(), &physical)?,
        return_before
    );
    assert_eq!(external_count(directory.path())?, 1);
    Ok((directory, physical))
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_native_128_captured_terminal_and_current_release_preserve_raw_workflow(
) -> TestResult {
    let (directory, physical) = Box::pin(captured_at_native_ceiling()).await?;
    let physical_bytes = chio_core::canonical_json_bytes(&physical)?;
    let raw_before = captured_return_bytes(directory.path(), &physical)?.1;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let terminal = fixture
        .authority
        .admission_operation_store()
        .inspect_captured_workflow_terminal_for_test(
            fixture.runtime.scope(),
            &physical.workflow_id,
        )?;
    assert!(matches!(
        terminal.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(terminal.admission_closed && terminal.historical_hold.is_none());
    assert!(matches!(
        terminal.release,
        ReleaseDispositionV1::Withheld { .. }
    ));
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        physical_bytes
    );
    require_original_terminal_receipt(&fixture, &physical)?;
    assert_eq!(
        captured_return_bytes(&fixture.path, &physical)?.1,
        raw_before
    );
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    let first = fixture
        .kernel
        .replay_recovery_result(&actor, &physical.workflow_id)?;
    assert!(first.output.is_some());
    assert!(first.execution_nonce.is_none());
    let release = fixture.record(&physical.workflow_id)?;
    assert!(matches!(
        release.release,
        ReleaseDispositionV1::Released { .. }
    ));
    let quota_before_replay = retained_workflow_quota_bytes(&fixture.path, &physical)?;
    let quota: Value = serde_json::from_slice(&quota_before_replay.1)?;
    assert_eq!(quota["native"].as_u64(), Some(128));
    assert!(quota.get("native_terminal").is_some() && quota.get("native_release").is_some());
    assert!(quota.get("native_hold").is_none());
    assert!(quota_before_replay.1.len() <= 4096);
    let events = recovery_event_count(&fixture.path)?;
    let second = fixture
        .kernel
        .replay_recovery_result(&actor, &physical.workflow_id)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&first.receipt)?,
        chio_core::canonical_json_bytes(&second.receipt)?
    );
    assert_eq!(
        retained_workflow_quota_bytes(&fixture.path, &physical)?,
        quota_before_replay
    );
    assert_eq!(recovery_event_count(&fixture.path)?, events);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        physical_bytes
    );
    let completed_native = native_original_bytes(&fixture.path, &physical)?;
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    drop(fixture);
    let reopened = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let actor = reopened.kernel.authenticate_recovery_actor(
        reopened.runtime.scope(),
        &reopened.control,
        RecoveryPermission::Inspect,
    )?;
    reopened
        .kernel
        .replay_recovery_result(&actor, &physical.workflow_id)?;
    assert_eq!(recovery_event_count(&reopened.path)?, events);
    assert_eq!(
        retained_workflow_quota_bytes(&reopened.path, &physical)?,
        quota_before_replay
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&reopened.path)?)?,
        physical_bytes
    );
    assert_eq!(
        native_original_bytes(&reopened.path, &physical)?,
        completed_native
    );
    reopened
        .authority
        .revocation_store()
        .revoke(&reopened.control.id)?;
    assert!(reopened
        .kernel
        .replay_recovery_result(&actor, &physical.workflow_id)
        .is_err());
    assert_eq!(recovery_event_count(&reopened.path)?, events);
    assert_eq!(
        native_original_bytes(&reopened.path, &physical)?,
        completed_native
    );
    assert_eq!(external_count(&reopened.path)?, 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_terminal_report_first_replay_and_conflict_preserve_native_128_raw_custody(
) -> TestResult {
    let (directory, physical) = Box::pin(captured_at_native_ceiling()).await?;
    let physical_bytes = chio_core::canonical_json_bytes(&physical)?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let completed_native = native_original_bytes(&fixture.path, &physical)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Report,
    )?;
    let command = fixture.command(
        "native-ceiling-report-original",
        RecoveryCommandBodyV1::ReportDecision {
            workflow_id: physical.workflow_id.clone(),
            expected_revision: physical.revision,
            decision: RecoveryReportedDecision::Accepted,
        },
    )?;
    let accepted = fixture.kernel.execute_recovery_command(&actor, &command)?;
    assert_eq!(accepted.revision, physical.revision);
    assert_eq!(
        fixture.record(&physical.workflow_id)?.reported_decision,
        Some(RecoveryReportedDecision::Accepted)
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        physical_bytes
    );
    let quota = retained_workflow_quota_bytes(&fixture.path, &physical)?;
    let events = recovery_event_count(&fixture.path)?;
    let replay = fixture.kernel.execute_recovery_command(&actor, &command)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&replay)?,
        chio_core::canonical_json_bytes(&accepted)?
    );
    let conflict = fixture.command(
        "native-ceiling-report-original",
        RecoveryCommandBodyV1::ReportDecision {
            workflow_id: physical.workflow_id.clone(),
            expected_revision: physical.revision,
            decision: RecoveryReportedDecision::Declined,
        },
    )?;
    assert!(matches!(
        fixture.kernel.execute_recovery_command(&actor, &conflict),
        Err(chio_kernel::recovery::RecoveryCommandError::Conflict)
    ));
    assert_eq!(
        retained_workflow_quota_bytes(&fixture.path, &physical)?,
        quota
    );
    assert_eq!(recovery_event_count(&fixture.path)?, events);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        physical_bytes
    );
    assert_eq!(
        native_original_bytes(&fixture.path, &physical)?,
        completed_native
    );
    fixture
        .authority
        .revocation_store()
        .revoke(&fixture.control.id)?;
    assert!(fixture
        .kernel
        .execute_recovery_command(&actor, &command)
        .is_err());
    assert_eq!(
        retained_workflow_quota_bytes(&fixture.path, &physical)?,
        quota
    );
    assert_eq!(recovery_event_count(&fixture.path)?, events);
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_terminal_report_missing_original_source_is_not_pristine_feedback() -> TestResult {
    let directory = Box::pin(crash_after_capture("return-recorded")).await?;
    let physical = retained_workflow(directory.path())?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Report,
    )?;
    let report = fixture.command(
        "terminal-report-retained-source",
        RecoveryCommandBodyV1::ReportDecision {
            workflow_id: physical.workflow_id.clone(),
            expected_revision: physical.revision,
            decision: RecoveryReportedDecision::Accepted,
        },
    )?;
    fixture.kernel.execute_recovery_command(&actor, &report)?;
    let quota = retained_workflow_quota_bytes(&fixture.path, &physical)?;
    let native = native_original_bytes(&fixture.path, &physical)?;
    let raw = captured_return_bytes(&fixture.path, &physical)?;
    let events = recovery_event_count(&fixture.path)?;
    let probe = fixture
        .authority
        .admission_operation_store()
        .verify_recovery_report_retained_source_for_test(&physical.scope, &physical.workflow_id);
    assert_eq!(
        retained_workflow_quota_bytes(&fixture.path, &physical)?,
        quota
    );
    assert_eq!(native_original_bytes(&fixture.path, &physical)?, native);
    assert_eq!(captured_return_bytes(&fixture.path, &physical)?, raw);
    assert_eq!(recovery_event_count(&fixture.path)?, events);
    assert_eq!(
        chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
        chio_core::canonical_json_bytes(&physical)?
    );
    assert_eq!(
        fixture.record(&physical.workflow_id)?.reported_decision,
        Some(RecoveryReportedDecision::Accepted)
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    assert_eq!(
        probe.map_err(|error| format!("owning first Report source probe: {error}"))?,
        1
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_held_native_128_report_refuses_without_changing_original_custody() -> TestResult {
    let (directory, physical) = Box::pin(captured_at_native_ceiling()).await?;
    std::fs::write(
        directory
            .path()
            .join("current-recovery-post-return-unavailable"),
        b"1",
    )?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let held = fixture.record(&physical.workflow_id)?;
    assert!(held.historical_hold.is_some());
    assert_eq!(held.control, WorkflowControlV1::Quarantined);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Report,
    )?;
    let command = fixture.command(
        "held-native-ceiling-report",
        RecoveryCommandBodyV1::ReportDecision {
            workflow_id: physical.workflow_id.clone(),
            expected_revision: physical.revision,
            decision: RecoveryReportedDecision::Accepted,
        },
    )?;
    let quota = retained_workflow_quota_bytes(&fixture.path, &physical)?;
    let native = native_original_bytes(&fixture.path, &physical)?;
    let raw = captured_return_bytes(&fixture.path, &physical)?;
    let events = recovery_event_count(&fixture.path)?;
    for _ in 0..2 {
        assert!(matches!(
            fixture.kernel.execute_recovery_command(&actor, &command),
            Err(chio_kernel::recovery::RecoveryCommandError::Unavailable)
        ));
        assert_eq!(
            fixture.record(&physical.workflow_id)?.reported_decision,
            None
        );
        assert_eq!(
            retained_workflow_quota_bytes(&fixture.path, &physical)?,
            quota
        );
        assert_eq!(native_original_bytes(&fixture.path, &physical)?, native);
        assert_eq!(captured_return_bytes(&fixture.path, &physical)?, raw);
        assert_eq!(recovery_event_count(&fixture.path)?, events);
        assert_eq!(
            chio_core::canonical_json_bytes(&retained_workflow(&fixture.path)?)?,
            chio_core::canonical_json_bytes(&physical)?
        );
    }
    let quota: Value = serde_json::from_slice(&quota.1)?;
    assert_eq!(quota["native"].as_u64(), Some(128));
    assert!(quota.get("native_hold").is_some());
    assert!(quota.get("native_terminal").is_none() && quota.get("native_release").is_none());
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}
