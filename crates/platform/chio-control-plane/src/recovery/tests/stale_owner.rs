//! Live stale Kernel handles remain fenced after a real new writer opens.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::RevocationStoreError;
use chio_store_sqlite::admission_operation_store::NativeSetupPreparationError;

#[derive(Clone, Copy)]
enum StaleOwnerAction {
    Command,
    Finalize,
    Capture,
    Settle,
}

fn protected_counts(fixture: &RecoveryFixture) -> TestResult<(i64, i64, i64, i64)> {
    Ok(rusqlite::Connection::open(fixture.path.join("admission.db"))?.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events), (SELECT count(*) FROM admission_operation_commits), (SELECT count(*) FROM authority_global_commits), (SELECT count(*) FROM admission_operation_terminal_records WHERE record_kind='receipt')", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?)
}

/// The stale owner's replay route is refused by the revocation-store serving
/// owner fence during actor revalidation, before any completed original is
/// consulted, with the retained stale epoch as expected and the fresh owner's
/// current epoch as actual. Any other refusal shape is surfaced in full.
fn assert_replay_fenced_at_owner_epoch(
    result: &Result<chio_kernel::ToolCallResponse, KernelError>,
    stale_epoch: u64,
    current_epoch: u64,
) {
    match result {
        Err(KernelError::RevocationStore(RevocationStoreError::Fenced {
            expected_epoch,
            actual_epoch,
        })) => {
            assert_eq!(
                *expected_epoch, stale_epoch,
                "stale replay fence reported wrong expected epoch"
            );
            assert_eq!(
                *actual_epoch,
                Some(current_epoch),
                "stale replay fence reported wrong actual epoch"
            );
        }
        other => panic!(
            "stale replay_recovery_result must be revocation-store fenced with \
             expected epoch {stale_epoch} and actual epoch {current_epoch}, \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn live_stale_owner_cannot_command_finalize_capture_or_settle_after_restart() -> TestResult {
    for action in [
        StaleOwnerAction::Command,
        StaleOwnerAction::Finalize,
        StaleOwnerAction::Capture,
        StaleOwnerAction::Settle,
    ] {
        let stale = RecoveryFixture::new(false)?;
        let workflow = stale
            .ready_named("stale-live-original", "stale-live")
            .await?;
        let actor = stale.kernel.authenticate_recovery_actor(
            stale.runtime.scope(),
            &stale.control,
            RecoveryPermission::Resume,
        )?;
        let reservation = stale.runtime.prepare_original(&actor, &workflow)?;
        let custody = stale
            .kernel
            .load_recovery_request_custody(&actor, &workflow)?;
        stale
            .process
            .finalize_recovery_call(&reservation, &custody)?;
        let record = stale.record(&workflow)?;
        let envelope = record
            .envelope
            .as_ref()
            .ok_or("stale original envelope absent")?;
        let profile = stale.kernel.recovery_deployment(stale.runtime.scope())?;
        let identity = stale
            .kernel
            .recovery_native_identity(custody.request(), &profile.security_context)?;
        let stale_fence = stale.authority.mutation_fence();
        // Releases the actual OS lock only; no fabricated epoch, poison bit,
        // replacement database or changed authenticated operation is introduced.
        stale
            .authority
            .release_serving_lock_for_stale_owner_test()?;
        let current = RecoveryFixture::open(stale.path.clone(), None, false)?;
        assert!(current.authority.mutation_fence().owner_epoch > stale_fence.owner_epoch);
        let before = protected_counts(&current)?;
        match action {
            StaleOwnerAction::Command => assert!(stale
                .runtime
                .execute_command(
                    &stale.control,
                    &stale.command(
                        "stale-command",
                        RecoveryCommandBodyV1::ResumeWorkflow {
                            workflow_id: workflow.clone(),
                            expected_revision: record.revision
                        }
                    )?
                )
                .await
                .is_err()),
            StaleOwnerAction::Finalize => assert!(stale
                .kernel
                .finalize_recovery_envelope(&actor, &workflow, envelope, &identity)
                .is_err()),
            StaleOwnerAction::Capture => {
                let result = stale
                    .process
                    .invoke_known_only("root", reservation.operation_key(), custody.request())
                    .await;
                assert!(match &result {
                    Err(_) => true,
                    Ok(response) => response.verdict != Verdict::Allow,
                });
            }
            StaleOwnerAction::Settle => {
                assert!(stale.runtime.settle(&stale.control, &workflow).is_err())
            }
        }
        assert_eq!(protected_counts(&current)?, before);
        assert_eq!(external_count(&current.path)?, 0);
    }
    Ok(())
}

/// Setup custody observation, protected setup configuration, setup
/// preparation and completed-output replay all refuse on the live stale
/// owner exactly at the serving-owner fence. The fresh owner still
/// progresses through its own freshly authenticated state-changing command
/// chain, and neither the stale refusals nor the fresh progress disturb the
/// stale workflow's retained state or the external effect count.
///
/// The fenced setup refusals run before any selected setup profile exists
/// and the fenced replay refusal runs before any completed original exists,
/// so these are stale authority-route refusals only, not later
/// setup-qualification or completed-output positives. Setup needs a real
/// selected profile; completed output also needs the native finishing producer.
#[tokio::test]
async fn stale_owner_setup_and_output_routes_refuse_while_fresh_owner_progresses() -> TestResult {
    let stale = RecoveryFixture::new(false)?;
    let workflow = stale
        .ready_named("stale-setup-output", "stale-setup-output")
        .await?;
    let resume = stale.kernel.authenticate_recovery_actor(
        stale.runtime.scope(),
        &stale.control,
        RecoveryPermission::Resume,
    )?;
    let reservation = stale.runtime.prepare_original(&resume, &workflow)?;
    let custody = stale
        .kernel
        .load_recovery_request_custody(&resume, &workflow)?;
    stale
        .process
        .finalize_recovery_call(&reservation, &custody)?;
    let retained = stale.record(&workflow)?;
    assert!(
        retained.envelope.is_some(),
        "stale original envelope absent before takeover"
    );
    let inspect = stale.kernel.authenticate_recovery_actor(
        stale.runtime.scope(),
        &stale.control,
        RecoveryPermission::Inspect,
    )?;
    let setup_store = stale.authority.admission_operation_store();
    let stale_fence = stale.authority.mutation_fence();
    // Releases the actual OS lock only; no fabricated epoch, poison bit,
    // replacement database or changed authenticated operation is introduced.
    stale
        .authority
        .release_serving_lock_for_stale_owner_test()?;
    let current = RecoveryFixture::open(stale.path.clone(), None, false)?;
    assert!(current.authority.mutation_fence().owner_epoch > stale_fence.owner_epoch);
    let before = protected_counts(&current)?;
    let retained_bytes = chio_core::canonical_json_bytes(&current.record(&workflow)?)?;
    assert_eq!(external_count(&current.path)?, 0);
    // Setup custody observation route: the stale owner cannot even observe
    // setup custody through its own Kernel handles.
    assert!(matches!(
        stale.kernel.protected_recovery_setup_required(stale.runtime.scope()),
        Err(KernelError::DurableAdmission(detail))
            if detail == "admission operation mutation was fenced"
    ));
    // Protected setup configuration route: refused at the fence before the
    // setup profile, semantic mediator closure or operator root is consulted.
    assert!(matches!(
        setup_store.configure_protected_setup(
            stale.runtime.scope(),
            &workflow,
            &stale.kernel.receipt_signing_public_key(),
            &stale.approval_key.public_key(),
            &stale_fence,
            now_ms()?,
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    // Setup preparation route: the same fence refuses before the retained
    // setup selection is consulted, so no absent profile can mask it.
    assert!(matches!(
        setup_store.setup_preparation(&inspect, &stale_fence, now_ms()?),
        Err(NativeSetupPreparationError::Store(
            AdmissionOperationStoreError::Fenced
        ))
    ));
    // Completed-output replay route: the stale owner's actor revalidation
    // trips the revocation-store serving owner fence before the
    // completed-original prerequisite is ever consulted.
    assert_replay_fenced_at_owner_epoch(
        &stale.kernel.replay_recovery_result(&resume, &workflow),
        stale_fence.owner_epoch,
        current.authority.mutation_fence().owner_epoch,
    );
    // None of the refused stale routes mutated record, event, commit,
    // receipt or external effect state.
    assert_eq!(protected_counts(&current)?, before);
    assert_eq!(
        chio_core::canonical_json_bytes(&current.record(&workflow)?)?,
        retained_bytes
    );
    assert_eq!(external_count(&current.path)?, 0);
    // Actual fresh-owner progress: a complete state-changing command chain
    // (denied original, creation, selection and approval), with every step
    // freshly authenticated by the new owner's capability and authority.
    let progressed = current
        .ready_named("fresh-owner-progress", "fresh-owner-progress")
        .await?;
    assert_ne!(progressed, workflow);
    let progressed_record = current.record(&progressed)?;
    assert!(
        progressed_record.approval.is_some(),
        "fresh owner progress stopped before approval"
    );
    let after_progress = protected_counts(&current)?;
    assert!(
        after_progress.0 > before.0,
        "fresh owner progress recorded no new recovery events"
    );
    assert_eq!(external_count(&current.path)?, 0);
    // Fresh progress leaves the stale workflow's own retained state intact.
    let stale_through_current = current.record(&workflow)?;
    assert_eq!(stale_through_current.revision, retained.revision);
    assert_eq!(stale_through_current.control, retained.control);
    assert_eq!(
        chio_core::canonical_json_bytes(&stale_through_current.envelope)?,
        chio_core::canonical_json_bytes(&retained.envelope)?
    );
    assert!(!stale_through_current.captured);
    // The fence survives real concurrent-owner progress: every stale route
    // still refuses, still without any state change of its own.
    let progressed_counts = protected_counts(&current)?;
    assert!(stale.runtime.settle(&stale.control, &workflow).is_err());
    assert!(matches!(
        setup_store.setup_preparation(&inspect, &stale_fence, now_ms()?),
        Err(NativeSetupPreparationError::Store(
            AdmissionOperationStoreError::Fenced
        ))
    ));
    assert_replay_fenced_at_owner_epoch(
        &stale.kernel.replay_recovery_result(&resume, &workflow),
        stale_fence.owner_epoch,
        current.authority.mutation_fence().owner_epoch,
    );
    assert!(matches!(
        stale.kernel.protected_recovery_setup_required(stale.runtime.scope()),
        Err(KernelError::DurableAdmission(detail))
            if detail == "admission operation mutation was fenced"
    ));
    assert_eq!(protected_counts(&current)?, progressed_counts);
    assert_eq!(external_count(&current.path)?, 0);
    let final_stale_record = current.record(&workflow)?;
    assert_eq!(final_stale_record.revision, retained.revision);
    assert_eq!(final_stale_record.control, retained.control);
    assert_eq!(
        chio_core::canonical_json_bytes(&final_stale_record)?,
        retained_bytes
    );
    Ok(())
}
