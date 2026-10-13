//! Live stale Kernel handles remain fenced after a real new writer opens.
use super::*;

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
