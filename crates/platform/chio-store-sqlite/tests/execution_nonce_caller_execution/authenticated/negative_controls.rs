use super::*;
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

#[test]
fn authenticated_executor_pin_does_not_bypass_native_release_custody() -> TestResult {
    let (fixture, _) = fixture()?;
    let mut runtime = fixture.open()?;
    let request = reserve(&fixture, &runtime, "native-caller-refused")?;
    std::sync::Arc::get_mut(&mut runtime.kernel)
        .ok_or("test kernel must be exclusively owned before configuring enforcement")?
        .set_security_pre_dispatch_policy(chio_kernel::SecurityPreDispatchPolicy::Enforce);
    assert!(!matches!(
        runtime.kernel.start_caller_execution_blocking(
            request.execution_nonce.as_ref().ok_or("nonce")?,
            &request.arguments,
        ),
        Ok(CallerStartResponse::Authorized(_))
    ));
    assert_state(&fixture, &request, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &request)?, (1, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unused_expired_reservation_cannot_publish_start_authority() -> TestResult {
    let (fixture, _) = fixture()?;
    let runtime = fixture.open()?;
    let request = reserve(&fixture, &runtime, "expired-before-start")?;
    let nonce = request.execution_nonce.as_ref().ok_or("nonce")?;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(u64::try_from(nonce.expires_at())?, []);
    assert!(!matches!(
        runtime
            .kernel
            .start_caller_execution_blocking(nonce, &request.arguments),
        Ok(CallerStartResponse::Authorized(_))
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn changed_executor_pin_cannot_adopt_original_start_or_report() -> TestResult {
    let (mut fixture, key) = fixture()?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        4,
    )?;
    let (request, authorization, report) = {
        let runtime = fixture.open()?;
        let request = reserve(&fixture, &runtime, "pinned-start")?;
        let authorization = start(&runtime, &request)?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || Ok(crate::report()),
        )?;
        (request, authorization, report)
    };
    fixture
        .caller_executor
        .as_mut()
        .ok_or("executor")?
        .key_epoch += 1;
    let runtime = fixture.open()?;
    assert!(start(&runtime, &request).is_err());
    assert!(runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)
        .is_err());
    assert_state(&fixture, &request, "awaiting_caller_report")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}

#[test]
fn revocation_blocks_historical_output_and_completed_receipt_replay() -> TestResult {
    for completed_before_revoke in [false, true] {
        let (fixture, key) = fixture()?;
        let runtime = fixture.open()?;
        let request = reserve(&fixture, &runtime, "revoked-output")?;
        let authorization = start(&runtime, &request)?;
        let ledger = SqliteCallerExecutionLedger::provision(
            &fixture.directory.path().join("executor.db"),
            fixture.caller_executor.clone().ok_or("executor")?,
            4,
        )?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || Ok(crate::report()),
        )?;
        if completed_before_revoke {
            assert_eq!(
                runtime
                    .kernel
                    .reconcile_authenticated_caller_execution_blocking(&authorization, &report,)?
                    .verdict,
                Verdict::Allow
            );
        }
        runtime.kernel.revoke_capability(&request.capability.id)?;
        assert!(runtime
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)
            .is_err());
        assert_state(
            &fixture,
            &request,
            if completed_before_revoke {
                "completed"
            } else {
                "finalizing"
            },
        )?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    }
    Ok(())
}
