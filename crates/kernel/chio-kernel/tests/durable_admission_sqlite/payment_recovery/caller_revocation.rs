//! Current per-capability refusal retains the authentic return without blocking other rows.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationId, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionRecoveryError, AdmissionRecoveryFailureKind, AdmissionRecoveryPageQuery,
    AdmissionRecoveryPhase, AdmissionRecoveryPortError, AdmissionRecoveryStatusV1,
};
use chio_kernel::caller_delivery::{
    CallerDeliveryError, CallerExecutorIdentityV1, SignedCallerDeliveryReportV1,
    SignedCallerDispatchAuthorizationV1,
};
use chio_kernel::{CallerExecutionReport, CallerStartResponse, DurableFinalizationCutpoint};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::atomic::AtomicU8;
use std::sync::Mutex;

#[path = "caller_revocation/fixture.rs"]
mod fixture;
use fixture::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
enum RevocationMode {
    None,
    Leaf,
    Ancestor,
}

fn require_revocation(error: &KernelError, mode: RevocationMode, original_id: &str) -> TestResult {
    let expected_code = match mode {
        RevocationMode::Leaf => {
            let KernelError::CapabilityRevoked(id) = error else {
                return Err("exact current leaf revocation refusal required".into());
            };
            assert_eq!(id, original_id);
            "CHIO-KERNEL-CAPABILITY-REVOKED"
        }
        RevocationMode::Ancestor => {
            let KernelError::DelegationChainRevoked(id) = error else {
                return Err("exact current signed ancestor revocation refusal required".into());
            };
            assert_eq!(id, original_id);
            "CHIO-KERNEL-DELEGATION-CHAIN-REVOKED"
        }
        RevocationMode::None => return Err("unrevoked fixture has no revocation refusal".into()),
    };
    assert_eq!(error.report().code, expected_code);
    assert!(error.source().is_none());
    Ok(())
}

fn require_clock(error: &KernelError, expected: ClockError) -> TestResult {
    assert_eq!(error.report().code, expected.code());
    let KernelError::Clock(original) = error else {
        return Err("exact native global clock refusal required".into());
    };
    assert_eq!(*original, expected);
    let source = error
        .source()
        .ok_or("native clock source")?
        .downcast_ref::<ClockError>()
        .ok_or("native clock source type")?;
    assert!(std::ptr::eq(source, original));
    assert!(source.source().is_none());
    Ok(())
}

fn require_native_port(error: &KernelError, expected: AdmissionOperationStoreError) -> TestResult {
    assert_eq!(error.report().code, "CHIO-KERNEL-DURABLE-ADMISSION");
    let KernelError::AdmissionRecovery(retained) = error else {
        return Err("original typed global recovery port refusal required".into());
    };
    let outer = error
        .source()
        .ok_or("boxed recovery source")?
        .downcast_ref::<Box<AdmissionRecoveryError>>()
        .ok_or("boxed recovery source type")?;
    assert!(std::ptr::eq(outer, retained));
    let AdmissionRecoveryError::Port(AdmissionRecoveryPortError::Local(native)) = retained.as_ref()
    else {
        return Err("original local recovery port source required".into());
    };
    assert_eq!(*native, expected);
    let cause = outer
        .source()
        .ok_or("native local store cause")?
        .downcast_ref::<AdmissionOperationStoreError>()
        .ok_or("native local store cause type")?;
    assert!(std::ptr::eq(cause, native));
    assert!(cause.source().is_none());
    Ok(())
}

fn require_completed(pending: &PendingCallers, caller: &RecordedCaller) -> TestResult {
    let operation = pending
        .operations
        .load_by_operation_id(caller.id())?
        .ok_or("completed healthy caller")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(
        operation.dispatch_commit(),
        caller.original_operation.dispatch_commit()
    );
    let response = pending
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&caller.authorization, &caller.report)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(chio_kernel::ToolCallOutput::Value(
            caller.report.report.output.clone(),
        ))
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.kernel_key,
        pending.kernel.receipt_signing_public_key()
    );
    assert_eq!(response.receipt.capability_id, caller.request.capability.id);
    assert_eq!(caller.effects.load(Ordering::SeqCst), 1);
    assert_eq!(pending.remote_invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn revoked_caller_isolation(mode: RevocationMode) -> TestResult {
    let pending = PendingCallers::new(mode)?;
    let [refused, healthy] = &pending.callers;
    let revoked_id = refused
        .revocation_id
        .as_deref()
        .ok_or("real revoked capability identity")?;
    let before = pending.snapshot()?;
    let [refused_before, _] = before.as_slice() else {
        return Err("two initial caller snapshots".into());
    };
    let original_error = pending
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&refused.authorization, &refused.report)
        .err()
        .ok_or("revoked original output must remain unreleased")?;
    require_revocation(&original_error, mode, revoked_id)?;
    assert_eq!(pending.snapshot()?, before);
    let recovered = pending.kernel.reconcile_durable_admission_startup();
    if let Err(error) = &recovered {
        // Attribute only the intended original per-capability page abort.
        require_revocation(error, mode, revoked_id)?;
        assert_eq!(pending.snapshot()?, before);
    }
    // One healthy operation and its existing receipt are reconciled. The
    // refused caller remains nonterminal with its captured invocation intact.
    assert_eq!(recovered?, 2);
    let after = pending.snapshot()?;
    let [refused_after, _] = after.as_slice() else {
        return Err("two final caller snapshots".into());
    };
    assert_eq!(refused_after.operation, refused_before.operation);
    assert_eq!(refused_after.raw_digest, refused_before.raw_digest);
    assert_eq!(refused_after.outcome, refused_before.outcome);
    assert_eq!(refused_after.evaluation, refused_before.evaluation);
    assert_eq!(refused_after.usage, refused_before.usage);
    assert_eq!(refused_after.effects, 1);
    let status = refused_after
        .status
        .as_ref()
        .ok_or("fenced retained output refusal")?;
    assert!(status.quarantined);
    assert_eq!(status.deferral.phase, AdmissionRecoveryPhase::Returned);
    assert_eq!(
        status.deferral.failure_kind,
        AdmissionRecoveryFailureKind::OutputDenied
    );
    assert_eq!(status.deferral.operation_id, *refused.id());
    assert_eq!(
        status.deferral.operation_version,
        refused.original_operation.version()
    );
    assert_eq!(status.deferral.attempt_count, 1);
    assert_eq!(
        status.deferral.diagnostic_digest.as_str(),
        sha256_hex(original_error.to_string().as_bytes())
    );
    assert!(status.deferral.retry_not_before_unix_ms > status.deferral.last_failure_unix_ms);
    assert_eq!(
        pending
            .operations
            .load_payment_journal(refused.id().as_str(), &pending.fence)?,
        None
    );
    require_completed(&pending, healthy)?;
    assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 0);
    pending.finish_fresh_caller()?;
    let replay_error = pending
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&refused.authorization, &refused.report)
        .err()
        .ok_or("revoked retained output cannot become releasable")?;
    require_revocation(&replay_error, mode, revoked_id)?;
    assert_eq!(pending.snapshot()?, after);
    assert_eq!(refused.effects.load(Ordering::SeqCst), 1);
    assert_eq!(healthy.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn sqlite_review_retained_caller_leaf_revocation_does_not_block_later_or_fresh_capability(
) -> TestResult {
    revoked_caller_isolation(RevocationMode::Leaf)
}

#[test]
fn sqlite_review_retained_caller_ancestor_revocation_does_not_block_later_or_fresh_capability(
) -> TestResult {
    revoked_caller_isolation(RevocationMode::Ancestor)
}

#[test]
fn sqlite_review_unrevoked_retained_callers_recover_their_original_signed_outputs() -> TestResult {
    let pending = PendingCallers::new(RevocationMode::None)?;
    assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 4);
    for caller in &pending.callers {
        require_completed(&pending, caller)?;
    }
    assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 0);
    pending.finish_fresh_caller()?;
    for caller in &pending.callers {
        assert_eq!(caller.effects.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

fn clock_fault_preserves_cursor_and_latch(fault: ClockFault, expected: ClockError) -> TestResult {
    let pending = PendingCallers::new(RevocationMode::None)?;
    let before = pending.snapshot()?;
    let _ = pending.kernel.authority_clock_reading()?;
    pending.clock.fail_next_kernel_read(fault);
    let error = pending
        .kernel
        .reconcile_recoverable_admissions_batch(1)
        .err()
        .ok_or("global clock must abort bounded recovery")?;
    pending.clock.assert_triggered(fault);
    require_clock(&error, expected)?;
    assert_eq!(pending.snapshot()?, before);
    // The first physical candidate is still first after the failed batch.
    assert_eq!(pending.kernel.reconcile_recoverable_admissions_batch(1)?, 1);
    let [first, second] = &pending.callers;
    require_completed(&pending, first)?;
    assert_eq!(
        pending
            .operations
            .load_by_operation_id(second.id())?
            .ok_or("later retained caller")?
            .state(),
        AdmissionOperationState::Finalizing
    );
    let after_first = pending.snapshot()?;
    pending.clock.fail_next_kernel_read(fault);
    let error = pending
        .kernel
        .reconcile_durable_admission_startup()
        .err()
        .ok_or("global clock must abort startup recovery")?;
    pending.clock.assert_triggered(fault);
    require_clock(&error, expected)?;
    assert_eq!(pending.snapshot()?, after_first);
    // A successful retry must still reconcile the second operation plus both
    // existing terminal receipts; a falsely completed latch would return zero.
    assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 3);
    require_completed(&pending, second)?;
    assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 0);
    Ok(())
}

#[test]
fn sqlite_review_caller_recovery_clock_unavailable_remains_global_and_unlatched() -> TestResult {
    clock_fault_preserves_cursor_and_latch(ClockFault::Unavailable, ClockError::Unavailable)
}

#[test]
fn sqlite_review_caller_recovery_clock_regression_remains_global_and_unlatched() -> TestResult {
    clock_fault_preserves_cursor_and_latch(ClockFault::Regress, ClockError::WallClockRegression)
}

#[test]
fn sqlite_review_caller_recovery_original_stale_fence_remains_global() -> TestResult {
    let mut pending = PendingCallers::new(RevocationMode::None)?;
    let before = pending.snapshot()?;
    let stale = pending
        .callers
        .first()
        .ok_or("original caller")?
        .authorization
        .authorization
        .committed
        .dispatch_commit
        .store_fence
        .clone();
    assert!(stale.owner_epoch < pending.fence.owner_epoch);
    pending.kernel.set_durable_admission_store(
        pending.operations.clone(),
        Arc::new(pending.authority.tool_outcome_store()),
        stale,
    )?;
    for _ in 0..2 {
        let error = pending
            .kernel
            .reconcile_durable_admission_startup()
            .err()
            .ok_or("original stale authority must fail globally")?;
        require_native_port(&error, AdmissionOperationStoreError::Fenced)?;
        assert_eq!(pending.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn sqlite_review_caller_recovery_view_future_and_stale_remain_global_and_unlatched() -> TestResult {
    use chio_kernel_core::{RevocationSnapshot, RevocationView};
    for future in [true, false] {
        let mut pending = PendingCallers::new(RevocationMode::None)?;
        let before = pending.snapshot()?;
        let view = Arc::new(RevocationView::new());
        let observed = if future {
            pending.clock.now().checked_add(1)
        } else {
            pending.clock.now().checked_sub(501)
        }
        .ok_or("view test timestamp overflow")?;
        view.install_if_newer(RevocationSnapshot {
            epoch: 1,
            root_hash: [0; 32],
            issued_at_unix_ms: observed,
            revoked: Default::default(),
        })?;
        pending.kernel.set_revocation_view(view.clone());
        let error = pending
            .kernel
            .reconcile_durable_admission_startup()
            .err()
            .ok_or("untrusted current view must fail globally")?;
        if future {
            let KernelError::RevocationSnapshotFuture = error else {
                return Err("exact future current-view refusal required".into());
            };
            assert_eq!(
                error.report().code,
                "urn:chio:error:kernel:revocation-snapshot-future"
            );
        } else {
            let KernelError::RevocationSnapshotStale = error else {
                return Err("exact stale current-view refusal required".into());
            };
            assert_eq!(
                error.report().code,
                "urn:chio:error:kernel:revocation-snapshot-stale"
            );
        }
        assert!(error.source().is_none());
        assert_eq!(pending.snapshot()?, before);
        view.install_if_newer(RevocationSnapshot {
            epoch: 2,
            root_hash: [0; 32],
            issued_at_unix_ms: pending.clock.now(),
            revoked: Default::default(),
        })?;
        assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 4);
        for caller in &pending.callers {
            require_completed(&pending, caller)?;
        }
        assert_eq!(pending.kernel.reconcile_durable_admission_startup()?, 0);
    }
    Ok(())
}

#[test]
fn sqlite_review_forged_caller_report_cannot_change_retained_return_or_effects() -> TestResult {
    let pending = PendingCallers::new(RevocationMode::None)?;
    let before = pending.snapshot()?;
    let caller = pending.callers.first().ok_or("original caller")?;
    let mut forged = caller.report.clone();
    forged.report.output = serde_json::json!({"forged_caller_effect": true});
    let signature_error = forged
        .verify(
            &caller.authorization,
            &pending.kernel.public_key(),
            &caller.authorization.authorization.executor,
            &caller.authorization.authorization.invocation,
        )
        .err()
        .ok_or("modified original report signature must fail")?;
    assert_eq!(signature_error, CallerDeliveryError::Signature);
    let error = pending
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&caller.authorization, &forged)
        .err()
        .ok_or("forged report must not release caller output")?;
    let KernelError::DurableAdmission(detail) = &error else {
        return Err("existing caller authentication refusal required".into());
    };
    assert_eq!(detail, &signature_error.to_string());
    assert_eq!(error.report().code, "CHIO-KERNEL-DURABLE-ADMISSION");
    assert!(error.source().is_none());
    assert_eq!(pending.snapshot()?, before);
    Ok(())
}
