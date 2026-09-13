//! A dispatched caller's unknown outcome must never become a free retry.

use super::*;
use chio_kernel::CallerExecutionCheckpoint;

#[test]
fn an_unknown_caller_outcome_retains_its_share_and_capture_after_restart_and_expiry() -> TestResult
{
    let fixture = Fixture::with_nonce_ttl(300)?;
    let (siblings, first) = {
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        Arc::get_mut(&mut runtime.kernel)
            .ok_or("exclusive test kernel")?
            .install_caller_execution_checkpoint_hook(Arc::new(|checkpoint, operation| {
                assert!(
                    checkpoint != CallerExecutionCheckpoint::DispatchCommitted
                        || operation.binding().request_id().as_str() != "unknown-caller",
                    "injected interruption after caller dispatch commitment"
                );
            }));
        let first = reserve_child(&runtime, &request(&siblings.first, "unknown-caller")?)?;
        let nonce = first.execution_nonce.as_ref().ok_or("reserved nonce")?;
        let interrupted = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    runtime.kernel.reconcile_caller_execution_blocking(
                        nonce,
                        &first.arguments,
                        report(),
                    )
                })
                .join()
        });
        assert!(
            interrupted.is_err(),
            "the dispatch checkpoint must be reached"
        );
        assert_state(&fixture, &first, "outcome_unknown_after_dispatch")?;
        assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        (siblings, first)
    };
    let expiry = u64::try_from(
        first
            .execution_nonce
            .as_ref()
            .ok_or("reserved nonce")?
            .expires_at(),
    )?;
    let after_expiry = expiry.checked_add(1).ok_or("expiry overflow")?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(after_expiry, []);
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &first, "outcome_unknown_after_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let shares = runtime
        .authority
        .admission_operation_store()
        .load_caller_budget_shares(
            &parent,
            1,
            &runtime.authority.mutation_fence(),
            after_expiry.checked_mul(1_000).ok_or("clock overflow")?,
        )?;
    assert_eq!(
        shares.len(),
        1,
        "unknown terminal owners stay in the complete view"
    );
    assert_eq!(shares[0].child_id().as_str(), first.capability.id);
    assert!(shares[0].is_reserved_for_caller());
    let blocked = runtime.kernel.reserve_caller_execution_blocking(&request(
        &siblings.second,
        "sibling-after-unknown-caller",
    )?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    assert!(blocked
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("sibling-sum")));
    if let Ok(replayed) = reconcile(&runtime, &first) {
        assert_ne!(
            replayed.verdict,
            Verdict::Allow,
            "unknown effects cannot be replayed as success"
        );
    }
    assert_state(&fixture, &first, "outcome_unknown_after_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
