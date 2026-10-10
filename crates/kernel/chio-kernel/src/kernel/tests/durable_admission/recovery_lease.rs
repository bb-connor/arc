//! Qualified-port fault contracts, not physical backend qualification. Panics
//! occur outside fixture locks so poisoning of the caller's lock is observable.
use super::*;
use crate::admission_operation::QualifiedAdmissionOperationStoreExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{atomic::AtomicU8, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Stage {
    ClaimBefore = 1,
    ClaimAfter = 2,
    OperationRead = 3,
    Revalidate = 4,
}

#[derive(Default)]
pub(super) struct TestRecoveryLeaseFaults(AtomicU8);

impl TestRecoveryLeaseFaults {
    pub(super) fn arm(&self, stage: Stage) {
        assert_eq!(self.0.swap(stage as u8, Ordering::SeqCst), 0);
    }

    pub(super) fn trip(&self, stage: Stage) {
        let triggered = self
            .0
            .compare_exchange(stage as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        assert!(!triggered, "test recovery qualification panic at {stage:?}");
    }
}

fn exercise_panic(stage: Stage) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, request, store, invocations) = durable_admission_fixture("lease-qualification");
    let now = current_unix_timestamp_ms();
    let admission = kernel
        .begin_durable_tool_admission(&request, &security_binding::matching(&request)?, now)?
        .ok_or("durable admission")?;
    let original = admission.operation();
    let fence = store.fence.lock().expect("fence").clone();
    let claimant = AdmissionIdentifier::try_new("claimant", "test-qualification")?;
    let expires = now + 60_000;
    let sequencer = Mutex::new(());
    assert!(store.state.lock().expect("state").claim.is_none());
    store.recovery_lease_faults.arm(stage);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _guard = sequencer.lock().expect("caller sequencer");
        store.claim_recovery(
            original.binding().operation_id(),
            original.version(),
            &claimant,
            now,
            expires,
            &fence,
        )
    }));
    assert!(
        outcome.is_ok(),
        "{stage:?}: store panic escaped qualification"
    );
    assert!(
        matches!(
            outcome.expect("contained panic"),
            Err(AdmissionOperationStoreError::OutcomeUnknown(_))
        ),
        "a panicking callback cannot mint a lease or assert rollback"
    );
    let _guard = sequencer.lock().expect("caller sequencer remains usable");
    assert_eq!(store.operation(), *original);
    {
        let state = store.state.lock().expect("state");
        assert_eq!(state.claim.is_some(), stage != Stage::ClaimBefore);
        if let Some(claim) = &state.claim {
            assert_eq!(claim.operation_id(), original.binding().operation_id());
            assert_eq!(claim.claimant_id(), &claimant);
            assert_eq!(claim.claimed_version(), original.version());
            assert_eq!(claim.expires_at_unix_ms(), expires);
            assert_eq!(claim.store_fence(), &fence);
        }
    }
    // Fresh qualification against a healthy backend must still execute every
    // check. The previous unknown outcome itself conveys no reusable authority.
    let lease = store.claim_recovery(
        original.binding().operation_id(),
        original.version(),
        &claimant,
        now,
        expires,
        &fence,
    )?;
    assert_eq!(
        lease.untrusted_claim(),
        store
            .state
            .lock()
            .expect("state")
            .claim
            .as_ref()
            .expect("claim")
    );
    assert_eq!(store.operation(), *original);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn qualification_contains_claim_panic_before_persistence() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_panic(Stage::ClaimBefore)
}

#[test]
fn qualification_contains_claim_panic_after_persistence() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_panic(Stage::ClaimAfter)
}

#[test]
fn qualification_contains_operation_read_panic() -> Result<(), Box<dyn std::error::Error>> {
    exercise_panic(Stage::OperationRead)
}

#[test]
fn qualification_contains_revalidation_panic() -> Result<(), Box<dyn std::error::Error>> {
    exercise_panic(Stage::Revalidate)
}

#[test]
fn qualification_preserves_ordinary_errors_without_creating_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, request, store, invocations) = durable_admission_fixture("lease-errors");
    let now = current_unix_timestamp_ms();
    let admission = kernel
        .begin_durable_tool_admission(&request, &security_binding::matching(&request)?, now)?
        .ok_or("durable admission")?;
    let original = admission.operation();
    let fence = store.fence.lock().expect("fence").clone();
    let claimant = AdmissionIdentifier::try_new("claimant", "test-qualification")?;
    let stale_version = original.version() + 1;
    assert_eq!(
        store.claim_recovery(
            original.binding().operation_id(),
            stale_version,
            &claimant,
            now,
            now + 60_000,
            &fence
        ),
        Err(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::StaleVersion {
                expected: stale_version,
                actual: original.version(),
            }
        ))
    );
    let mut stale_fence = fence.clone();
    stale_fence.owner_epoch += 1;
    assert_eq!(
        store.claim_recovery(
            original.binding().operation_id(),
            original.version(),
            &claimant,
            now,
            now + 60_000,
            &stale_fence
        ),
        Err(AdmissionOperationStoreError::Fenced)
    );
    assert!(store.state.lock().expect("state").claim.is_none());
    assert_eq!(store.operation(), *original);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
