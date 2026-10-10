//! Issuance and validation must observe the same authority clock.
use super::*;
use crate::admission_operation::DurableAdmissionMode;
use chio_security_types::clock::FixedClock;

#[test]
fn aggregate_family_issuance_uses_kernel_time_at_both_epoch_extremes(
) -> Result<(), Box<dyn std::error::Error>> {
    for now in [3_600_000, 4_000_000_000_000] {
        let mut config = make_config();
        config.allow_ephemeral_receipt_log = false;
        let mut kernel = ChioKernel::new_with_clock(config, Arc::new(FixedClock::from_millis(now)));
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        let fence = admission_test_fence();
        let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
        kernel.set_durable_admission_store(store.clone(), store, fence)?;
        let subject = Keypair::generate().public_key();
        let scope = make_scope(vec![make_grant("tools", "read")]);
        let root = kernel.issue_aggregate_family_root(&subject, scope, 60, 2)?;
        assert_eq!(root.issued_at, now / 1_000);
        assert_eq!(root.expires_at, now / 1_000 + 60);
        assert!(root.verify_signature()?);
    }
    Ok(())
}

#[test]
fn aggregate_family_issuance_refuses_owner_clock_faults() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::replay_retention::tests::TestClock;
    use chio_security_types::clock::ClockError;
    for (wall, monotonic, expected) in [
        (None, 1, ClockError::Unavailable),
        (Some(99), 1, ClockError::WallClockRegression),
        (Some(100), 0, ClockError::MonotonicRegression),
    ] {
        let clock = Arc::new(TestClock::new(100));
        clock.set(100, 1);
        let mut config = make_config();
        config.allow_ephemeral_receipt_log = false;
        let mut kernel = ChioKernel::new_with_clock(config, clock.clone());
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        let fence = admission_test_fence();
        let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
        kernel.set_durable_admission_store(store.clone(), store, fence)?;
        let subject = Keypair::generate().public_key();
        let scope = make_scope(vec![make_grant("tools", "read")]);
        kernel.issue_aggregate_family_root(&subject, scope.clone(), 60, 2)?;
        if let Some(wall) = wall {
            clock.set(wall, monotonic);
        } else {
            clock.fail();
        }
        assert!(matches!(
            kernel.issue_aggregate_family_root(&subject, scope, 60, 2),
            Err(KernelError::Clock(cause)) if cause == expected
        ));
    }
    Ok(())
}
