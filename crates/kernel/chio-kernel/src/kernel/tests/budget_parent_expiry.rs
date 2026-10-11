use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};

/// Fails every read after `fail_after` successful reads.
struct CountingClock {
    reads: AtomicUsize,
    fail_after: AtomicUsize,
}

impl Clock for CountingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let read = self.reads.fetch_add(1, AtomicOrdering::SeqCst);
        if read >= self.fail_after.load(AtomicOrdering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading::new(
            UnixMillis::new(1_800_000_000_000),
            MonotonicInstant::from_nanos(1),
        ))
    }
}

fn delegation_parent(kernel: &ChioKernel) -> CapabilityToken {
    make_capability(
        kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    )
}

#[test]
fn lineage_registration_records_verified_parent_expiry() {
    let kernel = make_kernel(make_config());
    let parent = delegation_parent(&kernel);
    kernel.register_delegation_parent(&parent).unwrap();
    let budgets = kernel.budget_registry.lock().unwrap();
    assert!(budgets.split(&parent.id).is_some());
    assert_eq!(
        budgets.parent_expires_at_secs(&parent.id),
        Some(parent.expires_at)
    );
}

#[test]
fn lineage_registration_without_trusted_time_registers_nothing() {
    let clock = Arc::new(CountingClock {
        reads: AtomicUsize::new(0),
        fail_after: AtomicUsize::new(usize::MAX),
    });
    let kernel = ChioKernel::new_with_clock(make_config(), clock.clone());
    let measured = delegation_parent(&kernel);
    let refused = delegation_parent(&kernel);

    let before = clock.reads.load(AtomicOrdering::SeqCst);
    kernel.register_delegation_parent(&measured).unwrap();
    let reads_per_registration = clock.reads.load(AtomicOrdering::SeqCst) - before;
    assert!(reads_per_registration >= 2);

    // Admission validation succeeds; only the final registration read fails.
    clock.fail_after.store(
        clock.reads.load(AtomicOrdering::SeqCst) + reads_per_registration - 1,
        AtomicOrdering::SeqCst,
    );
    assert!(matches!(
        kernel.register_delegation_parent(&refused),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(
        clock.reads.load(AtomicOrdering::SeqCst),
        clock.fail_after.load(AtomicOrdering::SeqCst) + 1
    );
    assert!(kernel
        .budget_registry
        .lock()
        .unwrap()
        .split(&refused.id)
        .is_none());
}
