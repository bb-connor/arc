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

/// Reads observed while the budget registry is held land after the parent
/// expiry, as when registration waits behind a long registry holder.
struct RegistryContentionClock {
    kernel: std::sync::OnceLock<std::sync::Weak<ChioKernel>>,
    monotonic_nanos: AtomicU64,
}

const BEFORE_EXPIRY_MILLIS: u64 = 1_800_000_000_000;
const PARENT_TTL_SECS: u64 = 300;

impl Clock for RegistryContentionClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let registry_held = self
            .kernel
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|kernel| kernel.budget_registry.try_lock().is_err());
        let wall = if registry_held {
            BEFORE_EXPIRY_MILLIS + PARENT_TTL_SECS * 1_000
        } else {
            BEFORE_EXPIRY_MILLIS
        };
        Ok(ClockReading::new(
            UnixMillis::new(wall),
            MonotonicInstant::from_nanos(self.monotonic_nanos.fetch_add(1, AtomicOrdering::SeqCst)),
        ))
    }
}

#[test]
fn lineage_registration_reads_trusted_time_after_acquiring_the_registry() {
    let clock = Arc::new(RegistryContentionClock {
        kernel: std::sync::OnceLock::new(),
        monotonic_nanos: AtomicU64::new(1),
    });
    let kernel = Arc::new(ChioKernel::new_with_clock(make_config(), clock.clone()));
    let parent = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        PARENT_TTL_SECS,
    );
    assert!(clock.kernel.set(Arc::downgrade(&kernel)).is_ok());

    let expected = chio_kernel_core::BudgetSplitError::ExpiredParent {
        parent_token_id: parent.id.clone(),
    }
    .to_string();
    assert!(matches!(
        kernel.register_delegation_parent(&parent),
        Err(KernelError::DelegationInvalid(reason)) if reason == expected
    ));
    assert!(kernel
        .budget_registry
        .lock()
        .unwrap()
        .split(&parent.id)
        .is_none());
}
