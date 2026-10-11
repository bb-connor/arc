use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};

struct SwitchableClock(AtomicBool);
impl Clock for SwitchableClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.0.load(AtomicOrdering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading::new(
            UnixMillis::new(1_800_000_000_000),
            MonotonicInstant::from_nanos(1),
        ))
    }
}

#[test]
fn lineage_registration_records_verified_parent_expiry() {
    let kernel = make_kernel(make_config());
    let parent = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
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
    let clock = Arc::new(SwitchableClock(AtomicBool::new(false)));
    let kernel = ChioKernel::new_with_clock(make_config(), clock.clone());
    let parent = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    clock.0.store(true, AtomicOrdering::SeqCst);
    assert!(kernel.register_delegation_parent(&parent).is_err());
    assert!(kernel
        .budget_registry
        .lock()
        .unwrap()
        .split(&parent.id)
        .is_none());
}
