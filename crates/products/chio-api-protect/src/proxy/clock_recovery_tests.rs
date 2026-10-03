#![cfg(test)]
use super::*;
use chio_security_types::clock::{AuthorityDeadline, MonotonicInstant, UnixMillis};
use chio_test_support::prelude::*;

struct Source(Mutex<Result<ClockReading, ClockError>>);

impl Source {
    fn set(&self, wall: u64, mono: u64) {
        *self.0.lock().test_unwrap() = Ok(ClockReading::new(
            UnixMillis::new(wall),
            MonotonicInstant::from_nanos(mono),
        ));
    }
}

impl Clock for Source {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

fn controlled(wall: u64) -> (Arc<Source>, ProxyClock) {
    let source = Arc::new(Source(Mutex::new(Err(ClockError::Unavailable))));
    source.set(wall, 0);
    let clock = ProxyClock::new(source.clone());
    (source, clock)
}

#[test]
fn service_clock_backward_step_advances_expiry_instead_of_freezing_it() -> Result<(), ClockError> {
    let (source, clock) = controlled(100_000);
    let mut deadline = AuthorityDeadline::for_timeout_ms(clock.read()?, 2_000)?;
    source.set(10_000, 1_000_000_000);
    assert_eq!(clock.clone().millis()?, 101_000);
    assert_eq!(
        deadline.remaining(clock.read()?)?,
        std::time::Duration::from_secs(1)
    );
    source.set(11_000, 2_000_000_000);
    assert_eq!(clock.millis()?, 102_000);
    assert_eq!(deadline.remaining(clock.read()?), Err(ClockError::Expired));
    Ok(())
}

#[test]
fn service_clock_frequent_reads_retain_fractional_elapsed_time() -> Result<(), ClockError> {
    let (source, clock) = controlled(1_000);
    assert_eq!(clock.millis()?, 1_000);
    for (mono, expected) in [
        (400_000, 1_000),
        (800_000, 1_000),
        (1_200_000, 1_001),
        (1_600_000, 1_001),
        (2_000_000, 1_002),
    ] {
        source.set(999, mono);
        assert_eq!(clock.millis()?, expected);
    }
    source.set(2_000, 2_400_000);
    assert_eq!(clock.millis()?, 2_000);
    source.set(998, 3_400_000);
    assert_eq!(clock.millis()?, 2_001);
    Ok(())
}

#[test]
fn service_clock_faults_preserve_the_anchor_and_monotonic_floor() -> Result<(), ClockError> {
    let (source, clock) = controlled(100_000);
    clock.read()?;
    source.set(99_000, 1_000_000_000);
    assert_eq!(clock.millis()?, 101_000);
    *source.0.lock().test_unwrap() = Err(ClockError::Unavailable);
    assert_eq!(clock.read(), Err(ClockError::Unavailable));
    source.set(500_000, 999_999_999);
    assert_eq!(clock.read(), Err(ClockError::MonotonicRegression));
    source.set(98_000, 2_000_000_000);
    assert_eq!(clock.millis()?, 102_000);
    Ok(())
}

#[test]
fn service_clock_recovery_keeps_kernel_and_nonce_expiry_consistent(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::{ExecutionNonceStore, InMemoryBudgetStore, InMemoryExecutionNonceStore};
    let (source, clock) = controlled(1_700_000_000_000);
    let signer = chio_core_types::Keypair::from_seed(&[17; 32]);
    let directory = tempfile::tempdir()?;
    let mut kernel = super::super::build_mediation_kernel(
        &signer,
        Arc::new(InMemoryBudgetStore::with_clock(Arc::new(clock.clone()))),
        super::super::mediated::MediationPolicy {
            issuers: &[],
            hash: None,
        },
        Vec::new(),
        None,
        None,
        Arc::new(clock.clone()),
    )?;
    kernel.set_receipt_store(Box::new(chio_store_sqlite::SqliteReceiptStore::open(
        directory.path().join("receipts.db"),
    )?))?;
    let subject = chio_core_types::Keypair::from_seed(&[18; 32]).public_key();
    let capability = kernel.issue_capability(
        &subject,
        chio_core_types::capability::scope::ChioScope::default(),
        2,
    )?;
    let nonces = InMemoryExecutionNonceStore::with_clock(4, kernel.authority_clock());
    let mut deadline = AuthorityDeadline::for_timeout_ms(kernel.authority_clock_reading()?, 2_000)?;
    assert!(nonces.reserve_until("consumed", 1_700_000_002)?);
    source.set(1_699_999_900_000, 1_000_000_000);
    assert_eq!(
        kernel.authority_clock_reading()?.unix_millis().get(),
        1_700_000_001_000
    );
    assert_eq!(
        kernel
            .verify_retained_capability_liveness(&capability.id, &subject)?
            .id,
        capability.id
    );
    assert!(!nonces.reserve_until("consumed", 1_700_000_002)?);
    assert!(nonces.reserve_until("fresh", 1_700_000_002)?);
    source.set(1_699_999_901_000, 2_000_000_000);
    assert_eq!(
        deadline.remaining(kernel.authority_clock_reading()?),
        Err(ClockError::Expired)
    );
    assert!(matches!(
        nonces.reserve_until("expired", 1_700_000_002),
        Err(chio_kernel::KernelError::Clock(ClockError::Expired))
    ));
    assert!(
        matches!(kernel.verify_retained_capability_liveness(&capability.id, &subject), Err(chio_kernel::KernelError::GuardDenied(reason)) if reason == "capability has expired")
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn service_clock_is_shared_by_durable_admission_and_configured_budget_owners(
) -> Result<(), Box<dyn std::error::Error>> {
    use super::super::{build_budget_store, state::open_durable_admission, ProtectConfig};
    let directory = tempfile::tempdir()?;
    let base = chio_security_types::clock::SystemClock.unix_millis()?.get();
    let (source, clock) = controlled(base);
    let receipt_path = directory.path().join("receipts.db");
    let durable = open_durable_admission(
        receipt_path.to_str().ok_or("non-UTF8 path")?,
        Arc::new(clock.clone()),
    )?;
    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".into(),
        spec_content: Some("{}".into()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".into(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: Some(
            directory
                .path()
                .join("budget.db")
                .to_string_lossy()
                .into_owned(),
        ),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let legacy =
        build_budget_store(&config, Arc::new(clock.clone()))?.ok_or("missing budget store")?;
    let operation =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted("01".repeat(32))?;
    let stores = [legacy.store];
    source.set(base - 90_000, 1_000_000_000);
    assert!(durable
        .store
        .load_native_dispatch_ledger(&operation, &durable.fence, base + 1_000)?
        .is_none());
    for store in &stores {
        assert!(store.try_increment("clock-test", 0, Some(2))?);
        assert_eq!(
            store
                .get_usage("clock-test", 0)?
                .ok_or("missing usage")?
                .updated_at,
            i64::try_from((base + 1_000) / 1_000)?
        );
    }
    *source.0.lock().test_unwrap() = Err(ClockError::Unavailable);
    let error = durable
        .store
        .load_native_dispatch_ledger(&operation, &durable.fence, base + 1_000)
        .test_expect_err("durable owner must use the service clock");
    assert!(error.to_string().contains(ClockError::Unavailable.code()));
    for store in &stores {
        assert!(store.try_increment("clock-test", 0, Some(2)).is_err());
        assert_eq!(
            store
                .get_usage("clock-test", 0)?
                .ok_or("missing usage")?
                .invocation_count,
            1
        );
    }
    source.set(base - 89_000, 2_000_000_000);
    assert!(durable
        .store
        .load_native_dispatch_ledger(&operation, &durable.fence, base + 2_000)?
        .is_none());
    for store in &stores {
        assert!(store.try_increment("clock-test", 0, Some(2))?);
        assert!(!store.try_increment("clock-test", 0, Some(2))?);
    }
    Ok(())
}
