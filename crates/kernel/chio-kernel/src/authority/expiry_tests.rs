use super::*;
use chio_core::crypto::{Signature, SigningAlgorithm};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Clock;
impl chio_security_types::clock::Clock for Clock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value = 1_700_000_000_000;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

struct CountingBackend {
    key: Keypair,
    signs: AtomicUsize,
}
impl SigningBackend for CountingBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.key.public_key().algorithm()
    }
    fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<Signature> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        Ok(self.key.sign(message))
    }
}

#[test]
fn all_issuers_refuse_unrepresentable_expiry_before_signing() {
    let subject = Keypair::generate().public_key();
    let local = LocalCapabilityAuthority::new_with_clock(Keypair::generate(), Arc::new(Clock));
    let backend = Arc::new(CountingBackend {
        key: Keypair::generate(),
        signs: AtomicUsize::new(0),
    });
    let governed = GovernedCapabilityAuthority::new(backend.clone(), Arc::new(Clock));
    for result in [
        local.issue_capability(&subject, ChioScope::default(), u64::MAX),
        local.issue_aggregate_family_root(&subject, ChioScope::default(), u64::MAX, 5),
        governed.issue_capability(&subject, ChioScope::default(), u64::MAX),
        governed.issue_aggregate_family_root(&subject, ChioScope::default(), u64::MAX, 5),
        governed.issue_capability_with_aggregate_budget(
            &subject,
            ChioScope::default(),
            u64::MAX,
            5,
        ),
    ] {
        assert!(
            matches!(result, Err(KernelError::CapabilityIssuanceFailed(message))
            if message == "capability expiry overflows the timestamp domain")
        );
    }
    assert_eq!(backend.signs.load(Ordering::SeqCst), 0);
    let valid = governed.issue_capability(&subject, ChioScope::default(), 60);
    assert!(matches!(valid, Ok(ref token) if token.expires_at == 1_700_000_060));
    assert_eq!(backend.signs.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_maximum_expiry_is_representable_but_the_next_tick_is_not() {
    assert!(matches!(
        checked_capability_expiry(u64::MAX - 5, 5),
        Ok(u64::MAX)
    ));
    assert!(matches!(checked_capability_expiry(u64::MAX - 5, 6),
        Err(KernelError::CapabilityIssuanceFailed(message)) if message == "capability expiry overflows the timestamp domain"));
}

#[test]
fn response_validation_refuses_unrepresentable_requested_lifetime() -> Result<(), KernelError> {
    let subject = Keypair::generate().public_key();
    let authority = LocalCapabilityAuthority::new_with_clock(Keypair::generate(), Arc::new(Clock));
    let scope = ChioScope::default();
    let token = authority.issue_capability(&subject, scope.clone(), 60)?;
    validate_issued_capability_response_at(
        &token,
        &subject,
        &scope,
        60,
        &token.issuer,
        token.issued_at,
        0,
    )?;
    assert!(matches!(validate_issued_capability_response_at(
        &token, &subject, &scope, u64::MAX, &token.issuer, token.issued_at, 30,
    ), Err(KernelError::CapabilityIssuanceFailed(message))
        if message == "capability expiry overflows the timestamp domain"));
    Ok(())
}
