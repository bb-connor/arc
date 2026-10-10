//! The operator-pinned builder must preserve its owner's authority time.
use super::*;

fn pinned(
    clock: Arc<MutableClock>,
) -> TestResult<(
    Box<dyn CapabilityAuthority>,
    StatusServer,
    PublicKey,
    PublicKey,
)> {
    let (status, old, current) = rotated_status()?;
    let server = StatusServer::new(&status, usize::MAX)?;
    let authority = build_pinned_remote_capability_authority_with_clock(
        &server.endpoint(),
        "test-only-control",
        current.clone(),
        vec![old.clone(), old.clone()],
        clock,
    )?;
    Ok((authority, server, old, current))
}

#[test]
fn f048_pinned_builder_keeps_retiring_issuer_before_owner_deadline() -> TestResult {
    let clock = Arc::new(MutableClock::new());
    let (authority, server, old, current) = pinned(clock)?;
    let keys = authority.trusted_public_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&old));
    assert!(keys.contains(&current));
    authority.check_issuer_lifecycle(&old, 100, 109)?;
    assert!(server.finish()? >= 2);
    Ok(())
}

#[test]
fn f048_pinned_builder_retires_issuer_at_exact_owner_deadline() -> TestResult {
    let clock = Arc::new(MutableClock::new());
    let (authority, server, old, current) = pinned(clock.clone())?;
    clock.set(Ok(110_000))?;
    assert_eq!(authority.trusted_public_keys(), vec![current]);
    assert!(matches!(
        authority.check_issuer_lifecycle(&old, 100, 109),
        Err(KernelError::UntrustedIssuer)
    ));
    assert!(server.finish()? >= 2);
    Ok(())
}

#[test]
fn f048_pinned_builder_clock_fault_removes_trust_and_blocks_network_issuance() -> TestResult {
    let clock = Arc::new(MutableClock::new());
    let (authority, server, old, _) = pinned(clock.clone())?;
    clock.set(Err(ClockError::Unavailable))?;
    assert!(authority.trusted_public_keys().is_empty());
    assert!(matches!(
        authority.check_issuer_lifecycle(&old, 100, 109),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 1),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert_eq!(
        server.finish()?,
        1,
        "clock fault must prevent network requests"
    );
    Ok(())
}

#[test]
fn f048_legacy_pinned_builder_keeps_compatible_pin_validation() -> TestResult {
    let (status, old, current) = rotated_status()?;
    let server = StatusServer::new(&status, usize::MAX)?;
    let authority = build_pinned_remote_capability_authority(
        &server.endpoint(),
        "test-only-control",
        current.clone(),
        vec![old.clone(), old, current.clone()],
    )?;
    assert_eq!(authority.authority_public_key(), current);
    assert!(server.finish()? >= 1);
    Ok(())
}
