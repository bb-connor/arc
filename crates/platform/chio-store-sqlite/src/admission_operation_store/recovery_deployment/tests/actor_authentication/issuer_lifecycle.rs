use super::*;
use crate::SqliteCapabilityAuthority;
use chio_kernel::CapabilityAuthority;

struct IssuerClock(AtomicU64);

impl Clock for IssuerClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let millis = self.0.load(Ordering::SeqCst);
        if millis == u64::MAX {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading::new(
            UnixMillis::new(millis),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

fn managed_authority(
    harness: &mut Harness,
) -> TestResult<(SqliteCapabilityAuthority, Arc<IssuerClock>)> {
    let clock = Arc::new(IssuerClock(AtomicU64::new(now_ms()?)));
    let path = harness.fixture.temp.path().join("capability-authority.db");
    let authority = SqliteCapabilityAuthority::open_with_clock(&path, clock.clone())?;
    authority.initialize_replication("recovery-operator-issuers")?;
    harness
        .kernel
        .set_capability_authority(Box::new(SqliteCapabilityAuthority::open_with_clock(
            &path,
            clock.clone(),
        )?));
    Ok((authority, clock))
}

#[test]
fn managed_issuer_lifecycle_denies_authentication_and_revalidation() -> TestResult {
    for terminal in ["retired", "revoked", "verification-deadline"] {
        let mut harness = harness()?;
        let (authority, clock) = managed_authority(&mut harness)?;
        let old = authority.authority_public_key().unwrap();
        let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
        let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
        let before = writes(&harness.fixture)?;
        authority.rotate_with_verification_deadline(now_secs()? + 2)?;
        match terminal {
            "retired" => {
                authority.retire_issuer(&old)?;
            }
            "revoked" => {
                authority.revoke_issuer(&old)?;
            }
            "verification-deadline" => {
                clock.0.store(now_ms()? + 2_000, Ordering::SeqCst);
            }
            _ => return Err("unknown issuer lifecycle control".into()),
        }
        denied(authenticate(
            &harness,
            &capability,
            RecoveryPermission::Inspect,
        ))?;
        denied(harness.kernel.revalidate_recovery_actor(&actor))?;
        assert_eq!(writes(&harness.fixture)?, before);
        assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn issuer_backend_failure_remains_an_operational_refusal() -> TestResult {
    let mut harness = harness()?;
    let (_authority, clock) = managed_authority(&mut harness)?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    let before = writes(&harness.fixture)?;
    clock.0.store(u64::MAX, Ordering::SeqCst);
    for result in [
        authenticate(&harness, &capability, RecoveryPermission::Inspect).map(|_| ()),
        harness.kernel.revalidate_recovery_actor(&actor),
    ] {
        assert!(
            matches!(
                &result,
                Err(KernelError::Internal(reason))
                    if reason == "recovery capability authentication unavailable"
            ),
            "{result:?}"
        );
    }
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
