//! Blocking authority lookups must not retain pre-wait trust time.
use super::*;
use chio_kernel::{CapabilityAuthority, KernelError};
use chio_security_types::clock::ClockError;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "clock_tests/fixture.rs"]
mod fixture;
#[path = "clock_tests/native_dispatch.rs"]
mod native_dispatch;
#[path = "clock_tests/pinned.rs"]
mod pinned;
use fixture::{remote, rotated_status, MutableClock, StatusServer};

fn lifecycle_after_refresh(value: Result<u64, ClockError>) -> TestResult<Result<(), KernelError>> {
    let (status, old, _) = rotated_status()?;
    let clock = Arc::new(MutableClock::new());
    let mut server = StatusServer::new(&status, 1)?;
    let remote = remote(&status, &server.endpoint(), clock.clone(), false)?;
    let result = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| remote.check_issuer_lifecycle(&old, 100, 109));
        assert_eq!(server.pause_and_change(&clock, value)?, 1);
        worker
            .join()
            .map_err(|_| "lifecycle worker panicked".into())
    })?;
    assert_eq!(server.finish()?, 1);
    Ok(result)
}

#[test]
fn remote_lifecycle_refresh_accepts_before_retirement() -> TestResult {
    lifecycle_after_refresh(Ok(109_999))??;
    Ok(())
}

#[test]
fn remote_lifecycle_refresh_rejects_exact_retirement() -> TestResult {
    assert!(matches!(
        lifecycle_after_refresh(Ok(110_000))?,
        Err(KernelError::UntrustedIssuer)
    ));
    Ok(())
}

#[test]
fn remote_lifecycle_refresh_rejects_after_retirement() -> TestResult {
    assert!(matches!(
        lifecycle_after_refresh(Ok(111_000))?,
        Err(KernelError::UntrustedIssuer)
    ));
    Ok(())
}

#[test]
fn remote_lifecycle_refresh_reports_failed_clock() -> TestResult {
    assert!(matches!(
        lifecycle_after_refresh(Err(ClockError::Unavailable))?,
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    Ok(())
}

fn keys_after_refresh(
    value: Result<u64, ClockError>,
) -> TestResult<(Vec<PublicKey>, PublicKey, PublicKey)> {
    let (status, old, current) = rotated_status()?;
    let clock = Arc::new(MutableClock::new());
    let mut server = StatusServer::new(&status, 1)?;
    let remote = remote(&status, &server.endpoint(), clock.clone(), true)?;
    let result = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| remote.trusted_public_keys());
        assert_eq!(server.pause_and_change(&clock, value)?, 1);
        worker.join().map_err(|_| "trust worker panicked".into())
    })?;
    assert_eq!(server.finish()?, 1);
    Ok((result, old, current))
}

#[test]
fn remote_trust_refresh_accepts_before_retirement() -> TestResult {
    let (keys, old, current) = keys_after_refresh(Ok(109_999))?;
    assert!(keys.contains(&old));
    assert!(keys.contains(&current));
    assert_eq!(keys.len(), 2);
    Ok(())
}

#[test]
fn remote_trust_refresh_removes_exactly_expired_issuer() -> TestResult {
    let (keys, old, current) = keys_after_refresh(Ok(110_000))?;
    assert_eq!(keys, vec![current]);
    assert!(!keys.contains(&old));
    Ok(())
}

#[test]
fn remote_trust_refresh_rejects_failed_clock() -> TestResult {
    let (keys, _, _) = keys_after_refresh(Err(ClockError::Unavailable))?;
    assert!(keys.is_empty());
    Ok(())
}

fn keys_after_cache_wait(
    value: Result<u64, ClockError>,
) -> TestResult<(Vec<PublicKey>, PublicKey)> {
    let (status, _, current) = rotated_status()?;
    let clock = Arc::new(MutableClock::new());
    let observed = clock.observe_next_read()?;
    let server = StatusServer::new(&status, usize::MAX)?;
    let remote = remote(&status, &server.endpoint(), clock.clone(), false)?;
    let mut cache = remote.cache.lock().map_err(|_| "cache poisoned")?;
    let result = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| remote.trusted_public_keys());
        let read = fixture::wait_for_read(observed);
        let changed = if read.is_ok() {
            clock.set(value)
        } else {
            Ok(())
        };
        // Keep this a fresh-cache contention case even on a stalled test host.
        cache.refreshed_at = Instant::now();
        drop(cache);
        read?;
        changed?;
        worker.join().map_err(|_| "trust worker panicked".into())
    })?;
    assert_eq!(
        server.finish()?,
        0,
        "fresh cache must avoid network refresh"
    );
    Ok((result, current))
}

#[test]
fn remote_trust_cache_wait_observes_exact_retirement() -> TestResult {
    let (keys, current) = keys_after_cache_wait(Ok(110_000))?;
    assert_eq!(keys, vec![current]);
    Ok(())
}

#[test]
fn remote_trust_cache_wait_rejects_failed_clock() -> TestResult {
    assert!(keys_after_cache_wait(Err(ClockError::Unavailable))?
        .0
        .is_empty());
    Ok(())
}

#[test]
fn remote_lifecycle_retains_later_caller_floor() -> TestResult {
    let (status, old, _) = rotated_status()?;
    let clock = Arc::new(MutableClock::new());
    let mut server = StatusServer::new(&status, 1)?;
    let remote = remote(&status, &server.endpoint(), clock.clone(), false)?;
    let result = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| remote.check_issuer_lifecycle(&old, 100, 110));
        server.pause_and_change(&clock, Ok(109_999))?;
        worker
            .join()
            .map_err(|_| "lifecycle worker panicked".into())
    })?;
    assert!(matches!(result, Err(KernelError::UntrustedIssuer)));
    assert_eq!(server.finish()?, 1);
    Ok(())
}
