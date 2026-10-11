//! Shared observation and failure custody for ACP audit owners.
use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, SystemClock};
use std::sync::{Arc, Mutex};

/// An injected clock whose clones share one serialized high-water fence.
#[derive(Clone)]
pub struct AcpClock(Arc<Owner>);

struct Owner {
    source: Arc<dyn Clock>,
    fence: Mutex<ClockFence>,
}

impl AcpClock {
    /// Bind ACP logging, signing and certificate generation to one source.
    pub fn new(source: Arc<dyn Clock>) -> Self {
        Self(Arc::new(Owner {
            source,
            fence: Mutex::new(ClockFence::default()),
        }))
    }

    pub(crate) fn seconds(&self) -> Result<u64, AcpAuditError> {
        Ok(self.read()?.unix_millis().get() / 1_000)
    }
}

impl Default for AcpClock {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}
impl std::fmt::Debug for AcpClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpClock").finish_non_exhaustive()
    }
}
impl Clock for AcpClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut fence = self.0.fence.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(self.0.source.read()?)
    }
}

/// Local audit causes. Display and Debug never include receipt input.
#[derive(thiserror::Error)]
pub enum AcpAuditError {
    /// A trusted observation failed or regressed.
    #[error("{}", .0.code())]
    Clock(#[from] ClockError),
    /// Canonical serialization failed.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Canonical(#[from] chio_core::error::Error),
    /// The event did not contain a numeric Unix timestamp.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Timestamp(#[from] std::num::ParseIntError),
}
impl std::fmt::Debug for AcpAuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

pub(crate) fn event_timestamp(value: &str, now: ClockReading) -> Result<u64, AcpAuditError> {
    let seconds = value.parse::<u64>()?;
    let millis = seconds.checked_mul(1_000).ok_or(ClockError::Overflow)?;
    if millis > now.unix_millis().get() {
        return Err(ClockError::NotYetValid.into());
    }
    Ok(seconds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_security_types::clock::{MonotonicInstant, UnixMillis};
    struct Mutable(Mutex<Result<ClockReading, ClockError>>);
    impl Clock for Mutable {
        fn read(&self) -> Result<ClockReading, ClockError> {
            *self.0.lock().unwrap()
        }
    }
    fn reading(wall: u64, mono: u64) -> ClockReading {
        ClockReading::new(UnixMillis::new(wall), MonotonicInstant::from_nanos(mono))
    }
    #[test]
    fn clones_retain_the_fence_after_faults_and_rollback() {
        let source = Arc::new(Mutable(Mutex::new(Ok(reading(2_000, 2)))));
        let clock = AcpClock::new(source.clone());
        assert_eq!(clock.seconds().unwrap(), 2);
        *source.0.lock().unwrap() = Err(ClockError::Unavailable);
        assert!(matches!(
            clock.clone().seconds(),
            Err(AcpAuditError::Clock(ClockError::Unavailable))
        ));
        *source.0.lock().unwrap() = Ok(reading(1_000, 3));
        assert_eq!(clock.read(), Err(ClockError::WallClockRegression));
        *source.0.lock().unwrap() = Ok(reading(3_000, 1));
        assert_eq!(clock.read(), Err(ClockError::MonotonicRegression));
        *source.0.lock().unwrap() = Ok(reading(3_000, 4));
        assert_eq!(clock.seconds().unwrap(), 3);
    }
    #[test]
    fn persisted_events_reject_bad_future_and_overflowing_time() {
        use std::error::Error;
        let now = reading(2_000, 1);
        assert_eq!(event_timestamp("2", now).unwrap(), 2);
        let malformed = event_timestamp("private_timestamp", now).unwrap_err();
        assert!(malformed
            .source()
            .unwrap()
            .downcast_ref::<std::num::ParseIntError>()
            .is_some());
        assert!(!format!("{malformed:?}").contains("private_timestamp"));
        assert!(matches!(
            event_timestamp("3", now),
            Err(AcpAuditError::Clock(ClockError::NotYetValid))
        ));
        assert!(matches!(
            event_timestamp(&u64::MAX.to_string(), now),
            Err(AcpAuditError::Clock(ClockError::Overflow))
        ));
    }
}
