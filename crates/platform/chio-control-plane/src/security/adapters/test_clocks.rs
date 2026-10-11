use chio_security_types::clock as trusted_time;
use chio_security_types::ports::{PortError, PortResult};
use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) struct FixedClock(pub(super) u64);

impl trusted_time::Clock for FixedClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.0;
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}

pub(super) struct AdvancingClock {
    pub(super) calls: AtomicUsize,
    first_unix_ms: u64,
}

impl AdvancingClock {
    pub(super) fn new(first_unix_ms: u64) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            first_unix_ms,
        }
    }
}

impl trusted_time::Clock for AdvancingClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value: PortResult<u64> = (|| {
            let elapsed = u64::try_from(self.calls.fetch_add(1, Ordering::SeqCst))
                .map_err(|_| PortError::unavailable())?;
            self.first_unix_ms
                .checked_add(elapsed)
                .ok_or_else(PortError::unavailable)
        })();
        let value = value.map_err(|_| trusted_time::ClockError::Unavailable)?;
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}
