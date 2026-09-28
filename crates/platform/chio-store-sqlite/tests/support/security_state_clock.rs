use chio_security_types::clock as trusted_time;
use std::sync::atomic::{AtomicU64, Ordering};
pub(super) struct FixedSecurityStateClock {
    now_unix_ms: AtomicU64,
}

impl FixedSecurityStateClock {
    pub(super) fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms: AtomicU64::new(now_unix_ms),
        }
    }

    pub(super) fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::Release);
    }
}

impl trusted_time::Clock for FixedSecurityStateClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.now_unix_ms.load(Ordering::Acquire);
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}
