use chio_security_types::clock as trusted_time;
use chio_security_types::ports::{PortError, PortResult};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) struct FixedClock(pub(super) u64);

impl trusted_time::Clock for FixedClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.0;
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}

pub(super) struct MutableClock(AtomicU64);

impl MutableClock {
    pub(super) fn new(now_unix_ms: u64) -> Self {
        Self(AtomicU64::new(now_unix_ms))
    }

    pub(super) fn set(&self, now_unix_ms: u64) {
        self.0.store(now_unix_ms, Ordering::Release);
    }
}

impl trusted_time::Clock for MutableClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.0.load(Ordering::Acquire);
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}

pub(super) struct ToggleClock {
    pub(super) ready: AtomicBool,
    pub(super) now_unix_ms: u64,
}

impl trusted_time::Clock for ToggleClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value: PortResult<u64> = if self.ready.load(Ordering::Acquire) {
            Ok(self.now_unix_ms)
        } else {
            Err(PortError::unavailable())
        };
        let value = value.map_err(|_| trusted_time::ClockError::Unavailable)?;
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}
