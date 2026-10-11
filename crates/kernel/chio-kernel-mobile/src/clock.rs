//! Native mobile time shares the security clock's failure and regression rules.
#![forbid(unsafe_code)]
use chio_kernel_core::clock::{Clock, ClockError, ClockReading, SystemClock};
#[derive(Debug, Clone, Copy, Default)]
pub struct MobileClock;
impl MobileClock {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
impl Clock for MobileClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        SystemClock.read()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mobile_clock_returns_recent_timestamp() -> Result<(), ClockError> {
        assert!(MobileClock.read()?.unix_millis().as_secs() > 1_577_836_800);
        Ok(())
    }
}
