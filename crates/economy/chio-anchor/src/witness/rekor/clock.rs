//! One fallible authority-time owner shared by client clones.
use chio_security_types::clock::{Clock, ClockError, ClockFence};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct AuthorityClock {
    clock: Arc<dyn Clock>,
    fence: Arc<Mutex<ClockFence>>,
}

impl std::fmt::Debug for AuthorityClock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthorityClock")
    }
}

impl AuthorityClock {
    pub(super) fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            fence: Arc::new(Mutex::new(ClockFence::default())),
        }
    }

    pub(super) fn now(&self) -> Result<i64, ClockError> {
        // Sampling and observation must share the lock, including across clones.
        let mut fence = self.fence.lock().map_err(|_| ClockError::Unavailable)?;
        let reading = fence.observe(self.clock.read()?)?;
        i64::try_from(reading.unix_millis().as_secs()).map_err(|_| ClockError::Overflow)
    }
}
