//! A supplied clock and one shared fence for each SQLite owner and its workers.

use std::sync::{Arc, Mutex};

use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, UnixMillis};

#[derive(Clone)]
pub(crate) struct StoreClock {
    clock: Arc<dyn Clock>,
    fence: Arc<Mutex<ClockFence>>,
}

impl StoreClock {
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_fence(clock, Arc::new(Mutex::new(ClockFence::default())))
    }

    pub(crate) fn with_fence(clock: Arc<dyn Clock>, fence: Arc<Mutex<ClockFence>>) -> Self {
        Self { clock, fence }
    }

    pub(crate) fn unix_millis(&self) -> Result<UnixMillis, ClockError> {
        self.read().map(ClockReading::unix_millis)
    }

    pub(crate) fn now_secs(&self) -> Result<i64, ClockError> {
        i64::try_from(self.unix_millis()?.as_secs()).map_err(|_| ClockError::Overflow)
    }
}

impl Clock for StoreClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut fence = self.fence.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(self.clock.read()?)
    }
}
