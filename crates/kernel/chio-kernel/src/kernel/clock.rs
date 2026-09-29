//! One trusted clock fence for kernel evaluation and its durable runtime.

use chio_security_types::clock::{
    Clock, ClockError, ClockFence, ClockReading, MonotonicInstant, UnixMillis,
};
use std::sync::{Arc, Mutex};

pub(super) fn read(clock: &dyn Clock, fence: &Mutex<ClockFence>) -> Result<UnixMillis, ClockError> {
    if let Some(now) = super::fixed_runtime_unix_secs_for_current_thread() {
        return UnixMillis::from_secs(now);
    }
    let mut fence = fence.lock().map_err(|_| ClockError::Unavailable)?;
    Ok(fence.observe(clock.read()?)?.unix_millis())
}

struct AuthorityClock {
    source: Arc<dyn Clock>,
    fence: Arc<Mutex<ClockFence>>,
}
impl Clock for AuthorityClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut fence = self.fence.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(self.source.read()?)
    }
}

impl super::ChioKernel {
    /// Share the kernel clock and its high-water fence with service authority owners.
    pub fn authority_clock(&self) -> Arc<dyn Clock> {
        Arc::new(AuthorityClock {
            source: self.clock.clone(),
            fence: self.clock_fence.clone(),
        })
    }

    /// Observe the kernel's fenced clock for protocol deadlines. A caller must
    /// retain the resulting deadline across retries, never resample its origin.
    pub fn authority_clock_reading(&self) -> Result<ClockReading, ClockError> {
        if let Some(now) = super::fixed_runtime_unix_secs_for_current_thread() {
            return Ok(ClockReading::new(
                UnixMillis::from_secs(now)?,
                MonotonicInstant::from_nanos(0),
            ));
        }
        self.clock_fence
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .observe(self.clock.read()?)
    }

    pub(super) fn read_authority_time(&self) -> Result<UnixMillis, ClockError> {
        read(self.clock.as_ref(), &self.clock_fence)
    }

    pub(crate) fn trusted_now_millis(&self) -> Result<UnixMillis, super::KernelError> {
        self.read_authority_time().map_err(Into::into)
    }
}
