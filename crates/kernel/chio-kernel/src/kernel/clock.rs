//! One trusted clock fence for kernel evaluation and its durable runtime.

use chio_security_types::clock::{Clock, ClockError, ClockFence, UnixMillis};
use std::sync::Mutex;

pub(super) fn read(clock: &dyn Clock, fence: &Mutex<ClockFence>) -> Result<UnixMillis, ClockError> {
    if let Some(now) = super::fixed_runtime_unix_secs_for_current_thread() {
        return UnixMillis::from_secs(now);
    }
    let mut fence = fence.lock().map_err(|_| ClockError::Unavailable)?;
    Ok(fence.observe(clock.read()?)?.unix_millis())
}

impl super::ChioKernel {
    pub(super) fn read_authority_time(&self) -> Result<UnixMillis, ClockError> {
        read(self.clock.as_ref(), &self.clock_fence)
    }

    pub(crate) fn trusted_now_millis(&self) -> Result<UnixMillis, super::KernelError> {
        self.read_authority_time().map_err(Into::into)
    }
}
