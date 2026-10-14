//! One trusted clock fence for kernel evaluation and its durable runtime.

use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, UnixMillis};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

pub(super) fn read(clock: &dyn Clock, fence: &Mutex<ClockFence>) -> Result<UnixMillis, ClockError> {
    Ok(read_fenced(clock, fence)?.unix_millis())
}

fn read_fenced(clock: &dyn Clock, fence: &Mutex<ClockFence>) -> Result<ClockReading, ClockError> {
    let mut fence = fence.lock().map_err(|_| ClockError::Unavailable)?;
    // Keep clock observations ordered without letting a provider panic poison
    // the fence needed by subsequent recovery attempts.
    let reading =
        catch_unwind(AssertUnwindSafe(|| clock.read())).map_err(|_| ClockError::Unavailable)??;
    fence.observe(reading)
}

struct AuthorityClock {
    source: Arc<dyn Clock>,
    fence: Arc<Mutex<ClockFence>>,
}
impl Clock for AuthorityClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        read_fenced(self.source.as_ref(), &self.fence)
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
        read_fenced(self.clock.as_ref(), &self.clock_fence)
    }

    pub(crate) fn read_authority_time(&self) -> Result<UnixMillis, ClockError> {
        read(self.clock.as_ref(), &self.clock_fence)
    }

    pub(crate) fn trusted_now_millis(&self) -> Result<UnixMillis, super::KernelError> {
        self.read_authority_time().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::clock::FixedClock;

    struct UnavailableClock;
    impl Clock for UnavailableClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            Err(ClockError::Unavailable)
        }
    }

    #[test]
    fn receipt_scope_cannot_replace_injected_authority_time() -> Result<(), ClockError> {
        let clock = FixedClock::from_millis(20_000);
        let fence = Mutex::new(ClockFence::default());
        let _scope = crate::scope_receipt_ids_for_current_thread([]);
        assert_eq!(read(&clock, &fence)?.get(), 20_000);
        assert_eq!(
            crate::authority::capability_authority_now_unix_secs(&clock).ok(),
            Some(20)
        );
        assert_eq!(
            read(&FixedClock::from_millis(19_000), &fence),
            Err(ClockError::WallClockRegression)
        );
        assert_eq!(
            read(&UnavailableClock, &fence),
            Err(ClockError::Unavailable)
        );
        Ok(())
    }
}
