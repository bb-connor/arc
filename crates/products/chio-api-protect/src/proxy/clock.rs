//! One clock and high-water fence for every owner in a remote service.
use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, SystemClock};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ProxyClock(Arc<ClockOwner>);

struct ClockOwner {
    source: Arc<dyn Clock>,
    fence: Mutex<ClockFence>,
}

impl ProxyClock {
    pub fn new(source: Arc<dyn Clock>) -> Self {
        Self(Arc::new(ClockOwner {
            source,
            fence: Mutex::new(ClockFence::default()),
        }))
    }

    pub(crate) fn millis(&self) -> Result<u64, ClockError> {
        self.read().map(|reading| reading.unix_millis().get())
    }

    pub(crate) fn signed_seconds(&self) -> Result<i64, ClockError> {
        i64::try_from(self.seconds()?).map_err(|_| ClockError::Overflow)
    }

    pub(crate) fn seconds(&self) -> Result<u64, ClockError> {
        self.millis().map(|millis| millis / 1_000)
    }
}

impl Default for ProxyClock {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl std::fmt::Debug for ProxyClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyClock").finish_non_exhaustive()
    }
}

impl Clock for ProxyClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut fence = self.0.fence.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(self.0.source.read()?)
    }
}

pub(crate) fn rejection(error: ClockError) -> axum::response::Response {
    use axum::response::IntoResponse;
    super::input::with_source(
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, error.code()).into_response(),
        error,
    )
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
    fn reading(wall: u64, mono: u64) -> Result<ClockReading, ClockError> {
        Ok(ClockReading::new(
            UnixMillis::new(wall),
            MonotonicInstant::from_nanos(mono),
        ))
    }
    #[test]
    fn clones_share_high_water_and_faults_do_not_reset_it() {
        let source = Arc::new(Mutable(Mutex::new(reading(10, 20))));
        let clock = ProxyClock::new(source.clone());
        assert_eq!(clock.millis().unwrap(), 10);
        *source.0.lock().unwrap() = Err(ClockError::Unavailable);
        assert_eq!(clock.clone().read(), Err(ClockError::Unavailable));
        *source.0.lock().unwrap() = reading(9, 21);
        assert_eq!(clock.read(), Err(ClockError::WallClockRegression));
        *source.0.lock().unwrap() = reading(11, 19);
        assert_eq!(clock.read(), Err(ClockError::MonotonicRegression));
        *source.0.lock().unwrap() = reading(11, 22);
        assert_eq!(clock.millis().unwrap(), 11);
    }
}
