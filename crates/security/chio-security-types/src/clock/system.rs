use super::{Clock, ClockError, ClockFence, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Native clock adapter. All instances share one origin and high-water fence.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        static FENCE: Mutex<ClockFence> = Mutex::new(ClockFence(None));
        // Serialize sampling as well as publication, so thread scheduling cannot
        // make an older sample look like a regressing native clock.
        let mut fence = FENCE.lock().map_err(|_| ClockError::Unavailable)?;
        let origin = ORIGIN.get_or_init(Instant::now);
        let monotonic =
            u64::try_from(origin.elapsed().as_nanos()).map_err(|_| ClockError::Overflow)?;
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeEpoch)?;
        let unix = u64::try_from(unix.as_millis()).map_err(|_| ClockError::Overflow)?;
        fence.observe(ClockReading::new(
            UnixMillis::new(unix),
            MonotonicInstant::from_nanos(monotonic),
        ))
    }
}
