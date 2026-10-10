use super::{
    AdvancingClockFence, Clock, ClockError, ClockFence, ClockReading, MonotonicInstant, UnixMillis,
};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Native clock adapter. All instances share one origin and high-water fence.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        static FENCE: Mutex<ClockFence> = Mutex::new(ClockFence(None));
        // Serialize sampling as well as publication, so thread scheduling cannot
        // make an older sample look like a regressing native clock.
        let mut fence = FENCE.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(sample()?)
    }
}

/// Native service clock with a monotonic epoch floor owned by this instance.
/// Share one instance across a service's authority, replay and storage owners.
#[derive(Debug, Default)]
pub struct AdvancingSystemClock {
    fence: Mutex<AdvancingClockFence>,
}

impl Clock for AdvancingSystemClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut fence = self.fence.lock().map_err(|_| ClockError::Unavailable)?;
        fence.observe(sample()?)
    }
}

fn sample() -> Result<ClockReading, ClockError> {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    let monotonic = u64::try_from(origin.elapsed().as_nanos()).map_err(|_| ClockError::Overflow)?;
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockError::BeforeEpoch)?;
    let unix = u64::try_from(unix.as_millis()).map_err(|_| ClockError::Overflow)?;
    Ok(ClockReading::new(
        UnixMillis::new(unix),
        MonotonicInstant::from_nanos(monotonic),
    ))
}
