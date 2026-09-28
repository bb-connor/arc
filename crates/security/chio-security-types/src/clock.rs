//! Trusted time shared by security decisions and portable kernel adapters.
//!
//! Signed records use Unix milliseconds. Local timeouts use monotonic ticks
//! from one clock instance and never survive a process restart. Clock failure
//! or regression denies the operation; neither is a timestamp of zero.

use core::fmt;
use core::time::Duration;

/// Maximum unexplained skew for replay retention observations. This tolerates
/// queued writer samples; it never extends a signed authority window or permits
/// the trusted clock itself to regress.
pub const MAX_REPLAY_WALL_SKEW_SECS: u32 = 300;

/// Milliseconds since the Unix epoch, for signed or persisted timestamps.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMillis(u64);

impl UnixMillis {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000
    }
    pub const fn from_secs(value: u64) -> Result<Self, ClockError> {
        match value.checked_mul(1_000) {
            Some(value) => Ok(Self(value)),
            None => Err(ClockError::Overflow),
        }
    }
    pub const fn checked_add(self, millis: u64) -> Result<Self, ClockError> {
        match self.0.checked_add(millis) {
            Some(value) => Ok(Self(value)),
            None => Err(ClockError::Overflow),
        }
    }
    pub const fn duration_since(self, earlier: Self) -> Result<u64, ClockError> {
        match self.0.checked_sub(earlier.0) {
            Some(value) => Ok(value),
            None => Err(ClockError::WallClockRegression),
        }
    }
}

/// Nanosecond ticks in the local clock's monotonic domain.
///
/// Never serialize this value or compare ticks from different clock instances.
/// Epoch timestamps and monotonic instants cannot be compared:
/// ```compile_fail
/// use chio_security_types::clock::{UnixMillis, MonotonicInstant};
/// let _ = UnixMillis::new(1) < MonotonicInstant::from_nanos(1);
/// ```
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    #[must_use]
    pub const fn from_nanos(value: u64) -> Self {
        Self(value)
    }
    pub fn checked_add(self, duration: Duration) -> Result<Self, ClockError> {
        let nanos = u64::try_from(duration.as_nanos()).map_err(|_| ClockError::Overflow)?;
        self.0
            .checked_add(nanos)
            .map(Self)
            .ok_or(ClockError::Overflow)
    }
    pub const fn checked_add_millis(self, millis: u64) -> Result<Self, ClockError> {
        match millis.checked_mul(1_000_000) {
            Some(nanos) => match self.0.checked_add(nanos) {
                Some(value) => Ok(Self(value)),
                None => Err(ClockError::Overflow),
            },
            None => Err(ClockError::Overflow),
        }
    }
    pub const fn duration_since(self, earlier: Self) -> Result<Duration, ClockError> {
        match self.0.checked_sub(earlier.0) {
            Some(value) => Ok(Duration::from_nanos(value)),
            None => Err(ClockError::MonotonicRegression),
        }
    }
}

/// One observation of the two distinct time domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    unix_millis: UnixMillis,
    monotonic: MonotonicInstant,
}

impl ClockReading {
    #[must_use]
    pub const fn new(unix_millis: UnixMillis, monotonic: MonotonicInstant) -> Self {
        Self {
            unix_millis,
            monotonic,
        }
    }
    #[must_use]
    pub const fn unix_millis(self) -> UnixMillis {
        self.unix_millis
    }
    #[must_use]
    pub const fn monotonic(self) -> MonotonicInstant {
        self.monotonic
    }
}

/// Reasons trusted time cannot authorize an operation. No source text is leaked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    Unavailable,
    BeforeEpoch,
    Overflow,
    WallClockRegression,
    MonotonicRegression,
    Expired,
    NotYetValid,
    InvalidWindow,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "trusted clock unavailable",
            Self::BeforeEpoch => "trusted clock precedes Unix epoch",
            Self::Overflow => "trusted time exceeds representable range",
            Self::WallClockRegression => "trusted wall clock regressed",
            Self::MonotonicRegression => "trusted monotonic clock regressed",
            Self::Expired => "authority window expired",
            Self::NotYetValid => "authority window not yet valid",
            Self::InvalidWindow => "authority window is empty or reversed",
        })
    }
}
impl ClockError {
    /// Stable, input-independent reason suitable for signed evidence.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "urn:chio:error:kernel:clock-unavailable",
            Self::BeforeEpoch => "urn:chio:error:kernel:clock-before-epoch",
            Self::Overflow => "urn:chio:error:kernel:clock-overflow",
            Self::WallClockRegression => "urn:chio:error:kernel:clock-wall-clock-regression",
            Self::MonotonicRegression => "urn:chio:error:kernel:clock-monotonic-regression",
            Self::Expired => "urn:chio:error:kernel:clock-expired",
            Self::NotYetValid => "urn:chio:error:kernel:clock-not-yet-valid",
            Self::InvalidWindow => "urn:chio:error:kernel:clock-invalid-window",
        }
    }
}
impl core::error::Error for ClockError {}

/// The sole clock port. Implementations return coherent, nonregressing readings.
/// Reading errors must propagate before authority, effects, or cache hits.
pub trait Clock: Send + Sync {
    fn read(&self) -> Result<ClockReading, ClockError>;
    fn unix_millis(&self) -> Result<UnixMillis, ClockError> {
        self.read().map(ClockReading::unix_millis)
    }
    fn monotonic(&self) -> Result<MonotonicInstant, ClockError> {
        self.read().map(ClockReading::monotonic)
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn read(&self) -> Result<ClockReading, ClockError> {
        (**self).read()
    }
}

/// Fixed, injected time for portable evaluation. Monotonic time stays at zero.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(Result<UnixMillis, ClockError>);
impl FixedClock {
    #[must_use]
    pub const fn new(unix_seconds: u64) -> Self {
        Self(UnixMillis::from_secs(unix_seconds))
    }
    #[must_use]
    pub const fn from_millis(unix_millis: u64) -> Self {
        Self(Ok(UnixMillis::new(unix_millis)))
    }
}
impl Clock for FixedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.0
            .map(|unix| ClockReading::new(unix, MonotonicInstant::from_nanos(0)))
    }
}

/// High-water fence shared by native and deterministic clock adapters.
#[derive(Default, Debug)]
pub struct ClockFence(Option<ClockReading>);
impl ClockFence {
    pub fn observe(&mut self, next: ClockReading) -> Result<ClockReading, ClockError> {
        if let Some(previous) = self.0 {
            if next.unix_millis < previous.unix_millis {
                return Err(ClockError::WallClockRegression);
            }
            if next.monotonic < previous.monotonic {
                return Err(ClockError::MonotonicRegression);
            }
        }
        self.0 = Some(next);
        Ok(next)
    }
}

/// A signed epoch deadline capped once by a local monotonic deadline.
/// Reusing this value for retries cannot extend the original authority window.
#[derive(Clone, Copy, Debug)]
pub struct AuthorityDeadline {
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    observed: ClockReading,
    monotonic_deadline: MonotonicInstant,
}
impl AuthorityDeadline {
    pub fn for_timeout_ms(now: ClockReading, timeout_ms: u64) -> Result<Self, ClockError> {
        Self::new(
            now.unix_millis,
            now.unix_millis.checked_add(timeout_ms)?,
            now,
        )
    }
    #[must_use]
    pub const fn monotonic_deadline(&self) -> MonotonicInstant {
        self.monotonic_deadline
    }
    pub fn new(
        issued_at: UnixMillis,
        expires_at: UnixMillis,
        now: ClockReading,
    ) -> Result<Self, ClockError> {
        if issued_at >= expires_at {
            return Err(ClockError::InvalidWindow);
        }
        if now.unix_millis < issued_at {
            return Err(ClockError::NotYetValid);
        }
        let remaining = expires_at
            .duration_since(now.unix_millis)
            .map_err(|_| ClockError::Expired)?;
        if remaining == 0 {
            return Err(ClockError::Expired);
        }
        Ok(Self {
            issued_at,
            expires_at,
            observed: now,
            monotonic_deadline: now.monotonic.checked_add_millis(remaining)?,
        })
    }
    pub fn remaining(&mut self, now: ClockReading) -> Result<Duration, ClockError> {
        self.remaining_nanos(now).map(Duration::from_nanos)
    }
    /// Checked scalar boundary shared by local I/O and the full-width proof.
    pub fn remaining_nanos(&mut self, now: ClockReading) -> Result<u64, ClockError> {
        if now.unix_millis < self.observed.unix_millis {
            return Err(ClockError::WallClockRegression);
        }
        if now.monotonic < self.observed.monotonic {
            return Err(ClockError::MonotonicRegression);
        }
        self.observed = now;
        if now.unix_millis < self.issued_at {
            return Err(ClockError::NotYetValid);
        }
        let wall = self
            .expires_at
            .duration_since(now.unix_millis)
            .map_err(|_| ClockError::Expired)?;
        let mono = self
            .monotonic_deadline
            .0
            .checked_sub(now.monotonic.0)
            .ok_or(ClockError::Expired)?;
        let remaining = core::cmp::min(
            wall.checked_mul(1_000_000).ok_or(ClockError::Overflow)?,
            mono,
        );
        if remaining == 0 {
            Err(ClockError::Expired)
        } else {
            Ok(remaining)
        }
    }
}

/// Bound future-issued signed evidence without widening an expiry deadline.
pub fn validate_future_skew(
    observed: UnixMillis,
    now: UnixMillis,
    maximum_skew_ms: u64,
) -> Result<(), ClockError> {
    if observed > now.checked_add(maximum_skew_ms)? {
        Err(ClockError::NotYetValid)
    } else {
        Ok(())
    }
}

#[cfg(feature = "std")]
mod system;
#[cfg(feature = "std")]
pub use system::SystemClock;
#[cfg(test)]
mod tests;
