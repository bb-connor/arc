//! One fallible fenced clock for CLI authority observations in this process.
use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, SystemClock};
use std::sync::{LazyLock, Mutex};

static FENCE: LazyLock<Mutex<ClockFence>> = LazyLock::new(|| Mutex::new(ClockFence::default()));

fn observe(source: &dyn Clock, fence: &Mutex<ClockFence>) -> Result<ClockReading, ClockError> {
    let mut guard = fence.lock().map_err(|_| ClockError::Unavailable)?;
    guard.observe(source.read()?)
}

pub(crate) fn millis() -> Result<u64, crate::CliError> {
    observe(&SystemClock, &FENCE)
        .map(|reading| reading.unix_millis().get())
        .map_err(|source| {
            crate::CliError::with_source(&chio_errors::_generated::error_codes::CLI_OTHER, source)
        })
}

pub(crate) fn seconds() -> Result<u64, crate::CliError> {
    millis().map(|now| now / 1_000)
}

pub(crate) fn deadline(now: u64, lifetime: u64) -> Result<u64, crate::CliError> {
    now.checked_add(lifetime)
        .filter(|expiry| *expiry > now)
        .ok_or_else(|| crate::CliError::cli_other_error("authority lifetime is zero or overflows"))
}

pub(crate) fn seconds_or(value: Option<u64>) -> Result<u64, crate::CliError> {
    value.map_or_else(seconds, Ok)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_security_types::clock::{MonotonicInstant, UnixMillis};
    struct Fixed(Result<ClockReading, ClockError>);
    impl Clock for Fixed {
        fn read(&self) -> Result<ClockReading, ClockError> {
            self.0
        }
    }
    fn at(wall: u64, mono: u64) -> Fixed {
        Fixed(Ok(ClockReading::new(
            UnixMillis::new(wall),
            MonotonicInstant::from_nanos(mono),
        )))
    }
    #[test]
    fn clock_faults_never_mint_zero_or_reset_high_water() {
        let fence = Mutex::new(ClockFence::default());
        observe(&at(100, 100), &fence).unwrap();
        for fault in [
            ClockError::BeforeEpoch,
            ClockError::Unavailable,
            ClockError::Overflow,
        ] {
            assert_eq!(observe(&Fixed(Err(fault)), &fence), Err(fault));
        }
        assert_eq!(
            observe(&at(99, 101), &fence),
            Err(ClockError::WallClockRegression)
        );
        assert_eq!(
            observe(&at(101, 99), &fence),
            Err(ClockError::MonotonicRegression)
        );
        assert_eq!(
            observe(&at(101, 101), &fence).unwrap().unix_millis().get(),
            101
        );
    }
    #[test]
    fn deadline_checks_zero_overflow_and_exact_maximum() {
        assert_eq!(deadline(10, 2).unwrap(), 12);
        assert_eq!(deadline(u64::MAX - 1, 1).unwrap(), u64::MAX);
        assert!(deadline(10, 0).is_err());
        assert!(deadline(u64::MAX, 1).is_err());
        assert_eq!(seconds_or(Some(0)).unwrap(), 0);
    }
}
