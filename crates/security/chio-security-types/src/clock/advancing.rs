use super::{ClockError, ClockReading, MonotonicInstant};

/// Epoch time that advances at least as fast as its local monotonic clock.
///
/// A backward or stalled wall clock cannot extend an existing authority window.
/// Forward wall steps take effect immediately. Unavailable samples, monotonic
/// regression and overflow still deny the operation without changing the anchor.
/// This is an opt-in service policy; it does not change [`super::ClockFence`].
#[derive(Debug, Default)]
pub struct AdvancingClockFence(Option<Anchor>);

#[derive(Clone, Copy, Debug)]
struct Anchor {
    reading: ClockReading,
    last_monotonic: MonotonicInstant,
}

impl AdvancingClockFence {
    pub fn observe(&mut self, sample: ClockReading) -> Result<ClockReading, ClockError> {
        let Some(previous) = self.0 else {
            self.0 = Some(Anchor {
                reading: sample,
                last_monotonic: sample.monotonic(),
            });
            return Ok(sample);
        };
        sample.monotonic().duration_since(previous.last_monotonic)?;
        let elapsed = sample
            .monotonic()
            .duration_since(previous.reading.monotonic())?;
        let elapsed_millis =
            u64::try_from(elapsed.as_millis()).map_err(|_| ClockError::Overflow)?;
        let floor = previous.reading.unix_millis().checked_add(elapsed_millis)?;
        // Keep the original anchor during recovery, including equal millisecond
        // observations. Resetting it on every read would discard fractional time.
        let anchor = if sample.unix_millis() > floor {
            sample
        } else {
            previous.reading
        };
        let observed = ClockReading::new(sample.unix_millis().max(floor), sample.monotonic());
        self.0 = Some(Anchor {
            reading: anchor,
            last_monotonic: sample.monotonic(),
        });
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::UnixMillis;

    fn sample(wall: u64, nanos: u64) -> ClockReading {
        ClockReading::new(UnixMillis::new(wall), MonotonicInstant::from_nanos(nanos))
    }

    #[test]
    fn overflow_and_regression_cannot_replace_the_anchor() -> Result<(), ClockError> {
        let mut fence = AdvancingClockFence::default();
        fence.observe(sample(u64::MAX - 1, 1_000_000))?;
        assert_eq!(
            fence.observe(sample(0, 3_000_000)),
            Err(ClockError::Overflow)
        );
        assert_eq!(
            fence.observe(sample(0, 999_999)),
            Err(ClockError::MonotonicRegression)
        );
        assert_eq!(
            fence.observe(sample(0, 2_000_000))?.unix_millis().get(),
            u64::MAX
        );
        Ok(())
    }
}
