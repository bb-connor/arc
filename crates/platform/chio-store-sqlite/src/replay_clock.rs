use std::sync::{Arc, Mutex};

use chio_kernel::ReplayClockDirection;
use chio_security_types::clock::{Clock, ClockError, ClockFence, ClockReading, MonotonicInstant};

const MIN_REBASELINE_CONFIRMATION_SECS: u64 = 1;
const MAX_REBASELINE_DRIFT_SECS: u64 = 1;

#[derive(Debug)]
pub(crate) enum ReplayClockValidationError {
    Clock(ClockError),
    Anomaly {
        direction: ReplayClockDirection,
        observed: i64,
        high_water: i64,
    },
}
impl From<ClockError> for ReplayClockValidationError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

/// Trusted clock plus the durable replay-retention skew policy. Caller-supplied
/// observations may lag a serialized writer; the clock itself may not regress.
pub(crate) struct StableReplayClock {
    clock: Arc<dyn Clock>,
    state: Mutex<StableReplayClockState>,
    max_skew_secs: i64,
}

struct StableReplayClockState {
    anchor_wall: i64,
    anchor_monotonic: MonotonicInstant,
    fence: ClockFence,
    pending_rebaseline: Option<PendingReplayClockRebaseline>,
}

#[derive(Clone, Copy)]
struct PendingReplayClockRebaseline {
    observed_wall: i64,
    observed_monotonic: MonotonicInstant,
    unexplained_gap_secs: i64,
}

enum RebaselineConfirmation {
    Confirmed,
    Waiting,
    Inconsistent,
}

impl StableReplayClock {
    pub(crate) fn new(clock: Arc<dyn Clock>, max_skew_secs: i64) -> Result<Self, ClockError> {
        if max_skew_secs < 0 {
            return Err(ClockError::InvalidWindow);
        }
        let mut fence = ClockFence::default();
        let reading = fence.observe(clock.read()?)?;
        let anchor_wall = unix_seconds(reading)?;
        anchor_wall
            .checked_add(max_skew_secs)
            .ok_or(ClockError::Overflow)?;
        Ok(Self {
            clock,
            state: Mutex::new(StableReplayClockState {
                anchor_wall,
                anchor_monotonic: reading.monotonic(),
                fence,
                pending_rebaseline: None,
            }),
            max_skew_secs,
        })
    }

    pub(crate) fn now_secs(&self) -> Result<i64, ClockError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        unix_seconds(state.fence.observe(self.clock.read()?)?)
    }

    pub(crate) fn validate_persisted(
        &self,
        high_water: i64,
    ) -> Result<(), ReplayClockValidationError> {
        let expected = self.expected_wall_now()?;
        let maximum = expected
            .checked_add(self.max_skew_secs)
            .ok_or(ClockError::Overflow)?;
        if high_water < 0 {
            return Err(ClockError::BeforeEpoch.into());
        }
        if high_water > maximum {
            return Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::Rollback,
                observed: expected,
                high_water,
            });
        }
        Ok(())
    }

    pub(crate) fn expected_wall_now(&self) -> Result<i64, ReplayClockValidationError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        let reading = state.fence.observe(self.clock.read()?)?;
        Ok(expected_wall_now(&state, reading.monotonic())?)
    }

    pub(crate) fn validate_observed(
        &self,
        observed: i64,
        durable_high_water: i64,
    ) -> Result<(), ReplayClockValidationError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        let reading = state.fence.observe(self.clock.read()?)?;
        let sample_monotonic = reading.monotonic();
        if observed < 0 || durable_high_water < 0 {
            return Err(ClockError::BeforeEpoch.into());
        }
        let expected = expected_wall_now(&state, sample_monotonic)?;
        let upper = expected
            .checked_add(self.max_skew_secs)
            .ok_or(ClockError::Overflow)?;
        // Negative lower bounds are valid: Unix epoch observations within skew
        // remain representable in the signed SQLite domain.
        let lower = expected
            .checked_sub(self.max_skew_secs)
            .ok_or(ClockError::Overflow)?;
        let durable_lower = durable_high_water
            .checked_sub(self.max_skew_secs)
            .ok_or(ClockError::Overflow)?;
        // Do not publish a rebaseline before the durable bound also accepts it.
        if observed < durable_lower || observed < lower {
            state.pending_rebaseline = None;
            return Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::Rollback,
                observed,
                high_water: if observed < durable_lower {
                    durable_high_water
                } else {
                    expected
                },
            });
        }
        if observed > upper {
            let gap = observed.checked_sub(expected).ok_or(ClockError::Overflow)?;
            let confirmation = state
                .pending_rebaseline
                .map(|pending| rebaseline_confirmation(pending, observed, sample_monotonic, gap))
                .transpose()?;
            match confirmation {
                Some(RebaselineConfirmation::Confirmed) => {
                    state.anchor_wall = observed;
                    state.anchor_monotonic = sample_monotonic;
                    state.pending_rebaseline = None;
                }
                Some(RebaselineConfirmation::Waiting) => {
                    return Err(ReplayClockValidationError::Anomaly {
                        direction: ReplayClockDirection::ForwardJump,
                        observed,
                        high_water: expected,
                    });
                }
                Some(RebaselineConfirmation::Inconsistent) | None => {
                    state.pending_rebaseline = Some(PendingReplayClockRebaseline {
                        observed_wall: observed,
                        observed_monotonic: sample_monotonic,
                        unexplained_gap_secs: gap,
                    });
                    return Err(ReplayClockValidationError::Anomaly {
                        direction: ReplayClockDirection::ForwardJump,
                        observed,
                        high_water: expected,
                    });
                }
            }
        } else {
            state.pending_rebaseline = None;
        }
        Ok(())
    }
}

fn unix_seconds(reading: ClockReading) -> Result<i64, ClockError> {
    i64::try_from(reading.unix_millis().as_secs()).map_err(|_| ClockError::Overflow)
}

fn expected_wall_now(
    state: &StableReplayClockState,
    monotonic: MonotonicInstant,
) -> Result<i64, ClockError> {
    let elapsed = i64::try_from(monotonic.duration_since(state.anchor_monotonic)?.as_secs())
        .map_err(|_| ClockError::Overflow)?;
    state
        .anchor_wall
        .checked_add(elapsed)
        .ok_or(ClockError::Overflow)
}

fn rebaseline_confirmation(
    pending: PendingReplayClockRebaseline,
    observed_wall: i64,
    monotonic: MonotonicInstant,
    gap: i64,
) -> Result<RebaselineConfirmation, ClockError> {
    let monotonic_progress = monotonic
        .duration_since(pending.observed_monotonic)?
        .as_secs();
    let Some(wall_progress) = observed_wall
        .checked_sub(pending.observed_wall)
        .and_then(|p| u64::try_from(p).ok())
    else {
        return Ok(RebaselineConfirmation::Inconsistent);
    };
    if wall_progress.abs_diff(monotonic_progress) > MAX_REBASELINE_DRIFT_SECS
        || gap.abs_diff(pending.unexplained_gap_secs) > MAX_REBASELINE_DRIFT_SECS
    {
        return Ok(RebaselineConfirmation::Inconsistent);
    }
    Ok(if monotonic_progress < MIN_REBASELINE_CONFIRMATION_SECS {
        RebaselineConfirmation::Waiting
    } else {
        RebaselineConfirmation::Confirmed
    })
}

#[cfg(test)]
pub(crate) mod tests;
