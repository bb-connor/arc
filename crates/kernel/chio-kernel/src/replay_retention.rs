//! Replay retention in the shared clock's epoch and monotonic domains.
use crate::{KernelError, ReplayClockDirection};
use chio_security_types::clock::{
    ClockError, ClockReading, MonotonicInstant, UnixMillis, MAX_REPLAY_WALL_SKEW_SECS,
};
use std::time::Duration;

const MAX_REPLAY_CLOCK_SKEW: Duration = Duration::from_secs(MAX_REPLAY_WALL_SKEW_SECS as u64);
const REBASELINE_CONFIRMATION: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct PendingRebaseline {
    observed: ClockReading,
    unexplained_gap: Duration,
}

/// Each owner samples under its mutation lock. A refused jump may record a
/// pending observation, but cannot advance the pruning horizon.
#[derive(Clone, Default)]
pub(crate) struct ReplayClock {
    high_water: Option<ClockReading>,
    pending: Option<PendingRebaseline>,
}
impl ReplayClock {
    pub(crate) fn high_water(&self) -> Result<ClockReading, KernelError> {
        self.high_water.ok_or(ClockError::Unavailable.into())
    }
    pub(crate) fn validate(
        &self,
        store: &'static str,
        now: ClockReading,
    ) -> Result<(), KernelError> {
        if let Some(pending) = self.pending {
            return Err(jump(store, pending.observed, self.high_water()?));
        }
        self.clone().observe(store, now).map(|_| ())
    }
    pub(crate) fn observe(
        &mut self,
        store: &'static str,
        now: ClockReading,
    ) -> Result<ClockReading, KernelError> {
        if let Some(previous) = self.high_water {
            let monotonic_progress = now.monotonic().duration_since(previous.monotonic())?;
            let wall_progress =
                Duration::from_millis(now.unix_millis().duration_since(previous.unix_millis())?);
            let tolerated = monotonic_progress
                .checked_add(MAX_REPLAY_CLOCK_SKEW)
                .ok_or(ClockError::Overflow)?;
            if wall_progress > tolerated {
                let gap = wall_progress
                    .checked_sub(monotonic_progress)
                    .ok_or(ClockError::Overflow)?;
                if let Some(pending) = self.pending {
                    let mono = now
                        .monotonic()
                        .duration_since(pending.observed.monotonic())?;
                    if let Ok(wall) = now
                        .unix_millis()
                        .duration_since(pending.observed.unix_millis())
                    {
                        let wall = Duration::from_millis(wall);
                        if wall.abs_diff(mono) <= REBASELINE_CONFIRMATION
                            && gap.abs_diff(pending.unexplained_gap) <= REBASELINE_CONFIRMATION
                        {
                            if mono >= REBASELINE_CONFIRMATION {
                                self.high_water = Some(now);
                                self.pending = None;
                                return Ok(now);
                            }
                            return Err(jump(store, now, previous));
                        }
                    }
                }
                self.pending = Some(PendingRebaseline {
                    observed: now,
                    unexplained_gap: gap,
                });
                return Err(jump(store, now, previous));
            }
        }
        self.pending = None;
        self.high_water = Some(now);
        Ok(now)
    }
}
fn jump(store: &'static str, now: ClockReading, previous: ClockReading) -> KernelError {
    KernelError::ReplayClockAnomaly {
        store,
        direction: ReplayClockDirection::ForwardJump,
        // UnixMillis::as_secs fits i64 for its full u64 millisecond domain.
        observed_unix_secs: now.unix_millis().as_secs() as i64,
        high_water_unix_secs: previous.unix_millis().as_secs() as i64,
        max_tolerated_skew_secs: u64::from(MAX_REPLAY_WALL_SKEW_SECS),
    }
}

/// Input horizon. Projection is performed once, under the reservation lock.
#[derive(Clone, Copy)]
pub(crate) enum ReplayHorizon {
    Local(Duration),
    Until(u64),
    Through(u64),
}

/// A signed marker is reclaimable only after BOTH original deadlines. An
/// unrepresentable retention horizon is indefinite custody, never permission.
#[derive(Clone, Copy)]
pub(crate) enum ReplayRetention {
    Local {
        monotonic_deadline: Option<MonotonicInstant>,
    },
    Signed {
        absolute_deadline: Option<UnixMillis>,
        monotonic_deadline: Option<MonotonicInstant>,
    },
}
impl ReplayHorizon {
    pub(crate) fn project(self, now: ClockReading) -> ReplayRetention {
        match self {
            Self::Local(ttl) => ReplayRetention::Local {
                monotonic_deadline: now.monotonic().checked_add(ttl).ok(),
            },
            Self::Until(secs) => {
                ReplayRetention::signed_until_at(UnixMillis::from_secs(secs).ok(), now)
            }
            Self::Through(secs) => ReplayRetention::signed_until_at(
                secs.checked_add(1)
                    .and_then(|s| UnixMillis::from_secs(s).ok()),
                now,
            ),
        }
    }
}
impl ReplayRetention {
    pub(crate) fn signed_until_at(
        absolute_deadline: Option<UnixMillis>,
        now: ClockReading,
    ) -> Self {
        let monotonic_deadline = absolute_deadline.and_then(|deadline| {
            // Already elapsed authority gets a zero remaining retention span.
            let remaining = if deadline <= now.unix_millis() {
                0
            } else {
                deadline.get() - now.unix_millis().get()
            };
            now.monotonic().checked_add_millis(remaining).ok()
        });
        Self::Signed {
            absolute_deadline,
            monotonic_deadline,
        }
    }
    pub(crate) fn signed_horizon_elapsed_at(&self, now: UnixMillis) -> bool {
        matches!(self, Self::Signed { absolute_deadline: Some(deadline), .. } if now >= *deadline)
    }
    pub(crate) fn is_expired_at(&self, now: ClockReading) -> bool {
        match self {
            Self::Local { monotonic_deadline } => {
                monotonic_deadline.is_some_and(|deadline| now.monotonic() >= deadline)
            }
            Self::Signed {
                absolute_deadline,
                monotonic_deadline,
            } => {
                absolute_deadline.is_some_and(|deadline| now.unix_millis() >= deadline)
                    && monotonic_deadline.is_some_and(|deadline| now.monotonic() >= deadline)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests;
