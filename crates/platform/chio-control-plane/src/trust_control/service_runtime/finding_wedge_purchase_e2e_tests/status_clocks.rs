use super::*;
use chio_security_types::clock as trusted_time;

pub(super) struct FixedStatusAdmissionClock(pub(super) u64);

impl trusted_time::Clock for FixedStatusAdmissionClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.0;
        trusted_time::Clock::read(&trusted_time::FixedClock::new(value))
    }
}

pub(super) struct FinalBoundaryStatusAdmissionClock {
    pub(super) fresh_now: u64,
    pub(super) final_now: u64,
    pub(super) calls: AtomicU64,
}

impl trusted_time::Clock for FinalBoundaryStatusAdmissionClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.fresh_now
        } else {
            self.final_now
        };
        trusted_time::Clock::read(&trusted_time::FixedClock::new(value))
    }
}

pub(super) struct FinalBoundaryRetractionClock {
    pub(super) fresh_now: u64,
    pub(super) final_now: u64,
    pub(super) calls: AtomicU64,
}

impl trusted_time::Clock for FinalBoundaryRetractionClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
            self.fresh_now
        } else {
            self.final_now
        };
        trusted_time::Clock::read(&trusted_time::FixedClock::new(value))
    }
}

pub(super) struct RetractionBeforeCacheReleaseClock {
    pub(super) now: u64,
    pub(super) calls: AtomicU64,
    pub(super) store: SqliteFindingStatusStore,
    pub(super) feed_id: String,
    pub(super) operator_id: String,
    pub(super) finding_id: String,
    pub(super) intent_id: String,
    pub(super) intent_bytes: Vec<u8>,
    pub(super) inclusion_deadline: u64,
}

impl trusted_time::Clock for RetractionBeforeCacheReleaseClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value: Result<u64, chio_guards::finding_retraction::FindingRetractionResolveError> =
            (|| {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 2 {
                    self.store
                .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                    intent_id: &self.intent_id,
                    feed_id: &self.feed_id,
                    operator_id: &self.operator_id,
                    finding_id: &self.finding_id,
                    source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                    intent_bytes: &self.intent_bytes,
                    issued_at: self.now,
                    inclusion_deadline: self.inclusion_deadline,
                    created_at: self.now,
                })
                .map_err(|error| {
                    chio_guards::finding_retraction::FindingRetractionResolveError::ClockUnavailable(
                        error.to_string(),
                    )
                })?;
                }
                Ok(self.now)
            })();
        let value = value.map_err(|_| trusted_time::ClockError::Unavailable)?;
        trusted_time::Clock::read(&trusted_time::FixedClock::new(value))
    }
}

pub(super) struct RetractionOnRefreshClock {
    pub(super) now: u64,
    pub(super) calls: AtomicU64,
    pub(super) fire_on_call: u64,
    pub(super) store: SqliteFindingStatusStore,
    pub(super) feed_id: String,
    pub(super) operator_id: String,
    pub(super) finding_id: String,
    pub(super) intent_id: String,
    pub(super) intent_bytes: Vec<u8>,
    pub(super) inclusion_deadline: u64,
}

impl trusted_time::Clock for RetractionOnRefreshClock {
    fn read(&self) -> core::result::Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value: Result<u64, String> = (|| {
            if self.calls.fetch_add(1, Ordering::SeqCst) == self.fire_on_call {
                self.store
                    .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                        intent_id: &self.intent_id,
                        feed_id: &self.feed_id,
                        operator_id: &self.operator_id,
                        finding_id: &self.finding_id,
                        source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                        intent_bytes: &self.intent_bytes,
                        issued_at: self.now,
                        inclusion_deadline: self.inclusion_deadline,
                        created_at: self.now,
                    })
                    .map_err(|error| error.to_string())?;
            }
            Ok(self.now)
        })();
        let value = value.map_err(|_| trusted_time::ClockError::Unavailable)?;
        trusted_time::Clock::read(&trusted_time::FixedClock::new(value))
    }
}
