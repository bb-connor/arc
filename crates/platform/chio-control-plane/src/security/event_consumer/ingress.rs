


use super::SecurityEventIngress;
use super::CorrelationIngressStore;
use super::PortError;
use super::PortResult;
use super::SecurityEventVerifierPort;
use super::UnverifiedSecurityEvent;
use super::SecurityEventVerificationRecord;


use super::SqliteSecurityStateStore;
use super::Arc;
use super::Instant;

use super::CorrelationConsumerReport;
use super::ProductionCorrelationConsumer;






use super::AttestedFindingResponseRecoveryLimits;
use super::NativeSecurityEventVerifier;


/// Production adapter that publishes the complete ordered finding batch and a
/// durable response outbox. Batch bindings reserve planning identities only.
/// The kernel later derives the one authoritative execution dispatch identity.
pub struct VerifiedSecurityEventIngress {
    verifier: Arc<NativeSecurityEventVerifier>,
    store: Arc<SqliteSecurityStateStore>,
}

impl VerifiedSecurityEventIngress {
    pub fn new(
        verifier: Arc<NativeSecurityEventVerifier>,
        store: Arc<SqliteSecurityStateStore>,
    ) -> PortResult<Self> {
        verifier.ensure_ready()?;
        store.ensure_correlation_ingress_ready()?;
        Ok(Self { verifier, store })
    }
}

impl SecurityEventIngress for VerifiedSecurityEventIngress {
    fn verify_and_append(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<chio_security_types::ports::EventAppend> {
        let verified = SecurityEventVerifierPort::verify(self.verifier.as_ref(), event)?;
        self.store
            .enqueue_verified_correlation_event(event, &verified)
    }
}

/// Durable delivery loop from the authenticated ingress ledger into temporal
/// correlation. The source envelope is reverified on every recovery attempt;
/// acknowledgement happens only after correlation evidence and response work
/// have been durably read back by `ProductionCorrelationConsumer`.
pub(crate) struct DurableCorrelationIngress {
    store: Arc<dyn CorrelationIngressStore>,
    consumer: Arc<ProductionCorrelationConsumer>,
}

impl DurableCorrelationIngress {
    pub(crate) fn new(
        store: Arc<dyn CorrelationIngressStore>,
        consumer: Arc<ProductionCorrelationConsumer>,
    ) -> PortResult<Self> {
        store.ensure_correlation_ingress_ready()?;
        Ok(Self { store, consumer })
    }

    pub(crate) fn ensure_ready(&self) -> PortResult<()> {
        self.store.ensure_correlation_ingress_ready()
    }

    pub(crate) fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<CorrelationConsumerReport> {
        let verified = self.consumer.verify_live(event)?;
        self.store
            .enqueue_verified_correlation_event(event, &verified)?;
        let consumed = self.consumer.consume_verified(&verified)?;
        if consumed.finalized {
            self.store.acknowledge_correlated_event(event)?;
        }
        Ok(consumed.report)
    }

    pub(crate) fn drain_once(&self, max_results: u32) -> PortResult<u32> {
        let pending = self.store.load_pending_correlation_events(max_results)?;
        let mut acknowledged = 0_u32;
        for event in pending.as_slice() {
            let verified = self.consumer.verify_durable(event)?;
            self.store
                .validate_pending_correlation_event(event, &verified)?;
            let consumed = self.consumer.consume_verified(&verified)?;
            if consumed.finalized {
                self.store.acknowledge_correlated_event(event)?;
                acknowledged = acknowledged
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
        }
        Ok(acknowledged)
    }

    pub(crate) fn drain_until_empty(
        &self,
        limits: AttestedFindingResponseRecoveryLimits,
    ) -> PortResult<u64> {
        let started = Instant::now();
        let mut acknowledged = 0_u64;
        while acknowledged < limits.max_startup_records {
            if u64::try_from(started.elapsed().as_millis())
                .map_or(true, |elapsed| elapsed > limits.max_startup_wall_clock_ms)
            {
                return Err(PortError::unavailable());
            }
            let remaining = limits.max_startup_records.saturating_sub(acknowledged);
            let max_results = u64::from(limits.max_records_per_pass)
                .min(remaining)
                .try_into()
                .map_err(|_| PortError::integrity_failure())?;
            let drained = self.drain_once(max_results)?;
            acknowledged = acknowledged
                .checked_add(u64::from(drained))
                .ok_or_else(PortError::integrity_failure)?;
            let pending = self.store.count_pending_correlation_events()?;
            if pending == 0 {
                return Ok(acknowledged);
            }
            if drained == 0 {
                // A bounded-lateness tail remains durably pending until the
                // worker clock advances its idle watermark.
                return Ok(acknowledged);
            }
        }
        if self.store.count_pending_correlation_events()? == 0 {
            Ok(acknowledged)
        } else {
            Err(PortError::unavailable())
        }
    }
}

pub(super) trait CorrelationEventVerifier: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn now_unix_ms(&self) -> PortResult<u64>;
    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventVerificationRecord>;
    fn verify_durable(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventVerificationRecord>;
}
