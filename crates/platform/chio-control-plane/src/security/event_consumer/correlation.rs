

use super::AttestedCorrelationWriter;

use super::AuthoritativeCorrelatedFindingEvidence;
use super::CorrelationOutcome;
use super::CorrelationPolicy;
use super::CorrelationStatus;
use super::TemporalCorrelator;
use super::TemporalRule;
use super::AttestedFindingBatchKey;
use super::Digest32;
use super::EventPartitionScan;
use super::OpaqueReceiptRef;
use super::PortError;
use super::PortResult;
use super::RecordId;
use super::RuleId;
use super::SecurityEventStore;
#[cfg(test)]
use super::SecurityEventVerifierPort;
use super::TenantId;
use super::UnverifiedSecurityEvent;
use super::SecurityEventVerificationRecord;


use super::SecurityEventBody;
use super::SqliteSecurityStateStore;
use super::BTreeSet;
use super::Arc;
use super::AttestedFindingBatchPlanner;
use super::build_attested_finding_batch_publication;
use super::CorrelationEventVerifier;



use super::DurableAttestedFindingBatchPlanner;

use super::NativeSecurityEventVerifier;
use super::CorrelationConsumption;


pub(super) trait CorrelationPort: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn accepts_policy(&self, policy_version: &RecordId) -> bool;
    fn correlate(
        &self,
        event: &SecurityEventVerificationRecord,
        observed_at_unix_ms: u64,
    ) -> PortResult<Vec<RuleCorrelationOutcome>>;
}

pub(super) trait CorrelationAttestor: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    fn attest(
        &self,
        outcome: &CorrelationOutcome,
    ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>>;
}

impl CorrelationAttestor for AttestedCorrelationWriter {
    fn ensure_ready(&self) -> PortResult<()> {
        AttestedCorrelationWriter::ensure_ready(self)
    }

    fn attest(
        &self,
        outcome: &CorrelationOutcome,
    ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
        self.attest_outcome(outcome)
    }
}

pub(super) struct RuleCorrelationOutcome {
    rule_id: RuleId,
    outcome: CorrelationOutcome,
}

#[cfg(test)]
impl RuleCorrelationOutcome {
    pub(super) fn synthetic(rule_id: RuleId, outcome: CorrelationOutcome) -> Self {
        Self { rule_id, outcome }
    }
}

pub(super) fn correlation_delivery_error(outcome: &CorrelationOutcome) -> Option<PortError> {
    outcome
        .detector_health
        .iter()
        .find_map(|health| match health.kind {
            chio_security_types::DetectorHealthKind::StoreUnavailable
            | chio_security_types::DetectorHealthKind::TruncatedScan => {
                Some(PortError::unavailable())
            }
            chio_security_types::DetectorHealthKind::StoreConflict => Some(PortError::conflict()),
            chio_security_types::DetectorHealthKind::CorruptEvent
            | chio_security_types::DetectorHealthKind::CorruptState => {
                Some(PortError::integrity_failure())
            }
            chio_security_types::DetectorHealthKind::StateOverflow => None,
        })
}

pub(super) struct SqliteTemporalCorrelationPort {
    store: Arc<SqliteSecurityStateStore>,
    correlator: TemporalCorrelator<SqliteSecurityStateStore>,
    rules: Vec<TemporalRule>,
}

impl SqliteTemporalCorrelationPort {
    pub(super) fn new(
        store: Arc<SqliteSecurityStateStore>,
        policy: CorrelationPolicy,
        mut rules: Vec<TemporalRule>,
    ) -> PortResult<Self> {
        if rules.is_empty() {
            return Err(PortError::invalid_data());
        }
        rules.sort_by(|left, right| {
            (left.policy_version(), left.rule_id()).cmp(&(right.policy_version(), right.rule_id()))
        });
        if rules.array_windows::<2>().any(|pair| {
            pair[0].policy_version() == pair[1].policy_version()
                && pair[0].rule_id() == pair[1].rule_id()
        }) {
            return Err(PortError::invalid_data());
        }
        Ok(Self {
            store: Arc::clone(&store),
            correlator: TemporalCorrelator::new(store, policy),
            rules,
        })
    }
}

impl CorrelationPort for SqliteTemporalCorrelationPort {
    fn ensure_ready(&self) -> PortResult<()> {
        let tenant_id = TenantId::new("active-defense-readiness").map_err(PortError::from)?;
        let rule_id = RuleId::new("active-defense-readiness").map_err(PortError::from)?;
        self.store.scan_partition(&EventPartitionScan {
            tenant_id: tenant_id.clone(),
            rule_id: rule_id.clone(),
            partition_hash: Digest32::new([0_u8; 32]),
            after_event_time_unix_ms: None,
            after_event_id: None,
            through_event_time_unix_ms: 0,
            max_results: 1,
        })?;
        self.store
            .load_correlation_outcome(&chio_security_types::ports::CorrelationOutcomeKey {
                tenant_id,
                rule_id,
                event_id: chio_security_types::ports::EventId::new("active-defense-readiness")
                    .map_err(PortError::from)?,
            })
            .map(|_| ())
    }

    fn accepts_policy(&self, policy_version: &RecordId) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.policy_version() == policy_version)
    }

    fn correlate(
        &self,
        event: &SecurityEventVerificationRecord,
        observed_at_unix_ms: u64,
    ) -> PortResult<Vec<RuleCorrelationOutcome>> {
        let body: SecurityEventBody = chio_core::canonical::UntrustedJsonText::from_wire(event.canonical_body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::IntegrityFailure, error.code(), error))?;
        body.validate()
            .map_err(|_| PortError::integrity_failure())?;
        let mut outcomes = Vec::new();
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.policy_version() == &body.policy_version)
        {
            let outcome = match self.correlator.load_durable_outcome(rule, event)? {
                Some(outcome) => outcome,
                None => {
                    let attempted =
                        self.correlator
                            .ingest_observed_at(rule, event, observed_at_unix_ms);
                    self.correlator
                        .load_durable_outcome(rule, event)?
                        .unwrap_or(attempted)
                }
            };
            outcomes.push(RuleCorrelationOutcome {
                rule_id: rule.rule_id().clone(),
                outcome,
            });
        }
        if outcomes.is_empty() {
            return Err(PortError::integrity_failure());
        }
        Ok(outcomes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationRuleReport {
    pub rule_id: RuleId,
    pub status: CorrelationStatus,
    pub automatic_response_suppressed: bool,
    pub watermark_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationConsumerReport {
    pub event_id: chio_security_types::ports::EventId,
    pub rules: Vec<CorrelationRuleReport>,
    pub attested_finding_ids: Vec<OpaqueReceiptRef>,
}

pub struct ProductionCorrelationConsumer {
    verifier: Arc<dyn CorrelationEventVerifier>,
    correlation: Arc<dyn CorrelationPort>,
    attestor: Arc<dyn CorrelationAttestor>,
    planner: Arc<dyn AttestedFindingBatchPlanner>,
}

impl ProductionCorrelationConsumer {
    pub fn new(
        verifier: Arc<NativeSecurityEventVerifier>,
        security_store: Arc<SqliteSecurityStateStore>,
        correlation_policy: CorrelationPolicy,
        rules: Vec<TemporalRule>,
        attestor: Arc<AttestedCorrelationWriter>,
        planner: Arc<DurableAttestedFindingBatchPlanner>,
    ) -> PortResult<Self> {
        let rule_policy_versions: BTreeSet<_> = rules
            .iter()
            .map(|rule| rule.policy_version().clone())
            .collect();
        if verifier.max_future_skew_ms > correlation_policy.bounded_lateness_ms()
            || verifier
                .trusted
                .values()
                .any(|producer| !rule_policy_versions.contains(&producer.policy_version))
        {
            return Err(PortError::invalid_data());
        }
        let correlation = Arc::new(SqliteTemporalCorrelationPort::new(
            security_store,
            correlation_policy,
            rules,
        )?);
        let consumer = Self {
            verifier,
            correlation,
            attestor,
            planner,
        };
        consumer.ensure_bootstrap_ready()?;
        Ok(consumer)
    }

    #[cfg(test)]
    pub(super) fn from_parts(
        verifier: Arc<dyn CorrelationEventVerifier>,
        correlation: Arc<dyn CorrelationPort>,
        attestor: Arc<dyn CorrelationAttestor>,
        planner: Arc<dyn AttestedFindingBatchPlanner>,
    ) -> PortResult<Self> {
        let consumer = Self {
            verifier,
            correlation,
            attestor,
            planner,
        };
        consumer.ensure_ready()?;
        Ok(consumer)
    }

    pub(crate) fn ensure_bootstrap_ready(&self) -> PortResult<()> {
        self.verifier.ensure_ready()?;
        self.correlation.ensure_ready()?;
        self.attestor.ensure_ready()?;
        self.planner.ensure_bootstrap_ready()
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        self.verifier.ensure_ready()?;
        self.correlation.ensure_ready()?;
        self.attestor.ensure_ready()?;
        self.planner.ensure_ready()
    }

    #[cfg(test)]
    pub(super) fn consume(&self, event: &UnverifiedSecurityEvent) -> PortResult<CorrelationConsumerReport> {
        self.ensure_ready()?;
        let verified = self.verifier.verify(event)?;
        self.consume_verified_after_ready(&verified)
            .map(|consumed| consumed.report)
    }

    pub(super) fn verify_live(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventVerificationRecord> {
        let verified = self.verifier.verify(event)?;
        self.ensure_supported_policy(&verified)?;
        Ok(verified)
    }

    pub(super) fn verify_durable(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventVerificationRecord> {
        self.ensure_ready()?;
        let verified = self.verifier.verify_durable(event)?;
        self.ensure_supported_policy(&verified)?;
        Ok(verified)
    }

    fn ensure_supported_policy(&self, verified: &SecurityEventVerificationRecord) -> PortResult<()> {
        let body: SecurityEventBody = chio_core::canonical::UntrustedJsonText::from_wire(verified.canonical_body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::IntegrityFailure, error.code(), error))?;
        if self.correlation.accepts_policy(&body.policy_version) {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        }
    }

    pub(super) fn consume_verified(
        &self,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<CorrelationConsumption> {
        self.ensure_ready()?;
        self.consume_verified_after_ready(verified)
    }

    fn consume_verified_after_ready(
        &self,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<CorrelationConsumption> {
        let observed_at_unix_ms = self.verifier.now_unix_ms()?;
        let outcomes = self.correlation.correlate(verified, observed_at_unix_ms)?;
        let mut reports = Vec::with_capacity(outcomes.len());
        let mut authoritative = Vec::new();
        let mut evidence_ids = BTreeSet::new();
        let mut attested_finding_ids = Vec::new();
        let mut delivery_error = None;
        let mut finalized = true;
        for correlated in outcomes {
            let deferred = correlated.outcome.status == CorrelationStatus::Deferred;
            finalized &= !deferred;
            if delivery_error.is_none() {
                delivery_error = correlation_delivery_error(&correlated.outcome);
            }
            reports.push(CorrelationRuleReport {
                rule_id: correlated.rule_id,
                status: correlated.outcome.status,
                automatic_response_suppressed: correlated.outcome.automatic_response_suppressed,
                watermark_unix_ms: correlated.outcome.watermark_unix_ms,
            });
            if deferred {
                continue;
            }
            for finding in self.attestor.attest(&correlated.outcome)? {
                if !evidence_ids.insert(finding.evidence_id().clone()) {
                    return Err(PortError::integrity_failure());
                }
                attested_finding_ids.push(finding.evidence_id().clone());
                authoritative.push(finding);
            }
        }
        if let Some(error) = delivery_error {
            return Err(error);
        }
        if !authoritative.is_empty() {
            self.planner.publish_attested_batch(&authoritative)?;
            let expected = build_attested_finding_batch_publication(&authoritative)?;
            let persisted =
                self.planner
                    .load_published_attested_batch(&AttestedFindingBatchKey {
                        tenant_id: expected.body.tenant_id.clone(),
                        batch_id: expected.body.batch_id.clone(),
                    })?;
            if persisted != expected || persisted.body.bindings.len() != authoritative.len() {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(CorrelationConsumption {
            report: CorrelationConsumerReport {
                event_id: verified.event_id.clone(),
                rules: reports,
                attested_finding_ids,
            },
            finalized,
        })
    }
}

#[cfg(test)]
#[path = "tests/committed_correlation_outcome_survives_crash_before_attestation_and_reaches_outbox_once.rs"]
mod committed_correlation_outcome_survives_crash_before_attestation_and_reaches_outbox_once;
