use crate::rules::{GroupingKey, TemporalRule};
use chio_core_types::{canonical_json_bytes, sha256};
pub use chio_security_types::ports::CorrelationOutcomeStatus as CorrelationStatus;
use chio_security_types::ports::{
    CanonicalBody, CorrelationCasRequest, CorrelationEventAdmissionRequest,
    CorrelationEventIndexRequest, CorrelationOutcomeCommitRequest, CorrelationOutcomeKey,
    CorrelationOutcomePublication, CorrelationPartial, CorrelationPartitionKey, Digest32,
    EventAppend, EventId, EventPartitionScan, PortError, PortErrorKind, ProducerTrustClass,
    RecordId, SecurityEventStore, VerifiedSecurityEvent,
};
use chio_security_types::{
    CorrelatedFinding, CorrelatedFindingInput, DetectorGroupBindingEvidence,
    DetectorHealthEvidence, DetectorHealthKind, DetectorWatermarkEvidence, SecurityEventBody,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

const GROUP_HASH_DOMAIN: &[u8] = b"chio.temporal-group.v1\0";
const CAPACITY_KEY_DOMAIN: &[u8] = b"chio.temporal-capacity-key.v1\0";
const TRANSITION_ID_DOMAIN: &[u8] = b"chio.temporal-transition.v1\0";
const FINDING_ID_DOMAIN: &[u8] = b"chio.correlated-finding.v1\0";
const PARTITION_STATE_VERSION: u8 = 1;
const CAPACITY_STATE_VERSION: u8 = 1;
const CORRELATION_OUTCOME_JOURNAL_VERSION: u8 = 2;
const MAX_PORT_SCAN_EVENTS: u32 = 4_096;
const MAX_CAS_RETRIES: u8 = 32;
const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationOutcome {
    pub status: CorrelationStatus,
    pub findings: Vec<CorrelatedFinding>,
    pub detector_health: Vec<DetectorHealthEvidence>,
    pub automatic_response_suppressed: bool,
    pub watermark_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CorrelationOutcomeJournal {
    schema_version: u8,
    key: CorrelationOutcomeKey,
    partition_hash: Digest32,
    rule_version_hash: Digest32,
    event_body_hash: Digest32,
    event_evidence_hash: Digest32,
    outcome: CorrelationOutcome,
}

impl CorrelationOutcome {
    fn plain(status: CorrelationStatus, watermark_unix_ms: u64) -> Self {
        Self {
            status,
            findings: Vec::new(),
            detector_health: Vec::new(),
            automatic_response_suppressed: matches!(
                status,
                CorrelationStatus::AdvisoryOnly | CorrelationStatus::Suppressed
            ),
            watermark_unix_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationPolicy {
    bounded_lateness_ms: u64,
    max_scan_events: u32,
    cas_retries: u8,
    allow_verified_receipt: bool,
}

impl CorrelationPolicy {
    pub fn new(
        bounded_lateness_ms: u64,
        max_scan_events: u32,
        cas_retries: u8,
        allow_verified_receipt: bool,
    ) -> Result<Self, CorrelationError> {
        if max_scan_events == 0
            || max_scan_events > MAX_PORT_SCAN_EVENTS
            || cas_retries == 0
            || cas_retries > MAX_CAS_RETRIES
        {
            return Err(CorrelationError::InvalidPolicy);
        }
        Ok(Self {
            bounded_lateness_ms,
            max_scan_events,
            cas_retries,
            allow_verified_receipt,
        })
    }

    #[must_use]
    pub const fn bounded_lateness_ms(&self) -> u64 {
        self.bounded_lateness_ms
    }

    fn permits(self, trust_class: ProducerTrustClass) -> bool {
        match trust_class {
            ProducerTrustClass::InternalDetector => true,
            ProducerTrustClass::VerifiedReceipt => self.allow_verified_receipt,
        }
    }
}

pub struct TemporalCorrelator<S: SecurityEventStore + ?Sized> {
    store: Arc<S>,
    policy: CorrelationPolicy,
}

impl<S: SecurityEventStore + ?Sized> TemporalCorrelator<S> {
    #[must_use]
    pub const fn new(store: Arc<S>, policy: CorrelationPolicy) -> Self {
        Self { store, policy }
    }

    pub fn load_durable_outcome(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
    ) -> Result<Option<CorrelationOutcome>, PortError> {
        let key = CorrelationOutcomeKey {
            tenant_id: event.tenant_id.clone(),
            rule_id: rule.rule_id().clone(),
            event_id: event.event_id.clone(),
        };
        let body = parse_verified_event(event).map_err(|()| PortError::integrity_failure())?;
        let expected_partition_hash =
            group_hash(rule, &body).map_err(|()| PortError::integrity_failure())?;
        self.store
            .load_correlation_outcome(&key)?
            .map(|publication| {
                let journal: CorrelationOutcomeJournal =
                    serde_json::from_slice(publication.canonical_body.as_bytes())
                        .map_err(|_| PortError::integrity_failure())?;
                let canonical =
                    canonical_json_bytes(&journal).map_err(|_| PortError::integrity_failure())?;
                let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
                if canonical.as_slice() != publication.canonical_body.as_bytes()
                    || body_hash != publication.body_hash
                    || journal.schema_version != CORRELATION_OUTCOME_JOURNAL_VERSION
                    || journal.key != key
                    || journal.key != publication.key
                    || journal.partition_hash != expected_partition_hash
                    || journal.partition_hash != publication.partition_hash
                    || journal.outcome.status != publication.status
                    || journal.outcome.watermark_unix_ms != publication.watermark_unix_ms
                    || journal.rule_version_hash != rule.version_hash()
                    || journal.rule_version_hash != publication.rule_version_hash
                    || journal.event_body_hash != event.body_hash
                    || journal.event_body_hash != publication.event_body_hash
                    || journal.event_evidence_hash != event.evidence_hash
                    || journal.event_evidence_hash != publication.event_evidence_hash
                {
                    return Err(PortError::integrity_failure());
                }
                Ok(journal.outcome)
            })
            .transpose()
    }

    fn outcome_publication(
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        partition_hash: Digest32,
        outcome: &CorrelationOutcome,
    ) -> Result<CorrelationOutcomePublication, PortError> {
        let key = CorrelationOutcomeKey {
            tenant_id: event.tenant_id.clone(),
            rule_id: rule.rule_id().clone(),
            event_id: event.event_id.clone(),
        };
        let journal = CorrelationOutcomeJournal {
            schema_version: CORRELATION_OUTCOME_JOURNAL_VERSION,
            key: key.clone(),
            partition_hash,
            rule_version_hash: rule.version_hash(),
            event_body_hash: event.body_hash,
            event_evidence_hash: event.evidence_hash,
            outcome: outcome.clone(),
        };
        let (canonical_body, body_hash) =
            canonical_body_and_hash(&journal).map_err(|_| PortError::invalid_data())?;
        Ok(CorrelationOutcomePublication {
            key,
            partition_hash,
            status: outcome.status,
            watermark_unix_ms: outcome.watermark_unix_ms,
            rule_version_hash: rule.version_hash(),
            event_body_hash: event.body_hash,
            event_evidence_hash: event.evidence_hash,
            canonical_body,
            body_hash,
        })
    }

    fn finalize_plain_outcome(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        group_hash: Digest32,
        group_watermark: GroupWatermarkKnowledge,
        outcome: CorrelationOutcome,
    ) -> CorrelationOutcome {
        let publication = match Self::outcome_publication(rule, event, group_hash, &outcome) {
            Ok(publication) => publication,
            Err(error) => {
                return self.port_health_outcome(rule, event, group_hash, group_watermark, &error)
            }
        };
        match self.store.commit_correlation_outcome_only(&publication) {
            Ok(_) => outcome,
            Err(error) if error.kind() == PortErrorKind::Conflict => {
                match self.load_durable_outcome(rule, event) {
                    Ok(Some(_)) => outcome,
                    Ok(None) => {
                        self.port_health_outcome(rule, event, group_hash, group_watermark, &error)
                    }
                    Err(load_error) => self.port_health_outcome(
                        rule,
                        event,
                        group_hash,
                        group_watermark,
                        &load_error,
                    ),
                }
            }
            Err(error) => {
                self.port_health_outcome(rule, event, group_hash, group_watermark, &error)
            }
        }
    }

    pub fn ingest(&self, rule: &TemporalRule, event: &VerifiedSecurityEvent) -> CorrelationOutcome {
        self.ingest_with_idle_watermark(rule, event, None, event.received_at_unix_ms)
    }

    /// Admits an event durably, but defers its final outcome until either a
    /// later event or wall-clock idleness closes the bounded-lateness window.
    /// A deferred outcome is never written to the immutable outcome journal.
    #[must_use]
    pub fn ingest_observed_at(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        observed_at_unix_ms: u64,
    ) -> CorrelationOutcome {
        let idle_watermark_unix_ms =
            observed_at_unix_ms.saturating_sub(self.policy.bounded_lateness_ms);
        self.ingest_with_idle_watermark(
            rule,
            event,
            Some(idle_watermark_unix_ms),
            observed_at_unix_ms,
        )
    }

    fn ingest_with_idle_watermark(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        idle_watermark_unix_ms: Option<u64>,
        observed_at_unix_ms: u64,
    ) -> CorrelationOutcome {
        let body = match parse_verified_event(event) {
            Ok(body) => body,
            Err(()) => {
                return self.health_outcome(
                    rule,
                    event,
                    DetectorGroupBindingEvidence::Unresolved,
                    DetectorHealthKind::CorruptEvent,
                    DetectorWatermarkEvidence::Unknown,
                )
            }
        };
        if !self.policy.permits(event.trust_class) {
            return CorrelationOutcome::plain(CorrelationStatus::AdvisoryOnly, 0);
        }
        if &body.policy_version != rule.policy_version() {
            return CorrelationOutcome::plain(CorrelationStatus::Irrelevant, 0);
        }
        let group_hash = match group_hash(rule, &body) {
            Ok(hash) => hash,
            Err(()) => {
                return self.health_outcome(
                    rule,
                    event,
                    DetectorGroupBindingEvidence::Unresolved,
                    DetectorHealthKind::CorruptEvent,
                    DetectorWatermarkEvidence::Unknown,
                )
            }
        };
        if group_hash.as_bytes().iter().all(|byte| *byte == 0) {
            return self.health_outcome(
                rule,
                event,
                DetectorGroupBindingEvidence::Unresolved,
                DetectorHealthKind::CorruptEvent,
                DetectorWatermarkEvidence::Unknown,
            );
        }
        let key = CorrelationPartitionKey {
            tenant_id: event.tenant_id.clone(),
            rule_id: rule.rule_id().clone(),
            partition_hash: group_hash,
        };

        let index_transition = match transition_id(
            "index",
            &IndexTransition {
                tenant_id: event.tenant_id.as_str(),
                rule_id: rule.rule_id().as_str(),
                group_hash,
                event_id: event.event_id.as_str(),
            },
        ) {
            Ok(id) => id,
            Err(()) => {
                return self.known_health_outcome(
                    rule,
                    event,
                    group_hash,
                    DetectorHealthKind::CorruptState,
                    GroupWatermarkKnowledge::Unknown,
                )
            }
        };
        let index = CorrelationEventIndexRequest {
            key: key.clone(),
            event_id: event.event_id.clone(),
            transition_id: index_transition,
        };
        let mut last_group_watermark = GroupWatermarkKnowledge::Unknown;
        for _ in 0..self.policy.cas_retries {
            let initial = match self.store.load_correlation(&key) {
                Ok(partial) => partial,
                Err(error) => {
                    return self.port_health_outcome(
                        rule,
                        event,
                        group_hash,
                        last_group_watermark,
                        &error,
                    );
                }
            };
            if let Some(contradictory) =
                contradictory_stored_group_watermark(initial.as_ref(), observed_at_unix_ms)
            {
                return self.known_health_outcome(
                    rule,
                    event,
                    group_hash,
                    DetectorHealthKind::CorruptState,
                    contradictory,
                );
            }
            let initial_state = match initial.as_ref().map(load_partition_state).transpose() {
                Ok(state) => state,
                Err(()) => {
                    return self.known_health_outcome(
                        rule,
                        event,
                        group_hash,
                        DetectorHealthKind::CorruptState,
                        last_group_watermark,
                    )
                }
            };
            let group_watermark = match merge_validated_group_watermark(
                last_group_watermark,
                validated_group_watermark(initial.as_ref()),
            ) {
                ValidatedGroupWatermarkMerge::Accepted(knowledge) => knowledge,
                ValidatedGroupWatermarkMerge::Regression { retained } => {
                    return self.known_health_outcome(
                        rule,
                        event,
                        group_hash,
                        DetectorHealthKind::CorruptState,
                        retained,
                    )
                }
            };
            last_group_watermark = group_watermark;
            let watermark_unix_ms = group_watermark.as_legacy_unix_ms();
            if initial_state
                .as_ref()
                .is_some_and(|state| event.event_time_unix_ms <= state.watermark_unix_ms)
            {
                let append = match self.store.append_verified(event) {
                    Ok(append) => append,
                    Err(error) => {
                        return self.port_health_outcome(
                            rule,
                            event,
                            group_hash,
                            group_watermark,
                            &error,
                        )
                    }
                };
                let outcome = CorrelationOutcome::plain(
                    if append == EventAppend::Inserted {
                        CorrelationStatus::TooLate
                    } else {
                        CorrelationStatus::Duplicate
                    },
                    watermark_unix_ms,
                );
                return self.finalize_plain_outcome(
                    rule,
                    event,
                    group_hash,
                    group_watermark,
                    outcome,
                );
            }
            let capacity = match self.prepare_group_reservation(rule, event, group_hash) {
                CapacityReservation::Ready(capacity) => capacity.map(|request| *request),
                CapacityReservation::Overflow => {
                    return self.known_health_outcome(
                        rule,
                        event,
                        group_hash,
                        DetectorHealthKind::StateOverflow,
                        group_watermark,
                    );
                }
                CapacityReservation::Health(kind) => {
                    return self.known_health_outcome(
                        rule,
                        event,
                        group_hash,
                        kind,
                        group_watermark,
                    );
                }
            };
            match self
                .store
                .admit_verified_correlation_event(&CorrelationEventAdmissionRequest {
                    event: event.clone(),
                    index: index.clone(),
                    capacity,
                }) {
                Ok(admission) => {
                    return self.advance_partition(
                        rule,
                        event,
                        admission.append,
                        key,
                        PartitionAdvanceContext {
                            authoritative_group_watermark: group_watermark,
                            idle_watermark_unix_ms,
                            observed_at_unix_ms,
                        },
                    )
                }
                Err(error) if error.kind() == PortErrorKind::Conflict => continue,
                Err(error) => {
                    return self.port_health_outcome(
                        rule,
                        event,
                        group_hash,
                        group_watermark,
                        &error,
                    )
                }
            }
        }
        self.known_health_outcome(
            rule,
            event,
            group_hash,
            DetectorHealthKind::StoreConflict,
            last_group_watermark,
        )
    }

    fn advance_partition(
        &self,
        rule: &TemporalRule,
        trigger: &VerifiedSecurityEvent,
        append: EventAppend,
        key: CorrelationPartitionKey,
        context: PartitionAdvanceContext,
    ) -> CorrelationOutcome {
        let PartitionAdvanceContext {
            authoritative_group_watermark,
            idle_watermark_unix_ms,
            observed_at_unix_ms,
        } = context;
        let mut last_group_watermark = authoritative_group_watermark;
        for _ in 0..self.policy.cas_retries {
            let current = match self.store.load_correlation(&key) {
                Ok(partial) => partial,
                Err(error) => {
                    return self.port_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        last_group_watermark,
                        &error,
                    )
                }
            };
            if let Some(contradictory) =
                contradictory_stored_group_watermark(current.as_ref(), observed_at_unix_ms)
            {
                return self.known_health_outcome(
                    rule,
                    trigger,
                    key.partition_hash,
                    DetectorHealthKind::CorruptState,
                    contradictory,
                );
            }
            let mut state = match current.as_ref().map(load_partition_state).transpose() {
                Ok(Some(state)) => state,
                Ok(None) => PartitionState::empty(),
                Err(()) => {
                    return self.known_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        DetectorHealthKind::CorruptState,
                        last_group_watermark,
                    )
                }
            };
            let group_watermark = match merge_validated_group_watermark(
                last_group_watermark,
                validated_group_watermark(current.as_ref()),
            ) {
                ValidatedGroupWatermarkMerge::Accepted(knowledge) => knowledge,
                ValidatedGroupWatermarkMerge::Regression { retained } => {
                    return self.known_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        DetectorHealthKind::CorruptState,
                        retained,
                    )
                }
            };
            last_group_watermark = group_watermark;
            let indexed_max_seen_event_time =
                match self.store.load_correlation_max_seen_event_time(&key) {
                    Ok(max_seen) => max_seen.unwrap_or(0),
                    Err(error) => {
                        return self.port_health_outcome(
                            rule,
                            trigger,
                            key.partition_hash,
                            group_watermark,
                            &error,
                        )
                    }
                };
            if current.is_some() && trigger.event_time_unix_ms <= state.watermark_unix_ms {
                let status = if append == EventAppend::Duplicate {
                    CorrelationStatus::Duplicate
                } else {
                    CorrelationStatus::Accepted
                };
                let outcome = CorrelationOutcome::plain(status, state.watermark_unix_ms);
                return self.finalize_plain_outcome(
                    rule,
                    trigger,
                    key.partition_hash,
                    group_watermark,
                    outcome,
                );
            }
            state.max_seen_event_time_unix_ms = state
                .max_seen_event_time_unix_ms
                .max(indexed_max_seen_event_time)
                .max(trigger.event_time_unix_ms);
            let stream_watermark = state
                .max_seen_event_time_unix_ms
                .saturating_sub(self.policy.bounded_lateness_ms);
            let idle_watermark = idle_watermark_unix_ms
                .map(|watermark| watermark.min(state.max_seen_event_time_unix_ms))
                .unwrap_or(0);
            let next_watermark = stream_watermark
                .max(idle_watermark)
                .max(state.watermark_unix_ms);
            let next_group_watermark =
                GroupWatermarkKnowledge::committed(next_watermark, observed_at_unix_ms);
            if matches!(
                next_group_watermark,
                GroupWatermarkKnowledge::Contradictory { .. }
            ) {
                return self.known_health_outcome(
                    rule,
                    trigger,
                    key.partition_hash,
                    DetectorHealthKind::CorruptState,
                    next_group_watermark,
                );
            }
            if idle_watermark_unix_ms.is_some() && trigger.event_time_unix_ms > next_watermark {
                return CorrelationOutcome::plain(CorrelationStatus::Deferred, next_watermark);
            }
            let scan_request = EventPartitionScan {
                tenant_id: key.tenant_id.clone(),
                rule_id: key.rule_id.clone(),
                partition_hash: key.partition_hash,
                after_event_time_unix_ms: current.as_ref().map(|partial| partial.watermark_unix_ms),
                after_event_id: None,
                through_event_time_unix_ms: next_watermark,
                max_results: self.policy.max_scan_events,
            };
            let scan = match self.store.scan_partition(&scan_request) {
                Ok(scan) => scan,
                Err(error) => {
                    return self.port_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        group_watermark,
                        &error,
                    )
                }
            };
            if scan.truncated {
                return self.known_health_outcome(
                    rule,
                    trigger,
                    key.partition_hash,
                    DetectorHealthKind::TruncatedScan,
                    group_watermark,
                );
            }
            let process = match process_events(
                rule,
                &mut state,
                scan.events.as_slice(),
                key.partition_hash,
                next_watermark,
                self.policy.bounded_lateness_ms,
            ) {
                Ok(process) => process,
                Err(()) => {
                    return self.known_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        DetectorHealthKind::CorruptState,
                        group_watermark,
                    )
                }
            };
            state.watermark_unix_ms = next_watermark;
            let (canonical_body, body_hash) = match canonical_body_and_hash(&state) {
                Ok(value) => value,
                Err(()) => {
                    return self.known_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        DetectorHealthKind::CorruptState,
                        group_watermark,
                    )
                }
            };
            let generation = match current.as_ref() {
                Some(partial) => match partial.generation.checked_add(1) {
                    Some(generation) => generation,
                    None => {
                        return self.known_health_outcome(
                            rule,
                            trigger,
                            key.partition_hash,
                            DetectorHealthKind::CorruptState,
                            group_watermark,
                        )
                    }
                },
                None => 0,
            };
            let partial = CorrelationPartial {
                key: key.clone(),
                generation,
                watermark_unix_ms: next_watermark,
                expires_at_unix_ms: partition_expiry(rule, &state, self.policy.bounded_lateness_ms),
                canonical_body,
                body_hash,
            };
            let cas_transition = match transition_id(
                "partition",
                &PartitionTransition {
                    tenant_id: key.tenant_id.as_str(),
                    rule_id: key.rule_id.as_str(),
                    group_hash: key.partition_hash,
                    generation,
                    watermark_unix_ms: next_watermark,
                    body_hash,
                },
            ) {
                Ok(id) => id,
                Err(()) => {
                    return self.known_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        DetectorHealthKind::CorruptState,
                        group_watermark,
                    )
                }
            };
            let mut outcome = CorrelationOutcome::plain(
                if process.suppressed {
                    CorrelationStatus::Suppressed
                } else if process.findings.is_empty() {
                    CorrelationStatus::Accepted
                } else {
                    CorrelationStatus::Matched
                },
                next_watermark,
            );
            outcome.findings = process.findings;
            if process.overflow {
                outcome.detector_health.push(DetectorHealthEvidence {
                    tenant_id: trigger.tenant_id.clone(),
                    policy_version: rule.policy_version().clone(),
                    rule_id: rule.rule_id().clone(),
                    rule_version_hash: rule.version_hash(),
                    group_binding: detector_group_binding(key.partition_hash),
                    kind: DetectorHealthKind::StateOverflow,
                    event_id: trigger.event_id.clone(),
                    observed_at_unix_ms: trigger.received_at_unix_ms,
                    watermark: next_group_watermark.as_evidence(),
                });
                outcome.automatic_response_suppressed = true;
            }
            let publication =
                match Self::outcome_publication(rule, trigger, key.partition_hash, &outcome) {
                    Ok(publication) => publication,
                    Err(error) => {
                        return self.port_health_outcome(
                            rule,
                            trigger,
                            key.partition_hash,
                            group_watermark,
                            &error,
                        )
                    }
                };
            match self
                .store
                .commit_correlation_outcome(&CorrelationOutcomeCommitRequest {
                    correlation: CorrelationCasRequest {
                        scan: scan_request,
                        observed_partition_generation: scan.partition_generation,
                        partial,
                        expected_generation: current.as_ref().map(|partial| partial.generation),
                        transition_id: cas_transition,
                    },
                    outcome: publication,
                }) {
                Ok(_) => return outcome,
                Err(error) if error.kind() == PortErrorKind::Conflict => {
                    match self.load_durable_outcome(rule, trigger) {
                        Ok(Some(committed)) => {
                            return CorrelationOutcome::plain(
                                CorrelationStatus::Duplicate,
                                committed.watermark_unix_ms,
                            )
                        }
                        Ok(None) => continue,
                        Err(load_error) => {
                            return self.port_health_outcome(
                                rule,
                                trigger,
                                key.partition_hash,
                                group_watermark,
                                &load_error,
                            )
                        }
                    }
                }
                Err(error) => {
                    if let Ok(Some(committed)) = self.load_durable_outcome(rule, trigger) {
                        return committed;
                    }
                    return self.port_health_outcome(
                        rule,
                        trigger,
                        key.partition_hash,
                        group_watermark,
                        &error,
                    );
                }
            }
        }
        self.known_health_outcome(
            rule,
            trigger,
            key.partition_hash,
            DetectorHealthKind::StoreConflict,
            last_group_watermark,
        )
    }

    fn prepare_group_reservation(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        group_hash: Digest32,
    ) -> CapacityReservation {
        let key = match capacity_key(rule, event) {
            Ok(key) => key,
            Err(()) => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
        };
        let retention = match rule
            .maximum_window_ms()
            .checked_add(self.policy.bounded_lateness_ms)
        {
            Some(value) => value,
            None => return CapacityReservation::Overflow,
        };
        let expires_at = match event.event_time_unix_ms.checked_add(retention) {
            Some(value) => value,
            None => return CapacityReservation::Overflow,
        };
        let current = match self.store.load_correlation(&key) {
            Ok(partial) => partial,
            Err(error) => return CapacityReservation::Health(port_health_kind(&error)),
        };
        let mut state = match current.as_ref().map(load_capacity_state).transpose() {
            Ok(Some(state)) => state,
            Ok(None) => CapacityState::empty(rule.version_hash()),
            Err(()) => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
        };
        if state.rule_version_hash != rule.version_hash() {
            return CapacityReservation::Health(DetectorHealthKind::CorruptState);
        }
        if state.groups.len() > rule.max_groups() as usize {
            return CapacityReservation::Health(DetectorHealthKind::CorruptState);
        }
        let next_watermark = state.watermark_unix_ms.max(event.event_time_unix_ms);
        state
            .groups
            .retain(|entry| entry.expires_at_unix_ms >= next_watermark);
        if let Some(entry) = state
            .groups
            .iter_mut()
            .find(|entry| entry.group_hash == group_hash)
        {
            if entry.expires_at_unix_ms >= expires_at
                && state.watermark_unix_ms >= event.event_time_unix_ms
            {
                return CapacityReservation::Ready(None);
            }
            entry.expires_at_unix_ms = entry.expires_at_unix_ms.max(expires_at);
        } else {
            if state.groups.len() >= rule.max_groups() as usize {
                return CapacityReservation::Overflow;
            }
            state.groups.push(CapacityEntry {
                group_hash,
                expires_at_unix_ms: expires_at,
            });
        }
        state.groups.sort_by_key(|entry| entry.group_hash);
        state.watermark_unix_ms = next_watermark;
        let (canonical_body, body_hash) = match canonical_body_and_hash(&state) {
            Ok(value) => value,
            Err(()) => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
        };
        let generation = match current.as_ref() {
            Some(partial) => match partial.generation.checked_add(1) {
                Some(generation) => generation,
                None => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
            },
            None => 0,
        };
        let scan = EventPartitionScan {
            tenant_id: key.tenant_id.clone(),
            rule_id: key.rule_id.clone(),
            partition_hash: key.partition_hash,
            after_event_time_unix_ms: current.as_ref().map(|partial| partial.watermark_unix_ms),
            after_event_id: None,
            through_event_time_unix_ms: next_watermark,
            max_results: 1,
        };
        let observed = match self.store.scan_partition(&scan) {
            Ok(observed) if !observed.truncated && observed.events.is_empty() => observed,
            Ok(_) => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
            Err(error) => return CapacityReservation::Health(port_health_kind(&error)),
        };
        let transition = match transition_id(
            "capacity",
            &PartitionTransition {
                tenant_id: key.tenant_id.as_str(),
                rule_id: key.rule_id.as_str(),
                group_hash: key.partition_hash,
                generation,
                watermark_unix_ms: next_watermark,
                body_hash,
            },
        ) {
            Ok(id) => id,
            Err(()) => return CapacityReservation::Health(DetectorHealthKind::CorruptState),
        };
        let partial = CorrelationPartial {
            key: key.clone(),
            generation,
            watermark_unix_ms: next_watermark,
            expires_at_unix_ms: state
                .groups
                .iter()
                .map(|entry| entry.expires_at_unix_ms)
                .max()
                .unwrap_or(next_watermark),
            canonical_body,
            body_hash,
        };
        CapacityReservation::Ready(Some(Box::new(CorrelationCasRequest {
            scan,
            observed_partition_generation: observed.partition_generation,
            partial,
            expected_generation: current.as_ref().map(|partial| partial.generation),
            transition_id: transition,
        })))
    }

    fn port_health_outcome(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        group_hash: Digest32,
        watermark: GroupWatermarkKnowledge,
        error: &PortError,
    ) -> CorrelationOutcome {
        self.known_health_outcome(rule, event, group_hash, port_health_kind(error), watermark)
    }

    fn known_health_outcome(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        group_hash: Digest32,
        kind: DetectorHealthKind,
        watermark: GroupWatermarkKnowledge,
    ) -> CorrelationOutcome {
        let health_kind = if matches!(watermark, GroupWatermarkKnowledge::Contradictory { .. }) {
            DetectorHealthKind::CorruptState
        } else {
            kind
        };
        self.health_outcome(
            rule,
            event,
            detector_group_binding(group_hash),
            health_kind,
            watermark.as_evidence(),
        )
    }

    fn health_outcome(
        &self,
        rule: &TemporalRule,
        event: &VerifiedSecurityEvent,
        group_binding: DetectorGroupBindingEvidence,
        kind: DetectorHealthKind,
        watermark: DetectorWatermarkEvidence,
    ) -> CorrelationOutcome {
        let watermark_unix_ms = match &watermark {
            DetectorWatermarkEvidence::Unknown => 0,
            DetectorWatermarkEvidence::Committed { unix_ms } => *unix_ms,
            DetectorWatermarkEvidence::Contradictory { claimed_unix_ms } => {
                claimed_unix_ms.parse::<u64>().unwrap_or(u64::MAX)
            }
        };
        CorrelationOutcome {
            status: CorrelationStatus::Suppressed,
            findings: Vec::new(),
            detector_health: vec![DetectorHealthEvidence {
                tenant_id: event.tenant_id.clone(),
                policy_version: rule.policy_version().clone(),
                rule_id: rule.rule_id().clone(),
                rule_version_hash: rule.version_hash(),
                group_binding,
                kind,
                event_id: event.event_id.clone(),
                observed_at_unix_ms: event.received_at_unix_ms,
                watermark,
            }],
            automatic_response_suppressed: true,
            watermark_unix_ms,
        }
    }
}

fn detector_group_binding(group_key_hash: Digest32) -> DetectorGroupBindingEvidence {
    if group_key_hash.as_bytes().iter().all(|byte| *byte == 0) {
        DetectorGroupBindingEvidence::Unresolved
    } else {
        DetectorGroupBindingEvidence::Resolved { group_key_hash }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupWatermarkKnowledge {
    Unknown,
    Committed { unix_ms: u64 },
    Contradictory { unix_ms: u64 },
}

impl GroupWatermarkKnowledge {
    fn committed(unix_ms: u64, observed_at_unix_ms: u64) -> Self {
        if unix_ms == 0 || unix_ms > observed_at_unix_ms || unix_ms > MAX_JSON_SAFE_INTEGER {
            Self::Contradictory { unix_ms }
        } else {
            Self::Committed { unix_ms }
        }
    }

    fn as_evidence(self) -> DetectorWatermarkEvidence {
        match self {
            Self::Unknown => DetectorWatermarkEvidence::Unknown,
            Self::Committed { unix_ms } => DetectorWatermarkEvidence::Committed { unix_ms },
            Self::Contradictory { unix_ms } => DetectorWatermarkEvidence::Contradictory {
                claimed_unix_ms: unix_ms.to_string(),
            },
        }
    }

    const fn as_legacy_unix_ms(self) -> u64 {
        match self {
            Self::Committed { unix_ms } | Self::Contradictory { unix_ms } => unix_ms,
            Self::Unknown => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidatedGroupWatermarkMerge {
    Accepted(GroupWatermarkKnowledge),
    Regression { retained: GroupWatermarkKnowledge },
}

const fn merge_validated_group_watermark(
    previous: GroupWatermarkKnowledge,
    candidate: GroupWatermarkKnowledge,
) -> ValidatedGroupWatermarkMerge {
    match (previous, candidate) {
        (
            GroupWatermarkKnowledge::Committed { unix_ms: previous },
            GroupWatermarkKnowledge::Committed { unix_ms: candidate },
        ) if candidate < previous => ValidatedGroupWatermarkMerge::Regression {
            retained: GroupWatermarkKnowledge::Committed { unix_ms: previous },
        },
        (GroupWatermarkKnowledge::Committed { .. }, GroupWatermarkKnowledge::Unknown) => {
            ValidatedGroupWatermarkMerge::Accepted(previous)
        }
        (_, candidate) => ValidatedGroupWatermarkMerge::Accepted(candidate),
    }
}

fn contradictory_stored_group_watermark(
    partial: Option<&CorrelationPartial>,
    observed_at_unix_ms: u64,
) -> Option<GroupWatermarkKnowledge> {
    let claimed = partial?.watermark_unix_ms;
    (claimed == 0 || claimed > observed_at_unix_ms || claimed > MAX_JSON_SAFE_INTEGER)
        .then_some(GroupWatermarkKnowledge::Contradictory { unix_ms: claimed })
}

fn validated_group_watermark(partial: Option<&CorrelationPartial>) -> GroupWatermarkKnowledge {
    partial.map_or(GroupWatermarkKnowledge::Unknown, |partial| {
        GroupWatermarkKnowledge::Committed {
            unix_ms: partial.watermark_unix_ms,
        }
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PartitionState {
    schema_version: u8,
    max_seen_event_time_unix_ms: u64,
    watermark_unix_ms: u64,
    suppressed_until_unix_ms: Option<u64>,
    candidates: Vec<PartialCandidate>,
}

impl PartitionState {
    fn empty() -> Self {
        Self {
            schema_version: PARTITION_STATE_VERSION,
            max_seen_event_time_unix_ms: 0,
            watermark_unix_ms: 0,
            suppressed_until_unix_ms: None,
            candidates: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct PartialCandidate {
    stages: Vec<Option<StageContribution>>,
    lineage_seed: chio_security_types::ports::LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct StageContribution {
    event_id: EventId,
    evidence_digest: Digest32,
    source_receipt_id: chio_security_types::ports::OpaqueReceiptRef,
    event_time_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacityState {
    schema_version: u8,
    rule_version_hash: Digest32,
    watermark_unix_ms: u64,
    groups: Vec<CapacityEntry>,
}

impl CapacityState {
    fn empty(rule_version_hash: Digest32) -> Self {
        Self {
            schema_version: CAPACITY_STATE_VERSION,
            rule_version_hash,
            watermark_unix_ms: 0,
            groups: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacityEntry {
    group_hash: Digest32,
    expires_at_unix_ms: u64,
}

struct ProcessResult {
    findings: Vec<CorrelatedFinding>,
    overflow: bool,
    suppressed: bool,
}

struct PartitionAdvanceContext {
    authoritative_group_watermark: GroupWatermarkKnowledge,
    idle_watermark_unix_ms: Option<u64>,
    observed_at_unix_ms: u64,
}

enum CapacityReservation {
    Ready(Option<Box<CorrelationCasRequest>>),
    Overflow,
    Health(DetectorHealthKind),
}

fn process_events(
    rule: &TemporalRule,
    state: &mut PartitionState,
    events: &[VerifiedSecurityEvent],
    group_key_hash: Digest32,
    next_watermark: u64,
    bounded_lateness_ms: u64,
) -> Result<ProcessResult, ()> {
    if state.candidates.len() > rule.max_partial_matches_per_group() as usize
        || state
            .candidates
            .iter()
            .any(|candidate| !valid_candidate_shape(rule, candidate))
    {
        return Err(());
    }
    let ignored_through = state.suppressed_until_unix_ms;
    if ignored_through.is_some_and(|until| next_watermark > until) {
        state.suppressed_until_unix_ms = None;
    }
    if state.suppressed_until_unix_ms.is_some() {
        state.candidates.clear();
        return Ok(ProcessResult {
            findings: Vec::new(),
            overflow: false,
            suppressed: true,
        });
    }

    let mut ordered_events = events.to_vec();
    ordered_events.sort_by(|left, right| {
        left.event_time_unix_ms
            .cmp(&right.event_time_unix_ms)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let mut findings = BTreeMap::<String, CorrelatedFinding>::new();
    for event in &ordered_events {
        if ignored_through.is_some_and(|until| event.event_time_unix_ms <= until) {
            continue;
        }
        let body = parse_verified_event(event)?;
        if &body.policy_version != rule.policy_version()
            || group_hash(rule, &body)? != group_key_hash
        {
            return Err(());
        }
        let mut retained = Vec::with_capacity(state.candidates.len());
        for candidate in state.candidates.drain(..) {
            if candidate_deadline(rule, &candidate)? >= event.event_time_unix_ms {
                retained.push(candidate);
            }
        }
        state.candidates = retained;
        let base = state.candidates.clone();
        let mut working = state.candidates.clone();
        for (stage_index, stage) in rule.stages().iter().enumerate() {
            if !stage.matches(body.event_kind, body.severity) {
                continue;
            }
            let contribution = StageContribution {
                event_id: event.event_id.clone(),
                evidence_digest: event.evidence_hash,
                source_receipt_id: body.source_receipt_id.clone(),
                event_time_unix_ms: event.event_time_unix_ms,
            };
            let candidates = if stage_index == 0 {
                let mut stages = vec![None; rule.stages().len()];
                stages[0] = Some(contribution);
                vec![PartialCandidate {
                    stages,
                    lineage_seed: body.subject.lineage_seed.clone(),
                }]
            } else {
                let predecessor = stage.predecessor_index().ok_or(())?;
                let window = stage.within_ms().ok_or(())?;
                let sources = if rule.allow_event_reuse() {
                    working.clone()
                } else {
                    base.clone()
                };
                let mut extended = Vec::new();
                for source in sources {
                    if source.lineage_seed != body.subject.lineage_seed
                        || source.stages.get(stage_index).ok_or(())?.is_some()
                    {
                        continue;
                    }
                    let Some(predecessor_event) =
                        source.stages.get(predecessor).and_then(Option::as_ref)
                    else {
                        continue;
                    };
                    if !event_time_is_ordered_and_within(
                        event.event_time_unix_ms,
                        predecessor_event.event_time_unix_ms,
                        window,
                    ) || !rule.allow_event_reuse()
                        && source
                            .stages
                            .iter()
                            .flatten()
                            .any(|existing| existing.event_id == event.event_id)
                    {
                        continue;
                    }
                    let mut candidate = source;
                    candidate.stages[stage_index] = Some(contribution.clone());
                    extended.push(candidate);
                }
                extended
            };
            for candidate in candidates {
                if candidate.stages.iter().all(Option::is_some) {
                    let finding = correlated_finding(rule, group_key_hash, &body, &candidate)?;
                    findings.insert(finding.finding_id.as_str().to_owned(), finding);
                } else if !working.contains(&candidate) {
                    working.push(candidate);
                }
            }
            working.sort();
            working.dedup();
            if findings.len() > rule.max_partial_matches_per_group() as usize {
                return Ok(suppress_for_overflow(rule, state, bounded_lateness_ms));
            }
        }
        if working.len() > rule.max_partial_matches_per_group() as usize {
            return Ok(suppress_for_overflow(rule, state, bounded_lateness_ms));
        }
        state.candidates = working;
    }
    let mut retained = Vec::with_capacity(state.candidates.len());
    for candidate in state.candidates.drain(..) {
        if candidate_deadline(rule, &candidate)? > next_watermark {
            retained.push(candidate);
        }
    }
    state.candidates = retained;
    Ok(ProcessResult {
        findings: findings.into_values().collect(),
        overflow: false,
        suppressed: false,
    })
}

fn event_time_is_ordered_and_within(
    event_time_unix_ms: u64,
    predecessor_time_unix_ms: u64,
    within_ms: u64,
) -> bool {
    event_time_unix_ms
        .checked_sub(predecessor_time_unix_ms)
        .is_some_and(|elapsed| elapsed <= within_ms)
}

fn valid_candidate_shape(rule: &TemporalRule, candidate: &PartialCandidate) -> bool {
    candidate.stages.len() == rule.stages().len()
        && candidate.stages.first().is_some_and(Option::is_some)
        && candidate.stages.iter().any(Option::is_none)
}

fn candidate_deadline(rule: &TemporalRule, candidate: &PartialCandidate) -> Result<u64, ()> {
    if !valid_candidate_shape(rule, candidate) {
        return Err(());
    }
    let mut deadline = u64::MAX;
    for (stage_index, stage) in rule.stages().iter().enumerate().skip(1) {
        if candidate.stages[stage_index].is_some() {
            continue;
        }
        let predecessor = stage.predecessor_index().ok_or(())?;
        let Some(predecessor_event) = candidate.stages[predecessor].as_ref() else {
            continue;
        };
        let within = stage.within_ms().ok_or(())?;
        deadline = deadline.min(
            predecessor_event
                .event_time_unix_ms
                .checked_add(within)
                .ok_or(())?,
        );
    }
    if deadline == u64::MAX {
        return Err(());
    }
    Ok(deadline)
}

fn suppress_for_overflow(
    rule: &TemporalRule,
    state: &mut PartitionState,
    bounded_lateness_ms: u64,
) -> ProcessResult {
    let suppression_window = rule
        .maximum_window_ms()
        .checked_add(bounded_lateness_ms)
        .and_then(|window| state.max_seen_event_time_unix_ms.checked_add(window))
        .unwrap_or(u64::MAX);
    state.candidates.clear();
    state.suppressed_until_unix_ms = Some(suppression_window);
    ProcessResult {
        findings: Vec::new(),
        overflow: true,
        suppressed: true,
    }
}

fn partition_expiry(rule: &TemporalRule, state: &PartitionState, bounded_lateness_ms: u64) -> u64 {
    let candidate_expiry = state
        .candidates
        .iter()
        .filter_map(|candidate| candidate_deadline(rule, candidate).ok())
        .max()
        .unwrap_or(state.watermark_unix_ms);
    candidate_expiry
        .max(state.suppressed_until_unix_ms.unwrap_or(0))
        .saturating_add(bounded_lateness_ms)
}

fn parse_verified_event(event: &VerifiedSecurityEvent) -> Result<SecurityEventBody, ()> {
    let body: SecurityEventBody =
        serde_json::from_slice(event.canonical_body.as_bytes()).map_err(|_| ())?;
    body.validate().map_err(|_| ())?;
    let canonical = canonical_json_bytes(&body).map_err(|_| ())?;
    if canonical.as_slice() != event.canonical_body.as_bytes()
        || Digest32::new(*sha256(&canonical).as_bytes()) != event.body_hash
        || body.tenant_id != event.tenant_id
        || body.event_id != event.event_id
        || body.producer_id != event.producer_id
        || body.trust_class != event.trust_class
        || body.event_time_unix_ms != event.event_time_unix_ms
        || body.ingest_time_unix_ms != event.received_at_unix_ms
    {
        return Err(());
    }
    Ok(body)
}

#[derive(Serialize)]
struct GroupCommitment<'a> {
    tenant_id: &'a str,
    rule_id: &'a str,
    rule_version_hash: Digest32,
    grouping_key: GroupingKey,
    grouping_value: &'a str,
}

fn group_hash(rule: &TemporalRule, body: &SecurityEventBody) -> Result<Digest32, ()> {
    let value = match rule.group_by() {
        GroupingKey::AgentId => body.subject.agent_id.as_str(),
        GroupingKey::CapabilityId => body.subject.capability_id.as_str(),
        GroupingKey::LineageSeed => body.subject.lineage_seed.as_str(),
        GroupingKey::SessionId => body.subject.session_id.as_str(),
        GroupingKey::SubjectId => body.subject.subject_id.as_str(),
    };
    domain_hash(
        GROUP_HASH_DOMAIN,
        &GroupCommitment {
            tenant_id: body.tenant_id.as_str(),
            rule_id: rule.rule_id().as_str(),
            rule_version_hash: rule.version_hash(),
            grouping_key: rule.group_by(),
            grouping_value: value,
        },
    )
}

#[derive(Serialize)]
struct CapacityKeyCommitment<'a> {
    tenant_id: &'a str,
    rule_id: &'a str,
    rule_version_hash: Digest32,
}

fn capacity_key(
    rule: &TemporalRule,
    event: &VerifiedSecurityEvent,
) -> Result<CorrelationPartitionKey, ()> {
    Ok(CorrelationPartitionKey {
        tenant_id: event.tenant_id.clone(),
        rule_id: rule.rule_id().clone(),
        partition_hash: domain_hash(
            CAPACITY_KEY_DOMAIN,
            &CapacityKeyCommitment {
                tenant_id: event.tenant_id.as_str(),
                rule_id: rule.rule_id().as_str(),
                rule_version_hash: rule.version_hash(),
            },
        )?,
    })
}

#[derive(Serialize)]
struct FindingCommitment<'a> {
    tenant_id: &'a str,
    rule_id: &'a str,
    rule_version_hash: Digest32,
    policy_version: &'a str,
    group_key_hash: Digest32,
    ordered_event_ids: &'a [EventId],
    ordered_evidence_digests: &'a [Digest32],
    ordered_source_receipt_ids: &'a [chio_security_types::ports::OpaqueReceiptRef],
    first_event_time_unix_ms: u64,
    last_event_time_unix_ms: u64,
    lineage_seed: &'a str,
}

fn correlated_finding(
    rule: &TemporalRule,
    group_key_hash: Digest32,
    body: &SecurityEventBody,
    candidate: &PartialCandidate,
) -> Result<CorrelatedFinding, ()> {
    let contributions: Vec<&StageContribution> = candidate.stages.iter().flatten().collect();
    if contributions.len() != rule.stages().len() {
        return Err(());
    }
    let ordered_event_ids: Vec<EventId> = contributions
        .iter()
        .map(|contribution| contribution.event_id.clone())
        .collect();
    let ordered_evidence_digests: Vec<Digest32> = contributions
        .iter()
        .map(|contribution| contribution.evidence_digest)
        .collect();
    let ordered_source_receipt_ids = contributions
        .iter()
        .map(|contribution| contribution.source_receipt_id.clone())
        .collect::<Vec<_>>();
    let first = contributions
        .iter()
        .map(|contribution| contribution.event_time_unix_ms)
        .min()
        .ok_or(())?;
    let last = contributions
        .iter()
        .map(|contribution| contribution.event_time_unix_ms)
        .max()
        .ok_or(())?;
    let commitment = FindingCommitment {
        tenant_id: body.tenant_id.as_str(),
        rule_id: rule.rule_id().as_str(),
        rule_version_hash: rule.version_hash(),
        policy_version: rule.policy_version().as_str(),
        group_key_hash,
        ordered_event_ids: &ordered_event_ids,
        ordered_evidence_digests: &ordered_evidence_digests,
        ordered_source_receipt_ids: &ordered_source_receipt_ids,
        first_event_time_unix_ms: first,
        last_event_time_unix_ms: last,
        lineage_seed: candidate.lineage_seed.as_str(),
    };
    let digest = domain_hash(FINDING_ID_DOMAIN, &commitment)?;
    let finding_id =
        RecordId::new(format!("finding_{}", hex_bytes(digest.as_bytes()))).map_err(|_| ())?;
    CorrelatedFinding::new(CorrelatedFindingInput {
        finding_id,
        tenant_id: body.tenant_id.clone(),
        rule_id: rule.rule_id().clone(),
        rule_version_hash: rule.version_hash(),
        policy_version: rule.policy_version().clone(),
        group_key_hash,
        ordered_event_ids,
        ordered_evidence_digests,
        ordered_source_receipt_ids,
        first_event_time_unix_ms: first,
        last_event_time_unix_ms: last,
        lineage_seed: candidate.lineage_seed.clone(),
    })
    .map_err(|_| ())
}

#[derive(Serialize)]
struct IndexTransition<'a> {
    tenant_id: &'a str,
    rule_id: &'a str,
    group_hash: Digest32,
    event_id: &'a str,
}

#[derive(Serialize)]
struct PartitionTransition<'a> {
    tenant_id: &'a str,
    rule_id: &'a str,
    group_hash: Digest32,
    generation: u64,
    watermark_unix_ms: u64,
    body_hash: Digest32,
}

fn transition_id<T: Serialize>(kind: &str, value: &T) -> Result<RecordId, ()> {
    #[derive(Serialize)]
    struct Transition<'a, T> {
        kind: &'a str,
        value: &'a T,
    }
    let digest = domain_hash(TRANSITION_ID_DOMAIN, &Transition { kind, value })?;
    RecordId::new(format!("corr_{}", hex_bytes(digest.as_bytes()))).map_err(|_| ())
}

fn canonical_body_and_hash<T: Serialize>(value: &T) -> Result<(CanonicalBody, Digest32), ()> {
    let bytes = canonical_json_bytes(value).map_err(|_| ())?;
    let hash = Digest32::new(*sha256(&bytes).as_bytes());
    let body = CanonicalBody::new(bytes).map_err(|_| ())?;
    Ok((body, hash))
}

fn load_partition_state(partial: &CorrelationPartial) -> Result<PartitionState, ()> {
    validate_stored_body(partial)?;
    let state: PartitionState =
        serde_json::from_slice(partial.canonical_body.as_bytes()).map_err(|_| ())?;
    if state.schema_version != PARTITION_STATE_VERSION
        || state.watermark_unix_ms != partial.watermark_unix_ms
        || state.max_seen_event_time_unix_ms < state.watermark_unix_ms
        || state.candidates.iter().any(|candidate| {
            candidate.stages.is_empty()
                || candidate.stages.len() > chio_security_types::MAX_FINDING_EVENTS
                || candidate.stages.first().is_none_or(Option::is_none)
                || candidate.stages.iter().all(Option::is_some)
        })
    {
        return Err(());
    }
    Ok(state)
}

fn load_capacity_state(partial: &CorrelationPartial) -> Result<CapacityState, ()> {
    validate_stored_body(partial)?;
    let state: CapacityState =
        serde_json::from_slice(partial.canonical_body.as_bytes()).map_err(|_| ())?;
    if state.schema_version != CAPACITY_STATE_VERSION
        || state.watermark_unix_ms != partial.watermark_unix_ms
        || state
            .groups
            .windows(2)
            .any(|pair| pair[0].group_hash >= pair[1].group_hash)
    {
        return Err(());
    }
    Ok(state)
}

fn validate_stored_body(partial: &CorrelationPartial) -> Result<(), ()> {
    let canonical = canonical_json_bytes(
        &serde_json::from_slice::<serde_json::Value>(partial.canonical_body.as_bytes())
            .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    if canonical.as_slice() != partial.canonical_body.as_bytes()
        || Digest32::new(*sha256(&canonical).as_bytes()) != partial.body_hash
    {
        return Err(());
    }
    Ok(())
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, ()> {
    let canonical = canonical_json_bytes(value).map_err(|_| ())?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&input).as_bytes()))
}

fn port_health_kind(error: &PortError) -> DetectorHealthKind {
    match error.kind() {
        PortErrorKind::Conflict => DetectorHealthKind::StoreConflict,
        PortErrorKind::Unavailable => DetectorHealthKind::StoreUnavailable,
        PortErrorKind::InvalidData | PortErrorKind::IntegrityFailure => {
            DetectorHealthKind::CorruptState
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod mutation_tests {
    use super::{
        event_time_is_ordered_and_within, merge_validated_group_watermark, GroupWatermarkKnowledge,
        ValidatedGroupWatermarkMerge, MAX_JSON_SAFE_INTEGER,
    };

    #[test]
    fn event_time_window_rejects_reverse_and_expired_sequences() {
        assert!(event_time_is_ordered_and_within(120, 100, 20));
        assert!(!event_time_is_ordered_and_within(99, 100, 20));
        assert!(!event_time_is_ordered_and_within(121, 100, 20));
    }

    #[test]
    fn committed_group_watermark_rejects_contradictory_values() {
        assert_eq!(
            GroupWatermarkKnowledge::committed(0, 10),
            GroupWatermarkKnowledge::Contradictory { unix_ms: 0 }
        );
        assert_eq!(
            GroupWatermarkKnowledge::committed(11, 10),
            GroupWatermarkKnowledge::Contradictory { unix_ms: 11 }
        );
        assert_eq!(
            GroupWatermarkKnowledge::committed(
                MAX_JSON_SAFE_INTEGER.saturating_add(1),
                MAX_JSON_SAFE_INTEGER.saturating_add(1),
            ),
            GroupWatermarkKnowledge::Contradictory {
                unix_ms: MAX_JSON_SAFE_INTEGER.saturating_add(1),
            }
        );
        assert_eq!(
            GroupWatermarkKnowledge::committed(9, 10),
            GroupWatermarkKnowledge::Committed { unix_ms: 9 }
        );
    }

    #[test]
    fn validated_group_watermark_merge_is_numerically_monotonic() {
        let committed_90 = GroupWatermarkKnowledge::Committed { unix_ms: 90 };
        assert_eq!(
            merge_validated_group_watermark(GroupWatermarkKnowledge::Unknown, committed_90,),
            ValidatedGroupWatermarkMerge::Accepted(committed_90)
        );
        assert_eq!(
            merge_validated_group_watermark(committed_90, GroupWatermarkKnowledge::Unknown,),
            ValidatedGroupWatermarkMerge::Accepted(committed_90)
        );
        assert_eq!(
            merge_validated_group_watermark(
                committed_90,
                GroupWatermarkKnowledge::Committed { unix_ms: 100 },
            ),
            ValidatedGroupWatermarkMerge::Accepted(GroupWatermarkKnowledge::Committed {
                unix_ms: 100,
            })
        );
        assert_eq!(
            merge_validated_group_watermark(
                committed_90,
                GroupWatermarkKnowledge::Committed { unix_ms: 80 },
            ),
            ValidatedGroupWatermarkMerge::Regression {
                retained: committed_90,
            }
        );
    }
}

#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("correlation policy resource bounds are invalid")]
    InvalidPolicy,
}
