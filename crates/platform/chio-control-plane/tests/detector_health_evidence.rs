use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_control_plane::security::AttestedCorrelationWriter;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DetectorHealthReceiptBody, MAX_ACTIVE_DEFENSE_JSON_INTEGER,
};
use chio_kernel::{
    ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
    AuthoritativeCorrelatedFindingEvidence,
};
use chio_quarantine::{
    CorrelationOutcome, CorrelationPolicy, CorrelationStatus, RuleLimits, TemporalCorrelator,
    TemporalRule,
};
use chio_security_types::ports::{
    AdvisorySecurityEvent, CanonicalBody, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventAdmission, CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationOutcomeCommitRequest, CorrelationOutcomeKey, CorrelationOutcomePublication,
    CorrelationPartial, CorrelationPartitionKey, CorrelationScan, CreateOutcome, Digest32,
    EventAppend, EventId, EventPartitionScan, LineageId, OpaqueReceiptRef, PortError,
    PortErrorKind, PortResult, ProducerId, ProducerTrustClass, ReceiptAppendRequest, RecordId,
    RuleId, SecurityEventStore, SecurityReceiptSink, SessionId, TenantId, VerifiedSecurityEvent,
};
use chio_security_types::{
    DetectorGroupBindingEvidence, DetectorHealthEvidence, DetectorHealthKind,
    DetectorWatermarkEvidence, SecurityEventBody, SecurityEventBodyInput, SecurityEventKind,
    SecuritySeverity, SecuritySubject,
};
use chio_store_sqlite::SqliteSecurityStateStore;
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use tempfile::tempdir;

const OBSERVED_AT_UNIX_MS: u64 = 1_700_000_000_123;

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn tenant() -> TenantId {
    TenantId::new("tenant-detector-health").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn rule() -> TemporalRule {
    TemporalRule::parse_json(
        br#"{
            "rule_id":"rule-detector-health",
            "policy_version":"policy-detector-health-v1",
            "group_by":"session_id",
            "max_groups":8,
            "max_partial_matches_per_group":8,
            "allow_event_reuse":false,
            "stages":[
                {
                    "name":"first",
                    "event_kind":"credential_access",
                    "minimum_severity":"low"
                },
                {
                    "name":"second",
                    "event_kind":"egress_attempt",
                    "minimum_severity":"low",
                    "after":"first",
                    "within_ms":50
                }
            ]
        }"#,
        &RuleLimits::default(),
    )
    .unwrap_or_else(|error| panic!("temporal rule: {error}"))
}

fn correlation_policy() -> CorrelationPolicy {
    CorrelationPolicy::new(10, 128, 4, false)
        .unwrap_or_else(|error| panic!("correlation policy: {error}"))
}

fn event(
    event_id: &str,
    kind: SecurityEventKind,
    event_time_unix_ms: u64,
) -> VerifiedSecurityEvent {
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        event_time_unix_ms,
        ingest_time_unix_ms: event_time_unix_ms.saturating_add(100),
        tenant_id: tenant(),
        subject: SecuritySubject {
            subject_id: record("subject-detector-health"),
            agent_id: record("agent-detector-health"),
            session_id: SessionId::new("session-detector-health")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record("capability-detector-health"),
            lineage_seed: LineageId::new("lineage-detector-health")
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new(format!("source-receipt-{event_id}"))
            .unwrap_or_else(|error| panic!("source receipt id: {error}")),
        event_kind: kind,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new(format!("evidence-{event_id}"))
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id: ProducerId::new("producer-detector-health")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        producer_key_id: record("producer-key-detector-health"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("policy-detector-health-v1"),
    })
    .unwrap_or_else(|error| panic!("security event body: {error}"));
    let canonical = chio_core::canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("canonical security event: {error}"));
    VerifiedSecurityEvent {
        tenant_id: body.tenant_id.clone(),
        event_id: body.event_id.clone(),
        producer_id: body.producer_id.clone(),
        trust_class: body.trust_class,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("canonical event body: {error}")),
        body_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
        evidence_hash: digest(9),
    }
}

fn corrupt_event() -> VerifiedSecurityEvent {
    let mut corrupt = event("corrupt-event", SecurityEventKind::CredentialAccess, 100);
    let canonical = b"{}".to_vec();
    corrupt.canonical_body = CanonicalBody::new(canonical.clone())
        .unwrap_or_else(|error| panic!("corrupt canonical body: {error}"));
    corrupt.body_hash = Digest32::new(*chio_core::sha256(&canonical).as_bytes());
    corrupt
}

struct FaultingEventStore {
    inner: SqliteSecurityStateStore,
    fail_load: AtomicBool,
    fail_load_on_call: AtomicUsize,
    load_calls: AtomicUsize,
    fail_admit: AtomicBool,
    admit_conflicts_remaining: AtomicUsize,
    cas_conflicts_remaining: AtomicUsize,
    loaded_watermark_override: Mutex<Option<u64>>,
    main_load_overrides: Mutex<VecDeque<Option<MainLoadOverride>>>,
}

#[derive(Clone, Copy)]
enum MainLoadOverride {
    MetadataOnly(u64),
    Validated(u64),
}

impl FaultingEventStore {
    fn open(path: &Path) -> Self {
        Self {
            inner: SqliteSecurityStateStore::open(path)
                .unwrap_or_else(|error| panic!("open security event store: {error:?}")),
            fail_load: AtomicBool::new(false),
            fail_load_on_call: AtomicUsize::new(0),
            load_calls: AtomicUsize::new(0),
            fail_admit: AtomicBool::new(false),
            admit_conflicts_remaining: AtomicUsize::new(0),
            cas_conflicts_remaining: AtomicUsize::new(0),
            loaded_watermark_override: Mutex::new(None),
            main_load_overrides: Mutex::new(VecDeque::new()),
        }
    }

    fn fail_load(&self, fail: bool) {
        self.fail_load.store(fail, Ordering::SeqCst);
    }

    fn fail_admit(&self, fail: bool) {
        self.fail_admit.store(fail, Ordering::SeqCst);
    }

    fn fail_load_after(&self, successful_loads: usize) {
        let target = self
            .load_calls
            .load(Ordering::SeqCst)
            .saturating_add(successful_loads)
            .saturating_add(1);
        self.fail_load_on_call.store(target, Ordering::SeqCst);
    }

    fn override_loaded_watermark(&self, watermark_unix_ms: u64) {
        *self
            .loaded_watermark_override
            .lock()
            .unwrap_or_else(|_| panic!("loaded watermark override lock")) = Some(watermark_unix_ms);
    }

    fn script_main_loads(&self, overrides: impl IntoIterator<Item = Option<MainLoadOverride>>) {
        *self
            .main_load_overrides
            .lock()
            .unwrap_or_else(|_| panic!("main load overrides lock")) =
            overrides.into_iter().collect();
    }

    fn conflict_admissions(&self, count: usize) {
        self.admit_conflicts_remaining
            .store(count, Ordering::SeqCst);
    }

    fn conflict_partition_cas(&self, count: usize) {
        self.cas_conflicts_remaining.store(count, Ordering::SeqCst);
    }

    fn take_conflict(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    fn apply_main_load_override(
        partial: &mut CorrelationPartial,
        override_kind: MainLoadOverride,
    ) -> PortResult<()> {
        match override_kind {
            MainLoadOverride::MetadataOnly(watermark_unix_ms) => {
                partial.watermark_unix_ms = watermark_unix_ms;
            }
            MainLoadOverride::Validated(watermark_unix_ms) => {
                let mut value: Value = serde_json::from_slice(partial.canonical_body.as_bytes())
                    .map_err(|_| PortError::invalid_data())?;
                value["watermark_unix_ms"] = json!(watermark_unix_ms);
                let max_seen = value["max_seen_event_time_unix_ms"]
                    .as_u64()
                    .unwrap_or_default()
                    .max(watermark_unix_ms);
                value["max_seen_event_time_unix_ms"] = json!(max_seen);
                let canonical = chio_core::canonical_json_bytes(&value)
                    .map_err(|_| PortError::invalid_data())?;
                partial.canonical_body =
                    CanonicalBody::new(canonical.clone()).map_err(|_| PortError::invalid_data())?;
                partial.body_hash = Digest32::new(*chio_core::sha256(&canonical).as_bytes());
                partial.watermark_unix_ms = watermark_unix_ms;
            }
        }
        Ok(())
    }
}

impl SecurityEventStore for FaultingEventStore {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission> {
        if Self::take_conflict(&self.admit_conflicts_remaining) {
            Err(PortError::conflict())
        } else if self.fail_admit.load(Ordering::SeqCst) {
            Err(PortError::unavailable())
        } else {
            self.inner.admit_verified_correlation_event(request)
        }
    }

    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        self.inner.append_verified(event)
    }

    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        self.inner.append_advisory(event)
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        self.inner.index_partition_event(request)
    }

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        self.inner.scan_partition(scan)
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        let call = self.load_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_load.load(Ordering::SeqCst)
            || self.fail_load_on_call.load(Ordering::SeqCst) == call
        {
            Err(PortError::unavailable())
        } else {
            let loaded = self.inner.load_correlation(key)?;
            let override_watermark = *self
                .loaded_watermark_override
                .lock()
                .map_err(|_| PortError::unavailable())?;
            loaded
                .map(|mut partial| {
                    let value: Value = serde_json::from_slice(partial.canonical_body.as_bytes())
                        .map_err(|_| PortError::invalid_data())?;
                    if value.get("candidates").is_some() {
                        let scripted = self
                            .main_load_overrides
                            .lock()
                            .map_err(|_| PortError::unavailable())?
                            .pop_front()
                            .flatten();
                        if let Some(override_kind) = scripted {
                            Self::apply_main_load_override(&mut partial, override_kind)?;
                        }
                    }
                    if let Some(watermark_unix_ms) = override_watermark {
                        partial.watermark_unix_ms = watermark_unix_ms;
                    }
                    Ok(partial)
                })
                .transpose()
        }
    }

    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>> {
        self.inner.load_correlation_max_seen_event_time(key)
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        if Self::take_conflict(&self.cas_conflicts_remaining) {
            Err(PortError::conflict())
        } else {
            self.inner.compare_and_swap_correlation(request)
        }
    }

    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial> {
        if Self::take_conflict(&self.cas_conflicts_remaining) {
            Err(PortError::conflict())
        } else {
            self.inner.commit_correlation_outcome(request)
        }
    }

    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome> {
        self.inner.commit_correlation_outcome_only(outcome)
    }

    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>> {
        self.inner.load_correlation_outcome(key)
    }

    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()> {
        self.inner.delete_correlation(request)
    }
}

#[derive(Default)]
struct RecordingReceiptSink {
    requests: Mutex<Vec<ReceiptAppendRequest>>,
}

impl RecordingReceiptSink {
    fn bodies(&self) -> Vec<ActiveDefenseReceiptBody> {
        self.requests
            .lock()
            .unwrap_or_else(|_| panic!("receipt sink lock"))
            .iter()
            .map(|request| {
                serde_json::from_slice(request.canonical_body.as_bytes())
                    .unwrap_or_else(|error| panic!("decode detector health body: {error}"))
            })
            .collect()
    }
}

impl SecurityReceiptSink for RecordingReceiptSink {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        self.requests
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(request.clone());
        Ok(request.evidence_id.clone())
    }
}

struct NoFindingAuthority;

impl ActiveResponseFindingAuthority for NoFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        Ok(())
    }

    fn load_correlated_finding(
        &self,
        _: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        Ok(None)
    }
}

fn writer(sink: Arc<RecordingReceiptSink>) -> AttestedCorrelationWriter {
    AttestedCorrelationWriter::new(
        sink,
        Arc::new(NoFindingAuthority),
        BTreeMap::from([(record("policy-detector-health-v1"), digest(1))]),
    )
}

fn attest(
    writer: &AttestedCorrelationWriter,
    outcome: &CorrelationOutcome,
) -> Vec<AuthoritativeCorrelatedFindingEvidence> {
    writer
        .attest_outcome(outcome)
        .unwrap_or_else(|error| panic!("attest detector health: {error:?}"))
}

fn health_body(
    group_binding: DetectorGroupBindingEvidence,
    watermark: DetectorWatermarkEvidence,
) -> ActiveDefenseReceiptBody {
    health_body_with_kind(
        group_binding,
        DetectorHealthKind::StoreUnavailable,
        watermark,
    )
}

fn health_body_with_kind(
    group_binding: DetectorGroupBindingEvidence,
    health_kind: DetectorHealthKind,
    watermark: DetectorWatermarkEvidence,
) -> ActiveDefenseReceiptBody {
    let body = ActiveDefenseReceiptBody::DetectorHealth(DetectorHealthReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            OBSERVED_AT_UNIX_MS,
            tenant(),
            record("detector-health-transition"),
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("detector health header: {error}")),
        policy: ActiveDefensePolicyBinding {
            policy_version: record("policy-detector-health-v1"),
            policy_hash: digest(1),
        },
        rule_id: RuleId::new("rule-detector-health")
            .unwrap_or_else(|error| panic!("rule id: {error}")),
        rule_version_hash: digest(2),
        group_binding,
        event_id: EventId::new("event-detector-health")
            .unwrap_or_else(|error| panic!("event id: {error}")),
        health_kind,
        watermark,
        evidence_hash: digest(4),
    });
    body.validate()
        .unwrap_or_else(|error| panic!("detector health body: {error}"));
    body
}

fn health_evidence(
    group_binding: DetectorGroupBindingEvidence,
    watermark: DetectorWatermarkEvidence,
    observed_at_unix_ms: u64,
) -> DetectorHealthEvidence {
    DetectorHealthEvidence {
        tenant_id: tenant(),
        policy_version: record("policy-detector-health-v1"),
        rule_id: RuleId::new("rule-detector-health")
            .unwrap_or_else(|error| panic!("rule id: {error}")),
        rule_version_hash: digest(2),
        group_binding,
        kind: DetectorHealthKind::StoreUnavailable,
        event_id: EventId::new("event-detector-health")
            .unwrap_or_else(|error| panic!("event id: {error}")),
        observed_at_unix_ms,
        watermark,
    }
}

fn health_outcome(evidence: DetectorHealthEvidence) -> CorrelationOutcome {
    CorrelationOutcome {
        status: CorrelationStatus::Suppressed,
        findings: Vec::new(),
        detector_health: vec![evidence],
        automatic_response_suppressed: true,
        watermark_unix_ms: 0,
    }
}

fn require_invalid(mut value: Value, mutation: impl FnOnce(&mut Value)) {
    mutation(&mut value);
    let parsed = serde_json::from_value::<ActiveDefenseReceiptBody>(value);
    assert!(parsed.is_err() || parsed.is_ok_and(|body| body.validate().is_err()));
}

#[test]
fn corrupt_event_with_unresolved_group_attests_durably_without_fake_digest() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("corrupt-event.sqlite"),
    ));
    store.fail_load(true);
    let correlator = TemporalCorrelator::new(store, correlation_policy());
    let outcome = correlator.ingest(&rule(), &corrupt_event());
    assert_eq!(outcome.status, CorrelationStatus::Suppressed);
    assert!(outcome.automatic_response_suppressed);
    assert_eq!(outcome.detector_health.len(), 1);
    assert_eq!(
        outcome.detector_health[0].kind,
        DetectorHealthKind::CorruptEvent
    );
    assert_eq!(
        outcome.detector_health[0].group_binding,
        DetectorGroupBindingEvidence::Unresolved
    );
    assert_eq!(
        outcome.detector_health[0].watermark,
        DetectorWatermarkEvidence::Unknown
    );

    let sink = Arc::new(RecordingReceiptSink::default());
    assert!(attest(&writer(sink.clone()), &outcome).is_empty());
    let bodies = sink.bodies();
    assert_eq!(bodies.len(), 1);
    let ActiveDefenseReceiptBody::DetectorHealth(body) = &bodies[0] else {
        panic!("persisted receipt is not detector health");
    };
    assert_eq!(body.group_binding, DetectorGroupBindingEvidence::Unresolved);
    assert_eq!(body.watermark, DetectorWatermarkEvidence::Unknown);
}

#[test]
fn cold_partition_store_unavailable_attests_unknown_watermark_with_resolved_group() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("cold-partition.sqlite"),
    ));
    store.fail_load(true);
    let correlator = TemporalCorrelator::new(store, correlation_policy());
    let outcome = correlator.ingest(
        &rule(),
        &event("cold-event", SecurityEventKind::CredentialAccess, 100),
    );
    assert_eq!(outcome.status, CorrelationStatus::Suppressed);
    assert_eq!(outcome.detector_health.len(), 1);
    assert_eq!(
        outcome.detector_health[0].watermark,
        DetectorWatermarkEvidence::Unknown
    );
    let DetectorGroupBindingEvidence::Resolved { group_key_hash } =
        outcome.detector_health[0].group_binding
    else {
        panic!("derived group binding must be resolved");
    };
    assert_ne!(group_key_hash, Digest32::new([0_u8; 32]));

    let sink = Arc::new(RecordingReceiptSink::default());
    assert!(attest(&writer(sink.clone()), &outcome).is_empty());
    let ActiveDefenseReceiptBody::DetectorHealth(body) = &sink.bodies()[0] else {
        panic!("persisted receipt is not detector health");
    };
    assert_eq!(body.watermark, DetectorWatermarkEvidence::Unknown);
    assert_eq!(body.group_binding, outcome.detector_health[0].group_binding);
}

#[test]
fn loaded_partition_failure_attests_exact_committed_watermark() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("loaded-partition.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event("initial-event", SecurityEventKind::CredentialAccess, 100),
    );
    assert_eq!(initial.watermark_unix_ms, 90);
    store.fail_admit(true);
    let failed = correlator.ingest(
        &rule(),
        &event("failing-event", SecurityEventKind::EgressAttempt, 120),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );

    let sink = Arc::new(RecordingReceiptSink::default());
    assert!(attest(&writer(sink.clone()), &failed).is_empty());
    let ActiveDefenseReceiptBody::DetectorHealth(body) = &sink.bodies()[0] else {
        panic!("persisted receipt is not detector health");
    };
    assert_eq!(
        body.watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn contradictory_loaded_watermarks_are_not_laundered_to_unknown() {
    for (case, claimed) in [("zero", 0_u64), ("future", 221_u64), ("unsafe", u64::MAX)] {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(FaultingEventStore::open(
            &temp.path().join(format!("contradictory-{case}.sqlite")),
        ));
        let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
        let initial = correlator.ingest(
            &rule(),
            &event(
                &format!("contradictory-initial-{case}"),
                SecurityEventKind::CredentialAccess,
                100,
            ),
        );
        assert_eq!(initial.watermark_unix_ms, 90);

        store.override_loaded_watermark(claimed);
        let failed = correlator.ingest(
            &rule(),
            &event(
                &format!("contradictory-failing-{case}"),
                SecurityEventKind::EgressAttempt,
                120,
            ),
        );
        assert_eq!(failed.status, CorrelationStatus::Suppressed);
        assert_eq!(failed.detector_health.len(), 1);
        assert_eq!(
            failed.detector_health[0].kind,
            DetectorHealthKind::CorruptState
        );
        assert_eq!(
            failed.detector_health[0].watermark,
            DetectorWatermarkEvidence::Contradictory {
                claimed_unix_ms: claimed.to_string(),
            }
        );

        let sink = Arc::new(RecordingReceiptSink::default());
        assert!(attest(&writer(sink.clone()), &failed).is_empty());
        let ActiveDefenseReceiptBody::DetectorHealth(body) = &sink.bodies()[0] else {
            panic!("persisted receipt is not detector health");
        };
        assert_eq!(body.watermark, failed.detector_health[0].watermark);
    }
}

#[test]
fn safe_metadata_body_mismatch_without_prior_exact_watermark_attests_unknown() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("safe-metadata-mismatch.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event(
            "safe-mismatch-initial",
            SecurityEventKind::CredentialAccess,
            100,
        ),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.script_main_loads([Some(MainLoadOverride::MetadataOnly(80))]);
    let failed = correlator.ingest(
        &rule(),
        &event(
            "safe-mismatch-failing",
            SecurityEventKind::EgressAttempt,
            120,
        ),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::CorruptState
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Unknown
    );
}

#[test]
fn safe_metadata_body_mismatch_after_retry_retains_prior_exact_watermark() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("safe-metadata-mismatch-retry.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event(
            "safe-mismatch-retry-initial",
            SecurityEventKind::CredentialAccess,
            100,
        ),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.script_main_loads([None, Some(MainLoadOverride::MetadataOnly(80))]);
    store.conflict_admissions(1);
    let failed = correlator.ingest(
        &rule(),
        &event(
            "safe-mismatch-retry-failing",
            SecurityEventKind::EgressAttempt,
            120,
        ),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::CorruptState
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn admission_retry_rejects_validated_watermark_regression() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("admission-watermark-regression.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event(
            "admission-regression-initial",
            SecurityEventKind::CredentialAccess,
            100,
        ),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.script_main_loads([None, Some(MainLoadOverride::Validated(80))]);
    store.conflict_admissions(1);
    let failed = correlator.ingest(
        &rule(),
        &event(
            "admission-regression-failing",
            SecurityEventKind::EgressAttempt,
            120,
        ),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::CorruptState
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn cas_retry_rejects_validated_watermark_regression() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("cas-watermark-regression.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event(
            "cas-regression-initial",
            SecurityEventKind::CredentialAccess,
            100,
        ),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.script_main_loads([None, None, Some(MainLoadOverride::Validated(80))]);
    store.conflict_partition_cas(1);
    let failed = correlator.ingest(
        &rule(),
        &event(
            "cas-regression-failing",
            SecurityEventKind::EgressAttempt,
            120,
        ),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::CorruptState
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn capacity_load_failure_preserves_exact_main_group_watermark() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("capacity-load-failure.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event("capacity-initial", SecurityEventKind::CredentialAccess, 100),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.fail_load_after(1);
    let failed = correlator.ingest(
        &rule(),
        &event("capacity-failing", SecurityEventKind::EgressAttempt, 120),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::StoreUnavailable
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn advance_reload_failure_preserves_exact_main_group_watermark() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(FaultingEventStore::open(
        &temp.path().join("advance-load-failure.sqlite"),
    ));
    let correlator = TemporalCorrelator::new(store.clone(), correlation_policy());
    let initial = correlator.ingest(
        &rule(),
        &event("advance-initial", SecurityEventKind::CredentialAccess, 100),
    );
    assert_eq!(initial.watermark_unix_ms, 90);

    store.fail_load_after(2);
    let failed = correlator.ingest(
        &rule(),
        &event("advance-failing", SecurityEventKind::EgressAttempt, 120),
    );
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(failed.detector_health.len(), 1);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::StoreUnavailable
    );
    assert_eq!(
        failed.detector_health[0].watermark,
        DetectorWatermarkEvidence::Committed { unix_ms: 90 }
    );
}

#[test]
fn unknown_and_committed_watermarks_have_distinct_canonical_identity() {
    let unknown = health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
    );
    let committed = health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Committed { unix_ms: 1 },
    );
    assert_ne!(
        chio_core::canonical_json_bytes(&unknown)
            .unwrap_or_else(|error| panic!("canonical unknown watermark: {error}")),
        chio_core::canonical_json_bytes(&committed)
            .unwrap_or_else(|error| panic!("canonical committed watermark: {error}"))
    );
    assert_ne!(
        unknown
            .evidence_id()
            .unwrap_or_else(|error| panic!("unknown watermark evidence id: {error}")),
        committed
            .evidence_id()
            .unwrap_or_else(|error| panic!("committed watermark evidence id: {error}"))
    );
}

#[test]
fn contradictory_watermark_has_exact_signed_identity() {
    let claimed = MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1);
    let contradictory = health_body_with_kind(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorHealthKind::CorruptState,
        DetectorWatermarkEvidence::Contradictory {
            claimed_unix_ms: claimed.to_string(),
        },
    );
    let canonical = chio_core::canonical_json_bytes(&contradictory)
        .unwrap_or_else(|error| panic!("canonical contradictory watermark: {error}"));
    let decoded: Value = serde_json::from_slice(&canonical)
        .unwrap_or_else(|error| panic!("decode contradictory watermark: {error}"));
    assert_eq!(
        decoded["body"]["watermark"],
        json!({
            "kind": "contradictory",
            "claimed_unix_ms": claimed.to_string()
        })
    );

    let sink = Arc::new(RecordingReceiptSink::default());
    let mut evidence = health_evidence(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Contradictory {
            claimed_unix_ms: claimed.to_string(),
        },
        OBSERVED_AT_UNIX_MS,
    );
    evidence.kind = DetectorHealthKind::CorruptState;
    assert!(attest(&writer(sink.clone()), &health_outcome(evidence)).is_empty());
    let ActiveDefenseReceiptBody::DetectorHealth(body) = &sink.bodies()[0] else {
        panic!("persisted receipt is not detector health");
    };
    assert_eq!(body.watermark, contradictory_watermark(claimed));
}

fn contradictory_watermark(claimed: u64) -> DetectorWatermarkEvidence {
    DetectorWatermarkEvidence::Contradictory {
        claimed_unix_ms: claimed.to_string(),
    }
}

#[test]
fn unresolved_and_resolved_group_bindings_have_distinct_canonical_identity() {
    let unresolved = health_body(
        DetectorGroupBindingEvidence::Unresolved,
        DetectorWatermarkEvidence::Unknown,
    );
    let resolved = health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
    );
    assert_ne!(
        chio_core::canonical_json_bytes(&unresolved)
            .unwrap_or_else(|error| panic!("canonical unresolved group: {error}")),
        chio_core::canonical_json_bytes(&resolved)
            .unwrap_or_else(|error| panic!("canonical resolved group: {error}"))
    );
    assert_ne!(
        unresolved
            .evidence_id()
            .unwrap_or_else(|error| panic!("unresolved group evidence id: {error}")),
        resolved
            .evidence_id()
            .unwrap_or_else(|error| panic!("resolved group evidence id: {error}"))
    );
}

#[test]
fn detector_health_rejects_missing_unknown_or_forged_knowledge_tags() {
    let valid = serde_json::to_value(health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
    ))
    .unwrap_or_else(|error| panic!("serialize detector health: {error}"));
    require_invalid(valid.clone(), |value| {
        value["body"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("detector health body object"))
            .remove("watermark");
    });
    require_invalid(valid.clone(), |value| {
        value["body"]["watermark"] = json!({"kind": "future_watermark"});
    });
    require_invalid(valid.clone(), |value| {
        value["body"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("detector health body object"))
            .remove("group_binding");
    });
    require_invalid(valid.clone(), |value| {
        value["body"]["group_binding"] = json!({"kind": "future_group"});
    });
    require_invalid(valid, |value| {
        value["body"]["group_binding"] = json!({
            "kind": "resolved",
            "group_key_hash": vec![0_u8; 32]
        });
    });
}

#[test]
fn detector_health_rejects_committed_watermark_after_observation() {
    let value = serde_json::to_value(health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
    ))
    .unwrap_or_else(|error| panic!("serialize detector health: {error}"));
    require_invalid(value.clone(), |value| {
        value["body"]["watermark"] = json!({
            "kind": "committed",
            "unix_ms": OBSERVED_AT_UNIX_MS.saturating_add(1)
        });
    });
    require_invalid(value, |value| {
        value["body"]["watermark"] = json!({
            "kind": "committed",
            "unix_ms": 0
        });
    });
}

#[test]
fn detector_health_rejects_impossible_or_nonportable_knowledge() {
    let value = serde_json::to_value(health_body(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
    ))
    .unwrap_or_else(|error| panic!("serialize detector health: {error}"));
    require_invalid(value.clone(), |value| {
        value["body"]["group_binding"] = json!({"kind": "unresolved"});
        value["body"]["watermark"] = json!({"kind": "committed", "unix_ms": 1});
    });
    require_invalid(value.clone(), |value| {
        value["body"]["header"]["occurred_at_unix_ms"] =
            json!(MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1));
    });
    require_invalid(value, |value| {
        value["body"]["header"]["occurred_at_unix_ms"] = json!(MAX_ACTIVE_DEFENSE_JSON_INTEGER);
        value["body"]["watermark"] = json!({
            "kind": "committed",
            "unix_ms": MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1)
        });
    });

    let contradictory = serde_json::to_value(health_body_with_kind(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorHealthKind::CorruptState,
        contradictory_watermark(MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1)),
    ))
    .unwrap_or_else(|error| panic!("serialize contradictory detector health: {error}"));
    require_invalid(contradictory.clone(), |value| {
        value["body"]["group_binding"] = json!({"kind": "unresolved"});
    });
    require_invalid(contradictory.clone(), |value| {
        value["body"]["health_kind"] = json!("store_unavailable");
    });
    require_invalid(contradictory.clone(), |value| {
        value["body"]["watermark"]["claimed_unix_ms"] = json!("1");
    });
    require_invalid(contradictory.clone(), |value| {
        value["body"]["watermark"]["claimed_unix_ms"] = json!("01");
    });
    require_invalid(contradictory, |value| {
        value["body"]["watermark"]["claimed_unix_ms"] = json!("18446744073709551616");
    });

    let sink = Arc::new(RecordingReceiptSink::default());
    let unresolved_committed = health_outcome(health_evidence(
        DetectorGroupBindingEvidence::Unresolved,
        DetectorWatermarkEvidence::Committed { unix_ms: 1 },
        OBSERVED_AT_UNIX_MS,
    ));
    let error = writer(sink.clone())
        .attest_outcome(&unresolved_committed)
        .test_expect_err("unresolved committed watermark must be rejected");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);

    let mut unresolved_contradictory = health_evidence(
        DetectorGroupBindingEvidence::Unresolved,
        contradictory_watermark(MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1)),
        OBSERVED_AT_UNIX_MS,
    );
    unresolved_contradictory.kind = DetectorHealthKind::CorruptState;
    let error = writer(sink.clone())
        .attest_outcome(&health_outcome(unresolved_contradictory))
        .test_expect_err("unresolved contradictory watermark must be rejected");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);

    let unsafe_observation = health_outcome(health_evidence(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        DetectorWatermarkEvidence::Unknown,
        MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1),
    ));
    let error = writer(sink)
        .attest_outcome(&unsafe_observation)
        .test_expect_err("unsafe observation time must be rejected");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);

    let mut wrong_kind = health_evidence(
        DetectorGroupBindingEvidence::Resolved {
            group_key_hash: digest(3),
        },
        contradictory_watermark(MAX_ACTIVE_DEFENSE_JSON_INTEGER.saturating_add(1)),
        OBSERVED_AT_UNIX_MS,
    );
    wrong_kind.kind = DetectorHealthKind::StoreUnavailable;
    let error = writer(Arc::new(RecordingReceiptSink::default()))
        .attest_outcome(&health_outcome(wrong_kind))
        .test_expect_err("contradictory watermark with the wrong health kind must be rejected");
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
}

#[test]
fn detector_health_evidence_wire_shape_requires_both_knowledge_tags() {
    let evidence = DetectorHealthEvidence {
        tenant_id: tenant(),
        policy_version: record("policy-detector-health-v1"),
        rule_id: RuleId::new("rule-detector-health")
            .unwrap_or_else(|error| panic!("rule id: {error}")),
        rule_version_hash: digest(2),
        group_binding: DetectorGroupBindingEvidence::Unresolved,
        kind: DetectorHealthKind::CorruptEvent,
        event_id: EventId::new("event-detector-health")
            .unwrap_or_else(|error| panic!("event id: {error}")),
        observed_at_unix_ms: OBSERVED_AT_UNIX_MS,
        watermark: DetectorWatermarkEvidence::Unknown,
    };
    let value = serde_json::to_value(&evidence)
        .unwrap_or_else(|error| panic!("serialize detector health evidence: {error}"));
    assert_eq!(value["group_binding"], json!({"kind": "unresolved"}));
    assert_eq!(value["watermark"], json!({"kind": "unknown"}));
    let mut missing_group = value.clone();
    missing_group
        .as_object_mut()
        .unwrap_or_else(|| panic!("detector evidence object"))
        .remove("group_binding");
    assert!(serde_json::from_value::<DetectorHealthEvidence>(missing_group).is_err());
    let mut missing_watermark = value;
    missing_watermark
        .as_object_mut()
        .unwrap_or_else(|| panic!("detector evidence object"))
        .remove("watermark");
    assert!(serde_json::from_value::<DetectorHealthEvidence>(missing_watermark).is_err());
}
