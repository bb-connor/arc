use super::*;
use crate::security::event_consumer::ingress::{CorrelationIngressDrain, SealedEventDisposition};
use chio_security_types::ports::{CorrelationIngressRejection, CorrelationIngressRejectionReason};
use rusqlite::OptionalExtension;

fn trusted_detector_pinned(
    tenant_id: TenantId,
    producer_key_id: &str,
    key: &Keypair,
    policy_version: &str,
) -> TrustedSecurityEventProducer {
    TrustedSecurityEventProducer {
        policy_version: record(policy_version),
        ..trusted_detector(tenant_id, producer_key_id, key)
    }
}

fn detector_evidence_hash(event: &UnverifiedSecurityEvent) -> Digest32 {
    let mut preimage = chio_core::security_event::EVENT_EVIDENCE_HASH_DOMAIN.to_vec();
    preimage.extend_from_slice(event.source_evidence.as_bytes());
    Digest32::new(*chio_core::sha256(&preimage).as_bytes())
}

fn rejection_row(
    connection: &Connection,
    event: &UnverifiedSecurityEvent,
) -> Option<(String, String, String, Vec<u8>)> {
    connection
        .query_row(
            "SELECT producer_id, trust_class, reason, evidence_hash \
             FROM security_ingress_rejections WHERE tenant_id = ?1 AND event_id = ?2",
            [event.tenant_id.as_str(), event.event_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .unwrap_or_else(|error| panic!("rejection row {}: {error}", event.event_id.as_str()))
}

fn stored_evidence_hash(connection: &Connection, event: &UnverifiedSecurityEvent) -> Vec<u8> {
    connection
        .query_row(
            "SELECT evidence_hash FROM security_correlation_ingress \
             WHERE tenant_id = ?1 AND event_id = ?2",
            [event.tenant_id.as_str(), event.event_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("ingress evidence {}: {error}", event.event_id.as_str()))
}

fn rejected_count(store: &SqliteSecurityStateStore) -> u64 {
    store
        .count_rejected_correlation_events()
        .unwrap_or_else(|error| panic!("count rejected ingress: {error}"))
}

fn pending_count(store: &SqliteSecurityStateStore) -> u64 {
    store
        .count_pending_correlation_events()
        .unwrap_or_else(|error| panic!("count pending ingress: {error}"))
}

fn drained(acknowledged: u32, rejected: u32) -> CorrelationIngressDrain {
    CorrelationIngressDrain {
        acknowledged,
        rejected,
    }
}

fn rotated_runtime(
    fixture: &RotationFixture,
    rotated: &Keypair,
    bystander: &Keypair,
) -> IngressRuntime {
    fixture.clock.set(10_050);
    start_runtime(
        &fixture.store,
        &fixture.clock,
        vec![
            trusted_detector(tenant(), "detector-key-v2", rotated),
            trusted_detector(bystander_tenant(), "bystander-key-v1", bystander),
        ],
    )
}

fn ingest_healthy_rows(
    runtime: &IngressRuntime,
    rotated: &Keypair,
    bystander: &Keypair,
    prefix: &str,
) -> [UnverifiedSecurityEvent; 2] {
    let rows = [
        detector_event(
            tenant(),
            &format!("{prefix}-rotated-key"),
            "detector-key-v2",
            &format!("lineage-{prefix}-current"),
            9_950,
            10_050,
            rotated,
        ),
        detector_event(
            bystander_tenant(),
            &format!("{prefix}-other-tenant"),
            "bystander-key-v1",
            &format!("lineage-{prefix}-bystander"),
            9_960,
            10_050,
            bystander,
        ),
    ];
    for event in &rows {
        assert_eq!(
            runtime
                .ingress
                .verify_and_append(event)
                .unwrap_or_else(|error| panic!("ingest {}: {error}", event.event_id.as_str())),
            EventAppend::Inserted
        );
    }
    rows
}

#[test]
fn drain_pass_quarantines_the_retired_key_row_and_reports_typed_progress() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);
    let after = rotated_runtime(&fixture, &rotated, &bystander);
    let healthy = ingest_healthy_rows(&after, &rotated, &bystander, "quarantine");
    assert!(matches!(
        after.consumer.verify_pending(&fixture.deferred),
        Ok(SealedEventDisposition::Rejected(
            CorrelationIngressRejection {
                trust_class: ProducerTrustClass::InternalDetector,
                reason: CorrelationIngressRejectionReason::UnconfiguredProducerKey,
                ..
            }
        ))
    ));

    fixture.clock.set(10_500);
    assert_eq!(
        after.drainer.drain_pass(16).map_err(|error| error.kind()),
        Ok(drained(2, 1))
    );
    assert_eq!(
        rejection_row(&fixture.connection, &fixture.deferred),
        Some((
            producer().as_str().to_string(),
            "internal_detector".to_string(),
            "unconfigured_producer_key".to_string(),
            stored_evidence_hash(&fixture.connection, &fixture.deferred),
        ))
    );
    assert_eq!(acknowledged_flag(&fixture.connection, &fixture.deferred), 0);
    assert_eq!(
        event_rows(
            &fixture.connection,
            "security_correlation_outcomes",
            &fixture.deferred
        ),
        0
    );
    for event in &healthy {
        assert_eq!(acknowledged_flag(&fixture.connection, event), 1);
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            1
        );
    }
    assert_eq!(rejected_count(&fixture.store), 1);
    assert_eq!(pending_count(&fixture.store), 0);
    assert_eq!(
        after.drainer.drain_pass(16).map_err(|error| error.kind()),
        Ok(drained(0, 0))
    );

    let restored = start_runtime(
        &fixture.store,
        &fixture.clock,
        vec![
            trusted_detector(tenant(), "detector-key-v1", &retired),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ],
    );
    assert_eq!(
        restored
            .drainer
            .drain_pass(16)
            .map_err(|error| error.kind()),
        Ok(drained(0, 0))
    );
    let replay = rejected(
        restored.drainer.consume(&fixture.deferred),
        "restoring the retired key readmitted a rejected row",
    );
    assert_eq!(replay.kind(), PortErrorKind::Conflict);
    assert_eq!(acknowledged_flag(&fixture.connection, &fixture.deferred), 0);
    assert_eq!(
        event_rows(
            &fixture.connection,
            "security_correlation_outcomes",
            &fixture.deferred
        ),
        0
    );
}

#[test]
fn quarantine_reason_names_the_configuration_change() {
    let original = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let cases = [
        (
            "producer binding removed",
            vec![trusted_detector(
                bystander_tenant(),
                "bystander-key-v1",
                &bystander,
            )],
            CorrelationIngressRejectionReason::UnconfiguredProducer,
            "unconfigured_producer",
        ),
        (
            "producer key id rotated",
            vec![
                trusted_detector(tenant(), "detector-key-v2", &rotated),
                trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
            ],
            CorrelationIngressRejectionReason::UnconfiguredProducerKey,
            "unconfigured_producer_key",
        ),
        (
            "producer key replaced under the same key id",
            vec![
                trusted_detector(tenant(), "detector-key-v1", &rotated),
                trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
            ],
            CorrelationIngressRejectionReason::UnconfiguredProducerKey,
            "unconfigured_producer_key",
        ),
        (
            "policy pin changed",
            vec![
                trusted_detector_pinned(tenant(), "detector-key-v1", &original, "policy-v2"),
                trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
            ],
            CorrelationIngressRejectionReason::UnconfiguredPolicyVersion,
            "unconfigured_policy_version",
        ),
    ];
    for (label, producers, reason, reason_name) in cases {
        let fixture = deferred_row_signed_by(&original, &bystander);
        fixture.clock.set(10_500);
        let after = start_runtime(&fixture.store, &fixture.clock, producers);
        assert!(
            matches!(
                after.consumer.verify_pending(&fixture.deferred),
                Ok(SealedEventDisposition::Rejected(CorrelationIngressRejection {
                    trust_class: ProducerTrustClass::InternalDetector,
                    reason: found,
                    ..
                })) if found == reason
            ),
            "{label}"
        );
        assert_eq!(
            after.drainer.drain_pass(16).map_err(|error| error.kind()),
            Ok(drained(0, 1)),
            "{label}"
        );
        assert_eq!(
            rejection_row(&fixture.connection, &fixture.deferred).map(|row| row.2),
            Some(reason_name.to_string()),
            "{label}"
        );
        assert_eq!(
            event_rows(
                &fixture.connection,
                "security_correlation_outcomes",
                &fixture.deferred
            ),
            0,
            "{label}"
        );
    }
}

#[test]
fn admission_refuses_sealed_events_outside_the_current_producer_configuration() {
    let current = Keypair::from_seed(&[112_u8; 32]);
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let unbound = Keypair::from_seed(&[115_u8; 32]);
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("admission-configuration.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
    let clock = Arc::new(MutableClock::new(10_000));
    let runtime = start_runtime(
        &store,
        &clock,
        vec![trusted_detector_pinned(
            tenant(),
            "detector-key-v2",
            &current,
            "policy-v2",
        )],
    );
    let refused = [
        (
            "unconfigured producer",
            detector_event(
                bystander_tenant(),
                "admission-unconfigured-producer",
                "bystander-key-v1",
                "lineage-admission-refused",
                9_990,
                10_000,
                &unbound,
            ),
        ),
        (
            "retired producer key",
            detector_event(
                tenant(),
                "admission-retired-key",
                "detector-key-v1",
                "lineage-admission-refused",
                9_990,
                10_000,
                &retired,
            ),
        ),
        (
            "unpinned policy version",
            detector_event(
                tenant(),
                "admission-unpinned-policy",
                "detector-key-v2",
                "lineage-admission-refused",
                9_990,
                10_000,
                &current,
            ),
        ),
    ];
    for (label, event) in &refused {
        let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
            .unwrap_or_else(|error| panic!("{label} envelope: {error}"));
        let body = signed.body();
        assert!(
            matches!(
                signed.verify_trusted_producer(
                    &body.producer_id,
                    &body.producer_key_id,
                    signed.producer_key()
                ),
                Ok(true)
            ),
            "{label} must be sealed under its own key"
        );
        for (path, result) in [
            (
                "ingress",
                runtime.ingress.verify_and_append(event).map(|_| ()),
            ),
            ("consume", runtime.drainer.consume(event).map(|_| ())),
        ] {
            let error = rejected(result, &format!("{label} was admitted through {path}"));
            assert_eq!(
                error.kind(),
                PortErrorKind::IntegrityFailure,
                "{label} {path}"
            );
            assert_eq!(
                error.code().as_str(),
                "store.integrity_failure",
                "{label} {path}"
            );
        }
        for table in ["security_verified_events", "security_correlation_ingress"] {
            assert_eq!(
                event_rows(&connection, table, event),
                0,
                "{label} reached {table}"
            );
        }
        assert_eq!(rejection_row(&connection, event), None, "{label}");
    }
    assert_eq!(rejected_count(&store), 0);
    assert_eq!(pending_count(&store), 0);
}

#[test]
fn corrupt_row_after_a_quarantined_row_still_aborts_the_pass() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);
    let (corrupt, corrupt_record) = with_signature_from(
        &detector_event(
            tenant(),
            "quarantine-then-corrupt",
            "detector-key-v1",
            "lineage-quarantine-then-corrupt",
            9_920,
            10_000,
            &retired,
        ),
        &detector_event(
            tenant(),
            "quarantine-then-corrupt-donor",
            "detector-key-v1",
            "lineage-quarantine-then-corrupt-donor",
            9_920,
            10_000,
            &retired,
        ),
    );
    assert_eq!(
        fixture
            .store
            .enqueue_verified_correlation_event(&corrupt, &corrupt_record)
            .unwrap_or_else(|error| panic!("store the corrupt row: {error}")),
        EventAppend::Inserted
    );
    let after = rotated_runtime(&fixture, &rotated, &bystander);
    let [healthy, bystander_event] =
        ingest_healthy_rows(&after, &rotated, &bystander, "quarantine-then-corrupt");
    assert_eq!(
        pending_event_ids(&fixture.store),
        vec![
            fixture.deferred.event_id.clone(),
            corrupt.event_id.clone(),
            healthy.event_id.clone(),
            bystander_event.event_id.clone(),
        ]
    );

    fixture.clock.set(10_500);
    for pass in ["first", "second"] {
        let error = rejected(
            after.drainer.drain_pass(16),
            &format!("the {pass} pass progressed past a corrupt row"),
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{pass} pass");
        assert_eq!(
            error.code().as_str(),
            "store.integrity_failure",
            "{pass} pass"
        );
        assert_eq!(
            rejection_row(&fixture.connection, &fixture.deferred).map(|row| row.2),
            Some("unconfigured_producer_key".to_string()),
            "{pass} pass"
        );
        assert_eq!(
            rejection_row(&fixture.connection, &corrupt),
            None,
            "{pass} pass"
        );
        assert_eq!(rejected_count(&fixture.store), 1, "{pass} pass");
        for event in [&corrupt, &healthy, &bystander_event] {
            assert_eq!(
                acknowledged_flag(&fixture.connection, event),
                0,
                "{} acknowledged after the {pass} pass",
                event.event_id.as_str()
            );
            assert_eq!(
                event_rows(&fixture.connection, "security_correlation_outcomes", event),
                0,
                "{} correlated after the {pass} pass",
                event.event_id.as_str()
            );
        }
        assert_eq!(
            pending_event_ids(&fixture.store),
            vec![
                corrupt.event_id.clone(),
                healthy.event_id.clone(),
                bystander_event.event_id.clone(),
            ],
            "{pass} pass"
        );
    }
}

struct RejectionWriteFails {
    inner: Arc<SqliteSecurityStateStore>,
    fail: AtomicBool,
}

impl CorrelationIngressStore for RejectionWriteFails {
    fn ensure_correlation_ingress_ready(&self) -> PortResult<()> {
        self.inner.ensure_correlation_ingress_ready()
    }

    fn enqueue_verified_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<EventAppend> {
        self.inner
            .enqueue_verified_correlation_event(event, verified)
    }

    fn load_pending_correlation_events(
        &self,
        max_results: u32,
    ) -> PortResult<UnverifiedEventBatch> {
        self.inner.load_pending_correlation_events(max_results)
    }

    fn validate_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<()> {
        self.inner
            .validate_pending_correlation_event(event, verified)
    }

    fn acknowledge_correlated_event(&self, event: &UnverifiedSecurityEvent) -> PortResult<()> {
        self.inner.acknowledge_correlated_event(event)
    }

    fn count_pending_correlation_events(&self) -> PortResult<u64> {
        self.inner.count_pending_correlation_events()
    }

    fn reject_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        rejection: &CorrelationIngressRejection,
    ) -> PortResult<()> {
        if self.fail.load(Ordering::Acquire) {
            return Err(PortError::unavailable());
        }
        self.inner
            .reject_pending_correlation_event(event, rejection)
    }

    fn count_rejected_correlation_events(&self) -> PortResult<u64> {
        self.inner.count_rejected_correlation_events()
    }
}

#[test]
fn failed_rejection_write_ends_the_pass_before_later_rows() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);
    let after = rotated_runtime(&fixture, &rotated, &bystander);
    let healthy = ingest_healthy_rows(&after, &rotated, &bystander, "failed-rejection-write");
    let failing = Arc::new(RejectionWriteFails {
        inner: Arc::clone(&fixture.store),
        fail: AtomicBool::new(true),
    });
    let failing_store: Arc<dyn CorrelationIngressStore> = failing.clone();
    let drainer = DurableCorrelationIngress::new(failing_store, Arc::clone(&after.consumer))
        .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

    fixture.clock.set(10_500);
    let error = rejected(
        drainer.drain_pass(16),
        "the pass continued after the rejection write failed",
    );
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert_eq!(rejected_count(&fixture.store), 0);
    assert_eq!(rejection_row(&fixture.connection, &fixture.deferred), None);
    let mut expected_pending = vec![fixture.deferred.event_id.clone()];
    expected_pending.extend(healthy.iter().map(|event| event.event_id.clone()));
    assert_eq!(pending_event_ids(&fixture.store), expected_pending);
    for event in &healthy {
        assert_eq!(acknowledged_flag(&fixture.connection, event), 0);
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            0
        );
    }

    failing.fail.store(false, Ordering::Release);
    assert_eq!(
        drainer.drain_pass(16).map_err(|error| error.kind()),
        Ok(drained(2, 1))
    );
}

#[test]
fn store_rejection_is_exact_terminal_and_refuses_acknowledged_rows() {
    let key = Keypair::from_seed(&[111_u8; 32]);
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("store-rejection.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
    let clock = Arc::new(MutableClock::new(10_000));
    let runtime = start_runtime(
        &store,
        &clock,
        vec![trusted_detector(tenant(), "detector-key-v1", &key)],
    );
    let acknowledged = detector_event(
        tenant(),
        "store-rejection-acknowledged",
        "detector-key-v1",
        "lineage-store-rejection-acknowledged",
        9_900,
        10_000,
        &key,
    );
    assert_eq!(
        runtime
            .ingress
            .verify_and_append(&acknowledged)
            .unwrap_or_else(|error| panic!("ingest the acknowledged row: {error}")),
        EventAppend::Inserted
    );
    clock.set(10_500);
    assert_eq!(
        runtime.drainer.drain_pass(16).map_err(|error| error.kind()),
        Ok(drained(1, 0))
    );
    let pending = detector_event(
        tenant(),
        "store-rejection-pending",
        "detector-key-v1",
        "lineage-store-rejection-pending",
        10_450,
        10_500,
        &key,
    );
    assert_eq!(
        runtime
            .ingress
            .verify_and_append(&pending)
            .unwrap_or_else(|error| panic!("ingest the pending row: {error}")),
        EventAppend::Inserted
    );
    let verified = runtime
        .consumer
        .verify_durable(&pending)
        .unwrap_or_else(|error| panic!("verify the pending row: {error}"));
    let rejection = CorrelationIngressRejection {
        trust_class: ProducerTrustClass::InternalDetector,
        reason: CorrelationIngressRejectionReason::UnconfiguredProducerKey,
        evidence_hash: verified.evidence_hash,
    };
    assert_eq!(detector_evidence_hash(&pending), verified.evidence_hash);
    let unknown = detector_event(
        tenant(),
        "store-rejection-unknown",
        "detector-key-v1",
        "lineage-store-rejection-unknown",
        10_450,
        10_500,
        &key,
    );
    let rebound = detector_event(
        tenant(),
        "store-rejection-pending",
        "detector-key-v1",
        "lineage-store-rejection-rebound",
        10_450,
        10_500,
        &key,
    );
    let refusals = [
        (
            "an event that was never admitted",
            &unknown,
            CorrelationIngressRejection {
                evidence_hash: detector_evidence_hash(&unknown),
                ..rejection.clone()
            },
            PortErrorKind::IntegrityFailure,
        ),
        (
            "an evidence hash of another envelope",
            &pending,
            CorrelationIngressRejection {
                evidence_hash: detector_evidence_hash(&acknowledged),
                ..rejection.clone()
            },
            PortErrorKind::IntegrityFailure,
        ),
        (
            "another envelope under the admitted tenant and event id",
            &rebound,
            CorrelationIngressRejection {
                evidence_hash: detector_evidence_hash(&rebound),
                ..rejection.clone()
            },
            PortErrorKind::Conflict,
        ),
        (
            "an acknowledged row",
            &acknowledged,
            CorrelationIngressRejection {
                evidence_hash: detector_evidence_hash(&acknowledged),
                ..rejection.clone()
            },
            PortErrorKind::Conflict,
        ),
    ];
    for (label, event, candidate, kind) in &refusals {
        let error = rejected(
            store.reject_pending_correlation_event(event, candidate),
            &format!("{label} was rejected"),
        );
        assert_eq!(error.kind(), *kind, "{label}");
    }
    assert_eq!(rejected_count(&store), 0);
    assert_eq!(acknowledged_flag(&connection, &acknowledged), 1);

    for attempt in ["first", "repeated"] {
        store
            .reject_pending_correlation_event(&pending, &rejection)
            .unwrap_or_else(|error| panic!("{attempt} rejection: {error}"));
    }
    assert_eq!(rejected_count(&store), 1);
    let changed_reason = rejected(
        store.reject_pending_correlation_event(
            &pending,
            &CorrelationIngressRejection {
                reason: CorrelationIngressRejectionReason::UnconfiguredPolicyVersion,
                ..rejection.clone()
            },
        ),
        "a second rejection reason replaced the first",
    );
    assert_eq!(changed_reason.kind(), PortErrorKind::Conflict);
    for (label, result) in [
        (
            "validate",
            store.validate_pending_correlation_event(&pending, &verified),
        ),
        ("acknowledge", store.acknowledge_correlated_event(&pending)),
        (
            "enqueue",
            store
                .enqueue_verified_correlation_event(&pending, &verified)
                .map(|_| ()),
        ),
    ] {
        let error = rejected(result, &format!("{label} accepted a rejected row"));
        assert_eq!(error.kind(), PortErrorKind::Conflict, "{label}");
    }
    assert_eq!(acknowledged_flag(&connection, &pending), 0);
    assert!(pending_event_ids(&store).is_empty());
    assert_eq!(pending_count(&store), 0);
    store
        .ensure_correlation_ingress_ready()
        .unwrap_or_else(|error| panic!("readiness after rejection: {error}"));
}

#[test]
fn readiness_refuses_unbound_or_extended_rejection_state() {
    let key = Keypair::from_seed(&[111_u8; 32]);
    for tamper in [
        "rejection of an acknowledged row",
        "extra rejection trigger",
    ] {
        let directory =
            chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("rejection-readiness.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
        let clock = Arc::new(MutableClock::new(10_000));
        let runtime = start_runtime(
            &store,
            &clock,
            vec![trusted_detector(tenant(), "detector-key-v1", &key)],
        );
        let event = detector_event(
            tenant(),
            "rejection-readiness",
            "detector-key-v1",
            "lineage-rejection-readiness",
            9_900,
            10_000,
            &key,
        );
        assert_eq!(
            runtime
                .ingress
                .verify_and_append(&event)
                .unwrap_or_else(|error| panic!("ingest: {error}")),
            EventAppend::Inserted
        );
        clock.set(10_500);
        assert_eq!(
            runtime.drainer.drain_pass(16).map_err(|error| error.kind()),
            Ok(drained(1, 0))
        );
        store
            .ensure_correlation_ingress_ready()
            .unwrap_or_else(|error| panic!("readiness before {tamper}: {error}"));
        let statement = match tamper {
            "rejection of an acknowledged row" => {
                "INSERT INTO security_ingress_rejections \
                 (tenant_id, event_id, producer_id, trust_class, reason, evidence_hash) \
                 SELECT tenant_id, event_id, producer_id, 'internal_detector', \
                 'unconfigured_producer_key', evidence_hash \
                 FROM security_correlation_ingress WHERE acknowledged = 1"
            }
            _ => {
                "CREATE TRIGGER security_ingress_rejections_extra \
                 AFTER INSERT ON security_ingress_rejections BEGIN SELECT 1; END"
            }
        };
        connection
            .execute_batch(statement)
            .unwrap_or_else(|error| panic!("tamper with {tamper}: {error}"));
        let error = rejected(
            store.ensure_correlation_ingress_ready(),
            &format!("readiness accepted {tamper}"),
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{tamper}");
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let error = rejected(
            DurableCorrelationIngress::new(ingress_store, Arc::clone(&runtime.consumer)),
            &format!("the drainer started with {tamper}"),
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{tamper}");
    }
}

#[test]
fn startup_drain_counts_a_quarantined_row_as_progress() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);
    let after = rotated_runtime(&fixture, &rotated, &bystander);
    let healthy = ingest_healthy_rows(&after, &rotated, &bystander, "startup-progress");

    fixture.clock.set(10_500);
    assert_eq!(
        after
            .drainer
            .drain_until_empty(
                AttestedFindingResponseRecoveryLimits::new(1, 64, 5_000)
                    .unwrap_or_else(|error| panic!("startup limits: {error}")),
            )
            .map_err(|error| error.kind()),
        Ok(2)
    );
    assert_eq!(pending_count(&fixture.store), 0);
    assert_eq!(rejected_count(&fixture.store), 1);
    for event in &healthy {
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            1
        );
    }
}

#[test]
fn receipt_signer_replacement_quarantines_the_sealed_receipt_row() {
    let detector = Keypair::from_seed(&[111_u8; 32]);
    let original_signer = Keypair::from_seed(&[121_u8; 32]);
    let replacement_signer = Keypair::from_seed(&[122_u8; 32]);
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("receipt-signer-replacement.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
    let clock = Arc::new(MutableClock::new(10_000));
    let receipt_signer = |signer: &Keypair| TrustedSecurityEventReceiptProducer {
        tenant_id: tenant(),
        producer_id: receipt_producer(),
        signer_key_id: record("receipt-key-v1"),
        signer_key: signer.public_key(),
    };
    let event = receipt_event(&original_signer, ToolOrigin::ChioInternal, 9_900, 10_000);
    {
        let before = start_runtime_with_receipts(
            &store,
            &clock,
            vec![trusted_detector(tenant(), "detector-key-v1", &detector)],
            vec![receipt_signer(&original_signer)],
        );
        assert_eq!(
            before
                .ingress
                .verify_and_append(&event)
                .unwrap_or_else(|error| panic!("ingest the receipt row: {error}")),
            EventAppend::Inserted
        );
    }
    let after = start_runtime_with_receipts(
        &store,
        &clock,
        vec![trusted_detector(tenant(), "detector-key-v1", &detector)],
        vec![receipt_signer(&replacement_signer)],
    );
    assert!(matches!(
        after.consumer.verify_pending(&event),
        Ok(SealedEventDisposition::Rejected(
            CorrelationIngressRejection {
                trust_class: ProducerTrustClass::VerifiedReceipt,
                reason: CorrelationIngressRejectionReason::UnconfiguredProducerKey,
                ..
            }
        ))
    ));
    let error = rejected(
        after.drainer.consume(&event),
        "a receipt from the replaced signer was admitted",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);

    clock.set(10_500);
    assert_eq!(
        after.drainer.drain_pass(16).map_err(|error| error.kind()),
        Ok(drained(0, 1))
    );
    assert_eq!(
        rejection_row(&connection, &event).map(|row| (row.1, row.2)),
        Some((
            "verified_receipt".to_string(),
            "unconfigured_producer_key".to_string()
        ))
    );
    assert_eq!(
        event_rows(&connection, "security_correlation_outcomes", &event),
        0
    );
    assert_eq!(acknowledged_flag(&connection, &event), 0);
}
