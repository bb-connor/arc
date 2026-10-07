use super::*;

const BOUNDED_LATENESS_MS: u64 = 200;

fn bystander_tenant() -> TenantId {
    TenantId::new("tenant-bystander").unwrap_or_else(|error| panic!("bystander tenant: {error}"))
}

fn detector_event(
    tenant_id: TenantId,
    event_id: &str,
    producer_key_id: &str,
    lineage_seed: &str,
    event_time_unix_ms: u64,
    ingest_time_unix_ms: u64,
    signer: &Keypair,
) -> UnverifiedSecurityEvent {
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        event_time_unix_ms,
        ingest_time_unix_ms,
        tenant_id,
        subject: SecuritySubject {
            subject_id: record("subject-rotation"),
            agent_id: record("agent-rotation"),
            session_id: SessionId::new("session-rotation")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record("capability-rotation"),
            lineage_seed: chio_security_types::ports::LineageId::new(lineage_seed)
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-rotation-source")
            .unwrap_or_else(|error| panic!("source receipt id: {error}")),
        event_kind: SecurityEventKind::CanaryInvocation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("receipt-rotation-evidence")
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id: producer(),
        producer_key_id: record(producer_key_id),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("policy-v1"),
    })
    .unwrap_or_else(|error| panic!("event body: {error}"));
    let canonical_body =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical body: {error}"));
    let signed =
        SignedSecurityEvent::sign_with_backend(body.clone(), &Ed25519Backend::new(signer.clone()))
            .unwrap_or_else(|error| panic!("sign event: {error}"));
    let source_evidence = canonical_json_bytes(&signed)
        .unwrap_or_else(|error| panic!("canonical signed event: {error}"));
    UnverifiedSecurityEvent {
        tenant_id: body.tenant_id,
        event_id: body.event_id,
        producer_id: body.producer_id,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical_body.clone())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: Digest32::new(*chio_core::sha256(&canonical_body).as_bytes()),
        source_evidence: CanonicalBody::new(source_evidence)
            .unwrap_or_else(|error| panic!("source evidence: {error}")),
    }
}

fn trusted_detector(
    tenant_id: TenantId,
    producer_key_id: &str,
    key: &Keypair,
) -> TrustedSecurityEventProducer {
    TrustedSecurityEventProducer {
        tenant_id,
        producer_id: producer(),
        producer_key_id: record(producer_key_id),
        policy_version: record("policy-v1"),
        producer_key: key.public_key(),
    }
}

struct IngressRuntime {
    ingress: VerifiedSecurityEventIngress,
    consumer: Arc<ProductionCorrelationConsumer>,
    drainer: DurableCorrelationIngress,
}

fn start_runtime(
    store: &Arc<SqliteSecurityStateStore>,
    clock: &Arc<MutableClock>,
    producers: Vec<TrustedSecurityEventProducer>,
) -> IngressRuntime {
    let verifier = Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::clone(clock) as Arc<dyn Clock>,
            producers,
            Vec::new(),
            60_000,
            BOUNDED_LATENESS_MS,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    );
    let ingress = VerifiedSecurityEventIngress::new(Arc::clone(&verifier), Arc::clone(store))
        .unwrap_or_else(|error| panic!("ingress: {error}"));
    let correlation = Arc::new(
        SqliteTemporalCorrelationPort::new(
            Arc::clone(store),
            CorrelationPolicy::new(BOUNDED_LATENESS_MS, 4_096, 8, false)
                .unwrap_or_else(|error| panic!("correlation policy: {error}")),
            vec![native_tripwire_rule()],
        )
        .unwrap_or_else(|error| panic!("correlation port: {error}")),
    );
    let consumer = Arc::new(
        ProductionCorrelationConsumer::from_parts(
            verifier,
            correlation,
            Arc::new(OneFindingAttestor),
            Arc::new(RecordingPlanner::default()),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}")),
    );
    let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
    let drainer = DurableCorrelationIngress::new(ingress_store, Arc::clone(&consumer))
        .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
    IngressRuntime {
        ingress,
        consumer,
        drainer,
    }
}

fn event_rows(connection: &Connection, table: &str, event: &UnverifiedSecurityEvent) -> u64 {
    let query = match table {
        "security_verified_events" => {
            "SELECT COUNT(*) FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2"
        }
        "security_correlation_ingress" => {
            "SELECT COUNT(*) FROM security_correlation_ingress \
             WHERE tenant_id = ?1 AND event_id = ?2"
        }
        "security_correlation_outcomes" => {
            "SELECT COUNT(*) FROM security_correlation_outcomes \
             WHERE tenant_id = ?1 AND event_id = ?2"
        }
        _ => panic!("unsupported security event table: {table}"),
    };
    let count: i64 = connection
        .query_row(
            query,
            [event.tenant_id.as_str(), event.event_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count {table}: {error}"));
    checked_sqlite_count(count, table)
}

fn pending_event_ids(store: &SqliteSecurityStateStore) -> Vec<EventId> {
    store
        .load_pending_correlation_events(16)
        .unwrap_or_else(|error| panic!("load pending ingress: {error}"))
        .as_slice()
        .iter()
        .map(|event| event.event_id.clone())
        .collect()
}

struct RotationFixture {
    _directory: tempfile::TempDir,
    store: Arc<SqliteSecurityStateStore>,
    connection: Connection,
    clock: Arc<MutableClock>,
    deferred: UnverifiedSecurityEvent,
}

fn deferred_row_signed_by(retired: &Keypair, bystander: &Keypair) -> RotationFixture {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("producer-key-rotation.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
    let clock = Arc::new(MutableClock::new(10_000));
    let deferred = detector_event(
        tenant(),
        "rotation-deferred-under-retired-key",
        "detector-key-v1",
        "lineage-rotation-deferred",
        9_900,
        10_000,
        retired,
    );
    {
        let before = start_runtime(
            &store,
            &clock,
            vec![
                trusted_detector(tenant(), "detector-key-v1", retired),
                trusted_detector(bystander_tenant(), "bystander-key-v1", bystander),
            ],
        );
        assert_eq!(
            before
                .ingress
                .verify_and_append(&deferred)
                .unwrap_or_else(|error| panic!("ingest under the original key: {error}")),
            EventAppend::Inserted
        );
        assert_eq!(
            before
                .drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("defer under the original key: {error}")),
            0
        );
    }
    assert_eq!(pending_event_ids(&store), vec![deferred.event_id.clone()]);
    assert_eq!(
        event_rows(&connection, "security_correlation_outcomes", &deferred),
        0
    );
    RotationFixture {
        _directory: directory,
        store,
        connection,
        clock,
        deferred,
    }
}

#[test]
fn durable_ingress_drains_past_a_row_signed_by_a_retired_producer_key() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);

    fixture.clock.set(10_050);
    let after = start_runtime(
        &fixture.store,
        &fixture.clock,
        vec![
            trusted_detector(tenant(), "detector-key-v2", &rotated),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ],
    );
    let rotated_event = detector_event(
        tenant(),
        "rotation-signed-by-rotated-key",
        "detector-key-v2",
        "lineage-rotation-current",
        9_950,
        10_050,
        &rotated,
    );
    let bystander_event = detector_event(
        bystander_tenant(),
        "rotation-other-tenant",
        "bystander-key-v1",
        "lineage-rotation-bystander",
        9_960,
        10_050,
        &bystander,
    );
    for event in [&rotated_event, &bystander_event] {
        assert_eq!(
            after
                .ingress
                .verify_and_append(event)
                .unwrap_or_else(|error| panic!("ingest after rotation: {error}")),
            EventAppend::Inserted
        );
    }
    assert_eq!(
        pending_event_ids(&fixture.store),
        vec![
            fixture.deferred.event_id.clone(),
            rotated_event.event_id.clone(),
            bystander_event.event_id.clone(),
        ]
    );
    let retired_error = rejected(
        after.consumer.verify_durable(&fixture.deferred),
        "retired producer key still verified after rotation",
    );
    assert_eq!(retired_error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(retired_error.code().as_str(), "store.integrity_failure");
    for event in [&rotated_event, &bystander_event] {
        assert_eq!(
            after
                .consumer
                .verify_durable(event)
                .unwrap_or_else(|error| panic!("durable reverification after rotation: {error}"))
                .event_id,
            event.event_id
        );
    }

    fixture.clock.set(10_500);
    let drained = after.drainer.drain_once(16);
    let still_pending = pending_event_ids(&fixture.store);
    assert!(
        !still_pending.contains(&rotated_event.event_id)
            && !still_pending.contains(&bystander_event.event_id),
        "a retired-key row at the head of the ingress queue blocked later due events: \
         drain_once returned {drained:?}, still pending {still_pending:?}"
    );
    for event in [&rotated_event, &bystander_event] {
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            1,
            "{} was acknowledged without a correlation outcome",
            event.event_id.as_str()
        );
    }
    assert_eq!(
        event_rows(
            &fixture.connection,
            "security_correlation_outcomes",
            &fixture.deferred
        ),
        0
    );
    assert_eq!(
        after.drainer.drain_once(16).map_err(|error| error.kind()),
        Ok(0)
    );
    assert_eq!(
        after
            .drainer
            .drain_until_empty(
                AttestedFindingResponseRecoveryLimits::new(16, 64, 5_000)
                    .unwrap_or_else(|error| panic!("startup limits: {error}")),
            )
            .map_err(|error| error.kind()),
        Ok(0)
    );
}

#[test]
fn durable_ingress_drains_every_row_when_the_producer_key_is_unchanged() {
    let original = Keypair::from_seed(&[111_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let fixture = deferred_row_signed_by(&original, &bystander);

    fixture.clock.set(10_050);
    let restarted = start_runtime(
        &fixture.store,
        &fixture.clock,
        vec![
            trusted_detector(tenant(), "detector-key-v1", &original),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ],
    );
    let later_event = detector_event(
        tenant(),
        "rotation-control-same-key",
        "detector-key-v1",
        "lineage-rotation-current",
        9_950,
        10_050,
        &original,
    );
    let bystander_event = detector_event(
        bystander_tenant(),
        "rotation-control-other-tenant",
        "bystander-key-v1",
        "lineage-rotation-bystander",
        9_960,
        10_050,
        &bystander,
    );
    for event in [&later_event, &bystander_event] {
        assert_eq!(
            restarted
                .ingress
                .verify_and_append(event)
                .unwrap_or_else(|error| panic!("ingest after restart: {error}")),
            EventAppend::Inserted
        );
    }
    assert_eq!(
        restarted
            .consumer
            .verify_durable(&fixture.deferred)
            .unwrap_or_else(|error| panic!("unchanged key reverification: {error}"))
            .event_id,
        fixture.deferred.event_id
    );

    fixture.clock.set(10_500);
    assert_eq!(
        restarted
            .drainer
            .drain_once(16)
            .unwrap_or_else(|error| panic!("drain with an unchanged key: {error}")),
        3
    );
    assert!(pending_event_ids(&fixture.store).is_empty());
    for event in [&fixture.deferred, &later_event, &bystander_event] {
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            1,
            "{} has no correlation outcome",
            event.event_id.as_str()
        );
    }
}

#[test]
fn rotation_still_refuses_retired_key_and_forged_events() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let forger = Keypair::from_seed(&[114_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);

    fixture.clock.set(10_050);
    let after = start_runtime(
        &fixture.store,
        &fixture.clock,
        vec![
            trusted_detector(tenant(), "detector-key-v2", &rotated),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ],
    );
    let refused = [
        (
            "new event signed by the retired key",
            detector_event(
                tenant(),
                "rotation-new-event-retired-key",
                "detector-key-v1",
                "lineage-rotation-refused",
                9_990,
                10_050,
                &retired,
            ),
        ),
        (
            "retired key claiming the rotated key id",
            detector_event(
                tenant(),
                "rotation-retired-key-claims-v2",
                "detector-key-v2",
                "lineage-rotation-refused",
                9_990,
                10_050,
                &retired,
            ),
        ),
        (
            "forged event claiming the rotated key id",
            detector_event(
                tenant(),
                "rotation-forged-event",
                "detector-key-v2",
                "lineage-rotation-refused",
                9_990,
                10_050,
                &forger,
            ),
        ),
        (
            "rotated key signing for another tenant",
            detector_event(
                bystander_tenant(),
                "rotation-cross-tenant-signer",
                "bystander-key-v1",
                "lineage-rotation-refused",
                9_990,
                10_050,
                &rotated,
            ),
        ),
    ];
    for (label, event) in &refused {
        let error = rejected(
            after.ingress.verify_and_append(event),
            &format!("{label} entered verified ingress"),
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");
        assert_eq!(error.code().as_str(), "store.integrity_failure", "{label}");
        for table in ["security_verified_events", "security_correlation_ingress"] {
            assert_eq!(
                event_rows(&fixture.connection, table, event),
                0,
                "{label} reached {table}"
            );
        }
    }
    assert_eq!(
        pending_event_ids(&fixture.store),
        vec![fixture.deferred.event_id.clone()]
    );

    fixture.clock.set(10_500);
    match after.drainer.drain_once(16) {
        Ok(acknowledged) => assert_eq!(acknowledged, 0),
        Err(error) => assert_eq!(error.kind(), PortErrorKind::IntegrityFailure),
    }
    assert_eq!(
        event_rows(
            &fixture.connection,
            "security_correlation_outcomes",
            &fixture.deferred
        ),
        0
    );
    for (_, event) in &refused {
        assert_eq!(
            event_rows(&fixture.connection, "security_correlation_outcomes", event),
            0
        );
    }
}

fn with_signature_from(
    event: &UnverifiedSecurityEvent,
    donor: &UnverifiedSecurityEvent,
) -> (UnverifiedSecurityEvent, SecurityEventVerificationRecord) {
    let mut envelope: serde_json::Value = serde_json::from_slice(event.source_evidence.as_bytes())
        .unwrap_or_else(|error| panic!("decode envelope: {error}"));
    let donor_envelope: serde_json::Value =
        serde_json::from_slice(donor.source_evidence.as_bytes())
            .unwrap_or_else(|error| panic!("decode donor envelope: {error}"));
    envelope["signature"] = donor_envelope["signature"].clone();
    let source_evidence = canonical_json_bytes(&envelope)
        .unwrap_or_else(|error| panic!("canonical spliced envelope: {error}"));
    let signed: SignedSecurityEvent = serde_json::from_slice(&source_evidence)
        .unwrap_or_else(|error| panic!("spliced envelope shape: {error}"));
    let body = signed.body();
    assert!(
        matches!(
            signed.verify_trusted_producer(
                &body.producer_id,
                &body.producer_key_id,
                signed.producer_key()
            ),
            Ok(false)
        ),
        "the spliced envelope must not verify under its own producer key"
    );
    let mut preimage = chio_core::security_event::EVENT_EVIDENCE_HASH_DOMAIN.to_vec();
    preimage.extend_from_slice(&source_evidence);
    let mut corrupt = event.clone();
    corrupt.source_evidence = CanonicalBody::new(source_evidence)
        .unwrap_or_else(|error| panic!("spliced source evidence: {error}"));
    let record = SecurityEventVerificationRecord {
        tenant_id: corrupt.tenant_id.clone(),
        event_id: corrupt.event_id.clone(),
        producer_id: corrupt.producer_id.clone(),
        trust_class: ProducerTrustClass::InternalDetector,
        event_time_unix_ms: corrupt.event_time_unix_ms,
        received_at_unix_ms: corrupt.received_at_unix_ms,
        canonical_body: corrupt.canonical_body.clone(),
        body_hash: corrupt.body_hash,
        evidence_hash: Digest32::new(*chio_core::sha256(&preimage).as_bytes()),
    };
    (corrupt, record)
}

fn acknowledged_flag(connection: &Connection, event: &UnverifiedSecurityEvent) -> i64 {
    connection
        .query_row(
            "SELECT acknowledged FROM security_correlation_ingress \
             WHERE tenant_id = ?1 AND event_id = ?2",
            [event.tenant_id.as_str(), event.event_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("ingress row {}: {error}", event.event_id.as_str()))
}

fn assert_corrupt_head_row_aborts_every_drain(
    envelope_signer: &Keypair,
    envelope_key_id: &str,
    current_signer: &Keypair,
    current_key_id: &str,
) {
    let bystander = Keypair::from_seed(&[113_u8; 32]);
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("corrupt-head-row.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open ingress store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect ingress store: {error}"));
    let clock = Arc::new(MutableClock::new(10_000));
    let (corrupt, corrupt_record) = with_signature_from(
        &detector_event(
            tenant(),
            "corrupt-spliced-signature",
            envelope_key_id,
            "lineage-corrupt-head",
            9_900,
            10_000,
            envelope_signer,
        ),
        &detector_event(
            tenant(),
            "corrupt-signature-donor",
            envelope_key_id,
            "lineage-corrupt-donor",
            9_900,
            10_000,
            envelope_signer,
        ),
    );
    assert_eq!(
        store
            .enqueue_verified_correlation_event(&corrupt, &corrupt_record)
            .unwrap_or_else(|error| panic!("store the corrupt row: {error}")),
        EventAppend::Inserted
    );
    let runtime = start_runtime(
        &store,
        &clock,
        vec![
            trusted_detector(tenant(), current_key_id, current_signer),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ],
    );
    let healthy = detector_event(
        tenant(),
        "corrupt-head-later-same-tenant",
        current_key_id,
        "lineage-corrupt-head-later",
        9_950,
        10_000,
        current_signer,
    );
    let bystander_event = detector_event(
        bystander_tenant(),
        "corrupt-head-other-tenant",
        "bystander-key-v1",
        "lineage-corrupt-head-bystander",
        9_960,
        10_000,
        &bystander,
    );
    for event in [&healthy, &bystander_event] {
        assert_eq!(
            runtime
                .ingress
                .verify_and_append(event)
                .unwrap_or_else(|error| panic!("ingest a healthy event: {error}")),
            EventAppend::Inserted
        );
    }
    assert_eq!(
        pending_event_ids(&store),
        vec![
            corrupt.event_id.clone(),
            healthy.event_id.clone(),
            bystander_event.event_id.clone(),
        ]
    );
    let corrupt_error = rejected(
        runtime.consumer.verify_durable(&corrupt),
        "a stored envelope with a foreign signature reverified",
    );
    assert_eq!(corrupt_error.kind(), PortErrorKind::IntegrityFailure);
    for event in [&healthy, &bystander_event] {
        assert_eq!(
            runtime
                .consumer
                .verify_durable(event)
                .unwrap_or_else(|error| panic!("healthy reverification: {error}"))
                .event_id,
            event.event_id
        );
    }

    clock.set(10_500);
    for pass in ["first", "second"] {
        let error = rejected(
            runtime.drainer.drain_once(16),
            &format!("the {pass} drain progressed past a corrupt stored row"),
        );
        assert_eq!(
            error.kind(),
            PortErrorKind::IntegrityFailure,
            "{pass} drain"
        );
        assert_eq!(
            error.code().as_str(),
            "store.integrity_failure",
            "{pass} drain"
        );
        for event in [&corrupt, &healthy, &bystander_event] {
            assert_eq!(
                acknowledged_flag(&connection, event),
                0,
                "{} was acknowledged after the {pass} drain",
                event.event_id.as_str()
            );
            assert_eq!(
                event_rows(&connection, "security_correlation_outcomes", event),
                0,
                "{} was correlated after the {pass} drain",
                event.event_id.as_str()
            );
        }
        assert_eq!(
            pending_event_ids(&store),
            vec![
                corrupt.event_id.clone(),
                healthy.event_id.clone(),
                bystander_event.event_id.clone(),
            ],
            "{pass} drain"
        );
    }
}

#[test]
fn corrupt_stored_row_aborts_the_drain_without_acknowledging_later_rows() {
    let original = Keypair::from_seed(&[111_u8; 32]);
    assert_corrupt_head_row_aborts_every_drain(
        &original,
        "detector-key-v1",
        &original,
        "detector-key-v1",
    );
}

#[test]
fn corrupt_stored_row_from_a_retired_producer_key_still_aborts_the_drain() {
    let retired = Keypair::from_seed(&[111_u8; 32]);
    let rotated = Keypair::from_seed(&[112_u8; 32]);
    assert_corrupt_head_row_aborts_every_drain(
        &retired,
        "detector-key-v1",
        &rotated,
        "detector-key-v2",
    );
}
