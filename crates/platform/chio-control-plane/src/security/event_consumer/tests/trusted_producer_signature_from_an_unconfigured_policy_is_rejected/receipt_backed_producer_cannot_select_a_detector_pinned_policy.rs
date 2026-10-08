use super::*;

const RECEIPT_POLICY: &str = "policy-v1";
const DETECTOR_POLICY: &str = "policy-detector-only";

fn tripwire_rule(rule_id: &str, policy_version: &str) -> TemporalRule {
    let rule = json!({
        "rule_id": rule_id,
        "policy_version": policy_version,
        "group_by": "lineage_seed",
        "max_groups": 16,
        "max_partial_matches_per_group": 16,
        "allow_event_reuse": false,
        "stages": [{
            "name": "tripwire",
            "event_kind": "tripwire_observation",
            "minimum_severity": "high"
        }]
    });
    let bytes = serde_json::to_vec(&rule).unwrap_or_else(|error| panic!("rule json: {error}"));
    TemporalRule::parse_json(&bytes, &RuleLimits::default())
        .unwrap_or_else(|error| panic!("tripwire rule {rule_id}: {error}"))
}

fn event_body(
    event_id: &str,
    producer_id: ProducerId,
    producer_key_id: &str,
    trust_class: ProducerTrustClass,
    policy_version: &str,
) -> SecurityEventBody {
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        event_time_unix_ms: 9_900,
        ingest_time_unix_ms: 10_000,
        tenant_id: tenant(),
        subject: SecuritySubject {
            subject_id: record("subject-policy-pin"),
            agent_id: record("agent-policy-pin"),
            session_id: SessionId::new("session-policy-pin")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record("capability-policy-pin"),
            lineage_seed: chio_security_types::ports::LineageId::new(format!("lineage-{event_id}"))
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-policy-pin-source")
            .unwrap_or_else(|error| panic!("source receipt id: {error}")),
        event_kind: SecurityEventKind::TripwireObservation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("receipt-policy-pin-evidence")
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id,
        producer_key_id: record(producer_key_id),
        trust_class,
        policy_version: record(policy_version),
    })
    .unwrap_or_else(|error| panic!("event body: {error}"))
}

fn detector_event(
    event_id: &str,
    policy_version: &str,
    signer: &Keypair,
) -> UnverifiedSecurityEvent {
    let body = event_body(
        event_id,
        producer(),
        "detector-key-v1",
        ProducerTrustClass::InternalDetector,
        policy_version,
    );
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

fn projected_receipt_event(
    event_id: &str,
    policy_version: &str,
    signer: &Keypair,
) -> UnverifiedSecurityEvent {
    let body = event_body(
        event_id,
        receipt_producer(),
        "receipt-key-v1",
        ProducerTrustClass::VerifiedReceipt,
        policy_version,
    );
    let canonical_body =
        canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical body: {error}"));
    let body_hash = Digest32::new(*chio_core::sha256(&canonical_body).as_bytes());
    let projection = SecurityEventReceiptProjection {
        version: SECURITY_EVENT_RECEIPT_PROJECTION_VERSION.to_string(),
        body: body.clone(),
    };
    let action = ToolCallAction::from_parameters(json!({
        "event_id": body.event_id.as_str(),
        "producer_id": body.producer_id.as_str(),
        "projection_version": SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
    }))
    .unwrap_or_else(|error| panic!("receipt action: {error}"));
    let receipt = ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: String::new(),
            timestamp: body.ingest_time_unix_ms / 1_000,
            capability_id: "chio.security-event.projection".to_string(),
            tool_server: "chio.kernel".to_string(),
            tool_name: "security_event".to_string(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
            content_hash: hex::encode(body_hash.as_bytes()),
            policy_hash: hex::encode([9_u8; 32]),
            evidence: Vec::new(),
            metadata: Some(json!({"security_event_projection": projection})),
            trust_level: TrustLevel::Verified,
            tenant_id: Some(body.tenant_id.as_str().to_string()),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &Ed25519Backend::new(signer.clone()),
    )
    .unwrap_or_else(|error| panic!("receipt sign: {error}"));
    let source_evidence =
        canonical_json_bytes(&receipt).unwrap_or_else(|error| panic!("receipt evidence: {error}"));
    UnverifiedSecurityEvent {
        tenant_id: body.tenant_id,
        event_id: body.event_id,
        producer_id: body.producer_id,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical_body)
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash,
        source_evidence: CanonicalBody::new(source_evidence)
            .unwrap_or_else(|error| panic!("source evidence: {error}")),
    }
}

struct PolicyPinRuntime {
    _directory: tempfile::TempDir,
    connection: Connection,
    correlation: Arc<SqliteTemporalCorrelationPort>,
    drainer: DurableCorrelationIngress,
}

fn start_runtime(detector_key: &Keypair, receipt_key: &Keypair) -> PolicyPinRuntime {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("receipt-policy-pin.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect security store: {error}"));
    let verifier = Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::new(FixedClock(10_000)),
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record(DETECTOR_POLICY),
                producer_key: detector_key.public_key(),
            }],
            vec![TrustedSecurityEventReceiptProducer {
                tenant_id: tenant(),
                producer_id: receipt_producer(),
                signer_key_id: record("receipt-key-v1"),
                policy_version: record(RECEIPT_POLICY),
                signer_key: receipt_key.public_key(),
            }],
            60_000,
            0,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    );
    let correlation = Arc::new(
        SqliteTemporalCorrelationPort::new(
            Arc::clone(&store),
            CorrelationPolicy::new(0, 4_096, 8, true)
                .unwrap_or_else(|error| panic!("correlation policy: {error}")),
            vec![
                tripwire_rule("rule-receipt-projection", RECEIPT_POLICY),
                tripwire_rule("rule-detector-only", DETECTOR_POLICY),
            ],
        )
        .unwrap_or_else(|error| panic!("correlation port: {error}")),
    );
    let consumer = Arc::new(
        ProductionCorrelationConsumer::from_parts(
            verifier,
            Arc::clone(&correlation) as Arc<dyn CorrelationPort>,
            Arc::new(OneFindingAttestor),
            Arc::new(RecordingPlanner::default()),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}")),
    );
    let ingress_store: Arc<dyn CorrelationIngressStore> = store;
    let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
        .unwrap_or_else(|error| panic!("durable ingress: {error}"));
    PolicyPinRuntime {
        _directory: directory,
        connection,
        correlation,
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
        "security_correlation_events" => {
            "SELECT COUNT(*) FROM security_correlation_events \
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

fn assert_never_persisted(connection: &Connection, event: &UnverifiedSecurityEvent, label: &str) {
    for table in [
        "security_verified_events",
        "security_correlation_ingress",
        "security_correlation_events",
        "security_correlation_outcomes",
    ] {
        assert_eq!(
            event_rows(connection, table, event),
            0,
            "{label} reached {table}"
        );
    }
}

fn consumed_rules(
    runtime: &PolicyPinRuntime,
    event: &UnverifiedSecurityEvent,
) -> Vec<(String, CorrelationStatus)> {
    runtime
        .drainer
        .consume(event)
        .unwrap_or_else(|error| panic!("consume {}: {error}", event.event_id.as_str()))
        .rules
        .into_iter()
        .map(|rule| (rule.rule_id.as_str().to_owned(), rule.status))
        .collect()
}

fn rule_status(rule_id: &str, status: CorrelationStatus) -> Vec<(String, CorrelationStatus)> {
    vec![(rule_id.to_owned(), status)]
}

#[test]
fn receipt_backed_event_cannot_select_a_policy_pinned_to_an_internal_detector() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    let runtime = start_runtime(&detector_key, &receipt_key);

    assert!(
        runtime.correlation.accepts_policy(&record(DETECTOR_POLICY))
            && runtime.correlation.accepts_policy(&record(RECEIPT_POLICY))
    );
    assert_eq!(
        consumed_rules(
            &runtime,
            &detector_event("policy-pin-detector", DETECTOR_POLICY, &detector_key)
        ),
        rule_status("rule-detector-only", CorrelationStatus::Matched)
    );
    assert_eq!(
        consumed_rules(
            &runtime,
            &projected_receipt_event("policy-pin-receipt", RECEIPT_POLICY, &receipt_key)
        ),
        rule_status("rule-receipt-projection", CorrelationStatus::Matched)
    );

    let off_policy = projected_receipt_event(
        "policy-pin-receipt-off-policy",
        DETECTOR_POLICY,
        &receipt_key,
    );
    let receipt: ChioReceipt = serde_json::from_slice(off_policy.source_evidence.as_bytes())
        .unwrap_or_else(|error| panic!("decode off-policy receipt: {error}"));
    assert!(receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("off-policy receipt signature: {error}")));
    assert_eq!(receipt.kernel_key, receipt_key.public_key());
    let body: SecurityEventBody = serde_json::from_slice(off_policy.canonical_body.as_bytes())
        .unwrap_or_else(|error| panic!("decode off-policy body: {error}"));
    assert_eq!(body.trust_class, ProducerTrustClass::VerifiedReceipt);
    assert_eq!(body.producer_id, receipt_producer());
    assert_eq!(body.producer_key_id, record("receipt-key-v1"));
    assert_eq!(body.policy_version, record(DETECTOR_POLICY));

    let error = match runtime.drainer.consume(&off_policy) {
        Ok(report) => panic!(
            "receipt-backed producer drove the detector-pinned policy {DETECTOR_POLICY}: \
             rules {:?}",
            report.rules
        ),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code().as_str(), "store.integrity_failure");
    assert_never_persisted(&runtime.connection, &off_policy, "off-policy receipt event");
}

#[test]
fn receipt_and_detector_events_reach_only_their_own_policy_rules() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    let runtime = start_runtime(&detector_key, &receipt_key);

    let receipt =
        projected_receipt_event("policy-pin-receipt-healthy", RECEIPT_POLICY, &receipt_key);
    assert_eq!(
        consumed_rules(&runtime, &receipt),
        rule_status("rule-receipt-projection", CorrelationStatus::Matched)
    );
    let detector = detector_event(
        "policy-pin-detector-healthy",
        DETECTOR_POLICY,
        &detector_key,
    );
    assert_eq!(
        consumed_rules(&runtime, &detector),
        rule_status("rule-detector-only", CorrelationStatus::Matched)
    );
    for event in [&receipt, &detector] {
        for table in [
            "security_verified_events",
            "security_correlation_ingress",
            "security_correlation_outcomes",
        ] {
            assert_eq!(
                event_rows(&runtime.connection, table, event),
                1,
                "{} missing from {table}",
                event.event_id.as_str()
            );
        }
    }
}

#[test]
fn pinned_detector_and_untrusted_receipt_refusals_are_preserved() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    let untrusted_key = Keypair::from_seed(&[123_u8; 32]);
    let runtime = start_runtime(&detector_key, &receipt_key);

    let refused = [
        (
            "detector event outside its pinned policy",
            detector_event(
                "policy-pin-detector-off-policy",
                RECEIPT_POLICY,
                &detector_key,
            ),
        ),
        (
            "receipt event from an untrusted signer",
            projected_receipt_event(
                "policy-pin-receipt-untrusted",
                RECEIPT_POLICY,
                &untrusted_key,
            ),
        ),
        (
            "receipt event for an unconfigured policy",
            projected_receipt_event(
                "policy-pin-receipt-unknown",
                "policy-unconfigured",
                &receipt_key,
            ),
        ),
    ];
    for (label, event) in &refused {
        let error = match runtime.drainer.consume(event) {
            Ok(report) => panic!("{label} was correlated: rules {:?}", report.rules),
            Err(error) => error,
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{label}");
        assert_eq!(error.code().as_str(), "store.integrity_failure", "{label}");
        assert_never_persisted(&runtime.connection, event, label);
    }
}

struct ReadyReceiptSink;

impl chio_security_types::ports::SecurityReceiptSink for ReadyReceiptSink {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(
        &self,
        _: &chio_security_types::ports::ReceiptAppendRequest,
    ) -> PortResult<OpaqueReceiptRef> {
        Err(PortError::unavailable())
    }
}

fn receipt_signer(signer: &Keypair, policy_version: &str) -> TrustedSecurityEventReceiptProducer {
    TrustedSecurityEventReceiptProducer {
        tenant_id: tenant(),
        producer_id: receipt_producer(),
        signer_key_id: record("receipt-key-v1"),
        policy_version: record(policy_version),
        signer_key: signer.public_key(),
    }
}

fn pinned_verifier(
    detector_key: &Keypair,
    receipt_key: &Keypair,
    receipt_policy: &str,
) -> Arc<NativeSecurityEventVerifier> {
    Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::new(FixedClock(10_000)),
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record(DETECTOR_POLICY),
                producer_key: detector_key.public_key(),
            }],
            vec![receipt_signer(receipt_key, receipt_policy)],
            60_000,
            0,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    )
}

fn policy_rules() -> Vec<TemporalRule> {
    vec![
        tripwire_rule("rule-receipt-projection", RECEIPT_POLICY),
        tripwire_rule("rule-detector-only", DETECTOR_POLICY),
    ]
}

struct ReceiptPinRuntime {
    ingress: VerifiedSecurityEventIngress,
    consumer: Arc<ProductionCorrelationConsumer>,
    drainer: DurableCorrelationIngress,
}

fn receipt_pin_runtime(
    store: &Arc<SqliteSecurityStateStore>,
    verifier: Arc<NativeSecurityEventVerifier>,
    allow_verified_receipt: bool,
) -> ReceiptPinRuntime {
    let ingress = VerifiedSecurityEventIngress::new(Arc::clone(&verifier), Arc::clone(store))
        .unwrap_or_else(|error| panic!("ingress: {error}"));
    let correlation = Arc::new(
        SqliteTemporalCorrelationPort::new(
            Arc::clone(store),
            CorrelationPolicy::new(0, 4_096, 8, allow_verified_receipt)
                .unwrap_or_else(|error| panic!("correlation policy: {error}")),
            policy_rules(),
        )
        .unwrap_or_else(|error| panic!("correlation port: {error}")),
    );
    let consumer = Arc::new(
        ProductionCorrelationConsumer::from_parts(
            verifier,
            correlation as Arc<dyn CorrelationPort>,
            Arc::new(OneFindingAttestor),
            Arc::new(RecordingPlanner::default()),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}")),
    );
    let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
    let drainer = DurableCorrelationIngress::new(ingress_store, Arc::clone(&consumer))
        .unwrap_or_else(|error| panic!("durable ingress: {error}"));
    ReceiptPinRuntime {
        ingress,
        consumer,
        drainer,
    }
}

fn open_policy_store(name: &str) -> (tempfile::TempDir, Arc<SqliteSecurityStateStore>, Connection) {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join(name);
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security store: {error}")),
    );
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect security store: {error}"));
    (directory, store, connection)
}

#[test]
fn receipt_producer_policy_pin_must_be_correlated_at_construction() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    let construct = |receipt_policy: &str| {
        let (_directory, store, _connection) = open_policy_store("receipt-policy-coverage.sqlite");
        let attestor = Arc::new(crate::security::AttestedCorrelationWriter::new(
            Arc::new(ReadyReceiptSink),
            Arc::new(TestFindingAuthority::new(&[])),
            BTreeMap::new(),
        ));
        let planner = Arc::new(recovery_planner(
            Arc::clone(&store),
            &[],
            Arc::new(MissingArtifactResponsePolicy),
            Arc::new(ArtifactEnforcingCoordinator::default()),
            Arc::new(FixedClock(10_000)),
        ));
        ProductionCorrelationConsumer::new(
            pinned_verifier(&detector_key, &receipt_key, receipt_policy),
            store,
            CorrelationPolicy::new(0, 4_096, 8, true)
                .unwrap_or_else(|error| panic!("correlation policy: {error}")),
            policy_rules(),
            attestor,
            planner,
        )
        .map(|_| ())
    };

    construct(RECEIPT_POLICY)
        .unwrap_or_else(|error| panic!("receipt producer pinned to a correlated policy: {error}"));
    for policy in ["policy-uncorrelated", "*"] {
        let error = rejected(
            construct(policy),
            &format!("a receipt producer pinned to {policy} was constructed"),
        );
        assert_eq!(error.kind(), PortErrorKind::InvalidData, "{policy}");
        assert_eq!(error.code().as_str(), "store.invalid_data", "{policy}");
    }
}

#[test]
fn receipt_policy_pin_refuses_admission_and_quarantines_a_durable_row() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    let (_directory, store, connection) = open_policy_store("receipt-policy-repin.sqlite");
    let durable =
        projected_receipt_event("policy-pin-durable-receipt", RECEIPT_POLICY, &receipt_key);
    {
        let before = receipt_pin_runtime(
            &store,
            pinned_verifier(&detector_key, &receipt_key, RECEIPT_POLICY),
            true,
        );
        assert_eq!(
            before
                .ingress
                .verify_and_append(&durable)
                .unwrap_or_else(|error| panic!("ingest under the original pin: {error}")),
            EventAppend::Inserted
        );
    }
    let repinned = receipt_pin_runtime(
        &store,
        pinned_verifier(&detector_key, &receipt_key, DETECTOR_POLICY),
        true,
    );
    assert!(matches!(
        repinned.consumer.verify_pending(&durable),
        Ok(crate::security::event_consumer::ingress::SealedEventDisposition::Rejected(
            chio_security_types::ports::CorrelationIngressRejection {
                trust_class: ProducerTrustClass::VerifiedReceipt,
                reason: chio_security_types::ports::CorrelationIngressRejectionReason::UnconfiguredPolicyVersion,
                ..
            }
        ))
    ));
    let fresh = projected_receipt_event("policy-pin-after-repin", RECEIPT_POLICY, &receipt_key);
    for (path, result) in [
        (
            "ingress",
            repinned.ingress.verify_and_append(&fresh).map(|_| ()),
        ),
        ("consume", repinned.drainer.consume(&fresh).map(|_| ())),
    ] {
        let error = rejected(
            result,
            &format!("an unpinned receipt was admitted through {path}"),
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure, "{path}");
        assert_eq!(error.code().as_str(), "store.integrity_failure", "{path}");
    }
    assert_never_persisted(&connection, &fresh, "receipt outside the current pin");

    let drained = repinned
        .drainer
        .drain_pass(16)
        .unwrap_or_else(|error| panic!("drain after the pin changed: {error}"));
    assert_eq!((drained.acknowledged, drained.rejected), (0, 1));
    let rejection: (String, String) = connection
        .query_row(
            "SELECT trust_class, reason FROM security_ingress_rejections \
             WHERE tenant_id = ?1 AND event_id = ?2",
            [durable.tenant_id.as_str(), durable.event_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("rejection row: {error}"));
    assert_eq!(
        rejection,
        (
            "verified_receipt".to_string(),
            "unconfigured_policy_version".to_string()
        )
    );
    assert_eq!(
        event_rows(&connection, "security_correlation_outcomes", &durable),
        0
    );
}

#[test]
fn allow_verified_receipt_still_governs_a_correctly_pinned_receipt() {
    let detector_key = Keypair::from_seed(&[121_u8; 32]);
    let receipt_key = Keypair::from_seed(&[122_u8; 32]);
    for (allow_verified_receipt, status, suppressed) in [
        (true, CorrelationStatus::Matched, false),
        (false, CorrelationStatus::AdvisoryOnly, true),
    ] {
        let (_directory, store, _connection) = open_policy_store("receipt-policy-allow.sqlite");
        let runtime = receipt_pin_runtime(
            &store,
            pinned_verifier(&detector_key, &receipt_key, RECEIPT_POLICY),
            allow_verified_receipt,
        );
        let report = runtime
            .drainer
            .consume(&projected_receipt_event(
                "policy-pin-allow-receipt",
                RECEIPT_POLICY,
                &receipt_key,
            ))
            .unwrap_or_else(|error| panic!("pinned receipt: {error}"));
        let rules: Vec<_> = report
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.rule_id.as_str().to_owned(),
                    rule.status,
                    rule.automatic_response_suppressed,
                )
            })
            .collect();
        assert_eq!(
            rules,
            vec![("rule-receipt-projection".to_owned(), status, suppressed)],
            "allow_verified_receipt = {allow_verified_receipt}"
        );
    }
}
