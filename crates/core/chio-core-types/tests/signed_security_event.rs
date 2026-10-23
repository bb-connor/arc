use chio_core_types::{
    CanonicalBytes, Ed25519Backend, Keypair, Signature, SignedSecurityEvent,
    CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
};
use chio_security_types::ports::{
    EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass, RecordId, SessionId,
    TenantId,
};
use chio_security_types::{
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity, SecuritySubject,
};
use serde_json::{json, Value};

fn sign_body_as(key: &Keypair, schema_id: &str, body: &SecurityEventBody) -> Signature {
    key.sign_wrapped(
        schema_id,
        &CanonicalBytes::from_serializable(body)
            .unwrap_or_else(|error| panic!("canonical security event body: {error}")),
    )
    .unwrap_or_else(|error| panic!("sign security event body: {error}"))
}

fn record_id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id {value}: {error}"))
}

fn event_id(value: &str) -> EventId {
    EventId::new(value).unwrap_or_else(|error| panic!("event id {value}: {error}"))
}

fn tenant_id(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("tenant id {value}: {error}"))
}

fn producer_id(value: &str) -> ProducerId {
    ProducerId::new(value).unwrap_or_else(|error| panic!("producer id {value}: {error}"))
}

fn body() -> SecurityEventBody {
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: event_id("event-a"),
        event_time_unix_ms: 1_710_000_000_000,
        ingest_time_unix_ms: 1_710_000_000_100,
        tenant_id: tenant_id("tenant-a"),
        subject: SecuritySubject {
            subject_id: record_id("subject-a"),
            agent_id: record_id("agent-a"),
            session_id: SessionId::new("session-a")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record_id("capability-a"),
            lineage_seed: LineageId::new("lineage-a")
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-a")
            .unwrap_or_else(|error| panic!("receipt id: {error}")),
        event_kind: SecurityEventKind::TripwireObservation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("evidence-a")
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id: producer_id("detector-a"),
        producer_key_id: record_id("detector-key-a"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record_id("policy-a"),
    })
    .unwrap_or_else(|error| panic!("security event body: {error}"))
}

fn alternate_body() -> SecurityEventBody {
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: event_id("event-b"),
        event_time_unix_ms: 1_710_000_000_010,
        ingest_time_unix_ms: 1_710_000_000_200,
        tenant_id: tenant_id("tenant-b"),
        subject: SecuritySubject {
            subject_id: record_id("subject-b"),
            agent_id: record_id("agent-b"),
            session_id: SessionId::new("session-b")
                .unwrap_or_else(|error| panic!("session id: {error}")),
            capability_id: record_id("capability-b"),
            lineage_seed: LineageId::new("lineage-b")
                .unwrap_or_else(|error| panic!("lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-b")
            .unwrap_or_else(|error| panic!("receipt id: {error}")),
        event_kind: SecurityEventKind::FlowDenial,
        severity: SecuritySeverity::Critical,
        evidence_references: vec![OpaqueReceiptRef::new("evidence-b")
            .unwrap_or_else(|error| panic!("evidence id: {error}"))],
        producer_id: producer_id("detector-b"),
        producer_key_id: record_id("detector-key-b"),
        trust_class: ProducerTrustClass::VerifiedReceipt,
        policy_version: record_id("policy-b"),
    })
    .unwrap_or_else(|error| panic!("alternate security event body: {error}"))
}

fn signed_event(key: &Keypair) -> SignedSecurityEvent {
    SignedSecurityEvent::sign_with_backend(body(), &Ed25519Backend::new(key.clone()))
        .unwrap_or_else(|error| panic!("sign security event: {error}"))
}

fn verifies_as_trusted(event: &SignedSecurityEvent, key: &Keypair) -> bool {
    event
        .verify_trusted_producer(
            &producer_id("detector-a"),
            &record_id("detector-key-a"),
            &key.public_key(),
        )
        .unwrap_or(false)
}

fn replace_at_pointer(value: &mut Value, pointer: &str, replacement: Value) {
    let slot = value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("missing mutation pointer {pointer}"));
    *slot = replacement;
}

#[test]
fn trusted_producer_round_trip_uses_the_security_event_schema() {
    let key = Keypair::from_seed(&[7; 32]);
    let signed = signed_event(&key);

    assert!(verifies_as_trusted(&signed, &key));
    assert_eq!(signed.body(), &body());
    assert_eq!(signed.producer_key(), &key.public_key());
    assert_eq!(
        signed.signature(),
        &sign_body_as(&key, CHIO_SIGNED_SECURITY_EVENT_SCHEMA, signed.body())
    );

    let encoded =
        serde_json::to_vec(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    let decoded: SignedSecurityEvent = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("deserialize event: {error}"));
    assert!(verifies_as_trusted(&decoded, &key));
}

#[test]
fn trusted_producer_binding_rejects_wrong_identity_key_id_and_key() {
    let key = Keypair::from_seed(&[7; 32]);
    let other_key = Keypair::from_seed(&[8; 32]);
    let signed = signed_event(&key);

    assert!(!signed
        .verify_trusted_producer(
            &producer_id("detector-b"),
            &record_id("detector-key-a"),
            &key.public_key(),
        )
        .unwrap_or(false));
    assert!(!signed
        .verify_trusted_producer(
            &producer_id("detector-a"),
            &record_id("detector-key-b"),
            &key.public_key(),
        )
        .unwrap_or(false));
    assert!(!signed
        .verify_trusted_producer(
            &producer_id("detector-a"),
            &record_id("detector-key-a"),
            &other_key.public_key(),
        )
        .unwrap_or(false));
}

#[test]
fn signature_under_another_schema_id_is_rejected() {
    let key = Keypair::from_seed(&[7; 32]);
    let signed = signed_event(&key);

    let mut value =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    value["signature"] = serde_json::to_value(sign_body_as(
        &key,
        chio_core_types::CHIO_DECLASSIFICATION_GRANT_SCHEMA,
        signed.body(),
    ))
    .unwrap_or_else(|error| panic!("serialize wrong-schema signature: {error}"));
    let candidate: SignedSecurityEvent = serde_json::from_value(value)
        .unwrap_or_else(|error| panic!("decode wrong-domain event: {error}"));

    assert!(!verifies_as_trusted(&candidate, &key));
}

#[test]
fn every_body_field_and_envelope_cryptographic_field_is_bound() {
    let key = Keypair::from_seed(&[7; 32]);
    let other_key = Keypair::from_seed(&[8; 32]);
    let signed = signed_event(&key);
    let alternate = alternate_body();
    let alternate_signature =
        sign_body_as(&other_key, CHIO_SIGNED_SECURITY_EVENT_SCHEMA, signed.body());

    let mutations = [
        ("/body/event_id", json!(alternate.event_id)),
        (
            "/body/event_time_unix_ms",
            json!(alternate.event_time_unix_ms),
        ),
        (
            "/body/ingest_time_unix_ms",
            json!(alternate.ingest_time_unix_ms),
        ),
        ("/body/tenant_id", json!(alternate.tenant_id)),
        ("/body/subject", json!(alternate.subject)),
        (
            "/body/source_receipt_id",
            json!(alternate.source_receipt_id),
        ),
        ("/body/event_kind", json!(alternate.event_kind)),
        ("/body/severity", json!(alternate.severity)),
        (
            "/body/evidence_references",
            json!(alternate.evidence_references),
        ),
        ("/body/producer_id", json!(alternate.producer_id)),
        ("/body/producer_key_id", json!(alternate.producer_key_id)),
        ("/body/trust_class", json!(alternate.trust_class)),
        ("/body/policy_version", json!(alternate.policy_version)),
        ("/producer_key", json!(other_key.public_key())),
        ("/signature", json!(alternate_signature)),
    ];

    for (pointer, replacement) in mutations {
        let mut value = serde_json::to_value(&signed)
            .unwrap_or_else(|error| panic!("serialize event for {pointer}: {error}"));
        replace_at_pointer(&mut value, pointer, replacement);
        let candidate: SignedSecurityEvent = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("decode mutation at {pointer}: {error}"));
        assert!(
            !verifies_as_trusted(&candidate, &key),
            "mutation at {pointer} verified"
        );
    }
}

#[test]
fn strict_wire_decode_rejects_unknown_or_unsigned_envelopes() {
    let key = Keypair::from_seed(&[7; 32]);
    let signed = signed_event(&key);

    let mut unknown_envelope =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    unknown_envelope["unknown"] = json!(true);
    assert!(serde_json::from_value::<SignedSecurityEvent>(unknown_envelope).is_err());

    let mut algorithm_member =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    algorithm_member["algorithm"] = json!("ed25519");
    assert!(serde_json::from_value::<SignedSecurityEvent>(algorithm_member).is_err());

    let mut unknown_body =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    unknown_body["body"]["unknown"] = json!(true);
    assert!(serde_json::from_value::<SignedSecurityEvent>(unknown_body).is_err());

    let mut unsigned =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    unsigned
        .as_object_mut()
        .unwrap_or_else(|| panic!("signed event envelope is an object"))
        .remove("signature");
    assert!(serde_json::from_value::<SignedSecurityEvent>(unsigned).is_err());

    let mut forged =
        serde_json::to_value(&signed).unwrap_or_else(|error| panic!("serialize event: {error}"));
    forged["signature"] = json!(sign_body_as(
        &Keypair::from_seed(&[9; 32]),
        CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
        signed.body(),
    ));
    let decoded_forgery: SignedSecurityEvent = serde_json::from_value(forged)
        .unwrap_or_else(|error| panic!("decode signed-shaped forgery: {error}"));
    assert!(
        !verifies_as_trusted(&decoded_forgery, &key),
        "deserialization alone must never establish trusted-producer provenance"
    );
}
