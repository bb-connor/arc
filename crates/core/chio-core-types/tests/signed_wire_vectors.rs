#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, SignedSecurityEvent};
use chio_security_types::ports::{
    EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass, RecordId, SessionId,
    TenantId,
};
use chio_security_types::{
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity, SecuritySubject,
};

const PRODUCER_SEED: [u8; 32] = [119; 32];
const ENVELOPE: &str = "positive/signed-security-event-envelope-v1.json";

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/signed-wire")
}

fn event_body() -> SecurityEventBody {
    SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new("event-1").unwrap(),
        event_time_unix_ms: 100,
        ingest_time_unix_ms: 101,
        tenant_id: TenantId::new("tenant-1").unwrap(),
        subject: SecuritySubject {
            subject_id: RecordId::new("subject-1").unwrap(),
            agent_id: RecordId::new("agent-1").unwrap(),
            session_id: SessionId::new("session-1").unwrap(),
            capability_id: RecordId::new("capability-1").unwrap(),
            lineage_seed: LineageId::new("lineage-1").unwrap(),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-1").unwrap(),
        event_kind: SecurityEventKind::TripwireObservation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("evidence-1").unwrap()],
        producer_id: ProducerId::new("producer-1").unwrap(),
        producer_key_id: RecordId::new("key-1").unwrap(),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: RecordId::new("policy-1").unwrap(),
    })
    .unwrap()
}

fn signed_event() -> SignedSecurityEvent {
    SignedSecurityEvent::sign_with_backend(
        event_body(),
        &Ed25519Backend::new(Keypair::from_seed(&PRODUCER_SEED)),
    )
    .unwrap()
}

fn line(value: &impl serde::Serialize) -> Vec<u8> {
    let mut bytes = canonical_json_bytes(value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn committed_signed_security_event_matches_the_signing_path() {
    let committed = std::fs::read(vector_root().join(ENVELOPE)).unwrap();
    assert!(
        committed == line(&signed_event()),
        "fixture tests/bindings/vectors/security/signed-wire/{ENVELOPE} is out of date"
    );
    let decoded: SignedSecurityEvent = serde_json::from_slice(&committed).unwrap();
    assert!(decoded
        .verify_trusted_producer(
            &ProducerId::new("producer-1").unwrap(),
            &RecordId::new("key-1").unwrap(),
            &Keypair::from_seed(&PRODUCER_SEED).public_key(),
        )
        .unwrap());
}

#[test]
#[ignore = "regenerator: rewrites tests/bindings/vectors/security/signed-wire/positive/signed-security-event-envelope-v1.json"]
fn regenerate_signed_wire_security_event() {
    std::fs::write(vector_root().join(ENVELOPE), line(&signed_event())).unwrap();
}
