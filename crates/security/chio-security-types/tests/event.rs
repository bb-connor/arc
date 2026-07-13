use chio_security_types::ports::{
    Digest32, EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass, RecordId,
    RuleId, SessionId, TenantId,
};
use chio_security_types::{
    CorrelatedFinding, CorrelatedFindingInput, SecurityEventBody, SecurityEventBodyInput,
    SecurityEventKind, SecuritySeverity, SecuritySubject, MAX_EVENT_EVIDENCE_REFERENCES,
};

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn body_input() -> SecurityEventBodyInput {
    SecurityEventBodyInput {
        event_id: EventId::new("event-1")
            .unwrap_or_else(|error| panic!("invalid event id: {error}")),
        event_time_unix_ms: 100,
        ingest_time_unix_ms: 101,
        tenant_id: TenantId::new("tenant-1")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        subject: SecuritySubject {
            subject_id: record("subject-1"),
            agent_id: record("agent-1"),
            session_id: SessionId::new("session-1")
                .unwrap_or_else(|error| panic!("invalid session id: {error}")),
            capability_id: record("capability-1"),
            lineage_seed: LineageId::new("lineage-1")
                .unwrap_or_else(|error| panic!("invalid lineage id: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("receipt-1")
            .unwrap_or_else(|error| panic!("invalid receipt id: {error}")),
        event_kind: SecurityEventKind::TripwireObservation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("evidence-1")
            .unwrap_or_else(|error| panic!("invalid evidence id: {error}"))],
        producer_id: ProducerId::new("producer-1")
            .unwrap_or_else(|error| panic!("invalid producer id: {error}")),
        producer_key_id: record("key-1"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("policy-1"),
    }
}

#[test]
fn event_constructor_enforces_time_and_evidence_bounds() {
    assert!(SecurityEventBody::new(body_input()).is_ok());
    let mut future = body_input();
    future.event_time_unix_ms = 102;
    assert!(SecurityEventBody::new(future).is_err());
    let mut empty = body_input();
    empty.evidence_references.clear();
    assert!(SecurityEventBody::new(empty).is_err());
    let mut excessive = body_input();
    excessive.evidence_references = (0..=MAX_EVENT_EVIDENCE_REFERENCES)
        .map(|index| {
            OpaqueReceiptRef::new(format!("evidence-{index}"))
                .unwrap_or_else(|error| panic!("invalid evidence id: {error}"))
        })
        .collect();
    assert!(SecurityEventBody::new(excessive).is_err());
}

#[test]
fn portable_event_and_finding_reject_unknown_or_inconsistent_shapes() {
    let body = SecurityEventBody::new(body_input())
        .unwrap_or_else(|error| panic!("valid event rejected: {error}"));
    let mut value = serde_json::to_value(body)
        .unwrap_or_else(|error| panic!("event serialization failed: {error}"));
    value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SecurityEventBody>(value).is_err());

    let base = CorrelatedFindingInput {
        finding_id: record("finding-1"),
        tenant_id: TenantId::new("tenant-1")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        rule_id: RuleId::new("rule-1").unwrap_or_else(|error| panic!("invalid rule id: {error}")),
        rule_version_hash: Digest32::new([1_u8; 32]),
        policy_version: record("policy-1"),
        group_key_hash: Digest32::new([2_u8; 32]),
        ordered_event_ids: vec![],
        ordered_evidence_digests: vec![],
        first_event_time_unix_ms: 10,
        last_event_time_unix_ms: 9,
        lineage_seed: LineageId::new("lineage-1")
            .unwrap_or_else(|error| panic!("invalid lineage id: {error}")),
    };
    assert!(CorrelatedFinding::new(base).is_err());
}
