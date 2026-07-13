mod support;

use chio_core_types::{canonical_json_bytes, sha256};
use chio_quarantine::{
    CorrelationPolicy, CorrelationStatus, RuleLimits, TemporalCorrelator, TemporalRule,
};
use chio_security_types::ports::{
    CanonicalBody, Digest32, EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass,
    RecordId, SecurityEventStore, SessionId, TenantId, VerifiedSecurityEvent,
};
use chio_security_types::{
    DetectorHealthKind, SecurityEventBody, SecurityEventBodyInput, SecurityEventKind,
    SecuritySeverity, SecuritySubject,
};
use std::sync::Arc;
use support::TestStore;

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("invalid tenant id: {error}"))
}

fn session(value: &str) -> SessionId {
    SessionId::new(value).unwrap_or_else(|error| panic!("invalid session id: {error}"))
}

fn lineage(value: &str) -> LineageId {
    LineageId::new(value).unwrap_or_else(|error| panic!("invalid lineage id: {error}"))
}

fn rule_with(
    rule_id: &str,
    max_groups: u32,
    max_partials: u32,
    allow_reuse: bool,
    first_kind: SecurityEventKind,
    second_kind: SecurityEventKind,
    within_ms: u64,
) -> TemporalRule {
    let first = serde_json::to_string(&first_kind)
        .unwrap_or_else(|error| panic!("serialize first event kind: {error}"));
    let second = serde_json::to_string(&second_kind)
        .unwrap_or_else(|error| panic!("serialize second event kind: {error}"));
    let document = format!(
        r#"{{"rule_id":"{rule_id}","policy_version":"policy-v1","group_by":"session_id","max_groups":{max_groups},"max_partial_matches_per_group":{max_partials},"allow_event_reuse":{allow_reuse},"stages":[{{"name":"first","event_kind":{first},"minimum_severity":"low"}},{{"name":"second","event_kind":{second},"minimum_severity":"low","after":"first","within_ms":{within_ms}}}]}}"#
    );
    TemporalRule::parse_json(document.as_bytes(), &RuleLimits::default())
        .unwrap_or_else(|error| panic!("valid rule rejected: {error}"))
}

fn event(
    tenant_id: &str,
    event_id: &str,
    session_id: &str,
    lineage_id: &str,
    kind: SecurityEventKind,
    time: u64,
    trust_class: ProducerTrustClass,
) -> VerifiedSecurityEvent {
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new(event_id)
            .unwrap_or_else(|error| panic!("invalid event id: {error}")),
        event_time_unix_ms: time,
        ingest_time_unix_ms: time.saturating_add(100),
        tenant_id: tenant(tenant_id),
        subject: SecuritySubject {
            subject_id: record("subject-1"),
            agent_id: record("agent-1"),
            session_id: session(session_id),
            capability_id: record("capability-1"),
            lineage_seed: lineage(lineage_id),
        },
        source_receipt_id: OpaqueReceiptRef::new(format!("receipt-{event_id}"))
            .unwrap_or_else(|error| panic!("invalid receipt id: {error}")),
        event_kind: kind,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new(format!("evidence-{event_id}"))
            .unwrap_or_else(|error| panic!("invalid evidence id: {error}"))],
        producer_id: ProducerId::new("detector-1")
            .unwrap_or_else(|error| panic!("invalid producer id: {error}")),
        producer_key_id: record("detector-key-1"),
        trust_class,
        policy_version: record("policy-v1"),
    })
    .unwrap_or_else(|error| panic!("valid event rejected: {error}"));
    let canonical = canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("canonical event serialization failed: {error}"));
    let evidence = sha256(format!("evidence:{event_id}").as_bytes());
    VerifiedSecurityEvent {
        tenant_id: body.tenant_id.clone(),
        event_id: body.event_id.clone(),
        producer_id: body.producer_id.clone(),
        trust_class,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("canonical body rejected: {error}")),
        body_hash: Digest32::new(*sha256(&canonical).as_bytes()),
        evidence_hash: Digest32::new(*evidence.as_bytes()),
    }
}

fn policy(lateness_ms: u64) -> CorrelationPolicy {
    CorrelationPolicy::new(lateness_ms, 4_096, 8, false)
        .unwrap_or_else(|error| panic!("valid correlation policy rejected: {error}"))
}

#[test]
fn correlation_policy_requires_bounded_nonzero_resources() {
    assert!(CorrelationPolicy::new(10, 4_096, 8, false).is_ok());
    assert!(CorrelationPolicy::new(10, 0, 8, false).is_err());
    assert!(CorrelationPolicy::new(10, 4_097, 8, false).is_err());
    assert!(CorrelationPolicy::new(10, 4_096, 0, false).is_err());
}

#[test]
fn in_order_exact_window_duplicate_unrelated_group_and_expiry_are_deterministic() {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(Arc::clone(&store), policy(0));
    let rule = rule_with(
        "credential-egress",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let first = event(
        "tenant-a",
        "event-a",
        "session-a",
        "lineage-a",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::InternalDetector,
    );
    let boundary = event(
        "tenant-a",
        "event-b",
        "session-a",
        "lineage-a",
        SecurityEventKind::EgressAttempt,
        150,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(
        engine.ingest(&rule, &first).status,
        CorrelationStatus::Accepted
    );
    let matched = engine.ingest(&rule, &boundary);
    assert_eq!(matched.status, CorrelationStatus::Matched);
    assert_eq!(matched.findings.len(), 1);
    let ids: Vec<&str> = matched.findings[0]
        .ordered_event_ids
        .as_slice()
        .iter()
        .map(EventId::as_str)
        .collect();
    assert_eq!(ids, vec!["event-a", "event-b"]);
    assert_eq!(
        engine.ingest(&rule, &boundary).status,
        CorrelationStatus::Duplicate
    );

    let unrelated = event(
        "tenant-a",
        "event-c",
        "session-b",
        "lineage-b",
        SecurityEventKind::EgressAttempt,
        151,
        ProducerTrustClass::InternalDetector,
    );
    assert!(engine.ingest(&rule, &unrelated).findings.is_empty());

    let expired_first = event(
        "tenant-a",
        "event-d",
        "session-c",
        "lineage-c",
        SecurityEventKind::CredentialAccess,
        200,
        ProducerTrustClass::InternalDetector,
    );
    let advance = event(
        "tenant-a",
        "event-e",
        "session-c",
        "lineage-c",
        SecurityEventKind::ToolInvocation,
        251,
        ProducerTrustClass::InternalDetector,
    );
    let late_second = event(
        "tenant-a",
        "event-f",
        "session-c",
        "lineage-c",
        SecurityEventKind::EgressAttempt,
        252,
        ProducerTrustClass::InternalDetector,
    );
    assert!(engine.ingest(&rule, &expired_first).findings.is_empty());
    assert!(engine.ingest(&rule, &advance).findings.is_empty());
    assert!(engine.ingest(&rule, &late_second).findings.is_empty());
}

fn run_permutation(
    order: &[usize],
) -> (
    String,
    Vec<String>,
    Arc<TestStore>,
    Vec<VerifiedSecurityEvent>,
) {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(Arc::clone(&store), policy(10));
    let rule = rule_with(
        "permutation-rule",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        10,
    );
    let events = vec![
        event(
            "tenant-a",
            "perm-first",
            "session-p",
            "lineage-p",
            SecurityEventKind::CredentialAccess,
            115,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "perm-second",
            "session-p",
            "lineage-p",
            SecurityEventKind::EgressAttempt,
            120,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "perm-watermark",
            "session-p",
            "lineage-p",
            SecurityEventKind::ToolInvocation,
            130,
            ProducerTrustClass::InternalDetector,
        ),
    ];
    let mut findings = Vec::new();
    for index in order {
        findings.extend(engine.ingest(&rule, &events[*index]).findings);
    }
    assert_eq!(findings.len(), 1);
    let ids = findings[0]
        .ordered_event_ids
        .as_slice()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    (
        findings[0].finding_id.as_str().to_owned(),
        ids,
        store,
        events,
    )
}

#[test]
fn bounded_out_of_order_permutations_and_restart_replay_produce_one_identical_finding() {
    let (first_id, first_events, _, _) = run_permutation(&[0, 1, 2]);
    let (second_id, second_events, store, events) = run_permutation(&[1, 0, 2]);
    assert_eq!(first_id, second_id);
    assert_eq!(first_events, vec!["perm-first", "perm-second"]);
    assert_eq!(first_events, second_events);

    let restarted = TemporalCorrelator::new(store, policy(10));
    let rule = rule_with(
        "permutation-rule",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        10,
    );
    let replay_findings: usize = events
        .iter()
        .map(|event| restarted.ingest(&rule, event).findings.len())
        .sum();
    assert_eq!(replay_findings, 0);
}

#[test]
fn lateness_boundary_rejects_events_at_or_behind_the_watermark() {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(store, policy(10));
    let rule = rule_with(
        "lateness-rule",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        10,
    );
    let advance = event(
        "tenant-a",
        "late-advance",
        "session-l",
        "lineage-l",
        SecurityEventKind::ToolInvocation,
        200,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(engine.ingest(&rule, &advance).watermark_unix_ms, 190);
    let too_late = event(
        "tenant-a",
        "too-late",
        "session-l",
        "lineage-l",
        SecurityEventKind::CredentialAccess,
        190,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(
        engine.ingest(&rule, &too_late).status,
        CorrelationStatus::TooLate
    );
}

#[test]
fn append_without_partition_index_recovers_fail_closed_after_watermark_advance() {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(Arc::clone(&store), policy(0));
    let rule = rule_with(
        "append-gap",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let stranded = event(
        "tenant-a",
        "stranded-event",
        "session-gap",
        "lineage-gap",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::InternalDetector,
    );
    store
        .append_verified(&stranded)
        .unwrap_or_else(|error| panic!("seed append failed: {error}"));
    let advance = event(
        "tenant-a",
        "gap-advance",
        "session-gap",
        "lineage-gap",
        SecurityEventKind::ToolInvocation,
        200,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(engine.ingest(&rule, &advance).watermark_unix_ms, 200);
    let recovered = engine.ingest(&rule, &stranded);
    assert_eq!(recovered.status, CorrelationStatus::Suppressed);
    assert!(recovered.automatic_response_suppressed);
    assert_eq!(
        recovered.detector_health[0].kind,
        DetectorHealthKind::StoreConflict
    );
}

#[test]
fn event_reuse_requires_explicit_rule_permission() {
    let no_reuse = rule_with(
        "no-reuse",
        8,
        8,
        false,
        SecurityEventKind::ToolInvocation,
        SecurityEventKind::ToolInvocation,
        1,
    );
    let allow_reuse = rule_with(
        "allow-reuse",
        8,
        8,
        true,
        SecurityEventKind::ToolInvocation,
        SecurityEventKind::ToolInvocation,
        1,
    );
    let one = event(
        "tenant-a",
        "reuse-event",
        "session-r",
        "lineage-r",
        SecurityEventKind::ToolInvocation,
        100,
        ProducerTrustClass::InternalDetector,
    );
    let blocked = TemporalCorrelator::new(Arc::new(TestStore::default()), policy(0));
    assert!(blocked.ingest(&no_reuse, &one).findings.is_empty());
    let allowed = TemporalCorrelator::new(Arc::new(TestStore::default()), policy(0));
    let outcome = allowed.ingest(&allow_reuse, &one);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].ordered_event_ids.len(), 2);
}

#[test]
fn branching_predecessors_require_every_declared_stage_before_finding() {
    let document = br#"{
      "rule_id":"branching-rule",
      "policy_version":"policy-v1",
      "group_by":"session_id",
      "max_groups":8,
      "max_partial_matches_per_group":16,
      "allow_event_reuse":false,
      "stages":[
        {"name":"first","event_kind":"credential_access","minimum_severity":"low"},
        {"name":"second","event_kind":"egress_attempt","minimum_severity":"low","after":"first","within_ms":50},
        {"name":"third","event_kind":"flow_denial","minimum_severity":"low","after":"first","within_ms":50}
      ]
    }"#;
    let rule = TemporalRule::parse_json(document, &RuleLimits::default())
        .unwrap_or_else(|error| panic!("valid branching rule rejected: {error}"));

    let incomplete_engine = TemporalCorrelator::new(Arc::new(TestStore::default()), policy(10));
    let first = event(
        "tenant-a",
        "branch-first",
        "session-branch",
        "lineage-branch",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::InternalDetector,
    );
    let third = event(
        "tenant-a",
        "branch-third",
        "session-branch",
        "lineage-branch",
        SecurityEventKind::FlowDenial,
        115,
        ProducerTrustClass::InternalDetector,
    );
    let watermark = event(
        "tenant-a",
        "branch-watermark",
        "session-branch",
        "lineage-branch",
        SecurityEventKind::ToolInvocation,
        130,
        ProducerTrustClass::InternalDetector,
    );
    assert!(incomplete_engine.ingest(&rule, &first).findings.is_empty());
    assert!(incomplete_engine.ingest(&rule, &third).findings.is_empty());
    assert!(incomplete_engine
        .ingest(&rule, &watermark)
        .findings
        .is_empty());

    let complete_engine = TemporalCorrelator::new(Arc::new(TestStore::default()), policy(10));
    let second = event(
        "tenant-a",
        "branch-second",
        "session-branch",
        "lineage-branch",
        SecurityEventKind::EgressAttempt,
        120,
        ProducerTrustClass::InternalDetector,
    );
    assert!(complete_engine.ingest(&rule, &first).findings.is_empty());
    assert!(complete_engine.ingest(&rule, &second).findings.is_empty());
    assert!(complete_engine.ingest(&rule, &third).findings.is_empty());
    let outcome = complete_engine.ingest(&rule, &watermark);
    assert_eq!(outcome.findings.len(), 1);
    let ids: Vec<&str> = outcome.findings[0]
        .ordered_event_ids
        .as_slice()
        .iter()
        .map(EventId::as_str)
        .collect();
    assert_eq!(ids, vec!["branch-first", "branch-second", "branch-third"]);
    assert_eq!(outcome.findings[0].first_event_time_unix_ms, 100);
    assert_eq!(outcome.findings[0].last_event_time_unix_ms, 120);
}

#[test]
fn nested_branch_event_without_its_predecessor_is_ignored_without_corrupting_state() {
    let document = br#"{
      "rule_id":"nested-branch-rule",
      "policy_version":"policy-v1",
      "group_by":"session_id",
      "max_groups":8,
      "max_partial_matches_per_group":32,
      "allow_event_reuse":false,
      "stages":[
        {"name":"root","event_kind":"credential_access","minimum_severity":"low"},
        {"name":"left","event_kind":"egress_attempt","minimum_severity":"low","after":"root","within_ms":50},
        {"name":"right","event_kind":"flow_denial","minimum_severity":"low","after":"root","within_ms":50},
        {"name":"leaf","event_kind":"watermark_observation","minimum_severity":"low","after":"left","within_ms":50}
      ]
    }"#;
    let rule = TemporalRule::parse_json(document, &RuleLimits::default())
        .unwrap_or_else(|error| panic!("valid nested branch rule rejected: {error}"));
    let engine = TemporalCorrelator::new(Arc::new(TestStore::default()), policy(0));
    let corpus = [
        event(
            "tenant-a",
            "nested-root",
            "session-nested",
            "lineage-nested",
            SecurityEventKind::CredentialAccess,
            100,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "nested-right",
            "session-nested",
            "lineage-nested",
            SecurityEventKind::FlowDenial,
            110,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "nested-early-leaf",
            "session-nested",
            "lineage-nested",
            SecurityEventKind::WatermarkObservation,
            115,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "nested-left",
            "session-nested",
            "lineage-nested",
            SecurityEventKind::EgressAttempt,
            120,
            ProducerTrustClass::InternalDetector,
        ),
        event(
            "tenant-a",
            "nested-leaf",
            "session-nested",
            "lineage-nested",
            SecurityEventKind::WatermarkObservation,
            130,
            ProducerTrustClass::InternalDetector,
        ),
    ];

    for input in &corpus[..4] {
        let outcome = engine.ingest(&rule, input);
        assert_ne!(outcome.status, CorrelationStatus::Suppressed);
        assert!(outcome.findings.is_empty());
    }
    let outcome = engine.ingest(&rule, &corpus[4]);
    assert_eq!(outcome.status, CorrelationStatus::Matched);
    assert_eq!(outcome.findings.len(), 1);
    let ids: Vec<&str> = outcome.findings[0]
        .ordered_event_ids
        .as_slice()
        .iter()
        .map(EventId::as_str)
        .collect();
    assert_eq!(
        ids,
        vec!["nested-root", "nested-left", "nested-right", "nested-leaf"]
    );
}

#[test]
fn partition_and_group_overflow_and_store_failure_emit_health_and_suppress_response() {
    let partition_store = Arc::new(TestStore::default());
    let partition_engine = TemporalCorrelator::new(partition_store, policy(0));
    let partition_rule = rule_with(
        "partition-cap",
        8,
        1,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    for (id, time) in [("cap-a", 100), ("cap-b", 101)] {
        let outcome = partition_engine.ingest(
            &partition_rule,
            &event(
                "tenant-a",
                id,
                "session-cap",
                "lineage-cap",
                SecurityEventKind::CredentialAccess,
                time,
                ProducerTrustClass::InternalDetector,
            ),
        );
        if id == "cap-b" {
            assert_eq!(outcome.status, CorrelationStatus::Suppressed);
            assert!(outcome.automatic_response_suppressed);
            assert_eq!(
                outcome.detector_health[0].kind,
                DetectorHealthKind::StateOverflow
            );
            let after_overflow = partition_engine.ingest(
                &partition_rule,
                &event(
                    "tenant-a",
                    "cap-second-stage",
                    "session-cap",
                    "lineage-cap",
                    SecurityEventKind::EgressAttempt,
                    102,
                    ProducerTrustClass::InternalDetector,
                ),
            );
            assert!(after_overflow.findings.is_empty());
            assert!(after_overflow.automatic_response_suppressed);
        }
    }

    let group_store = Arc::new(TestStore::default());
    let group_engine = TemporalCorrelator::new(group_store, policy(0));
    let group_rule = rule_with(
        "group-cap",
        1,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let first_group = event(
        "tenant-a",
        "group-a",
        "session-a",
        "lineage-a",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::InternalDetector,
    );
    let second_group = event(
        "tenant-a",
        "group-b",
        "session-b",
        "lineage-b",
        SecurityEventKind::CredentialAccess,
        101,
        ProducerTrustClass::InternalDetector,
    );
    assert_eq!(
        group_engine.ingest(&group_rule, &first_group).status,
        CorrelationStatus::Accepted
    );
    assert_eq!(
        group_engine.ingest(&group_rule, &second_group).status,
        CorrelationStatus::Suppressed
    );

    let failing_store = Arc::new(TestStore::default());
    failing_store.set_fail(true);
    let failing_engine = TemporalCorrelator::new(failing_store, policy(0));
    let failed = failing_engine.ingest(&group_rule, &first_group);
    assert_eq!(failed.status, CorrelationStatus::Suppressed);
    assert_eq!(
        failed.detector_health[0].kind,
        DetectorHealthKind::StoreUnavailable
    );
}

#[test]
fn tenant_and_rule_partitions_never_complete_each_others_sequences() {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(store, policy(0));
    let rule_a = rule_with(
        "isolation-a",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let rule_b = rule_with(
        "isolation-b",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let first_a = event(
        "tenant-a",
        "isolation-first-a",
        "session-i",
        "lineage-i",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::InternalDetector,
    );
    let second_other_tenant = event(
        "tenant-b",
        "isolation-second-b",
        "session-i",
        "lineage-i",
        SecurityEventKind::EgressAttempt,
        110,
        ProducerTrustClass::InternalDetector,
    );
    let second_other_rule = event(
        "tenant-a",
        "isolation-second-rule",
        "session-i",
        "lineage-i",
        SecurityEventKind::EgressAttempt,
        110,
        ProducerTrustClass::InternalDetector,
    );
    assert!(engine.ingest(&rule_a, &first_a).findings.is_empty());
    assert!(engine
        .ingest(&rule_a, &second_other_tenant)
        .findings
        .is_empty());
    assert!(engine
        .ingest(&rule_b, &second_other_rule)
        .findings
        .is_empty());
}

#[test]
fn untrusted_receipt_and_corrupt_or_cross_tenant_event_cannot_enter_automatic_partition() {
    let store = Arc::new(TestStore::default());
    let engine = TemporalCorrelator::new(store, policy(0));
    let rule = rule_with(
        "trust-boundary",
        8,
        8,
        false,
        SecurityEventKind::CredentialAccess,
        SecurityEventKind::EgressAttempt,
        50,
    );
    let advisory = event(
        "tenant-a",
        "advisory-event",
        "session-a",
        "lineage-a",
        SecurityEventKind::CredentialAccess,
        100,
        ProducerTrustClass::VerifiedReceipt,
    );
    assert_eq!(
        engine.ingest(&rule, &advisory).status,
        CorrelationStatus::AdvisoryOnly
    );

    let mut forged = event(
        "tenant-a",
        "forged-event",
        "session-a",
        "lineage-a",
        SecurityEventKind::CredentialAccess,
        101,
        ProducerTrustClass::InternalDetector,
    );
    forged.body_hash = Digest32::new([7_u8; 32]);
    assert_eq!(
        engine.ingest(&rule, &forged).status,
        CorrelationStatus::Suppressed
    );

    let mut cross_tenant = event(
        "tenant-a",
        "cross-tenant-event",
        "session-a",
        "lineage-a",
        SecurityEventKind::CredentialAccess,
        102,
        ProducerTrustClass::InternalDetector,
    );
    cross_tenant.tenant_id = tenant("tenant-b");
    assert_eq!(
        engine.ingest(&rule, &cross_tenant).status,
        CorrelationStatus::Suppressed
    );
}
