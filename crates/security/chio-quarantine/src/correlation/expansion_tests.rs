use crate::correlation::{
    group_hash, parse_verified_event, process_events, PartialCandidate, PartitionState,
};
use crate::rules::{RuleLimits, TemporalRule};
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    CanonicalBody, Digest32, EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass,
    RecordId, SecurityEventVerificationRecord, SessionId, TenantId,
};
use chio_security_types::{
    SecurityEventBody, SecurityEventBodyInput, SecurityEventKind, SecuritySeverity, SecuritySubject,
};
use std::cell::Cell;

thread_local! {
    static CANDIDATE_CLONES: Cell<Option<usize>> = const { Cell::new(None) };
}

// The field copies match derived Clone; only this thread's active test is counted.
impl Clone for PartialCandidate {
    fn clone(&self) -> Self {
        CANDIDATE_CLONES.with(|counter| {
            if let Some(count) = counter.get() {
                counter.set(Some(count.saturating_add(1)));
            }
        });
        Self {
            stages: self.stages.clone(),
            lineage_seed: self.lineage_seed.clone(),
        }
    }
}

struct CloneCount {
    previous: Option<usize>,
}

impl CloneCount {
    fn begin() -> Self {
        Self {
            previous: CANDIDATE_CLONES.with(|counter| counter.replace(Some(0))),
        }
    }

    fn observed(&self) -> usize {
        CANDIDATE_CLONES.with(|counter| counter.get().unwrap_or_default())
    }
}

impl Drop for CloneCount {
    fn drop(&mut self) {
        CANDIDATE_CLONES.with(|counter| counter.set(self.previous));
    }
}

fn fan_out_rule(stage_count: usize, max_partials: u32) -> TemporalRule {
    let mut stages = vec![serde_json::json!({
        "name": "root",
        "event_kind": SecurityEventKind::ToolInvocation,
        "minimum_severity": "low"
    })];
    for index in 1..stage_count {
        stages.push(serde_json::json!({
            "name": format!("stage-{index}"),
            "event_kind": SecurityEventKind::ToolInvocation,
            "minimum_severity": "low",
            "after": "root",
            "within_ms": 10
        }));
    }
    let document = serde_json::to_vec(&serde_json::json!({
        "rule_id": "bounded-fan-out",
        "policy_version": "policy-v1",
        "group_by": "session_id",
        "max_groups": 1,
        "max_partial_matches_per_group": max_partials,
        "allow_event_reuse": true,
        "stages": stages
    }))
    .unwrap_or_else(|error| panic!("rule serialization failed: {error}"));
    TemporalRule::parse_json(&document, &RuleLimits::default())
        .unwrap_or_else(|error| panic!("valid fan-out rule rejected: {error}"))
}

fn verified_event() -> SecurityEventVerificationRecord {
    let body = SecurityEventBody::new(SecurityEventBodyInput {
        event_id: EventId::new("bounded-event")
            .unwrap_or_else(|error| panic!("event id rejected: {error}")),
        event_time_unix_ms: 100,
        ingest_time_unix_ms: 200,
        tenant_id: TenantId::new("bounded-tenant")
            .unwrap_or_else(|error| panic!("tenant id rejected: {error}")),
        subject: SecuritySubject {
            subject_id: record("bounded-subject"),
            agent_id: record("bounded-agent"),
            session_id: SessionId::new("bounded-session")
                .unwrap_or_else(|error| panic!("session id rejected: {error}")),
            capability_id: record("bounded-capability"),
            lineage_seed: LineageId::new("bounded-lineage")
                .unwrap_or_else(|error| panic!("lineage id rejected: {error}")),
        },
        source_receipt_id: OpaqueReceiptRef::new("bounded-receipt")
            .unwrap_or_else(|error| panic!("receipt id rejected: {error}")),
        event_kind: SecurityEventKind::ToolInvocation,
        severity: SecuritySeverity::High,
        evidence_references: vec![OpaqueReceiptRef::new("bounded-evidence")
            .unwrap_or_else(|error| panic!("evidence id rejected: {error}"))],
        producer_id: ProducerId::new("bounded-detector")
            .unwrap_or_else(|error| panic!("producer id rejected: {error}")),
        producer_key_id: record("bounded-detector-key"),
        trust_class: ProducerTrustClass::InternalDetector,
        policy_version: record("policy-v1"),
    })
    .unwrap_or_else(|error| panic!("event body rejected: {error}"));
    let canonical = canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("event serialization failed: {error}"));
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    SecurityEventVerificationRecord {
        tenant_id: body.tenant_id,
        event_id: body.event_id,
        producer_id: body.producer_id,
        trust_class: body.trust_class,
        event_time_unix_ms: body.event_time_unix_ms,
        received_at_unix_ms: body.ingest_time_unix_ms,
        canonical_body: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("canonical event rejected: {error}")),
        body_hash,
        evidence_hash: Digest32::new(*sha256(b"bounded-evidence").as_bytes()),
    }
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id rejected: {error}"))
}

#[test]
fn fan_out_reuse_expansion_overflows_before_exceeding_linear_clone_budget() {
    const STAGE_COUNT: usize = 6;
    let rule = fan_out_rule(STAGE_COUNT, 1);
    let event = verified_event();
    let body = parse_verified_event(&event).unwrap_or_else(|()| panic!("verified event rejected"));
    let group = group_hash(&rule, &body).unwrap_or_else(|()| panic!("group hash rejected"));
    let mut state = PartitionState::empty();
    state.max_seen_event_time_unix_ms = event.event_time_unix_ms;
    let clones = CloneCount::begin();

    let result = process_events(&rule, &mut state, &[event], group, 100, 0)
        .unwrap_or_else(|()| panic!("valid expansion rejected"));

    assert!(result.overflow);
    assert!(result.suppressed);
    assert!(result.findings.is_empty());
    assert!(state.candidates.is_empty());
    assert_eq!(state.suppressed_until_unix_ms, Some(110));
    // A bounded implementation may copy the cap for base, working and each stage.
    let linear_budget = 3 * STAGE_COUNT;
    assert!(
        clones.observed() <= linear_budget,
        "six stages with cap 1 copied {} candidates; linear budget {linear_budget}",
        clones.observed()
    );
}

#[test]
fn two_stage_reuse_matches_with_one_partial_slot() {
    let rule = fan_out_rule(2, 1);
    let event = verified_event();
    let body = parse_verified_event(&event).unwrap_or_else(|()| panic!("verified event rejected"));
    let group = group_hash(&rule, &body).unwrap_or_else(|()| panic!("group hash rejected"));
    let mut state = PartitionState::empty();

    let result = process_events(&rule, &mut state, &[event], group, 100, 0)
        .unwrap_or_else(|()| panic!("valid expansion rejected"));

    assert!(!result.overflow);
    assert!(!result.suppressed);
    assert_eq!(state.candidates.len(), 1);
    assert_eq!(result.findings.len(), 1);
    let finding = result
        .findings
        .first()
        .unwrap_or_else(|| panic!("complete finding missing"));
    assert_eq!(finding.ordered_event_ids.len(), 2);
    assert!(finding
        .ordered_event_ids
        .as_slice()
        .iter()
        .all(|event_id| event_id.as_str() == "bounded-event"));
}

#[test]
fn sibling_reuse_matches_at_exact_partial_capacity() {
    let rule = fan_out_rule(3, 3);
    let event = verified_event();
    let body = parse_verified_event(&event).unwrap_or_else(|()| panic!("verified event rejected"));
    let group = group_hash(&rule, &body).unwrap_or_else(|()| panic!("group hash rejected"));
    let mut state = PartitionState::empty();

    let result = process_events(&rule, &mut state, &[event], group, 100, 0)
        .unwrap_or_else(|()| panic!("valid expansion rejected"));

    assert!(!result.overflow);
    assert!(!result.suppressed);
    assert_eq!(state.candidates.len(), 3);
    assert_eq!(result.findings.len(), 1);
    let finding = result
        .findings
        .first()
        .unwrap_or_else(|| panic!("complete finding missing"));
    assert_eq!(finding.ordered_event_ids.len(), 3);
}

#[test]
fn duplicate_partial_and_finding_do_not_overflow_a_full_capacity() {
    let rule = fan_out_rule(3, 3);
    let event = verified_event();
    let body = parse_verified_event(&event).unwrap_or_else(|()| panic!("verified event rejected"));
    let group = group_hash(&rule, &body).unwrap_or_else(|()| panic!("group hash rejected"));
    let mut state = PartitionState::empty();
    let first = process_events(
        &rule,
        &mut state,
        std::slice::from_ref(&event),
        group,
        100,
        0,
    )
    .unwrap_or_else(|()| panic!("valid expansion rejected"));
    let original_candidates = state.candidates.clone();

    let duplicate = process_events(&rule, &mut state, &[event], group, 100, 0)
        .unwrap_or_else(|()| panic!("duplicate expansion rejected"));

    assert!(!duplicate.overflow);
    assert!(!duplicate.suppressed);
    assert_eq!(state.candidates, original_candidates);
    assert_eq!(duplicate.findings, first.findings);
    assert_eq!(duplicate.findings.len(), 1);
}

#[test]
fn repeated_event_deduplicates_a_finding_at_exact_finding_capacity() {
    let rule = fan_out_rule(2, 1);
    let event = verified_event();
    let body = parse_verified_event(&event).unwrap_or_else(|()| panic!("verified event rejected"));
    let group = group_hash(&rule, &body).unwrap_or_else(|()| panic!("group hash rejected"));
    let mut state = PartitionState::empty();

    let result = process_events(&rule, &mut state, &[event.clone(), event], group, 100, 0)
        .unwrap_or_else(|()| panic!("duplicate event rejected"));

    assert!(!result.overflow);
    assert!(!result.suppressed);
    assert_eq!(state.candidates.len(), 1);
    assert_eq!(result.findings.len(), 1);
}
