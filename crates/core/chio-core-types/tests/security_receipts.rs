use chio_core_types::canonical_json_string;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::security::{
    active_defense_body_digest, active_defense_evidence_id, ActiveDefenseReceiptBody,
    ActiveDefenseReceiptKind,
};
use serde_json::{json, Value};

const OCCURRED_AT_UNIX_MS: u64 = 1_700_000_000_123;

const FLOW_DENIAL_CANONICAL: &str = concat!(
    "{\"body\":{\"denial_code\":\"flow.clearance_denied\",",
    "\"destination_label_hash\":[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,",
    "4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],",
    "\"event_id\":\"event-flow-001\",",
    "\"guard_evidence_hash\":[5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,",
    "5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],",
    "\"header\":{\"occurred_at_unix_ms\":1700000000123,",
    "\"prior_receipt_ids\":[\"receipt-001\",\"receipt-002\"],",
    "\"schema_version\":1,\"tenant_id\":\"tenant-a\",",
    "\"transition_id\":\"transition-flow-001\"},",
    "\"policy\":{\"policy_hash\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,",
    "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],\"policy_version\":\"policy-v7\"},",
    "\"request_hash\":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,",
    "2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],",
    "\"source_label_hash\":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,",
    "3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]},\"kind\":\"flow_denial\"}"
);

fn digest(byte: u8) -> Value {
    json!(vec![byte; 32])
}

fn header(transition_id: &str) -> Value {
    json!({
        "schema_version": 1,
        "occurred_at_unix_ms": OCCURRED_AT_UNIX_MS,
        "tenant_id": "tenant-a",
        "transition_id": transition_id,
        "prior_receipt_ids": ["receipt-001", "receipt-002"]
    })
}

fn single_prior_header(transition_id: &str) -> Value {
    let mut value = header(transition_id);
    value["prior_receipt_ids"] = json!(["receipt-001"]);
    value
}

fn policy() -> Value {
    json!({
        "policy_version": "policy-v7",
        "policy_hash": digest(1)
    })
}

fn response_binding() -> Value {
    json!({
        "policy": policy(),
        "plan_hash": digest(6),
        "action_id": "action-001",
        "trigger_finding_id": "finding-001",
        "trigger_finding_hash": digest(7),
        "trigger_finding_receipt_id": "receipt-001",
        "affected_set_hash": digest(8),
        "plan_expires_at_unix_ms": OCCURRED_AT_UNIX_MS + 100_000
    })
}

fn execution_dispatch_binding() -> Value {
    json!({
        "schema_version": 1,
        "tenant_id": "tenant-a",
        "dispatch_id": "dispatch-001",
        "action_id": "action-001",
        "plan_hash": digest(6),
        "executor_authority_id": "response-authority-001",
        "executor_authority_generation": 1,
        "authorization_capability_hash": digest(40),
        "governed_intent_hash": digest(41),
        "policy_decision_hash": digest(42),
        "approval": { "approval_mode": "automatic" },
        "authorized_at_unix_ms": OCCURRED_AT_UNIX_MS - 10
    })
}

fn effect(effect_id: &str, ordinal: u16, kind: &str) -> Value {
    json!({
        "effect_id": effect_id,
        "ordinal": ordinal,
        "kind": kind,
        "target": {
            "target_type": "session",
            "session_id": "session-a"
        },
        "contribution_hash": digest(10 + u8::try_from(ordinal).unwrap_or_default()),
        "observed_base_version_hash": digest(20 + u8::try_from(ordinal).unwrap_or_default())
    })
}

fn effect_outcome(effect: Value, state: &str, byte: u8) -> Value {
    json!({
        "effect": effect,
        "outcome": {
            "state": state,
            "resulting_version_hash": digest(byte)
        }
    })
}

fn fixture(kind: ActiveDefenseReceiptKind) -> Value {
    match kind {
        ActiveDefenseReceiptKind::FlowDenial => json!({
            "kind": "flow_denial",
            "body": {
                "header": header("transition-flow-001"),
                "policy": policy(),
                "request_hash": digest(2),
                "source_label_hash": digest(3),
                "destination_label_hash": digest(4),
                "guard_evidence_hash": digest(5),
                "denial_code": "flow.clearance_denied",
                "event_id": "event-flow-001"
            }
        }),
        ActiveDefenseReceiptKind::DeclassificationConsumption => json!({
            "kind": "declassification_consumption",
            "body": {
                "header": header("transition-grant-consume-001"),
                "policy": policy(),
                "grant_id": "grant-001",
                "grant_hash": digest(2),
                "request_hash": digest(3),
                "event_id": "event-grant-consume-001",
                "state": "consumed_pending_dispatch"
            }
        }),
        ActiveDefenseReceiptKind::DeclassificationOutcome => json!({
            "kind": "declassification_outcome",
            "body": {
                "header": header("transition-grant-release-001"),
                "policy": policy(),
                "grant_id": "grant-001",
                "grant_hash": digest(2),
                "request_hash": digest(3),
                "event_id": "event-grant-release-001",
                "from_state": "consumed_pending_dispatch",
                "to_state": "released"
            }
        }),
        ActiveDefenseReceiptKind::TripwireObservation => json!({
            "kind": "tripwire_observation",
            "body": {
                "header": header("transition-tripwire-001"),
                "policy": policy(),
                "request_id": "request-tripwire-001",
                "request_hash": digest(2),
                "event_id": "event-tripwire-001",
                "tripwire_kind": "honey_tool",
                "artifact_id_hash": digest(3),
                "artifact_version_hash": digest(4),
                "observation_hash": digest(5),
                "severity": "high"
            }
        }),
        ActiveDefenseReceiptKind::CorrelatedFinding => json!({
            "kind": "correlated_finding",
            "body": {
                "header": header("transition-finding-001"),
                "policy": policy(),
                "finding_id": "finding-001",
                "finding_hash": digest(2),
                "rule_id": "rule-001",
                "rule_version_hash": digest(3),
                "group_key_hash": digest(4),
                "ordered_event_ids": ["event-001", "event-002"],
                "ordered_evidence_digests": [digest(5), digest(6)],
                "ordered_source_receipt_ids": ["receipt-001", "receipt-002"],
                "first_event_time_unix_ms": OCCURRED_AT_UNIX_MS - 20,
                "last_event_time_unix_ms": OCCURRED_AT_UNIX_MS - 10,
                "lineage_seed": "lineage-001"
            }
        }),
        ActiveDefenseReceiptKind::ResponsePlan => json!({
            "kind": "response_plan",
            "body": {
                "header": header("transition-plan-001"),
                "response": response_binding(),
                "plan_created_at_unix_ms": OCCURRED_AT_UNIX_MS - 1,
                "effects": [
                    effect("effect-001", 0, "throttle_session"),
                    effect("effect-002", 1, "restrict_egress")
                ]
            }
        }),
        ActiveDefenseReceiptKind::ResponseStateTransition => json!({
            "kind": "response_state_transition",
            "body": {
                "header": single_prior_header("transition-response-applying-001"),
                "response": response_binding(),
                "generation": 1,
                "from_state": "planned",
                "to_state": "applying",
                "cause": "apply_started",
                "applying_lease_expires_at_unix_ms": OCCURRED_AT_UNIX_MS + 1_000,
                "scheduler_lease_owner_id": null,
                "scheduler_fencing_token": null,
                "error_code": null
            }
        }),
        ActiveDefenseReceiptKind::EffectTransition => json!({
            "kind": "effect_transition",
            "body": {
                "header": single_prior_header("transition-effect-001"),
                "response": response_binding(),
                "effect": effect("effect-002", 1, "restrict_egress"),
                "generation": 4,
                "scheduler_fencing_token": 9,
                "outcome": {
                    "state": "applied",
                    "resulting_version_hash": digest(30)
                }
            }
        }),
        ActiveDefenseReceiptKind::ResponseCompletion => json!({
            "kind": "response_completion",
            "body": {
                "header": single_prior_header("transition-response-complete-001"),
                "response": response_binding(),
                "execution_dispatch": null,
                "dispatch_authorization_hash": null,
                "response_generation": 7,
                "response_body_hash": digest(29),
                "final_state": "active",
                "error_code": null,
                "effects": [
                    effect_outcome(
                        effect("effect-001", 0, "throttle_session"),
                        "applied",
                        30
                    ),
                    effect_outcome(
                        effect("effect-002", 1, "restrict_egress"),
                        "applied",
                        31
                    )
                ]
            }
        }),
        ActiveDefenseReceiptKind::LiftRollbackCompletion => json!({
            "kind": "lift_rollback_completion",
            "body": {
                "header": single_prior_header("transition-lift-complete-001"),
                "response": response_binding(),
                "execution_dispatch": null,
                "dispatch_authorization_hash": null,
                "response_generation": 11,
                "response_body_hash": digest(39),
                "final_state": "lifted",
                "effects": [
                    effect_outcome(
                        effect("effect-001", 0, "throttle_session"),
                        "restored",
                        40
                    ),
                    effect_outcome(
                        effect("effect-002", 1, "restrict_egress"),
                        "restored",
                        41
                    )
                ]
            }
        }),
        ActiveDefenseReceiptKind::DetectorHealth => json!({
            "kind": "detector_health",
            "body": {
                "header": header("transition-detector-health-001"),
                "policy": policy(),
                "rule_id": "rule-001",
                "rule_version_hash": digest(2),
                "group_binding": {
                    "kind": "resolved",
                    "group_key_hash": digest(3)
                },
                "event_id": "event-detector-health-001",
                "health_kind": "truncated_scan",
                "watermark": {
                    "kind": "committed",
                    "unix_ms": OCCURRED_AT_UNIX_MS - 1
                },
                "evidence_hash": digest(4)
            }
        }),
        ActiveDefenseReceiptKind::SchedulerHealth => json!({
            "kind": "scheduler_health",
            "body": {
                "header": header("transition-scheduler-health-001"),
                "response": response_binding(),
                "event_id": "scheduler-health-001",
                "first_failure_at_unix_ms": OCCURRED_AT_UNIX_MS - 50,
                "attempts": 3,
                "scheduler_fencing_token": 9,
                "error_code": "scheduler.store_unavailable",
                "evidence_hash": digest(2)
            }
        }),
    }
}

fn all_kinds() -> [ActiveDefenseReceiptKind; 12] {
    [
        ActiveDefenseReceiptKind::FlowDenial,
        ActiveDefenseReceiptKind::DeclassificationConsumption,
        ActiveDefenseReceiptKind::DeclassificationOutcome,
        ActiveDefenseReceiptKind::TripwireObservation,
        ActiveDefenseReceiptKind::CorrelatedFinding,
        ActiveDefenseReceiptKind::ResponsePlan,
        ActiveDefenseReceiptKind::ResponseStateTransition,
        ActiveDefenseReceiptKind::EffectTransition,
        ActiveDefenseReceiptKind::ResponseCompletion,
        ActiveDefenseReceiptKind::LiftRollbackCompletion,
        ActiveDefenseReceiptKind::DetectorHealth,
        ActiveDefenseReceiptKind::SchedulerHealth,
    ]
}

fn parse(value: Value) -> ActiveDefenseReceiptBody {
    serde_json::from_value(value)
        .unwrap_or_else(|error| panic!("active-defense fixture must validate: {error}"))
}

#[derive(Clone, Debug)]
enum JsonPathSegment {
    Key(String),
    Index(usize),
}

fn collect_semantic_field_paths(
    value: &Value,
    current: &mut Vec<JsonPathSegment>,
    paths: &mut Vec<Vec<JsonPathSegment>>,
) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                current.push(JsonPathSegment::Key(key.clone()));
                collect_semantic_field_paths(child, current, paths);
                current.pop();
            }
        }
        Value::Array(items)
            if items
                .iter()
                .all(|item| !matches!(item, Value::Object(_) | Value::Array(_))) =>
        {
            paths.push(current.clone());
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                current.push(JsonPathSegment::Index(index));
                collect_semantic_field_paths(child, current, paths);
                current.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            paths.push(current.clone());
        }
    }
}

fn mutate_semantic_field(value: &mut Value) -> bool {
    match value {
        Value::Null => {
            *value = json!("tampered");
            true
        }
        Value::Bool(flag) => {
            *flag = !*flag;
            true
        }
        Value::Number(number) => {
            let Some(original) = number.as_u64() else {
                return false;
            };
            let Some(mutated) = original.checked_add(1) else {
                return false;
            };
            *number = serde_json::Number::from(mutated);
            true
        }
        Value::String(text) => {
            text.push_str("-tampered");
            true
        }
        Value::Array(items) => {
            if let Some(first) = items.first_mut() {
                mutate_semantic_field(first)
            } else {
                items.push(json!("tampered"));
                true
            }
        }
        Value::Object(_) => false,
    }
}

fn mutate_at_path(value: &mut Value, path: &[JsonPathSegment]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return mutate_semantic_field(value);
    };
    match (first, value) {
        (JsonPathSegment::Key(key), Value::Object(fields)) => fields
            .get_mut(key)
            .is_some_and(|child| mutate_at_path(child, rest)),
        (JsonPathSegment::Index(index), Value::Array(items)) => items
            .get_mut(*index)
            .is_some_and(|child| mutate_at_path(child, rest)),
        _ => false,
    }
}

fn signed_active_defense_receipt(kind: ActiveDefenseReceiptKind) -> ChioReceipt {
    let keypair = Keypair::from_seed(&[83_u8; 32]);
    let active_defense_body = fixture(kind);
    let body = ChioReceiptBody {
        id: format!("active-defense-field-matrix-{kind:?}"),
        timestamp: OCCURRED_AT_UNIX_MS / 1_000,
        capability_id: "chio.active-defense.receipt".to_string(),
        tool_server: "chio.kernel".to_string(),
        tool_name: "active_defense_evidence".to_string(),
        action: ToolCallAction::from_parameters(json!({
            "receipt_kind": format!("{kind:?}")
        }))
        .unwrap_or_else(|error| panic!("active-defense receipt action: {error}")),
        decision: None,
        receipt_kind: ReceiptKind::TraceObservation,
        boundary_class: BoundaryClass::DetectOnly,
        observation_outcome: Some(ObservationOutcome::Observed),
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: Vec::new(),
        content_hash: hex::encode([84_u8; 32]),
        policy_hash: hex::encode([85_u8; 32]),
        evidence: Vec::new(),
        metadata: Some(json!({"active_defense_body": active_defense_body})),
        trust_level: TrustLevel::Verified,
        tenant_id: Some("tenant-a".to_string()),
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, &keypair)
        .unwrap_or_else(|error| panic!("sign active-defense receipt: {error}"))
}

#[test]
fn closed_vocabulary_round_trips_every_kind() {
    for expected_kind in all_kinds() {
        let body = parse(fixture(expected_kind));
        assert_eq!(body.kind(), expected_kind);
        body.validate()
            .unwrap_or_else(|error| panic!("validated body became invalid: {error}"));

        let encoded = serde_json::to_value(&body)
            .unwrap_or_else(|error| panic!("active-defense body must serialize: {error}"));
        let decoded: ActiveDefenseReceiptBody = serde_json::from_value(encoded)
            .unwrap_or_else(|error| panic!("active-defense body must round trip: {error}"));
        assert_eq!(decoded, body);
    }
}

#[test]
fn every_active_defense_body_field_tamper_fails_closed() {
    for kind in all_kinds() {
        let signed = signed_active_defense_receipt(kind);
        let encoded = serde_json::to_value(&signed)
            .unwrap_or_else(|error| panic!("encode signed active-defense receipt: {error}"));
        let active_defense_body = encoded
            .get("metadata")
            .and_then(|metadata| metadata.get("active_defense_body"))
            .unwrap_or_else(|| panic!("signed receipt must embed its active-defense body"));
        let mut paths = Vec::new();
        collect_semantic_field_paths(active_defense_body, &mut Vec::new(), &mut paths);
        assert!(
            !paths.is_empty(),
            "{kind:?} exposed no signed semantic fields"
        );

        for path in paths {
            let mut tampered = encoded.clone();
            let embedded = tampered
                .get_mut("metadata")
                .and_then(|metadata| metadata.get_mut("active_defense_body"))
                .unwrap_or_else(|| panic!("tamper target must remain present"));
            assert!(
                mutate_at_path(embedded, &path),
                "{kind:?} field path could not be mutated: {path:?}"
            );
            if let Ok(receipt) = serde_json::from_value::<ChioReceipt>(tampered) {
                assert!(
                    !receipt.verify_signature().unwrap_or_else(|error| {
                        panic!("verify tampered {kind:?} receipt at {path:?}: {error}")
                    }),
                    "{kind:?} field tamper retained a valid signature at {path:?}"
                );
            }
        }
    }
}

#[test]
fn flow_denial_digest_and_evidence_id_match_fixed_vectors() {
    let body = parse(fixture(ActiveDefenseReceiptKind::FlowDenial));
    let canonical = canonical_json_string(&body)
        .unwrap_or_else(|error| panic!("flow-denial body must canonicalize: {error}"));
    assert_eq!(canonical, FLOW_DENIAL_CANONICAL);

    let digest = active_defense_body_digest(&body)
        .unwrap_or_else(|error| panic!("flow-denial digest must compute: {error}"));
    assert_eq!(
        hex::encode(digest.as_bytes()),
        "44d0cab26fd6046e1bd6d02047ac99ff7ac4c9e7fb744f35391c95bb7c3e408b"
    );
    assert_eq!(
        body.body_digest()
            .unwrap_or_else(|error| panic!("method digest must compute: {error}")),
        digest
    );

    let evidence_id = active_defense_evidence_id(&body)
        .unwrap_or_else(|error| panic!("flow-denial evidence id must compute: {error}"));
    assert_eq!(
        evidence_id.as_str(),
        "active_defense_evidence_9bfafcfae8362050bc3b948412bd159539181e15000e0398f4ae8dde2d8cb479"
    );
    assert_eq!(
        body.evidence_id()
            .unwrap_or_else(|error| panic!("method evidence id must compute: {error}")),
        evidence_id
    );
}

#[test]
fn closed_bodies_reject_secret_bearing_and_unknown_fields() {
    for kind in all_kinds() {
        for forbidden_field in ["raw_payload", "marker", "credential", "rollback_secret"] {
            let mut value = fixture(kind);
            value["body"][forbidden_field] = json!("seeded-secret-value");
            assert!(
                serde_json::from_value::<ActiveDefenseReceiptBody>(value).is_err(),
                "{kind:?} accepted forbidden field {forbidden_field}"
            );
        }
    }

    let encoded = serde_json::to_string(&parse(fixture(
        ActiveDefenseReceiptKind::LiftRollbackCompletion,
    )))
    .unwrap_or_else(|error| panic!("receipt must serialize: {error}"));
    assert!(!encoded.contains("seeded-secret-value"));
    assert!(!encoded.contains("rollback_secret"));
}

#[test]
fn header_requires_exact_schema_time_and_sorted_unique_prior_links() {
    let base = fixture(ActiveDefenseReceiptKind::FlowDenial);
    for (path, invalid) in [
        ("schema_version", json!(2)),
        ("occurred_at_unix_ms", json!(0)),
        ("prior_receipt_ids", json!(["receipt-002", "receipt-001"])),
        ("prior_receipt_ids", json!(["receipt-001", "receipt-001"])),
    ] {
        let mut value = base.clone();
        value["body"]["header"][path] = invalid;
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(value).is_err());
    }

    let mut missing = base;
    missing["body"]["header"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("header fixture must be an object"))
        .remove("transition_id");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing).is_err());
}

#[test]
fn declassification_receipts_enforce_one_way_consumption_states() {
    let mut consumption = fixture(ActiveDefenseReceiptKind::DeclassificationConsumption);
    consumption["body"]["state"] = json!("released");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(consumption).is_err());

    let mut outcome = fixture(ActiveDefenseReceiptKind::DeclassificationOutcome);
    outcome["body"]["from_state"] = json!("released");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(outcome).is_err());

    let mut outcome = fixture(ActiveDefenseReceiptKind::DeclassificationOutcome);
    outcome["body"]["to_state"] = json!("consumed_pending_dispatch");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(outcome).is_err());
}

#[test]
fn correlated_finding_requires_ordered_unique_events_and_matching_evidence() {
    let mut duplicate = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    duplicate["body"]["ordered_event_ids"] = json!(["event-001", "event-001"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(duplicate).is_err());

    let mut mismatched = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    mismatched["body"]["ordered_evidence_digests"] = json!([digest(5)]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(mismatched).is_err());

    let mut source_mismatched = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    source_mismatched["body"]["ordered_source_receipt_ids"] = json!(["receipt-001"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(source_mismatched).is_err());

    let mut omitted_prior = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    omitted_prior["body"]["header"]["prior_receipt_ids"] = json!(["receipt-001"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(omitted_prior).is_err());

    let mut extra_prior = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    extra_prior["body"]["header"]["prior_receipt_ids"] =
        json!(["receipt-001", "receipt-002", "receipt-003"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(extra_prior).is_err());

    let mut future = fixture(ActiveDefenseReceiptKind::CorrelatedFinding);
    future["body"]["last_event_time_unix_ms"] = json!(OCCURRED_AT_UNIX_MS + 1);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(future).is_err());
}

#[test]
fn response_plan_requires_canonical_effect_order_and_target_binding() {
    let mut empty = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    empty["body"]["effects"] = json!([]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(empty).is_err());

    let mut skipped_ordinal = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    skipped_ordinal["body"]["effects"][1]["ordinal"] = json!(2);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(skipped_ordinal).is_err());

    let mut duplicate_id = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    duplicate_id["body"]["effects"][1]["effect_id"] = json!("effect-001");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(duplicate_id).is_err());

    let mut wrong_target = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    wrong_target["body"]["effects"][0]["target"] = json!({
        "target_type": "tenant",
        "tenant_id": "tenant-a"
    });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(wrong_target).is_err());

    let mut cross_tenant = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    cross_tenant["body"]["effects"][0]["kind"] = json!("escalate_alert");
    cross_tenant["body"]["effects"][0]["target"] = json!({
        "target_type": "tenant",
        "tenant_id": "tenant-b"
    });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(cross_tenant).is_err());
}

#[test]
fn response_plan_requires_the_exact_trigger_finding_receipt_as_a_prior() {
    let mut missing = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    missing["body"]["header"]["prior_receipt_ids"] = json!(["receipt-002"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing).is_err());

    let mut rebound = fixture(ActiveDefenseReceiptKind::ResponsePlan);
    rebound["body"]["response"]["trigger_finding_receipt_id"] = json!("receipt-003");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(rebound).is_err());
}

#[test]
fn response_state_transition_enforces_exact_edge_cause_and_applying_lease() {
    let mut wrong_cause = fixture(ActiveDefenseReceiptKind::ResponseStateTransition);
    wrong_cause["body"]["cause"] = json!("rollback_requested");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(wrong_cause).is_err());

    let mut illegal_edge = fixture(ActiveDefenseReceiptKind::ResponseStateTransition);
    illegal_edge["body"]["to_state"] = json!("lifted");
    illegal_edge["body"]["applying_lease_expires_at_unix_ms"] = Value::Null;
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(illegal_edge).is_err());

    let mut missing_lease = fixture(ActiveDefenseReceiptKind::ResponseStateTransition);
    missing_lease["body"]["applying_lease_expires_at_unix_ms"] = Value::Null;
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing_lease).is_err());

    let mut late_lease = fixture(ActiveDefenseReceiptKind::ResponseStateTransition);
    late_lease["body"]["applying_lease_expires_at_unix_ms"] = json!(OCCURRED_AT_UNIX_MS + 100_001);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(late_lease).is_err());

    let mut renewal = fixture(ActiveDefenseReceiptKind::ResponseStateTransition);
    renewal["body"]["from_state"] = json!("applying");
    renewal["body"]["to_state"] = json!("applying");
    renewal["body"]["cause"] = json!("applying_lease_renewed");
    renewal["body"]["scheduler_lease_owner_id"] = json!("worker-1");
    renewal["body"]["scheduler_fencing_token"] = json!(7);
    parse(renewal.clone());

    let mut missing_owner = renewal.clone();
    missing_owner["body"]["scheduler_lease_owner_id"] = Value::Null;
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing_owner).is_err());

    let mut zero_token = renewal.clone();
    zero_token["body"]["scheduler_fencing_token"] = json!(0);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(zero_token).is_err());

    let mut fenced_initial_apply = renewal;
    fenced_initial_apply["body"]["from_state"] = json!("planned");
    fenced_initial_apply["body"]["cause"] = json!("apply_started");
    parse(fenced_initial_apply);
}

#[test]
fn failed_completion_requires_a_resolved_unapplied_effect_shape() {
    let mut all_planned = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    all_planned["body"]["final_state"] = json!("failed");
    all_planned["body"]["error_code"] = json!("response.validation_failed");
    for outcome in all_planned["body"]["effects"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("completion effects must be an array"))
    {
        outcome["outcome"] = json!({ "state": "planned" });
    }
    parse(all_planned);

    let mut one_failed = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    one_failed["body"]["final_state"] = json!("failed");
    one_failed["body"]["error_code"] = json!("effect.external_failure");
    one_failed["body"]["effects"][0]["outcome"] = json!({
        "state": "apply_failed",
        "error_code": "effect.external_failure"
    });
    one_failed["body"]["effects"][1]["outcome"] = json!({ "state": "planned" });
    parse(one_failed.clone());

    let mut requested = one_failed.clone();
    requested["body"]["effects"][0]["outcome"] = json!({ "state": "requested" });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(requested).is_err());

    let mut multiple_failures = one_failed;
    multiple_failures["body"]["effects"][1]["outcome"] = json!({
        "state": "apply_failed",
        "error_code": "effect.second_external_failure"
    });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(multiple_failures).is_err());

    let mut mismatch = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    mismatch["body"]["final_state"] = json!("failed");
    mismatch["body"]["error_code"] = json!("response.other_failure");
    mismatch["body"]["effects"][0]["outcome"] = json!({
        "state": "apply_failed",
        "error_code": "effect.external_failure"
    });
    mismatch["body"]["effects"][1]["outcome"] = json!({ "state": "planned" });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(mismatch).is_err());

    let mut extra_prior = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    extra_prior["body"]["header"]["prior_receipt_ids"] = json!(["receipt-001", "receipt-002"]);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(extra_prior).is_err());
}

#[test]
fn partial_apply_cannot_validate_as_active_completion() {
    let mut partial = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    partial["body"]["effects"][1]["outcome"] = json!({
        "state": "apply_failed",
        "error_code": "effect.external_failure"
    });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(partial.clone()).is_err());

    partial["body"]["final_state"] = json!("apply_partial");
    partial["body"]["error_code"] = json!("effect.external_failure");
    parse(partial);

    let mut false_failure = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    false_failure["body"]["final_state"] = json!("failed");
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(false_failure).is_err());
}

#[test]
fn applying_lease_timeout_after_every_effect_applied_is_still_partial_completion() {
    let mut timed_out = fixture(ActiveDefenseReceiptKind::ResponseCompletion);
    timed_out["body"]["final_state"] = json!("apply_partial");
    timed_out["body"]["error_code"] = json!("response.applying_lease_expired");

    parse(timed_out);
}

#[test]
fn completion_dispatch_proofs_require_an_exact_nonzero_paired_binding() {
    for kind in [
        ActiveDefenseReceiptKind::ResponseCompletion,
        ActiveDefenseReceiptKind::LiftRollbackCompletion,
    ] {
        let mut valid = fixture(kind);
        valid["body"]["execution_dispatch"] = execution_dispatch_binding();
        valid["body"]["dispatch_authorization_hash"] = digest(43);
        parse(valid.clone());

        for field in [
            "plan_hash",
            "authorization_capability_hash",
            "governed_intent_hash",
            "policy_decision_hash",
        ] {
            let mut zero = valid.clone();
            zero["body"]["execution_dispatch"][field] = digest(0);
            assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(zero).is_err());
        }

        for (field, value) in [
            ("schema_version", json!(2)),
            ("tenant_id", json!("tenant-b")),
            ("action_id", json!("action-002")),
            ("executor_authority_generation", json!(0)),
            ("authorized_at_unix_ms", json!(0)),
            (
                "authorized_at_unix_ms",
                json!(OCCURRED_AT_UNIX_MS + 100_000),
            ),
        ] {
            let mut mismatched = valid.clone();
            mismatched["body"]["execution_dispatch"][field] = value;
            assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(mismatched).is_err());
        }

        let mut missing_authorization = valid.clone();
        missing_authorization["body"]["dispatch_authorization_hash"] = Value::Null;
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing_authorization).is_err());

        let mut missing_dispatch = valid.clone();
        missing_dispatch["body"]["execution_dispatch"] = Value::Null;
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(missing_dispatch).is_err());

        let mut zero_authorization = valid.clone();
        zero_authorization["body"]["dispatch_authorization_hash"] = digest(0);
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(zero_authorization).is_err());

        let mut governed = valid;
        governed["body"]["execution_dispatch"]["approval"] = json!({
            "approval_mode": "governed",
            "admission_operation_id": "admission-operation-001",
            "admission_operation_version": 0,
            "approval_set_hash": digest(44)
        });
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(governed.clone()).is_err());
        governed["body"]["execution_dispatch"]["approval"]["admission_operation_version"] =
            json!(1);
        governed["body"]["execution_dispatch"]["approval"]["approval_set_hash"] = digest(0);
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(governed).is_err());
    }
}

#[test]
fn partial_rollback_cannot_validate_as_lifted_completion() {
    let mut partial = fixture(ActiveDefenseReceiptKind::LiftRollbackCompletion);
    partial["body"]["effects"][1]["outcome"] = json!({
        "state": "rollback_failed",
        "error_code": "effect.restore_conflict"
    });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(partial.clone()).is_err());

    partial["body"]["final_state"] = json!("rollback_partial");
    parse(partial);
}

#[test]
fn lift_completion_allows_effects_that_durably_never_applied_but_not_unknown_requests() {
    let mut apply_failed = fixture(ActiveDefenseReceiptKind::LiftRollbackCompletion);
    apply_failed["body"]["effects"][1]["outcome"] = json!({
        "state": "apply_failed",
        "error_code": "effect.external_failure"
    });
    parse(apply_failed);

    let mut requested = fixture(ActiveDefenseReceiptKind::LiftRollbackCompletion);
    requested["body"]["effects"][1]["outcome"] = json!({ "state": "requested" });
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(requested).is_err());
}

#[test]
fn health_receipts_reject_zero_or_future_operational_state() {
    let mut detector = fixture(ActiveDefenseReceiptKind::DetectorHealth);
    detector["body"]["watermark"]["unix_ms"] = json!(OCCURRED_AT_UNIX_MS + 1);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(detector).is_err());

    let mut scheduler = fixture(ActiveDefenseReceiptKind::SchedulerHealth);
    scheduler["body"]["first_failure_at_unix_ms"] = json!(OCCURRED_AT_UNIX_MS + 1);
    assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(scheduler).is_err());

    for field in ["attempts", "scheduler_fencing_token"] {
        let mut scheduler = fixture(ActiveDefenseReceiptKind::SchedulerHealth);
        scheduler["body"][field] = json!(0);
        assert!(serde_json::from_value::<ActiveDefenseReceiptBody>(scheduler).is_err());
    }
}
