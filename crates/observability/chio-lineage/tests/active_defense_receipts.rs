use std::collections::BTreeSet;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::security::{ActiveDefenseReceiptBody, ActiveDefenseReceiptKind};
use chio_lineage::ingest_active_defense::ActiveDefenseReceiptIngest;
use chio_lineage::schema::{EdgeKind, EvidenceClass};
use serde_json::json;

const OCCURRED_AT_UNIX_MS: u64 = 1_720_000_000_100;

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn header(transition_id: &str, prior_receipt_ids: &[&str]) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "occurred_at_unix_ms": OCCURRED_AT_UNIX_MS,
        "tenant_id": "tenant-lineage",
        "transition_id": transition_id,
        "prior_receipt_ids": prior_receipt_ids,
    })
}

fn response_binding() -> serde_json::Value {
    json!({
        "policy": {
            "policy_version": "policy-lineage-v1",
            "policy_hash": digest(1),
        },
        "plan_hash": digest(2),
        "action_id": "action-lineage",
        "trigger_finding_id": "finding-lineage",
        "trigger_finding_hash": digest(3),
        "trigger_finding_receipt_id": "active_defense_evidence_trigger",
        "affected_set_hash": digest(4),
        "plan_expires_at_unix_ms": OCCURRED_AT_UNIX_MS + 60_000,
    })
}

fn response_effect() -> serde_json::Value {
    json!({
        "effect_id": "effect-lineage",
        "ordinal": 0,
        "kind": "throttle_session",
        "target": {
            "target_type": "session",
            "session_id": "session-lineage",
        },
        "contribution_hash": digest(5),
        "observed_base_version_hash": digest(6),
    })
}

fn response_plan() -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "response_plan",
        "body": {
            "header": header(
                "transition-plan-lineage",
                &["active_defense_evidence_trigger"],
            ),
            "response": response_binding(),
            "plan_created_at_unix_ms": OCCURRED_AT_UNIX_MS - 1,
            "effects": [response_effect()],
        },
    }))
    .unwrap_or_else(|error| panic!("response plan fixture must be valid: {error}"))
}

fn applying_transition(plan_evidence_id: &str) -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "response_state_transition",
        "body": {
            "header": header("transition-applying-lineage", &[plan_evidence_id]),
            "response": response_binding(),
            "generation": 1,
            "from_state": "planned",
            "to_state": "applying",
            "cause": "apply_started",
            "applying_lease_expires_at_unix_ms": OCCURRED_AT_UNIX_MS + 30_000,
            "scheduler_lease_owner_id": null,
            "scheduler_fencing_token": null,
            "error_code": null,
        },
    }))
    .unwrap_or_else(|error| panic!("response transition fixture must be valid: {error}"))
}

fn effect_transition(prior_evidence_id: &str) -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "effect_transition",
        "body": {
            "header": header("transition-effect-lineage", &[prior_evidence_id]),
            "response": response_binding(),
            "effect": response_effect(),
            "generation": 2,
            "scheduler_fencing_token": 1,
            "outcome": {
                "state": "applied",
                "resulting_version_hash": digest(7),
            },
        },
    }))
    .unwrap_or_else(|error| panic!("effect transition fixture must be valid: {error}"))
}

fn response_completion(prior_evidence_id: &str) -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "response_completion",
        "body": {
            "header": header("transition-response-complete-lineage", &[prior_evidence_id]),
            "response": response_binding(),
            "execution_dispatch": null,
            "dispatch_authorization_hash": null,
            "response_generation": 3,
            "response_body_hash": digest(8),
            "final_state": "active",
            "error_code": null,
            "effects": [{
                "effect": response_effect(),
                "outcome": {
                    "state": "applied",
                    "resulting_version_hash": digest(7),
                },
            }],
        },
    }))
    .unwrap_or_else(|error| panic!("response completion fixture must be valid: {error}"))
}

fn lift_completion(prior_evidence_id: &str) -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "lift_rollback_completion",
        "body": {
            "header": header("transition-lift-complete-lineage", &[prior_evidence_id]),
            "response": response_binding(),
            "execution_dispatch": null,
            "dispatch_authorization_hash": null,
            "response_generation": 4,
            "response_body_hash": digest(9),
            "final_state": "lifted",
            "effects": [{
                "effect": response_effect(),
                "outcome": {
                    "state": "restored",
                    "resulting_version_hash": digest(10),
                },
            }],
        },
    }))
    .unwrap_or_else(|error| panic!("lift completion fixture must be valid: {error}"))
}

fn scheduler_health(prior_evidence_id: &str) -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "scheduler_health",
        "body": {
            "header": header("transition-scheduler-health-lineage", &[prior_evidence_id]),
            "response": response_binding(),
            "event_id": "scheduler-health-lineage",
            "first_failure_at_unix_ms": OCCURRED_AT_UNIX_MS - 1,
            "attempts": 1,
            "scheduler_fencing_token": 1,
            "error_code": "scheduler.store_unavailable",
            "evidence_hash": digest(11),
        },
    }))
    .unwrap_or_else(|error| panic!("scheduler health fixture must be valid: {error}"))
}

fn signed_native_receipt(body: &ActiveDefenseReceiptBody, keypair: &Keypair) -> ChioReceipt {
    let evidence_id = body
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive evidence id: {error}"));
    let body_digest = body
        .body_digest()
        .unwrap_or_else(|error| panic!("derive body digest: {error}"));
    let action = ToolCallAction::from_parameters(json!({
        "evidence_id": evidence_id.as_str(),
        "kind": body.kind().as_str(),
        "transition_id": body.header().transition_id.as_str(),
    }))
    .unwrap_or_else(|error| panic!("build action: {error}"));
    let (receipt_kind, boundary_class, observation_outcome, trust_level) = match body {
        ActiveDefenseReceiptBody::ResponsePlan(_) => (
            ReceiptKind::AdvisoryEvaluation,
            BoundaryClass::AdvisoryOnly,
            Some(ObservationOutcome::Evaluated),
            TrustLevel::Advisory,
        ),
        _ => (
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            Some(ObservationOutcome::Observed),
            TrustLevel::Verified,
        ),
    };
    let receipt_body = ChioReceiptBody {
        id: String::new(),
        timestamp: body.header().occurred_at_unix_ms / 1_000,
        capability_id: "chio.active-defense.system".to_string(),
        tool_server: "chio.kernel".to_string(),
        tool_name: body.kind().as_str().to_string(),
        action,
        decision: None,
        receipt_kind,
        boundary_class,
        observation_outcome,
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: Vec::new(),
        content_hash: encode_hex(body_digest.as_bytes()),
        policy_hash: encode_hex(&digest(1)),
        evidence: Vec::new(),
        metadata: Some(json!({
            "active_defense_body": body,
            "active_defense_evidence_id": evidence_id.as_str(),
            "occurred_at_unix_ms": body.header().occurred_at_unix_ms,
        })),
        trust_level,
        tenant_id: Some(body.header().tenant_id.as_str().to_string()),
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(receipt_body, keypair)
        .unwrap_or_else(|error| panic!("sign native receipt: {error}"))
}

#[test]
fn active_defense_lineage_links_every_transition_to_its_plan_trigger_and_prior_receipts() {
    let keypair = Keypair::from_seed(&[41; 32]);
    let plan = response_plan();
    let plan_evidence_id = plan
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive plan evidence id: {error}"));
    let state_transition = applying_transition(plan_evidence_id.as_str());
    let state_transition_evidence_id = state_transition
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive state transition evidence id: {error}"));
    let effect_transition = effect_transition(state_transition_evidence_id.as_str());
    let effect_transition_evidence_id = effect_transition
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive effect transition evidence id: {error}"));
    let response_completion = response_completion(effect_transition_evidence_id.as_str());
    let response_completion_evidence_id = response_completion
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive response completion evidence id: {error}"));
    let lift_completion = lift_completion(response_completion_evidence_id.as_str());
    let scheduler_health = scheduler_health(response_completion_evidence_id.as_str());
    let bodies = [
        plan,
        state_transition,
        effect_transition,
        response_completion,
        lift_completion,
        scheduler_health,
    ];
    assert_eq!(
        bodies
            .iter()
            .map(ActiveDefenseReceiptBody::kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ActiveDefenseReceiptKind::ResponsePlan,
            ActiveDefenseReceiptKind::ResponseStateTransition,
            ActiveDefenseReceiptKind::EffectTransition,
            ActiveDefenseReceiptKind::ResponseCompletion,
            ActiveDefenseReceiptKind::LiftRollbackCompletion,
            ActiveDefenseReceiptKind::SchedulerHealth,
        ])
    );
    let evidence_ids = bodies
        .iter()
        .map(|body| {
            body.evidence_id()
                .unwrap_or_else(|error| panic!("derive response evidence id: {error}"))
        })
        .collect::<Vec<_>>();
    let receipts = bodies
        .iter()
        .map(|body| signed_native_receipt(body, &keypair))
        .collect::<Vec<_>>();
    let trusted = BTreeSet::from([keypair.public_key().to_hex()]);

    let graph = ActiveDefenseReceiptIngest::new(trusted)
        .unwrap_or_else(|error| panic!("trusted signer set: {error}"))
        .ingest_all(&receipts)
        .unwrap_or_else(|error| panic!("ingest active-defense receipts: {error}"));

    let edge_exists = |from: &str, to: &str, source_table: &str, source_id: &str| {
        graph.edges.iter().any(|edge| {
            edge.from == format!("rcpt:{from}")
                && edge.to == format!("rcpt:{to}")
                && edge.kind == EdgeKind::ReceiptLineageParent
                && edge.evidence_class == EvidenceClass::Verified
                && edge.source_table.as_deref() == Some(source_table)
                && edge.source_id.as_deref() == Some(source_id)
        })
    };
    let expected_priors = [
        "active_defense_evidence_trigger",
        evidence_ids[0].as_str(),
        evidence_ids[1].as_str(),
        evidence_ids[2].as_str(),
        evidence_ids[3].as_str(),
        evidence_ids[3].as_str(),
    ];
    for ((evidence_id, receipt), expected_prior) in evidence_ids
        .iter()
        .zip(receipts.iter())
        .zip(expected_priors)
    {
        assert!(edge_exists(
            expected_prior,
            evidence_id.as_str(),
            "active_defense.prior_receipt",
            receipt.id.as_str(),
        ));
        assert!(edge_exists(
            "active_defense_evidence_trigger",
            evidence_id.as_str(),
            "active_defense.trigger_finding",
            receipt.id.as_str(),
        ));
    }

    let plan_node = format!("rcpt:{plan_evidence_id}");
    for evidence_id in evidence_ids.iter().skip(1) {
        let target = format!("rcpt:{evidence_id}");
        let mut reachable = BTreeSet::from([plan_node.clone()]);
        loop {
            if reachable.contains(&target) {
                break;
            }
            let previous_len = reachable.len();
            for edge in &graph.edges {
                if edge.kind == EdgeKind::ReceiptLineageParent
                    && edge.source_table.as_deref() == Some("active_defense.prior_receipt")
                    && reachable.contains(&edge.from)
                {
                    reachable.insert(edge.to.clone());
                }
            }
            assert_ne!(
                reachable.len(),
                previous_len,
                "{} has no verified prior-receipt path to the response plan",
                evidence_id.as_str(),
            );
        }
    }
}

#[test]
fn response_plan_preserves_prior_and_trigger_relationships_when_ids_coincide() {
    let keypair = Keypair::from_seed(&[42; 32]);
    let plan = response_plan();
    let plan_evidence_id = plan
        .evidence_id()
        .unwrap_or_else(|error| panic!("derive plan evidence id: {error}"));
    let receipt = signed_native_receipt(&plan, &keypair);
    let receipt_id = receipt.id.clone();
    let trusted = BTreeSet::from([keypair.public_key().to_hex()]);

    let graph = ActiveDefenseReceiptIngest::new(trusted)
        .unwrap_or_else(|error| panic!("trusted signer set: {error}"))
        .ingest_all(&[receipt])
        .unwrap_or_else(|error| panic!("ingest active-defense response plan: {error}"));

    let matching_edges = graph
        .edges
        .iter()
        .filter(|edge| {
            edge.from == "rcpt:active_defense_evidence_trigger"
                && edge.to == format!("rcpt:{plan_evidence_id}")
                && edge.kind == EdgeKind::ReceiptLineageParent
        })
        .collect::<Vec<_>>();
    assert_eq!(matching_edges.len(), 2);
    assert_eq!(
        matching_edges
            .iter()
            .filter_map(|edge| edge.source_table.as_deref())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "active_defense.prior_receipt",
            "active_defense.trigger_finding",
        ])
    );
    assert!(matching_edges.iter().all(|edge| {
        edge.evidence_class == EvidenceClass::Verified
            && edge.source_id.as_deref() == Some(receipt_id.as_str())
    }));
}
