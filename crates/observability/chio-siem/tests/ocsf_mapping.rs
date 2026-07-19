//! Integration tests for the OCSF 1.3.0 Authorization mapping.
//!
//! These tests exercise `chio_siem::ocsf::receipt_to_ocsf` and
//! `chio_siem::OcsfExporter::format_events` against fully-signed
//! [`ChioReceipt`] fixtures covering each [`Decision`] variant.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::{Keypair, Signature};
use chio_core::receipt::security::ActiveDefenseReceiptBody;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ObservationOutcome, kinds::ReceiptKind, kinds::RedactionMode,
    kinds::ToolOrigin, kinds::TrustLevel, metadata::GuardEvidence,
};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportError;
use chio_siem::ocsf::{
    receipt_to_ocsf, siem_event_to_ocsf, OCSF_CATEGORY_UID, OCSF_CLASS_UID, OCSF_SCHEMA_VERSION,
};
use chio_siem::Exporter;
use chio_siem::{OcsfExporter, OcsfExporterConfig, OcsfPayloadFormat};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn receipt_with(
    id: &str,
    decision: Decision,
    trust_level: TrustLevel,
    evidence: Vec<GuardEvidence>,
    metadata: Option<serde_json::Value>,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let semantics = match trust_level {
        TrustLevel::Advisory => {
            chio_core::receipt::metadata::ReceiptSemanticFields::advisory_only()
        }
        TrustLevel::Verified => {
            chio_core::receipt::metadata::ReceiptSemanticFields::trace_detect_only()
        }
        TrustLevel::Mediated => {
            chio_core::receipt::metadata::ReceiptSemanticFields::mediated_prevent()
        }
    };
    let decision =
        if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
            Some(decision)
        } else {
            None
        };
    let body = ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1_712_345_678,
        capability_id: "cap-xyz".to_string(),
        tool_server: "srv-shell".to_string(),
        tool_name: "bash".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
            .expect("action parameters serialize"),
        decision,
        receipt_kind: semantics.receipt_kind,
        boundary_class: semantics.boundary_class,
        observation_outcome: semantics.observation_outcome,
        tool_origin: semantics.tool_origin,
        redaction_mode: semantics.redaction_mode,
        actor_chain: semantics.actor_chain,
        content_hash: "content-hash".to_string(),
        policy_hash: "policy-hash".to_string(),
        evidence,
        metadata,
        trust_level,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, &keypair).unwrap()
}

fn allow_receipt() -> ChioReceipt {
    receipt_with(
        "rc-allow-1",
        Decision::Allow,
        TrustLevel::Mediated,
        vec![],
        None,
    )
}

fn deny_receipt() -> ChioReceipt {
    receipt_with(
        "rc-deny-1",
        Decision::Deny {
            reason: "forbidden path".to_string(),
            guard: "ForbiddenPathGuard".to_string(),
        },
        TrustLevel::Mediated,
        vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: false,
            details: Some("path matches deny-list".to_string()),
        }],
        None,
    )
}

fn trusted_event(receipt: ChioReceipt) -> SiemEvent {
    let trusted_kernel_keys = BTreeSet::from([receipt.kernel_key.to_hex()]);
    SiemEvent::from_receipt_with_trusted_kernel_keys(receipt, Some(&trusted_kernel_keys))
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

fn active_defense_response_plan_receipt() -> ChioReceipt {
    let keypair = Keypair::from_seed(&[53; 32]);
    let occurred_at_unix_ms = 1_720_000_000_100_u64;
    let digest = |byte: u8| vec![byte; 32];
    let body: ActiveDefenseReceiptBody = serde_json::from_value(serde_json::json!({
        "kind": "response_plan",
        "body": {
            "header": {
                "schema_version": 1,
                "occurred_at_unix_ms": occurred_at_unix_ms,
                "tenant_id": "tenant-siem",
                "transition_id": "transition-siem-plan",
                "prior_receipt_ids": ["active_defense_evidence_trigger_siem"],
            },
            "response": {
                "policy": {
                    "policy_version": "policy-siem-v1",
                    "policy_hash": digest(1),
                },
                "plan_hash": digest(2),
                "action_id": "action-siem",
                "trigger_finding_id": "finding-siem",
                "trigger_finding_hash": digest(3),
                "trigger_finding_receipt_id": "active_defense_evidence_trigger_siem",
                "affected_set_hash": digest(4),
                "plan_expires_at_unix_ms": occurred_at_unix_ms + 60_000,
            },
            "plan_created_at_unix_ms": occurred_at_unix_ms - 1,
            "effects": [{
                "effect_id": "effect-siem",
                "ordinal": 0,
                "kind": "escalate_alert",
                "target": {
                    "target_type": "tenant",
                    "tenant_id": "tenant-siem",
                },
                "contribution_hash": digest(5),
                "observed_base_version_hash": digest(6),
            }],
        },
    }))
    .unwrap_or_else(|error| panic!("active-defense SIEM fixture: {error}"));
    let evidence_id = body
        .evidence_id()
        .unwrap_or_else(|error| panic!("active-defense evidence id: {error}"));
    let body_digest = body
        .body_digest()
        .unwrap_or_else(|error| panic!("active-defense body digest: {error}"));
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "evidence_id": evidence_id.as_str(),
        "kind": body.kind().as_str(),
        "transition_id": body.header().transition_id.as_str(),
    }))
    .unwrap_or_else(|error| panic!("active-defense action: {error}"));
    let receipt_body = ChioReceiptBody {
        id: String::new(),
        timestamp: occurred_at_unix_ms / 1_000,
        capability_id: "chio.active-defense.system".to_string(),
        tool_server: "chio.kernel".to_string(),
        tool_name: body.kind().as_str().to_string(),
        action,
        decision: None,
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: Vec::new(),
        content_hash: encode_hex(body_digest.as_bytes()),
        policy_hash: encode_hex(&digest(1)),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({
            "active_defense_body": body,
            "active_defense_evidence_id": evidence_id.as_str(),
            "occurred_at_unix_ms": occurred_at_unix_ms,
        })),
        trust_level: TrustLevel::Advisory,
        tenant_id: Some("tenant-siem".to_string()),
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(receipt_body, &keypair)
        .unwrap_or_else(|error| panic!("sign active-defense SIEM fixture: {error}"))
}

fn active_defense_projection(receipt: ChioReceipt) -> Value {
    siem_event_to_ocsf(&trusted_event(receipt))["unmapped"]["chio"]["active_defense"].clone()
}

fn assert_invalid_active_defense_projection(projection: &Value, error: &str) {
    assert_eq!(projection["valid"], false);
    assert_eq!(projection["error"], error);
}

// -- Tests --------------------------------------------------------------------

#[test]
fn trusted_allow_receipt_maps_to_success_event() {
    let ev = siem_event_to_ocsf(&trusted_event(allow_receipt()));

    assert_eq!(ev["class_uid"], OCSF_CLASS_UID);
    assert_eq!(ev["category_uid"], OCSF_CATEGORY_UID);
    assert_eq!(ev["status_id"], 1, "Allow -> Success");
    assert_eq!(ev["status"], "Success");
    assert_eq!(ev["severity_id"], 1, "Allow -> Informational");
    assert_eq!(ev["severity"], "Informational");
    assert_eq!(ev["activity_id"], 1);
    assert_eq!(ev["activity_name"], "Grant");
    assert_eq!(ev["type_uid"], 300_201);
    assert_eq!(ev["metadata"]["version"], OCSF_SCHEMA_VERSION);
}

#[test]
fn active_defense_receipt_maps_closed_body_into_structured_ocsf_fields() {
    let event = siem_event_to_ocsf(&trusted_event(active_defense_response_plan_receipt()));

    let active = &event["unmapped"]["chio"]["active_defense"];
    assert_eq!(active["valid"], true);
    assert_eq!(active["kind"], "response_plan");
    assert_eq!(active["transition_id"], "transition-siem-plan");
    assert_eq!(active["response"]["action_id"], "action-siem");
    assert_eq!(
        active["response"]["trigger_finding_receipt_id"],
        "active_defense_evidence_trigger_siem"
    );
    assert_eq!(
        active["prior_receipt_ids"],
        serde_json::json!(["active_defense_evidence_trigger_siem"])
    );
    assert_eq!(active["body"]["kind"], "response_plan");
    assert_eq!(active["verification"]["envelope_valid"], true);
    assert_eq!(active["verification"]["signer_trusted"], true);
    assert_eq!(active["verification"]["semantics_valid"], true);
    assert_eq!(active["verification"]["binding_valid"], true);

    let observables = event["observables"]
        .as_array()
        .unwrap_or_else(|| panic!("active-defense observables must be an array"));
    assert!(observables
        .iter()
        .any(|observable| observable["name"] == "chio.active_defense.evidence_id"));
    assert!(observables
        .iter()
        .any(|observable| observable["name"] == "chio.active_defense.transition_id"));

    let enrichments = event["enrichments"]
        .as_array()
        .unwrap_or_else(|| panic!("active-defense enrichments must be an array"));
    assert!(enrichments
        .iter()
        .any(|enrichment| enrichment["name"] == "chio.active_defense"));
}

#[test]
fn raw_active_defense_receipt_does_not_treat_embedded_self_signature_as_trust() {
    let event = receipt_to_ocsf(&active_defense_response_plan_receipt());
    let projection = &event["unmapped"]["chio"]["active_defense"];

    assert_invalid_active_defense_projection(projection, "untrusted_active_defense_signer");
    assert_eq!(projection["verification"]["signature_valid"], true);
    assert_eq!(projection["verification"]["receipt_id_valid"], true);
    assert_eq!(projection["verification"]["parameter_hash_valid"], true);
    assert_eq!(projection["verification"]["signer_trusted"], false);
}

#[test]
fn forged_siem_event_trust_boolean_cannot_validate_active_defense_projection() {
    let mut event = SiemEvent::from_receipt(active_defense_response_plan_receipt());
    event.authoritative = true;
    event.signature_valid = true;
    event.receipt_id_valid = true;
    event.parameter_hash_valid = true;
    event.signer_trusted = true;
    event.authorized = true;

    let mapped = siem_event_to_ocsf(&event);
    let projection = &mapped["unmapped"]["chio"]["active_defense"];
    assert_invalid_active_defense_projection(projection, "untrusted_active_defense_signer");
    assert_eq!(projection["verification"]["signature_valid"], true);
    assert_eq!(projection["verification"]["receipt_id_valid"], true);
    assert_eq!(projection["verification"]["signer_trusted"], false);
}

#[test]
fn deserialized_siem_event_must_rederive_active_defense_signer_trust() {
    let event = trusted_event(active_defense_response_plan_receipt());
    let encoded = serde_json::to_value(event)
        .unwrap_or_else(|error| panic!("serialize trusted SIEM event: {error}"));
    let decoded: SiemEvent = serde_json::from_value(encoded)
        .unwrap_or_else(|error| panic!("deserialize trusted SIEM event: {error}"));

    let mapped = siem_event_to_ocsf(&decoded);
    let projection = &mapped["unmapped"]["chio"]["active_defense"];
    assert_invalid_active_defense_projection(projection, "untrusted_active_defense_signer");
    assert_eq!(projection["verification"]["signature_valid"], true);
    assert_eq!(projection["verification"]["signer_trusted"], false);
}

#[test]
fn trusted_siem_event_proof_is_bound_to_the_original_receipt_signer() {
    let mut event = trusted_event(active_defense_response_plan_receipt());
    let replacement_keypair = Keypair::from_seed(&[54; 32]);
    let mut replacement_body = event.receipt.body();
    replacement_body.id.clear();
    replacement_body.kernel_key = replacement_keypair.public_key();
    event.receipt = ChioReceipt::sign(replacement_body, &replacement_keypair)
        .unwrap_or_else(|error| panic!("sign replacement active-defense receipt: {error}"));

    let mapped = siem_event_to_ocsf(&event);
    let projection = &mapped["unmapped"]["chio"]["active_defense"];
    assert_invalid_active_defense_projection(projection, "untrusted_active_defense_signer");
    assert_eq!(projection["verification"]["signature_valid"], true);
    assert_eq!(projection["verification"]["receipt_id_valid"], true);
    assert_eq!(projection["verification"]["signer_trusted"], false);
}

#[test]
fn active_defense_projection_rejects_signature_mutation() {
    let mut receipt = active_defense_response_plan_receipt();
    receipt.signature = Signature::from_bytes(&[0xA5; 64]);

    let projection = active_defense_projection(receipt);
    assert_invalid_active_defense_projection(&projection, "invalid_active_defense_envelope");
    assert_eq!(projection["verification"]["signature_valid"], false);
}

#[test]
fn active_defense_projection_rejects_receipt_id_body_mismatch() {
    let mut receipt = active_defense_response_plan_receipt();
    receipt.id = "not-the-active-defense-body-address".to_string();

    let projection = active_defense_projection(receipt);
    assert_invalid_active_defense_projection(&projection, "invalid_active_defense_envelope");
    assert_eq!(projection["verification"]["receipt_id_valid"], false);
}

#[test]
fn active_defense_projection_rejects_each_closed_semantic_field_mismatch() {
    let receipt = active_defense_response_plan_receipt();

    let mut wrong_kind = receipt.clone();
    wrong_kind.receipt_kind = ReceiptKind::TraceObservation;
    let mut wrong_boundary = receipt.clone();
    wrong_boundary.boundary_class = BoundaryClass::Prevent;
    let mut wrong_decision = receipt.clone();
    wrong_decision.decision = Some(Decision::Allow);
    let mut wrong_trust = receipt;
    wrong_trust.trust_level = TrustLevel::Verified;

    for (field, mutated) in [
        ("receipt_kind", wrong_kind),
        ("boundary_class", wrong_boundary),
        ("decision", wrong_decision),
        ("trust_level", wrong_trust),
    ] {
        let projection = active_defense_projection(mutated);
        assert_eq!(projection["valid"], false, "field {field}");
        assert_eq!(
            projection["verification"]["semantics_valid"], false,
            "field {field}"
        );
    }
}

#[test]
fn active_defense_projection_rejects_re_signed_alternate_semantic_tuples() {
    let keypair = Keypair::from_seed(&[53; 32]);
    let mut trace_body = active_defense_response_plan_receipt().body();
    trace_body.id.clear();
    trace_body.receipt_kind = ReceiptKind::TraceObservation;
    trace_body.boundary_class = BoundaryClass::DetectOnly;
    trace_body.observation_outcome = Some(ObservationOutcome::Observed);
    trace_body.decision = None;
    trace_body.trust_level = TrustLevel::Verified;

    let mut mediated_body = active_defense_response_plan_receipt().body();
    mediated_body.id.clear();
    mediated_body.receipt_kind = ReceiptKind::MediatedDecision;
    mediated_body.boundary_class = BoundaryClass::Prevent;
    mediated_body.observation_outcome = None;
    mediated_body.decision = Some(Decision::Allow);
    mediated_body.trust_level = TrustLevel::Mediated;

    for (tuple, body) in [("trace", trace_body), ("mediated_allow", mediated_body)] {
        let receipt = ChioReceipt::sign(body, &keypair)
            .unwrap_or_else(|error| panic!("sign alternate {tuple} semantic tuple: {error}"));
        assert!(receipt.verify_signature().unwrap_or(false), "tuple {tuple}");

        let projection = active_defense_projection(receipt);
        assert_invalid_active_defense_projection(&projection, "invalid_active_defense_semantics");
        assert_eq!(
            projection["verification"]["signature_valid"], true,
            "tuple {tuple}"
        );
        assert_eq!(
            projection["verification"]["receipt_id_valid"], true,
            "tuple {tuple}"
        );
        assert_eq!(
            projection["verification"]["envelope_valid"], true,
            "tuple {tuple}"
        );
        assert_eq!(
            projection["verification"]["semantics_valid"], false,
            "tuple {tuple}"
        );
    }
}

#[test]
fn invalid_receipt_id_never_exports_as_authorized() {
    let mut receipt = allow_receipt();
    receipt.id = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let ev = receipt_to_ocsf(&receipt);

    assert_eq!(ev["activity_name"], "Other");
    assert_eq!(ev["status"], "Other");
    assert_eq!(ev["actor"]["authorizations"][0]["decision"], "Unverified");
    assert_eq!(ev["unmapped"]["chio"]["authorized"], false);
    assert_eq!(ev["unmapped"]["chio"]["result"], "Unverified");
    assert_ne!(ev["unmapped"]["chio"]["decision.verdict"], "allow");
}

#[test]
fn deny_receipt_maps_to_failure_event() {
    let ev = receipt_to_ocsf(&deny_receipt());

    assert_eq!(ev["class_uid"], OCSF_CLASS_UID);
    assert_eq!(ev["status_id"], 2, "Deny -> Failure");
    assert_eq!(ev["status"], "Failure");
    assert_eq!(ev["severity_id"], 4, "Deny -> High");
    assert_eq!(ev["severity"], "High");
    assert_eq!(ev["status_detail"], "forbidden path");
    assert_eq!(
        ev["unmapped"]["chio"]["decision.guard"],
        "ForbiddenPathGuard"
    );
}

#[test]
fn cancelled_receipt_uses_other_activity_and_low_severity() {
    let receipt = receipt_with(
        "rc-cancel-1",
        Decision::Cancelled {
            reason: "user cancelled".to_string(),
        },
        TrustLevel::Mediated,
        vec![],
        None,
    );
    let ev = receipt_to_ocsf(&receipt);

    assert_eq!(ev["activity_id"], 99);
    assert_eq!(ev["activity_name"], "Other");
    assert_eq!(ev["status_id"], 2);
    assert_eq!(ev["severity_id"], 2);
    assert_eq!(ev["severity"], "Low");
}

#[test]
fn receipt_with_trust_level_populates_enrichment() {
    let receipt = receipt_with(
        "rc-trust-1",
        Decision::Incomplete {
            reason: "advisory observation".to_string(),
        },
        TrustLevel::Advisory,
        vec![],
        None,
    );
    let ev = receipt_to_ocsf(&receipt);

    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    let trust = enrichments
        .iter()
        .find(|e| e["name"] == "chio.trust_level")
        .expect("trust_level enrichment present");
    assert_eq!(trust["value"], "advisory");
    assert_eq!(trust["data"]["trust_level"], "advisory");
    assert_eq!(ev["unmapped"]["chio"]["trust_level"], "advisory");
}

#[test]
fn receipt_observables_contain_tool_and_capability() {
    let ev = receipt_to_ocsf(&allow_receipt());
    let observables = ev["observables"].as_array().expect("observables array");

    let names: Vec<&str> = observables
        .iter()
        .filter_map(|o| o["name"].as_str())
        .collect();

    for expected in [
        "chio.receipt.id",
        "chio.capability.id",
        "chio.tool.server",
        "chio.tool.name",
        "chio.policy.hash",
        "chio.content.hash",
    ] {
        assert!(
            names.contains(&expected),
            "observables missing {expected}: {names:?}",
        );
    }

    let capability = observables
        .iter()
        .find(|o| o["name"] == "chio.capability.id")
        .expect("capability observable");
    assert_eq!(capability["value"], "cap-xyz");
    assert_eq!(capability["type_id"], 10);
}

#[test]
fn deny_receipt_observables_include_guard() {
    let ev = receipt_to_ocsf(&deny_receipt());
    let observables = ev["observables"].as_array().expect("observables array");
    let guard = observables
        .iter()
        .find(|o| o["name"] == "chio.guard")
        .expect("guard observable present on deny");
    assert_eq!(guard["value"], "ForbiddenPathGuard");
}

#[test]
fn tenant_id_surfaces_only_from_top_level_receipt_field() {
    let mut receipt = receipt_with(
        "rc-tenant-1",
        Decision::Allow,
        TrustLevel::Mediated,
        vec![],
        Some(serde_json::json!({"tenant_id": "metadata-tenant"})),
    );
    receipt.tenant_id = Some("tenant-42".to_string());
    let ev = receipt_to_ocsf(&receipt);

    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    assert!(
        enrichments
            .iter()
            .any(|e| e["name"] == "chio.tenant_id" && e["value"] == "tenant-42"),
        "expected tenant_id enrichment: {enrichments:?}",
    );
    assert_eq!(ev["unmapped"]["chio"]["tenant_id"], "tenant-42");
}

#[test]
fn metadata_tenant_id_is_not_authoritative() {
    let metadata = serde_json::json!({"tenant_id": "metadata-tenant"});
    let receipt = receipt_with(
        "rc-tenant-metadata-only",
        Decision::Allow,
        TrustLevel::Mediated,
        vec![],
        Some(metadata),
    );
    let ev = receipt_to_ocsf(&receipt);

    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    assert!(
        !enrichments.iter().any(|e| e["name"] == "chio.tenant_id"),
        "metadata tenant_id must not create authoritative tenant enrichment: {enrichments:?}",
    );
    assert!(ev["unmapped"]["chio"]["tenant_id"].is_null());
}

#[test]
fn guard_evidence_populates_enrichments() {
    let ev = receipt_to_ocsf(&deny_receipt());
    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    let guard_enrichment = enrichments
        .iter()
        .find(|e| e["name"] == "chio.guard.evidence.0")
        .expect("guard evidence enrichment");
    assert_eq!(guard_enrichment["value"], "ForbiddenPathGuard");
    assert_eq!(guard_enrichment["data"]["verdict"], false);
    assert_eq!(
        guard_enrichment["data"]["details"],
        "path matches deny-list"
    );
}

#[test]
fn canonical_json_roundtrip_preserves_raw_data_field() {
    let receipt = allow_receipt();
    let ev = receipt_to_ocsf(&receipt);

    let raw = ev["raw_data"].as_str().expect("raw_data is a string");
    let parsed: Value = serde_json::from_str(raw).expect("raw_data is valid JSON");
    assert_eq!(parsed["id"], receipt.id);
    assert_eq!(parsed["capability_id"], receipt.capability_id);
    assert_eq!(parsed["tool_server"], receipt.tool_server);
    assert_eq!(parsed["tool_name"], receipt.tool_name);
}

#[test]
fn time_is_emitted_in_milliseconds() {
    let receipt = allow_receipt();
    let ev = receipt_to_ocsf(&receipt);

    let expected_ms = (receipt.timestamp as u128) * 1_000;
    assert_eq!(ev["time"].as_u64().unwrap() as u128, expected_ms);
}

#[test]
fn unknown_decision_yields_non_panicking_event_with_defined_status() {
    // Exercise all Decision variants to guarantee total coverage without a
    // panic. The enum is a closed set, so "unknown" here means every non-Allow
    // variant must still produce a well-formed event.
    for decision in [
        Decision::Deny {
            reason: "r".to_string(),
            guard: "g".to_string(),
        },
        Decision::Cancelled {
            reason: "c".to_string(),
        },
        Decision::Incomplete {
            reason: "i".to_string(),
        },
    ] {
        let receipt = receipt_with("rc-variant", decision, TrustLevel::Mediated, vec![], None);
        let ev = receipt_to_ocsf(&receipt);
        assert_eq!(ev["class_uid"], OCSF_CLASS_UID);
        assert!(
            ev["status_id"].is_number(),
            "status_id must always be numeric, got {:?}",
            ev["status_id"],
        );
        assert!(ev["severity_id"].is_number());
    }
}

#[test]
fn ocsf_exporter_emits_one_json_object_per_receipt() {
    let events = vec![
        trusted_event(allow_receipt()),
        trusted_event(deny_receipt()),
    ];
    let mapped = OcsfExporter::format_events(&events);
    assert_eq!(mapped.len(), 2);
    assert!(mapped.iter().all(|v| v.is_object()));
    assert_eq!(mapped[0]["status_id"], 1);
    assert_eq!(mapped[1]["status_id"], 2);
}

#[test]
fn ocsf_exporter_preserves_untrusted_signer_state() {
    let trusted_kernel_keys = BTreeSet::new();
    let events = vec![SiemEvent::from_receipt_with_trusted_kernel_keys(
        allow_receipt(),
        Some(&trusted_kernel_keys),
    )];

    let mapped = OcsfExporter::format_events(&events);

    assert_eq!(mapped.len(), 1);
    assert_eq!(mapped[0]["activity_id"], 99);
    assert_eq!(mapped[0]["status_id"], 99);
    assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], false);
    assert_eq!(mapped[0]["unmapped"]["chio"]["signer_trusted"], false);
    assert_eq!(
        mapped[0]["unmapped"]["chio"]["decision.verdict"],
        "mediated_decision"
    );
}

#[test]
fn ocsf_exporter_ndjson_body_contains_one_line_per_receipt() {
    let cfg = OcsfExporterConfig {
        payload_format: OcsfPayloadFormat::Ndjson,
        ..OcsfExporterConfig::default()
    };
    let exporter = OcsfExporter::new(cfg).expect("build exporter");
    let events = vec![
        SiemEvent::from_receipt(allow_receipt()),
        SiemEvent::from_receipt(deny_receipt()),
    ];

    // Formatter-only export path: empty endpoint short-circuits network I/O
    // and returns the number of mapped events.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let count = rt
        .block_on(chio_siem::Exporter::export_batch(&exporter, &events))
        .expect("formatter-only export succeeds");
    assert_eq!(count, 2);

    // Verify the serialized body form independently.
    let mapped = OcsfExporter::format_events(&events);
    let mut body = String::new();
    for ev in &mapped {
        body.push_str(&serde_json::to_string(ev).unwrap());
        body.push('\n');
    }
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let parsed: Value = serde_json::from_str(line).expect("each ndjson line parses");
        assert_eq!(parsed["class_uid"], OCSF_CLASS_UID);
    }
}

#[test]
fn ocsf_exporter_rejects_plaintext_endpoint_when_bearer_token_is_configured() {
    let cfg = OcsfExporterConfig {
        endpoint: "http://collector.example.test/ocsf".to_string(),
        bearer_token: Some("secret-token".to_string()),
        ..OcsfExporterConfig::default()
    };

    let err = match OcsfExporter::new(cfg) {
        Ok(_) => panic!("plaintext bearer endpoint must be rejected"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("https"),
        "error should explain the HTTPS requirement: {err}"
    );
    assert!(
        !err.to_string().contains("secret-token"),
        "error must not echo the bearer token: {err}"
    );
}

#[tokio::test]
async fn ocsf_exporter_honors_configured_request_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/ocsf"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
        .mount(&server)
        .await;

    let cfg = OcsfExporterConfig {
        endpoint: format!("{}/ocsf", server.uri()),
        timeout: Duration::from_millis(25),
        ..OcsfExporterConfig::default()
    };
    let exporter = OcsfExporter::new_plaintext_for_tests(cfg).expect("build exporter");
    let events = vec![SiemEvent::from_receipt(allow_receipt())];

    let started = Instant::now();
    let err = exporter
        .export_batch(&events)
        .await
        .expect_err("slow endpoint should time out");

    match err {
        ExportError::HttpError(message) => {
            assert!(
                message.contains("OCSF sink request failed"),
                "message: {message}"
            );
        }
        other => panic!("expected HttpError, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "configured timeout should fire before the mock response delay"
    );
}
