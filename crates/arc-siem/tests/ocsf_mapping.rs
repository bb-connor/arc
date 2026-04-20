//! Integration tests for the OCSF 1.3.0 Authorization mapping.
//!
//! These tests exercise `arc_siem::ocsf::receipt_to_ocsf` and
//! `arc_siem::OcsfExporter::format_events` against fully-signed
//! [`ArcReceipt`] fixtures covering each [`Decision`] variant.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use arc_core::crypto::Keypair;
use arc_core::receipt::{
    ArcReceipt, ArcReceiptBody, Decision, GuardEvidence, ToolCallAction, TrustLevel,
};
use arc_siem::event::SiemEvent;
use arc_siem::ocsf::{receipt_to_ocsf, OCSF_CATEGORY_UID, OCSF_CLASS_UID, OCSF_SCHEMA_VERSION};
use arc_siem::{OcsfExporter, OcsfExporterConfig, OcsfPayloadFormat};
use serde_json::Value;

fn receipt_with(
    id: &str,
    decision: Decision,
    trust_level: TrustLevel,
    evidence: Vec<GuardEvidence>,
    metadata: Option<serde_json::Value>,
) -> ArcReceipt {
    let keypair = Keypair::generate();
    let body = ArcReceiptBody {
        id: id.to_string(),
        timestamp: 1_712_345_678,
        capability_id: "cap-xyz".to_string(),
        tool_server: "srv-shell".to_string(),
        tool_name: "bash".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
            .expect("action parameters serialize"),
        decision,
        content_hash: "content-hash".to_string(),
        policy_hash: "policy-hash".to_string(),
        evidence,
        metadata,
        trust_level,
        tenant_id: None,
        kernel_key: keypair.public_key(),
    };
    ArcReceipt::sign(body, &keypair).unwrap()
}

fn allow_receipt() -> ArcReceipt {
    receipt_with(
        "rc-allow-1",
        Decision::Allow,
        TrustLevel::Mediated,
        vec![],
        None,
    )
}

fn deny_receipt() -> ArcReceipt {
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

// -- Tests --------------------------------------------------------------------

#[test]
fn allow_receipt_maps_to_success_event() {
    let ev = receipt_to_ocsf(&allow_receipt());

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
fn deny_receipt_maps_to_failure_event() {
    let ev = receipt_to_ocsf(&deny_receipt());

    assert_eq!(ev["class_uid"], OCSF_CLASS_UID);
    assert_eq!(ev["status_id"], 2, "Deny -> Failure");
    assert_eq!(ev["status"], "Failure");
    assert_eq!(ev["severity_id"], 4, "Deny -> High");
    assert_eq!(ev["severity"], "High");
    assert_eq!(ev["status_detail"], "forbidden path");
    assert_eq!(
        ev["unmapped"]["arc"]["decision.guard"],
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
        Decision::Allow,
        TrustLevel::Advisory,
        vec![],
        None,
    );
    let ev = receipt_to_ocsf(&receipt);

    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    let trust = enrichments
        .iter()
        .find(|e| e["name"] == "arc.trust_level")
        .expect("trust_level enrichment present");
    assert_eq!(trust["value"], "advisory");
    assert_eq!(trust["data"]["trust_level"], "advisory");
    assert_eq!(ev["unmapped"]["arc"]["trust_level"], "advisory");
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
        "arc.receipt.id",
        "arc.capability.id",
        "arc.tool.server",
        "arc.tool.name",
        "arc.policy.hash",
        "arc.content.hash",
    ] {
        assert!(
            names.contains(&expected),
            "observables missing {expected}: {names:?}",
        );
    }

    let capability = observables
        .iter()
        .find(|o| o["name"] == "arc.capability.id")
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
        .find(|o| o["name"] == "arc.guard")
        .expect("guard observable present on deny");
    assert_eq!(guard["value"], "ForbiddenPathGuard");
}

#[test]
fn tenant_id_in_metadata_surfaces_in_enrichments_and_unmapped() {
    let metadata = serde_json::json!({"tenant_id": "tenant-42"});
    let receipt = receipt_with(
        "rc-tenant-1",
        Decision::Allow,
        TrustLevel::Mediated,
        vec![],
        Some(metadata),
    );
    let ev = receipt_to_ocsf(&receipt);

    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    assert!(
        enrichments
            .iter()
            .any(|e| e["name"] == "arc.tenant_id" && e["value"] == "tenant-42"),
        "expected tenant_id enrichment: {enrichments:?}",
    );
    assert_eq!(ev["unmapped"]["arc"]["tenant_id"], "tenant-42");
}

#[test]
fn guard_evidence_populates_enrichments() {
    let ev = receipt_to_ocsf(&deny_receipt());
    let enrichments = ev["enrichments"].as_array().expect("enrichments array");
    let guard_enrichment = enrichments
        .iter()
        .find(|e| e["name"] == "arc.guard.evidence.0")
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
        SiemEvent::from_receipt(allow_receipt()),
        SiemEvent::from_receipt(deny_receipt()),
    ];
    let mapped = OcsfExporter::format_events(&events);
    assert_eq!(mapped.len(), 2);
    assert!(mapped.iter().all(|v| v.is_object()));
    assert_eq!(mapped[0]["status_id"], 1);
    assert_eq!(mapped[1]["status_id"], 2);
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
        .block_on(arc_siem::Exporter::export_batch(&exporter, &events))
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
