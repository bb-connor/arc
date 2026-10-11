use super::*;

#[test]
fn original_bundle_artifact_count_is_bounded_before_verification() {
    let mut bundle = enterprise_bundle(EnterpriseCase::Valid);
    verify_enterprise_export(&bundle).test_expect("positive control verifies");
    for index in 0..4096 {
        bundle
            .artifacts
            .insert(format!("unused-{index}"), Vec::new());
    }
    let error =
        verify_enterprise_export(&bundle).test_expect_err("total input count must be bounded");
    assert!(matches!(
        error,
        chio_transaction_passport::TransactionPassportError::EvidenceLimit
    ));
}

#[test]
fn enterprise_export_rejects_telemetry_schema_only_receipt_ref() {
    let mut bundle = enterprise_bundle(EnterpriseCase::Valid);
    bundle.artifacts.insert(
        "schema-only-siem-receipt.json".to_string(),
        json_bytes(json!({
            "schema": CHIO_RECEIPT_SCHEMA,
            "id": "schema-only-siem-receipt"
        })),
    );
    let data_governance = bundle
        .artifacts
        .get("data-governance-report.json")
        .test_expect("data governance artifact exists");
    let mut telemetry: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("telemetry-projection.json")
            .test_expect("telemetry artifact exists"),
    )
    .test_expect("telemetry artifact parses");
    telemetry["events"]
        .as_array_mut()
        .test_expect("telemetry events are an array")
        .push(json!({
            "event_id": "siem-export-event",
            "event_kind": "siem_export",
            "artifact_ref": "data-governance-report.json",
            "artifact_sha256": chio_core_types::sha256_hex(data_governance),
            "receipt_ref": "schema-only-siem-receipt.json"
        }));
    replace_graph_artifact(
        &mut bundle,
        "telemetry-projection.json",
        "telemetry-projection",
        telemetry,
    );

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("schema-only telemetry receipt must fail closed");

    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn original_auxiliary_risk_receipt_preserves_parser_cause() {
    let mut bundle = enterprise_bundle(EnterpriseCase::RiskSettlementCounterpartyBound);
    verify_enterprise_export(&bundle).test_expect("positive enterprise control");
    let report: Value = serde_json::from_slice(&bundle.artifacts["risk-comptroller-report.json"])
        .test_expect("risk report fixture parses");
    let reference = report["reserve_ledger"][0]["receipt_ref"]
        .as_str()
        .test_expect("reserve receipt reference");
    let path = format!("{reference}.json");
    let mut original =
        String::from_utf8(bundle.artifacts[&path].clone()).test_expect("receipt JSON");
    let end = original.rfind('}').test_expect("receipt is object");
    original.insert_str(end, ",\"private-marker\":1,\"private-marker\":2");
    replace_graph_artifact_bytes(&mut bundle, &path, &path, original.into_bytes());
    let error =
        verify_enterprise_export(&bundle).test_expect_err("ambiguous auxiliary evidence rejects");
    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
    assert!(!format!("{error:?} {error}").contains("private-marker"));
}
