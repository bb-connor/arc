use chio_runtime_core::RuntimeProofSourceRecord;

#[test]
fn runtime_source_record_has_one_receipt_binding() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "stepIndex": 0,
        "toolReceiptSha256": "1".repeat(64),
        "bilateralDsseSha256": "2".repeat(64),
        "workflowStepSha256": "3".repeat(64)
    });
    let record: RuntimeProofSourceRecord = serde_json::from_value(value.clone())?;
    assert_eq!(record.tool_receipt_sha256, "1".repeat(64));
    let mut retired = value;
    retired["admissionReceiptSha256"] = serde_json::json!("1".repeat(64));
    let error = match serde_json::from_value::<RuntimeProofSourceRecord>(retired) {
        Ok(_) => panic!("retired duplicate receipt binding accepted"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "unknown field `admissionReceiptSha256`, expected one of `stepIndex`, `toolReceiptSha256`, `bilateralDsseSha256`, `workflowStepSha256`");
    Ok(())
}
