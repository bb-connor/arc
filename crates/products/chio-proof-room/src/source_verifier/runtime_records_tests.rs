use super::ensure_source_runtime_regeneration_records_bind_workflow_steps;

#[test]
fn source_record_reader_refuses_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let record = serde_json::json!({
        "stepIndex": 0,
        "toolReceiptSha256": "1".repeat(64),
        "bilateralDsseSha256": "2".repeat(64),
        "workflowStepSha256": "3".repeat(64)
    });
    let workflow = serde_json::to_vec(&serde_json::json!({"stepEvidence": [record.clone()]}))?;
    ensure_source_runtime_regeneration_records_bind_workflow_steps(
        &serde_json::to_vec(&serde_json::json!({"sourceRecords": [record.clone()]}))?,
        &workflow,
    )?;
    for field in ["admissionReceiptSha256", "unexpectedBinding"] {
        let mut extra = record.clone();
        extra[field] = serde_json::json!("4".repeat(64));
        let error = match ensure_source_runtime_regeneration_records_bind_workflow_steps(
            &serde_json::to_vec(&serde_json::json!({"sourceRecords": [extra]}))?,
            &workflow,
        ) {
            Ok(()) => panic!("unknown source-record field accepted: {field}"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "proof-room.runtime-regeneration.source-record-unknown-field"
        );
    }
    Ok(())
}
