use crate::{input, validate_json_artifact_schema, ProofRoomError, CHIO_RECEIPT_SCHEMA};

const RECEIPT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/commerce-payments/offline-psp-valid/authority-receipts/receipt-intent-commerce-001.json"
));

fn assert_receipt_shape_refusal(bytes: &[u8]) {
    let Err(ProofRoomError::Validation(message)) =
        validate_json_artifact_schema(bytes, CHIO_RECEIPT_SCHEMA, "receipt")
    else {
        panic!("expected receipt schema validation refusal");
    };
    assert_eq!(
        message,
        "proof-room.schema-violation: receipt is not a chio.receipt.v1 receipt"
    );
}

#[test]
fn closed_receipt_without_schema_is_accepted() -> Result<(), ProofRoomError> {
    validate_json_artifact_schema(RECEIPT, CHIO_RECEIPT_SCHEMA, "receipt")
}

#[test]
fn advertised_receipt_schema_alone_is_refused() {
    assert_receipt_shape_refusal(br#"{"schema":"chio.receipt.v1"}"#);
}

#[test]
fn closed_receipt_with_schema_member_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = input::decode(RECEIPT)?;
    value["schema"] = serde_json::json!(CHIO_RECEIPT_SCHEMA);
    assert_receipt_shape_refusal(&serde_json::to_vec(&value)?);
    Ok(())
}

#[test]
fn schemaless_non_receipt_is_refused() {
    assert_receipt_shape_refusal(br#"{"id":"not-a-receipt"}"#);
}

#[test]
fn other_artifact_schema_still_requires_an_exact_match() -> Result<(), ProofRoomError> {
    let bytes = br#"{"schema":"chio.example.v1"}"#;
    validate_json_artifact_schema(bytes, "chio.example.v1", "other")?;
    let Err(ProofRoomError::Validation(message)) =
        validate_json_artifact_schema(bytes, "chio.different.v1", "other")
    else {
        panic!("expected schema mismatch");
    };
    assert_eq!(
        message,
        "proof-room.schema-mismatch: other expected chio.different.v1 got chio.example.v1"
    );
    Ok(())
}

#[test]
fn receipt_with_duplicate_parameter_member_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(RECEIPT)?;
    let bytes = text.replacen(
        r#""parameters":{"#,
        r#""parameters":{"order_id":"forged","#,
        1,
    );
    let error = validate_json_artifact_schema(bytes.as_bytes(), CHIO_RECEIPT_SCHEMA, "receipt")
        .err()
        .ok_or("duplicate receipt parameter was accepted")?;
    assert!(matches!(
        error,
        ProofRoomError::Input(chio_core_types::canonical::UntrustedJsonError::SignedInput(
            _
        ))
    ));
    Ok(())
}
