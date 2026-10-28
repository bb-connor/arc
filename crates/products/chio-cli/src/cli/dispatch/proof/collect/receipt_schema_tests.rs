use super::{artifact_declares_schema, artifact_schema_from_file, CHIO_RECEIPT_SCHEMA};

const RECEIPT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/commerce-payments/offline-psp-valid/authority-receipts/receipt-intent-commerce-001.json"
));

fn classify(bytes: &[u8]) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("artifact.json");
    std::fs::write(&path, bytes)?;
    Ok((
        artifact_schema_from_file(&path)?,
        artifact_declares_schema(&path, CHIO_RECEIPT_SCHEMA)?,
    ))
}

#[test]
fn closed_receipt_without_schema_is_collected() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(classify(RECEIPT)?, (CHIO_RECEIPT_SCHEMA.to_string(), true));
    Ok(())
}

#[test]
fn advertised_receipt_schema_alone_is_not_collected() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        classify(br#"{"schema":"chio.receipt.v1"}"#)?,
        (String::new(), false)
    );
    Ok(())
}

#[test]
fn closed_receipt_with_schema_member_is_not_collected() -> Result<(), Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = crate::input::json(RECEIPT)?;
    value["schema"] = serde_json::json!(CHIO_RECEIPT_SCHEMA);
    assert_eq!(classify(&serde_json::to_vec(&value)?)?, (String::new(), false));
    Ok(())
}

#[test]
fn schemaless_non_receipt_is_not_collected() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        classify(br#"{"id":"not-a-receipt"}"#)?,
        (String::new(), false)
    );
    Ok(())
}

#[test]
fn other_artifact_schema_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        classify(br#"{"schema":"chio.example.v1"}"#)?,
        ("chio.example.v1".to_string(), false)
    );
    Ok(())
}

#[test]
fn receipt_with_duplicate_parameter_member_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(RECEIPT)?;
    let bytes = text.replacen(r#""parameters":{"#, r#""parameters":{"order_id":"forged","#, 1);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("artifact.json");
    std::fs::write(&path, bytes)?;
    let error = artifact_schema_from_file(&path)
        .err()
        .ok_or("duplicate receipt parameter was accepted")?;
    assert_eq!(
        error.report().code,
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    assert!(matches!(
        error,
        crate::CliError::SignedJson(chio_core::canonical::UntrustedJsonError::SignedInput(_))
    ));
    assert!(!artifact_declares_schema(&path, CHIO_RECEIPT_SCHEMA)?);
    Ok(())
}
