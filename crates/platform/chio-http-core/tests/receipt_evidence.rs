use chio_core_types::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_http_core::{
    canonical_json_bytes, sha256_hex, HttpMethod, HttpReceipt, HttpReceiptBody, Keypair, Verdict,
};
use chio_test_support::prelude::*;
use serde_json::Value;

fn keypair() -> Keypair {
    Keypair::from_seed(&[89; 32])
}

fn body(metadata: Option<Value>) -> HttpReceiptBody {
    HttpReceiptBody {
        id: String::new(),
        request_id: "metadata-request".into(),
        route_pattern: "/receipts".into(),
        method: HttpMethod::Get,
        caller_identity_hash: sha256_hex(b"caller"),
        session_id: None,
        verdict: Verdict::Allow,
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        evidence: Vec::new(),
        response_status: 200,
        timestamp: 1_775_137_626,
        content_hash: sha256_hex(b"request"),
        policy_hash: sha256_hex(b"policy"),
        trust_level: TrustLevel::Mediated,
        capability_id: None,
        metadata,
        kernel_key: keypair().public_key(),
    }
}

#[test]
fn explicit_null_metadata_preserves_http_body_roundtrip() -> Result<(), Box<dyn std::error::Error>>
{
    let body = body(Some(Value::Null));
    let encoded = serde_json::to_vec(&body)?;
    let decoded: HttpReceiptBody = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.metadata, Some(Value::Null));
    assert_eq!(
        canonical_json_bytes(&decoded)?,
        canonical_json_bytes(&body)?
    );
    Ok(())
}

#[test]
fn explicit_null_metadata_preserves_http_signature_roundtrip(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = HttpReceipt::sign(body(Some(Value::Null)), &keypair())?;
    assert!(receipt.verify_integrity_embedded_key()?);
    let encoded = serde_json::to_vec(&receipt)?;
    let decoded: HttpReceipt = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.metadata, Some(Value::Null));
    assert!(decoded.verify_integrity_embedded_key()?);
    Ok(())
}

#[test]
fn absent_metadata_preserves_http_signature_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = HttpReceipt::sign(body(None), &keypair())?;
    let encoded = serde_json::to_vec(&receipt)?;
    let decoded: HttpReceipt = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.metadata, None);
    assert!(decoded.verify_integrity_embedded_key()?);
    Ok(())
}

#[test]
fn adding_null_metadata_invalidates_http_signature() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = HttpReceipt::sign(body(None), &keypair())?;
    let mut value = serde_json::to_value(&receipt)?;
    value["metadata"] = Value::Null;
    let decoded: HttpReceipt = serde_json::from_value(value)?;
    assert!(matches!(decoded.verify_integrity_embedded_key(), Ok(false)));
    Ok(())
}

#[test]
fn removing_null_metadata_invalidates_http_signature() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = HttpReceipt::sign(body(Some(Value::Null)), &keypair())?;
    let mut value = serde_json::to_value(&receipt)?;
    value.as_object_mut().test_unwrap().remove("metadata");
    let decoded: HttpReceipt = serde_json::from_value(value)?;
    assert!(matches!(decoded.verify_integrity_embedded_key(), Ok(false)));
    Ok(())
}
