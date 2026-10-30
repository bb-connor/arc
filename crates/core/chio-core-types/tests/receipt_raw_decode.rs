//! Raw receipt text decodes through `UntrustedJsonText::decode_signed`, which
//! refuses duplicate keys at every depth before a `serde_json::Value` can keep
//! only the last one, and keeps the native signed numeric domain.

use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
use chio_core_types::receipt::metadata::GuardEvidence;
use chio_core_types::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core_types::{Error, Keypair};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signed_receipt(parameters: Value) -> TestResult<String> {
    let kernel = Keypair::from_seed(&[8; 32]);
    let body = ChioReceiptBody {
        id: "rcpt-raw".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-raw".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "read".to_string(),
        action: ToolCallAction::from_parameters(parameters)?,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "deadbeefdeadbeef".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: Some(json!({"surface": {"lane": "a"}})),
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    let receipt = ChioReceipt::sign(body, &kernel)?;
    Ok(String::from_utf8(canonical_json_bytes(&receipt)?)?)
}

fn signed_child_receipt() -> TestResult<String> {
    let kernel = Keypair::from_seed(&[9; 32]);
    let body = ChildRequestReceiptBody {
        id: "child-raw".to_string(),
        timestamp: 1_710_000_001,
        session_id: SessionId::new("sess-raw"),
        parent_request_id: RequestId::new("parent-raw"),
        request_id: RequestId::new("child-req-raw"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
        policy_hash: "aabbccddaabbccdd".to_string(),
        metadata: Some(json!({"surface": {"lane": "a"}})),
        kernel_key: kernel.public_key(),
    };
    let receipt = ChildRequestReceipt::sign(body, &kernel)?;
    Ok(String::from_utf8(canonical_json_bytes(&receipt)?)?)
}

fn inject_once(text: &str, anchor: &str, inserted: &str) -> TestResult<String> {
    if text.matches(anchor).count() != 1 {
        return Err(format!("anchor {anchor} must appear once").into());
    }
    Ok(text.replacen(anchor, &format!("{anchor}{inserted}"), 1))
}

fn assert_duplicate_refused<T: DeserializeOwned>(text: &str, key: &str) -> TestResult {
    let error = UntrustedJsonText::new(text)
        .decode_signed::<T>()
        .err()
        .ok_or("duplicate key decoded")?;
    let expected = format!("duplicate object key: {key:?} at line ");
    assert!(
        matches!(&error, UntrustedJsonError::SignedInput(Error::CanonicalJson(message)) if message.starts_with(&expected)),
        "{key}: {error:?}"
    );
    Ok(())
}

#[test]
fn raw_duplicate_keys_refused_by_decode_signed() -> TestResult {
    let receipt = signed_receipt(json!({"path": "/workspace/a"}))?;
    UntrustedJsonText::new(&receipt).decode_signed::<ChioReceipt>()?;
    for (duplicate, key) in [
        (receipt.replacen('{', "{\"id\":\"forged\",", 1), "id"),
        (
            inject_once(&receipt, "\"parameters\":{", "\"path\":\"/etc/shadow\",")?,
            "path",
        ),
        (
            inject_once(&receipt, "\"evidence\":[{", "\"verdict\":false,")?,
            "verdict",
        ),
        (
            inject_once(&receipt, "\"surface\":{", "\"lane\":\"b\",")?,
            "lane",
        ),
        (
            inject_once(&receipt, "\"metadata\":{", "\"surface\":{\"lane\":\"b\"},")?,
            "surface",
        ),
    ] {
        let collapsed: Value = serde_json::from_str(&duplicate)?;
        assert!(collapsed.is_object(), "raw serde_json keeps one {key}");
        assert_duplicate_refused::<ChioReceipt>(&duplicate, key)?;
    }

    let child = signed_child_receipt()?;
    UntrustedJsonText::new(&child).decode_signed::<ChildRequestReceipt>()?;
    let duplicate = inject_once(&child, "\"surface\":{", "\"lane\":\"b\",")?;
    assert_duplicate_refused::<ChildRequestReceipt>(&duplicate, "lane")
}

#[test]
fn decode_signed_keeps_native_numeric_domain() -> TestResult {
    let receipt = signed_receipt(json!({"count": 9_007_199_254_740_993_u64, "ratio": 100.0}))?;
    let decoded: ChioReceipt = UntrustedJsonText::new(&receipt).decode_signed()?;
    assert!(decoded.verify_integrity_embedded_key()?);
    assert_eq!(String::from_utf8(canonical_json_bytes(&decoded)?)?, receipt);
    Ok(())
}

#[test]
fn records_without_value_members_refuse_raw_duplicate_fields() {
    assert!(serde_json::from_str::<GuardEvidence>(
        r#"{"guard_name":"g","verdict":true,"verdict":false}"#
    )
    .is_err());
    assert!(serde_json::from_str::<Decision>(
        r#"{"verdict":"deny","reason":"a","reason":"b","guard":"g"}"#
    )
    .is_err());
}
