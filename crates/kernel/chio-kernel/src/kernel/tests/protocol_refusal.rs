//! Protocol refusal observations cannot be forged into execution receipts.

use super::*;
use crate::{ProtocolRefusalReason, ProtocolRefusalSummary, ProtocolRequestDigest};
use chio_core::receipt::kinds::{BoundaryClass, ReceiptKind, ToolOrigin, TrustLevel};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn summary() -> ProtocolRefusalSummary {
    ProtocolRefusalSummary::new(
        ProtocolRefusalReason::CapabilityNotMatched,
        "tools/call",
        Some("raw-target-sentinel"),
        ProtocolRequestDigest::from_wire_bytes(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"secret":"raw-argument-sentinel"},"_meta":{"token":"raw-token-sentinel","protocol_refusal":{"auth_epoch":9000,"tenant_id":"forged"}}}}"#,
        ),
    )
}

#[test]
fn protocol_refusal_is_a_bounded_nonauthorizing_observation() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    let summary = summary();
    let receipt = kernel.record_session_protocol_refusal(&context, &summary)?;
    assert!(receipt.verify_signature()?);
    assert!(receipt.action.verify_hash()?);
    assert_eq!(receipt.kernel_key, kernel.receipt_signing_public_key());
    assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
    assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
    assert_eq!(receipt.tool_origin, ToolOrigin::ChioInternal);
    assert_eq!(receipt.trust_level, TrustLevel::Verified);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert!(receipt.capability_id.is_empty());
    assert!(receipt.financial_budget_authority_metadata().is_none());
    assert!(receipt.evidence.is_empty());
    let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
    assert_eq!(event["schema"], "chio.session.protocol-refusal.v1");
    assert_eq!(event["reason"], "capability_not_matched");
    assert_eq!(event["request_digest"]["source"], "original_wire");
    assert_eq!(event["method_sha256"], sha256_hex(b"tools/call"));
    assert_eq!(event["target_sha256"], sha256_hex(b"raw-target-sentinel"));
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(event)?)
    );
    let encoded = serde_json::to_string(&receipt)?;
    for sentinel in [
        "raw-target-sentinel",
        "raw-argument-sentinel",
        "raw-token-sentinel",
        "forged",
    ] {
        assert!(
            !encoded.contains(sentinel),
            "raw protocol data entered the report"
        );
    }
    let session = kernel.session(&context.session_id).ok_or("session")?;
    assert!(session.inflight().is_empty());
    assert!(session.request_lineage(&context.request_id).is_none());
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    Ok(())
}

#[test]
fn protocol_refusal_hashes_unbounded_identifiers_and_labels_decoded_identity() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    let request =
        serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"value":0.5}});
    let summary = ProtocolRefusalSummary::new(
        ProtocolRefusalReason::CapabilityMatcherInvalid,
        &"method-sentinel".repeat(100_000),
        Some(&"target-sentinel".repeat(100_000)),
        ProtocolRequestDigest::from_decoded_json(&request)?,
    );
    let receipt = kernel.record_session_protocol_refusal(&context, &summary)?;
    let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
    assert_eq!(event["request_digest"]["source"], "decoded_json");
    let encoded = serde_json::to_string(event)?;
    assert!(encoded.len() < 2048);
    assert!(!encoded.contains("sentinel"));
    Ok(())
}

#[test]
fn protocol_refusal_decoded_digest_rejects_deep_or_oversized_values() {
    let mut deep = serde_json::Value::Null;
    for _ in 0..129 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    for value in [
        deep,
        serde_json::Value::String("x".repeat(8 * 1024 * 1024 + 1)),
        serde_json::Value::Array(vec![serde_json::Value::Null; 1024 * 1024]),
        serde_json::Value::String("\n".repeat(4 * 1024 * 1024)),
    ] {
        assert!(matches!(
            ProtocolRequestDigest::from_decoded_json(&value),
            Err(KernelError::InvalidReceiptMetadata(_))
        ));
    }
}

#[test]
fn protocol_refusal_decoded_digest_preserves_unsigned_numbers_and_exact_byte_boundary() -> TestResult
{
    let ordinary = serde_json::json!({"ordinary":12.5,"scientific":1e-3});
    let digest = ProtocolRequestDigest::from_decoded_json(&ordinary)?;
    assert_eq!(
        digest.sha256(),
        sha256_hex(br#"{"ordinary":12.5,"scientific":0.001}"#)
    );
    assert_eq!(
        digest.source(),
        crate::ProtocolRequestDigestSource::DecodedJson
    );
    let boundary = serde_json::Value::String("\n".repeat(4 * 1024 * 1024 - 1));
    assert!(ProtocolRequestDigest::from_decoded_json(&boundary).is_ok());
    Ok(())
}

#[test]
fn protocol_refusal_survives_durable_store_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("refusal.db");
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;
    kernel.config.allow_ephemeral_receipt_log = false;
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    kernel.set_session_auth_context(
        &context.session_id,
        oauth_auth_with_enterprise_tenant("tenant-A"),
    )?;
    let receipt = kernel.record_session_protocol_refusal(&context, &summary())?;
    let signed_bytes = canonical_json_bytes(&receipt)?;
    drop(kernel);
    let reopened = SqliteReceiptStore::open(&path)?;
    let retained = reopened
        .load_chio_receipt(&receipt.id)?
        .ok_or("refusal not retained")?;
    assert_eq!(canonical_json_bytes(&retained)?, signed_bytes);
    assert!(retained.verify_signature()?);
    assert_eq!(retained.tenant_id.as_deref(), Some("tenant-A"));
    assert!(!retained.is_allowed());
    Ok(())
}

#[test]
fn protocol_refusal_uses_session_tenant_and_rejects_old_lineage_epoch() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    let _request_scope = kernel.scope_receipt_tenant_id_for_request(
        context.request_id.as_str(),
        Some("ambient-request".into()),
    );
    let _thread_scope = scope_receipt_tenant_id(Some("ambient-thread".into()));
    kernel.set_session_auth_context(
        &context.session_id,
        oauth_auth_with_enterprise_tenant("tenant-A"),
    )?;
    let receipt = kernel.record_session_protocol_refusal(&context, &summary())?;
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-A"));
    let snapshot = kernel
        .session(&context.session_id)
        .ok_or("session")?
        .session_anchor_snapshot();
    let event = &receipt.metadata.as_ref().ok_or("metadata")?["protocol_refusal"];
    assert_eq!(event["session_anchor_id"], snapshot.session_anchor.id());
    assert_eq!(event["auth_epoch"], snapshot.session_anchor.auth_epoch());
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    kernel.set_session_auth_context(
        &context.session_id,
        oauth_auth_with_enterprise_tenant("tenant-B"),
    )?;
    let before = kernel.receipt_log().receipts().len();
    assert!(
        matches!(kernel.record_session_protocol_refusal(&context, &summary()),
        Err(KernelError::ReceiptSigningFailed(reason)) if reason.contains("different authentication epoch"))
    );
    assert_eq!(kernel.receipt_log().receipts().len(), before);
    Ok(())
}

#[test]
fn protocol_refusal_rejects_substituted_or_unknown_session_context() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    let mut wrong = context.clone();
    wrong.agent_id = "wrong-agent".into();
    assert!(matches!(
        kernel.record_session_protocol_refusal(&wrong, &summary()),
        Err(KernelError::Session(
            crate::session::SessionError::ContextAgentMismatch { .. }
        ))
    ));
    wrong.session_id = SessionId::new("unknown-session");
    assert!(matches!(
        kernel.record_session_protocol_refusal(&wrong, &summary()),
        Err(KernelError::UnknownSession(_))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[test]
fn repeated_protocol_refusals_do_not_begin_or_terminalize_execution() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    let first = kernel.record_session_protocol_refusal(&context, &summary())?;
    let second = kernel.record_session_protocol_refusal(&context, &summary())?;
    assert_ne!(first.id, second.id);
    assert_eq!(first.content_hash, second.content_hash);
    assert!(!first.is_allowed() && !second.is_allowed());
    let session = kernel.session(&context.session_id).ok_or("session")?;
    assert!(session.request_lineage(&context.request_id).is_none());
    assert!(session.inflight().is_empty());
    Ok(())
}

#[test]
fn protocol_refusal_persistence_failure_returns_no_receipt_or_local_mirror() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, _) = super::session_reports::report_operation(&kernel)?;
    kernel.config.allow_ephemeral_receipt_log = false;
    assert!(matches!(
        kernel.record_session_protocol_refusal(&context, &summary()),
        Err(KernelError::Internal(reason)) if reason.contains("no receipt store configured")
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    let called = Arc::new(AtomicBool::new(false));
    kernel.set_receipt_store(Box::new(FailingAppendReceiptStore {
        called: called.clone(),
    }))?;
    assert!(matches!(
        kernel.record_session_protocol_refusal(&context, &summary()),
        Err(KernelError::ReceiptPersistence(
            ReceiptStoreError::Conflict(_)
        ))
    ));
    assert!(called.load(Ordering::SeqCst));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[test]
fn protocol_refusal_metadata_cannot_be_injected_at_tool_evaluation() -> TestResult {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("refusal-metadata", &capability, "read_file", "srv-a");
    let result = kernel.evaluate_tool_call_blocking_with_metadata(
        &request,
        Some(serde_json::json!({
            "protocol_refusal": {"reason": "capability_not_matched", "decision": "allow"},
        })),
    );
    assert!(matches!(
        result,
        Err(KernelError::InvalidReceiptMetadata(_))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}
