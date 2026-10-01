//! Failure reports preserve receipt authority without inventing execution authority.

use super::*;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn report_operation(
    kernel: &ChioKernel,
) -> TestResult<(OperationContext, ToolCallOperation)> {
    let agent = make_keypair();
    let cap = make_capability(
        kernel,
        &agent,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let session = kernel.open_session(agent.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session)?;
    Ok((
        make_operation_context(
            &session,
            "session-report-request",
            &agent.public_key().to_hex(),
        ),
        ToolCallOperation {
            capability: cap,
            server_id: "srv-a".into(),
            tool_name: "read_file".into(),
            arguments: serde_json::json!({"path": "/original"}),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
            model_metadata: None,
            extra_metadata: None,
        },
    ))
}

#[test]
fn report_binds_original_operation_and_exact_content_without_caller_authority() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, mut operation) = report_operation(&kernel)?;
    operation.execution_nonce = Some(serde_json::json!({"invalid": "original nonce"}));
    operation.extra_metadata = Some(serde_json::json!({
        "budget_authority": {"authorized": true}, "financial": {"cost_charged": 100},
        "tenant_id": "forged",
        "session_report": {"execution_outcome": "completed"}, "secret": "do not copy",
    }));
    let receipt = kernel.record_session_tool_failure(&context, &operation)?;
    assert_eq!(receipt.kernel_key, kernel.receipt_signing_public_key());
    assert_eq!(receipt.policy_hash, kernel.config.policy_hash);
    assert!(receipt.verify_signature()?);
    assert!(receipt.action.verify_hash()?);
    assert_eq!(receipt.action.parameters, operation.arguments);
    assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
    assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Observed)
    );
    assert_eq!(receipt.tool_origin, ToolOrigin::ChioInternal);
    assert_eq!(receipt.trust_level, TrustLevel::Verified);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert!(receipt.financial_budget_authority_metadata().is_none());
    assert!(receipt.evidence.is_empty());
    let metadata = receipt.metadata.as_ref().ok_or("metadata missing")?;
    assert!(metadata.get("budget_authority").is_none());
    assert!(metadata.get("financial").is_none());
    assert!(metadata.get("secret").is_none());
    let event = metadata.get("session_report").ok_or("report missing")?;
    assert_eq!(event["kind"], "evaluation_failure_reported");
    assert_eq!(event["execution_outcome"], "unknown");
    assert_eq!(
        event["operation_sha256"],
        sha256_hex(&canonical_json_bytes(&operation)?)
    );
    assert_eq!(
        event["capability_sha256"],
        sha256_hex(&canonical_json_bytes(&operation.capability)?)
    );
    assert_eq!(
        event["context_sha256"],
        sha256_hex(&canonical_json_bytes(&context)?)
    );
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(event)?)
    );
    let session = kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert!(session.request_lineage(&context.request_id).is_none());
    let log = kernel.receipt_log();
    assert_eq!(
        canonical_json_bytes(&receipt)?,
        canonical_json_bytes(&log.receipts()[0])?
    );
    Ok(())
}

#[test]
fn report_tenant_is_explicit_session_snapshot_not_ambient_or_caller_metadata() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    let _request_scope = kernel.scope_receipt_tenant_id_for_request(
        context.request_id.as_str(),
        Some("ambient-request".into()),
    );
    let _thread_scope = scope_receipt_tenant_id(Some("ambient-thread".into()));
    let anonymous = kernel.record_session_tool_failure(&context, &operation)?;
    assert!(anonymous.tenant_id.is_none());
    kernel.set_session_auth_context(
        &context.session_id,
        oauth_auth_with_enterprise_tenant("tenant-A"),
    )?;
    let receipt = kernel.record_session_tool_failure(&context, &operation)?;
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-A"));
    let snapshot = kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .session_anchor_snapshot();
    let event = &receipt.metadata.as_ref().ok_or("metadata missing")?["session_report"];
    assert_eq!(event["session_anchor_id"], snapshot.session_anchor.id());
    assert_eq!(event["auth_epoch"], snapshot.session_anchor.auth_epoch());
    assert!(receipt.verify_signature()?);
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    kernel.set_session_auth_context(
        &context.session_id,
        oauth_auth_with_enterprise_tenant("tenant-B"),
    )?;
    let before = kernel.receipt_log().receipts().len();
    assert!(
        matches!(kernel.record_session_tool_failure(&context, &operation),
        Err(KernelError::ReceiptSigningFailed(reason)) if reason.contains("different authentication epoch"))
    );
    assert_eq!(kernel.receipt_log().receipts().len(), before);
    Ok(())
}

#[test]
fn unknown_or_mismatched_session_cannot_mint_a_report() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    let mut wrong_agent = context.clone();
    wrong_agent.agent_id = "other-agent".into();
    assert!(matches!(
        kernel.record_session_tool_failure(&wrong_agent, &operation),
        Err(KernelError::Session(
            crate::session::SessionError::ContextAgentMismatch { .. }
        ))
    ));
    let mut unknown = context;
    unknown.session_id = SessionId::new("unknown-session");
    assert!(matches!(
        kernel.record_session_tool_failure(&unknown, &operation),
        Err(KernelError::UnknownSession(_))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[test]
fn repeated_failure_reports_have_distinct_signed_ids() -> TestResult {
    let kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    let first = kernel.record_session_tool_failure(&context, &operation)?;
    let second = kernel.record_session_tool_failure(&context, &operation)?;
    assert_ne!(first.id, second.id);
    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(kernel.receipt_log().receipts().len(), 2);
    Ok(())
}

#[test]
fn missing_required_receipt_store_cannot_return_a_report() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    kernel.config.allow_ephemeral_receipt_log = false;
    assert!(
        matches!(kernel.record_session_tool_failure(&context, &operation),
        Err(KernelError::Internal(reason)) if reason.contains("no receipt store"))
    );
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[test]
fn dead_writer_cannot_return_a_report() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    kernel.set_receipt_store(Box::new(DeadWriterReceiptStore))?;
    assert!(
        matches!(kernel.record_session_tool_failure(&context, &operation),
        Err(KernelError::Internal(reason)) if reason.contains("commit writer is not serving"))
    );
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[test]
fn append_failure_cannot_return_or_locally_mirror_a_report() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    let called = Arc::new(AtomicBool::new(false));
    kernel.set_receipt_store(Box::new(FailingAppendReceiptStore {
        called: called.clone(),
    }))?;
    assert!(kernel
        .record_session_tool_failure(&context, &operation)
        .is_err());
    assert!(called.load(Ordering::SeqCst));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

struct UnavailableSigner(PublicKey);

impl chio_core::SigningBackend for UnavailableSigner {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        chio_core::SigningAlgorithm::Ed25519
    }
    fn public_key(&self) -> PublicKey {
        self.0.clone()
    }
    fn sign_bytes(&self, _: &[u8]) -> Result<chio_core::Signature, chio_core::Error> {
        Err(chio_core::Error::InvalidSignature(
            "test signer unavailable".into(),
        ))
    }
}

#[test]
fn failed_signer_cannot_fall_back_to_an_independent_key() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    kernel.signing_authority.backend = Arc::new(UnavailableSigner(kernel.public_key()));
    assert!(matches!(
        kernel.record_session_tool_failure(&context, &operation),
        Err(KernelError::ReceiptSigningFailed(reason)) if reason.contains("test signer unavailable")
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn report_refuses_classical_signer_below_boot_floor() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let (context, operation) = report_operation(&kernel)?;
    kernel.signing_authority.floor = KernelCryptoFloor::PqRequired;
    assert!(
        matches!(kernel.record_session_tool_failure(&context, &operation),
        Err(KernelError::ReceiptSigningFailed(reason)) if reason.contains("boot signing floor"))
    );
    assert!(kernel.receipt_log().receipts().is_empty());
    Ok(())
}
