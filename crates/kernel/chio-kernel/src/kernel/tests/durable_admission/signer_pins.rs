//! Retained and local receipts verify only under this kernel's own receipt
//! signer; a valid signature under any other key is refused first.

use super::*;
use crate::admission_operation::{AdmissionRecoveryError, AdmissionRecoveryFailureKind};
use crate::kernel::signing_authority::KernelSigningAuthority;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signer_unavailable(error: &KernelError) -> bool {
    matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), AdmissionRecoveryError::Item {
            kind: AdmissionRecoveryFailureKind::ContractChanged,
            detail,
        } if detail == "original receipt signing authority is unavailable"))
}

#[test]
fn local_parent_receipt_signed_by_another_kernel_is_refused() -> TestResult {
    let foreign = make_kernel(make_config());
    let local = make_kernel(make_config());
    let content = br#"{"result":"parent"}"#;
    let receipt = foreign.build_and_sign_receipt(ReceiptParams {
        request_id: Some("parent-receipt-request"),
        capability_id: "parent-receipt-capability",
        tool_name: "read_file",
        server_id: "srv-a",
        decision: Decision::Allow,
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "/allowed"}))?,
        content_hash: sha256_hex(content),
        canonical_content: content.to_vec(),
        metadata: None,
        timestamp: 1_800_000_000,
        trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
        tenant_id: None,
    })?;
    let parent = LocalReceiptArtifact::Tool(Box::new(receipt));
    assert!(parent.verify_signature_with_floor(
        &foreign.receipt_signing_public_key()?,
        ReceiptCryptoFloor::AllowClassical,
    )?);
    let error = parent
        .verify_signature_with_floor(
            &local.receipt_signing_public_key()?,
            ReceiptCryptoFloor::AllowClassical,
        )
        .expect_err("a parent receipt from another kernel is refused");
    assert!(
        matches!(&error, KernelError::GovernedTransactionDenied(reason)
            if reason == "governed call_chain parent receipt signer is not the local kernel"),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn completed_replay_refuses_a_receipt_signed_by_a_replaced_signer() -> TestResult {
    let (mut kernel, request, _store, calls) = durable_admission_fixture("replay-signer-pin");
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(initial.verdict, Verdict::Allow, "{:?}", initial.reason);
    kernel.signing_authority = KernelSigningAuthority::classical(&Keypair::generate());
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("a retained receipt under a replaced signer is refused");
    assert!(signer_unavailable(&error), "{error:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn refusal_replay_refuses_a_receipt_signed_by_a_replaced_signer() -> TestResult {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, _store, calls) =
        durable_admission_fixture_with_grants("refusal-replay-signer-pin", vec![grant]);
    assert!(kernel.with_budget_store(|budget| {
        Ok(budget.try_increment(&request.capability.id, 0, Some(1))?)
    })?);
    let initial = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(initial.verdict, Verdict::Deny);
    kernel.signing_authority = KernelSigningAuthority::classical(&Keypair::generate());
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("a retained refusal under a replaced signer is refused");
    assert!(signer_unavailable(&error), "{error:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
