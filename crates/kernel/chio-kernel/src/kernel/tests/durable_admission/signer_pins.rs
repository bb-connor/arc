//! A local parent receipt verifies only under a key this kernel trusts; a
//! valid signature under any other key is refused first.

use super::*;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
        &[foreign.receipt_signing_public_key()?],
        ReceiptCryptoFloor::AllowClassical,
    )?);
    let mut trusted = local.trusted_issuer_keys();
    trusted.push(local.receipt_signing_public_key()?);
    let error = parent
        .verify_signature_with_floor(&trusted, ReceiptCryptoFloor::AllowClassical)
        .expect_err("a parent receipt from another kernel is refused");
    assert!(
        matches!(&error, KernelError::GovernedTransactionDenied(reason)
            if reason == "governed call_chain parent receipt signer is not trusted"),
        "{error:?}"
    );
    Ok(())
}
