//! Bilateral cross-kernel DSSE co-signing tests.
//!
//! Covers the happy path (the tool-host kernel obtains the origin kernel's
//! DSSE signature and the envelope verifies under both pinned keys), the
//! forged Org B signature rejection, the unknown origin rejection, and the
//! wrong origin key rejection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::{
    bilateral::co_sign_with_origin, bilateral::BilateralCoSigningError,
    bilateral::InProcessCoSigner, bilateral_dsse::receipt_subject_name,
    bilateral_dsse::verify_dsse_envelope,
};

const ORIGIN_KERNEL_ID: &str = "kernel.org-a";
const TOOL_HOST_KERNEL_ID: &str = "kernel.org-b";
const TIMESTAMP_UNIX_MS: u64 = 1_734_000_000_000;

fn sample_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({
        "path": "/data/federation-test.txt"
    }))
    .unwrap()
}

fn sample_receipt(tool_host_kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-fed-20.3".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-fed-001".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: sample_action(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "fed-policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: tool_host_kp.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, tool_host_kp).unwrap()
}

#[test]
fn origin_cosigns_dsse_envelope_verifiable_by_both_orgs() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let receipt = sample_receipt(&tool_host_kp);
    let cosigner = InProcessCoSigner::new(
        ORIGIN_KERNEL_ID,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let envelope = co_sign_with_origin(
        ORIGIN_KERNEL_ID,
        &origin_kp.public_key(),
        TOOL_HOST_KERNEL_ID,
        &tool_host_kp,
        &receipt,
        &cosigner,
        "file_read",
        TIMESTAMP_UNIX_MS,
    )
    .unwrap();

    let statement = verify_dsse_envelope(
        &envelope,
        &origin_kp.public_key(),
        &tool_host_kp.public_key(),
    )
    .unwrap();
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));
    assert!(envelope.attests_receipt(&receipt).unwrap());
    let mut other = receipt.body();
    other.id = "rcpt-fed-other".to_string();
    let other = ChioReceipt::sign(other, &tool_host_kp).unwrap();
    assert!(!envelope.attests_receipt(&other).unwrap());
    assert_eq!(
        statement.predicate.tool_server_a.kernel_id,
        ORIGIN_KERNEL_ID
    );
    assert_eq!(
        statement.predicate.tool_server_b.kernel_id,
        TOOL_HOST_KERNEL_ID
    );
}

#[test]
fn cosigner_rejects_forged_org_b_signature() {
    // The origin verifies Org B's PAE signature against the pinned
    // tool-host key before signing, so an attacker key cannot obtain an
    // Org A co-signature.
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let cosigner = InProcessCoSigner::new(
        ORIGIN_KERNEL_ID,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let err = co_sign_with_origin(
        ORIGIN_KERNEL_ID,
        &origin_kp.public_key(),
        TOOL_HOST_KERNEL_ID,
        &attacker_kp,
        &sample_receipt(&attacker_kp),
        &cosigner,
        "file_read",
        TIMESTAMP_UNIX_MS,
    )
    .expect_err("origin must refuse to co-sign an attacker-signed PAE");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn cosigner_rejects_unknown_origin_kernel_id() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let cosigner = InProcessCoSigner::new(
        ORIGIN_KERNEL_ID,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let err = co_sign_with_origin(
        "kernel.org-c",
        &origin_kp.public_key(),
        TOOL_HOST_KERNEL_ID,
        &tool_host_kp,
        &sample_receipt(&tool_host_kp),
        &cosigner,
        "file_read",
        TIMESTAMP_UNIX_MS,
    )
    .expect_err("cosigner must refuse a request naming another origin");
    assert_eq!(
        err,
        BilateralCoSigningError::UnknownPeer("kernel.org-c".to_string())
    );
}

#[test]
fn origin_signature_under_unpinned_key_is_rejected() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let pinned_origin_kp = Keypair::generate();
    let cosigner = InProcessCoSigner::new(
        ORIGIN_KERNEL_ID,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let err = co_sign_with_origin(
        ORIGIN_KERNEL_ID,
        &pinned_origin_kp.public_key(),
        TOOL_HOST_KERNEL_ID,
        &tool_host_kp,
        &sample_receipt(&tool_host_kp),
        &cosigner,
        "file_read",
        TIMESTAMP_UNIX_MS,
    )
    .expect_err("an Org A signature under an unpinned key must not verify");
    assert_eq!(err, BilateralCoSigningError::OrgASignatureInvalid);
}

#[test]
fn dual_signed_receipt_shape_is_not_a_dsse_envelope() {
    let tool_host_kp = Keypair::generate();
    let receipt = sample_receipt(&tool_host_kp);
    let signature = tool_host_kp.sign_exempt(
        chio_core_types::crypto::ExemptFormat::DssePae,
        b"bilateral",
    );
    let value = serde_json::json!({
        "schema": "chio.bilateral.dual-signed-receipt.v1",
        "body": receipt,
        "orgAKernelId": ORIGIN_KERNEL_ID,
        "orgBKernelId": TOOL_HOST_KERNEL_ID,
        "orgASignature": signature,
        "orgBSignature": signature,
    });
    let error = serde_json::from_value::<chio_federation::bilateral_dsse::DsseEnvelope>(value)
        .expect_err("a dual-signed receipt is refused");
    let message = error.to_string();
    assert!(
        message.starts_with("unknown field `")
            && message.contains("expected one of `payloadType`, `payload`, `signatures`"),
        "{message}"
    );
}
