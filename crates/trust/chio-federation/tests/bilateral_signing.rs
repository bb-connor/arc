//! Bilateral cross-kernel co-signing tests.
//!
//! Covers the happy path (two kernels both sign the same receipt and either
//! side can verify the dual-signed artifact), the wrong-peer-key rejection
//! (a third-party key cannot impersonate either org), and the tampered-body
//! rejection (a mutated body fails verification fail-closed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair, Signature, SigningBackend};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::{
    bilateral::co_sign_with_origin, bilateral::BilateralCoSigningError, bilateral::CoSigningBody,
    bilateral::DualSignedReceipt, bilateral::ExpectedBilateralPeers, bilateral::InProcessCoSigner,
    bilateral::BILATERAL_DUAL_RECEIPT_SCHEMA,
};

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
fn happy_path_dual_signs_and_verifies_on_both_sides() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt.clone(),
        &cosigner,
    )
    .expect("co-sign happy path");

    assert_eq!(dual.org_a_kernel_id, origin_kernel_id);
    assert_eq!(dual.org_b_kernel_id, tool_host_kernel_id);
    assert_eq!(dual.body.id, receipt.id);

    // Both sides can verify with the same pinned peer keys.
    dual.verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect("dual-signed receipt verifies with both pinned peer keys");
    dual.verify_pinned(ExpectedBilateralPeers {
        org_a_kernel_id: origin_kernel_id,
        org_a_public_key: &origin_kp.public_key(),
        org_b_kernel_id: tool_host_kernel_id,
        org_b_public_key: &tool_host_kp.public_key(),
    })
    .expect("dual-signed receipt verifies with independently pinned identities");
}

#[test]
fn verify_pinned_rejects_self_declared_identity_substitution() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let mut dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    dual.org_a_kernel_id = "kernel.attacker-a".to_string();
    dual.org_b_kernel_id = "kernel.attacker-b".to_string();

    let err = dual
        .verify_pinned(ExpectedBilateralPeers {
            org_a_kernel_id: origin_kernel_id,
            org_a_public_key: &origin_kp.public_key(),
            org_b_kernel_id: tool_host_kernel_id,
            org_b_public_key: &tool_host_kp.public_key(),
        })
        .expect_err("self-declared kernel IDs must not override pinned peer IDs");
    assert_eq!(err, BilateralCoSigningError::PeerIdentityMismatch);
}

#[test]
fn verify_pinned_rejects_duplicate_peer_keys() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    let err = dual
        .verify_pinned(ExpectedBilateralPeers {
            org_a_kernel_id: origin_kernel_id,
            org_a_public_key: &origin_kp.public_key(),
            org_b_kernel_id: tool_host_kernel_id,
            org_b_public_key: &origin_kp.public_key(),
        })
        .expect_err("distinct peers must not share the same verification key");
    assert_eq!(err, BilateralCoSigningError::PeerIdentityMismatch);
}

#[test]
fn verify_fails_when_wrong_peer_key_is_supplied_for_either_side() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    // Swap origin key with a stranger's -- origin signature must fail.
    let err = dual
        .verify(&attacker_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("attacker origin key must be rejected");
    assert_eq!(err, BilateralCoSigningError::OrgASignatureInvalid);

    // Swap tool-host key with a stranger's -- tool-host signature must fail.
    let err = dual
        .verify(&origin_kp.public_key(), &attacker_kp.public_key())
        .expect_err("attacker tool-host key must be rejected");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn verify_fails_when_body_is_tampered() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let mut dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    // Mutate a covered field in the body.
    dual.body.tool_name = "file_write".to_string();
    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("tampered body must be rejected");
    // The origin signature is checked first, so we get OrgASignatureInvalid.
    assert_eq!(err, BilateralCoSigningError::OrgASignatureInvalid);
}

#[test]
fn verify_fails_when_detached_signatures_cover_receipt_with_bad_embedded_signature() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let mut receipt = sample_receipt(&tool_host_kp);
    receipt.content_hash = sha256_hex(b"tampered-after-receipt-signing");
    let (org_a_signature, org_b_signature) = detached_dual_signatures(
        &receipt,
        &origin_kp,
        &tool_host_kp,
        origin_kernel_id,
        tool_host_kernel_id,
    );
    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature,
        org_b_signature,
    };

    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("embedded Chio receipt signature must be verified");
    assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
}

#[test]
fn verify_fails_when_embedded_receipt_kernel_key_is_not_tool_host_key() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let rogue_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let receipt = sample_receipt(&rogue_kp);
    let (org_a_signature, org_b_signature) = detached_dual_signatures(
        &receipt,
        &origin_kp,
        &tool_host_kp,
        origin_kernel_id,
        tool_host_kernel_id,
    );
    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature,
        org_b_signature,
    };

    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("embedded receipt kernel_key must be the tool-host key");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn cosigner_rejects_forged_org_b_signature() {
    // Attacker tries to dump a receipt signed by their own key and have
    // the origin kernel co-sign it. The origin verifies Org B's declared
    // signature against the pinned tool-host key before signing, so this
    // must fail fail-closed.
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let err = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &attacker_kp,
        sample_receipt(&attacker_kp),
        &cosigner,
    )
    .expect_err("origin must refuse to co-sign an attacker-signed body");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn canonical_body_roundtrip_is_stable() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let receipt = sample_receipt(&tool_host_kp);

    let body_a = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b").unwrap();
    let body_b = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b").unwrap();
    assert_eq!(
        body_a.canonical_bytes().unwrap(),
        body_b.canonical_bytes().unwrap()
    );

    // Demonstrate that a DualSignedReceipt serializes and deserializes without
    // drift (receipt body stays intact, both signatures survive).
    let cosigner =
        InProcessCoSigner::new("kernel.org-a", origin_kp.clone(), tool_host_kp.public_key());
    let dual = co_sign_with_origin(
        "kernel.org-a",
        &origin_kp.public_key(),
        "kernel.org-b",
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    let json = serde_json::to_string(&dual).unwrap();
    let restored: DualSignedReceipt = serde_json::from_str(&json).unwrap();
    restored
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect("round-tripped dual receipt must still verify");
}

fn detached_dual_signatures(
    receipt: &ChioReceipt,
    origin_kp: &Keypair,
    tool_host_kp: &Keypair,
    origin_kernel_id: &str,
    tool_host_kernel_id: &str,
) -> (Signature, Signature) {
    let bytes = CoSigningBody::from_receipt(receipt, origin_kernel_id, tool_host_kernel_id)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let org_a_signature = Ed25519Backend::new(origin_kp.clone())
        .sign_bytes(&bytes)
        .unwrap();
    let org_b_signature = Ed25519Backend::new(tool_host_kp.clone())
        .sign_bytes(&bytes)
        .unwrap();
    (org_a_signature, org_b_signature)
}

// ---------------------------------------------------------------------------
// Preimage discipline: a co-signing key also signs receipts, so the co-sign
// endpoints must reconstruct the content they are asked to sign and refuse
// anything they cannot rebuild.
// ---------------------------------------------------------------------------

/// The canonical signing preimage of a receipt attributed to `kernel_key`.
/// A signature over these bytes IS a receipt issued by that kernel.
fn receipt_signing_preimage(kernel_key: &chio_core_types::crypto::PublicKey) -> Vec<u8> {
    let mut body = sample_receipt(&Keypair::generate()).body();
    body.kernel_key = kernel_key.clone();
    let body = chio_core_types::receipt::body::prepare_receipt_body_for_signing(body).unwrap();
    chio_core_types::canonical::canonical_json_bytes(
        &chio_core_types::receipt::signing::ChioReceiptSigningBody::from(&body),
    )
    .unwrap()
}

fn kernel_identity(
    kernel_id: &str,
    keypair: &Keypair,
) -> chio_federation::bilateral_dsse::KernelIdentity {
    chio_federation::bilateral_dsse::KernelIdentity {
        kernel_id: kernel_id.to_string(),
        passport_key_fingerprint: chio_federation::bilateral_dsse::Keyid::from_public_key(
            &keypair.public_key(),
        ),
        alg: "ed25519".to_string(),
    }
}

fn dsse_pae_preimage(org_a_kp: &Keypair, org_b_kp: &Keypair) -> Vec<u8> {
    let receipt = sample_receipt(org_b_kp);
    let predicate = chio_federation::bilateral_dsse::build_predicate(
        &receipt,
        kernel_identity("kernel.org-a", org_a_kp),
        kernel_identity("kernel.org-b", org_b_kp),
        &receipt.tool_name,
        1_734_000_000_000,
    )
    .unwrap();
    let statement = chio_federation::bilateral_dsse::build_statement(&receipt, predicate).unwrap();
    chio_federation::bilateral_dsse::pae(
        chio_federation::bilateral_dsse::PAYLOAD_TYPE_IN_TOTO,
        &statement.canonical_bytes().unwrap(),
    )
}

fn dsse_binding<'a>(
    org_a_public: &'a chio_core_types::crypto::PublicKey,
    org_b_public: &'a chio_core_types::crypto::PublicKey,
) -> chio_federation::bilateral_dsse::DssePreimageBinding<'a> {
    chio_federation::bilateral_dsse::DssePreimageBinding {
        org_a_kernel_id: "kernel.org-a",
        org_a_public_key: org_a_public,
        org_b_kernel_id: "kernel.org-b",
        org_b_public_key: org_b_public,
    }
}

#[test]
fn cosigning_body_reconstruction_accepts_only_the_body_it_can_rebuild() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let receipt = sample_receipt(&tool_host_kp);
    let body = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b").unwrap();
    let bytes = body.canonical_bytes().unwrap();

    chio_federation::bilateral::reconstruct_cosigning_body(&bytes, "kernel.org-a", "kernel.org-b")
        .expect("the canonical body rebuilds from the receipt it carries");

    // A receipt signing preimage is not a co-signing body: the key that would
    // sign it also signs receipts, so this is the forgery the reconstruction
    // exists to refuse.
    let forgery = receipt_signing_preimage(&origin_kp.public_key());
    assert!(matches!(
        chio_federation::bilateral::reconstruct_cosigning_body(
            &forgery,
            "kernel.org-a",
            "kernel.org-b"
        ),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));

    // Neither is a DSSE pre-authentication encoding.
    let pae = dsse_pae_preimage(&origin_kp, &tool_host_kp);
    assert!(matches!(
        chio_federation::bilateral::reconstruct_cosigning_body(
            &pae,
            "kernel.org-a",
            "kernel.org-b"
        ),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));

    // A body addressed to another pair of kernels is refused before any rebuild.
    assert_eq!(
        chio_federation::bilateral::reconstruct_cosigning_body(
            &bytes,
            "kernel.org-a",
            "kernel.org-c"
        )
        .err(),
        Some(BilateralCoSigningError::PeerIdentityMismatch)
    );

    // A body that parses but does not re-canonicalise to the bytes presented
    // (here the embedded receipt JSON carries insignificant whitespace) is
    // refused: the signer signs only what it rebuilt.
    let mut loose = body.clone();
    loose.receipt_canonical_json = format!(" {}", loose.receipt_canonical_json);
    let loose_bytes = loose.canonical_bytes().unwrap();
    assert_eq!(
        chio_federation::bilateral::reconstruct_cosigning_body(
            &loose_bytes,
            "kernel.org-a",
            "kernel.org-b"
        )
        .err(),
        Some(BilateralCoSigningError::ReceiptMismatch)
    );
}

#[test]
fn dsse_pae_reconstruction_accepts_only_the_preimage_it_can_rebuild() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_public = origin_kp.public_key();
    let tool_host_public = tool_host_kp.public_key();
    let pae = dsse_pae_preimage(&origin_kp, &tool_host_kp);

    chio_federation::bilateral_dsse::reconstruct_dsse_pae(
        &pae,
        dsse_binding(&origin_public, &tool_host_public),
    )
    .expect("a real pae preimage rebuilds from the statement it carries");

    // The cross-family case: a receipt signing preimage handed to the DSSE
    // endpoint.
    let forgery = receipt_signing_preimage(&origin_public);
    assert!(matches!(
        chio_federation::bilateral_dsse::reconstruct_dsse_pae(
            &forgery,
            dsse_binding(&origin_public, &tool_host_public)
        ),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));

    // A canonical co-signing body is not a pae preimage either.
    let receipt = sample_receipt(&tool_host_kp);
    let body_bytes = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b")
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert!(matches!(
        chio_federation::bilateral_dsse::reconstruct_dsse_pae(
            &body_bytes,
            dsse_binding(&origin_public, &tool_host_public)
        ),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));

    // A statement that does not name this kernel, with this kernel's key, as
    // the origin is refused.
    let third_party = Keypair::generate().public_key();
    assert_eq!(
        chio_federation::bilateral_dsse::reconstruct_dsse_pae(
            &pae,
            dsse_binding(&third_party, &tool_host_public)
        )
        .err(),
        Some(BilateralCoSigningError::PeerIdentityMismatch)
    );

    // Truncated framing fails closed rather than signing a prefix.
    assert!(matches!(
        chio_federation::bilateral_dsse::reconstruct_dsse_pae(
            &pae[..pae.len() - 1],
            dsse_binding(&origin_public, &tool_host_public)
        ),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));
}

#[test]
fn in_process_cosigner_refuses_a_receipt_preimage_on_the_dsse_profile() {
    use chio_federation::bilateral::BilateralCoSigningProtocol;
    use chio_federation::bilateral::DsseCoSigningRequest;

    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let cosigner =
        InProcessCoSigner::new("kernel.org-a", origin_kp.clone(), tool_host_kp.public_key());

    // The peer authenticates bytes of its own choosing: the canonical signing
    // preimage of a receipt it invented and attributed to the origin kernel.
    let forgery = receipt_signing_preimage(&origin_kp.public_key());
    let request = DsseCoSigningRequest::new(
        "kernel.org-a".to_string(),
        "kernel.org-b".to_string(),
        forgery.clone(),
        tool_host_kp.sign(&forgery),
    );
    assert!(matches!(
        cosigner.request_dsse_cosignature(&request),
        Err(BilateralCoSigningError::CanonicalJson(_))
    ));

    // The real preimage still co-signs.
    let pae = dsse_pae_preimage(&origin_kp, &tool_host_kp);
    let request = DsseCoSigningRequest::new(
        "kernel.org-a".to_string(),
        "kernel.org-b".to_string(),
        pae.clone(),
        tool_host_kp.sign(&pae),
    );
    let response = cosigner
        .request_dsse_cosignature(&request)
        .expect("a real pae preimage co-signs");
    assert!(origin_kp
        .public_key()
        .verify(&pae, &response.org_a_signature));
}
