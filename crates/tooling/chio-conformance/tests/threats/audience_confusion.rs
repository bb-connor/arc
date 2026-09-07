// Threat test for threat ID `audience_confusion` (Audience confusion).
//
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_custody_hw::capability::PasskeyCapability::require_audience`
// function directly. Build a signed capability minted for audience A
// ("urn:chio:audience:kernel"), then drive the production `require_audience`
// fail-closed check by presenting it to a verifier that expects audience B
// ("urn:chio:audience:other"). The production code returns
// `Err(CustodyError::AudienceMismatch { expected, found })` when the
// audiences disagree; this is the deny path that closes audience-confusion
// at the application layer.
//
// Production call site:
// `crates/trust/chio-custody-hw/src/capability.rs:179` (`require_audience`).
//
// Revert-to-prove-it-fails recipe: replace the body of
// `PasskeyCapability::require_audience` in
// `crates/trust/chio-custody-hw/src/capability.rs` with `Ok(())` (drop the
// audience comparison). Both deny-arm assertions below then fail
// because the verifier accepts the cross-audience capability.

use std::sync::Arc;

use chio_core::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_custody_hw::capability::{PasskeyCapability, ScopeSet};
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::mint::signing_message;
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};

fn fixed_iat() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_iat fixture must construct"),
    }
}

fn signed_capability(audience: &str) -> (PasskeyCapability, PublicKey) {
    let backend = Ed25519Backend::new(Keypair::from_seed(&[0x31; 32]));
    let public_key = backend.public_key();
    let service = IssuerService::with_signer(audience, Arc::new(backend));
    let assertion = VerifiedAssertion {
        credential_id_b64: "AAAA".to_string(),
        user_verified: true,
    };
    let request = MintRequest {
        audience: audience.to_string(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: "nonce-audience-confusion".to_string(),
    };
    let response = match service.mint_capability(&assertion, &request, fixed_iat()) {
        Ok(response) => response,
        Err(error) => panic!("signed capability fixture MUST mint: {error}"),
    };
    assert!(
        !response.capability.signature.is_empty(),
        "audience-confusion fixture must exercise a signed envelope"
    );
    (response.capability, public_key)
}

#[test]
fn threat_audience_confusion_require_audience_rejects_mismatch() {
    // covers: audience_confusion
    //
    // Mint a capability for audience "kernel" and present it to a
    // verifier expecting audience "other". The production
    // `require_audience` call MUST return
    // `CustodyError::AudienceMismatch`.
    let (cap, _public_key) = signed_capability("urn:chio:audience:kernel");

    let result = cap.require_audience("urn:chio:audience:other");
    let err = match result {
        Ok(()) => panic!(
            "production require_audience MUST reject when minted audience \
             differs from the verifier-expected audience; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CustodyError::AudienceMismatch { .. }),
        "expected CustodyError::AudienceMismatch, got {err:?}"
    );

    // Sanity: the matched audience is accepted.
    if let Err(err) = cap.require_audience("urn:chio:audience:kernel") {
        panic!(
            "matched audience MUST verify (otherwise the deny guard \
             is over-rejecting); got {err:?}"
        );
    }
}

#[test]
fn threat_audience_confusion_carries_expected_and_found_audiences() {
    // covers: audience_confusion
    //
    // The `AudienceMismatch` variant carries the verifier-expected and
    // capability-found audiences so an auditor can see the bound
    // identities side-by-side. Pin both fields so a future variant
    // shape change cannot silently drop one of the two values.
    let (cap, _public_key) = signed_capability("urn:chio:audience:tenant-a");

    let err = match cap.require_audience("urn:chio:audience:tenant-b") {
        Ok(()) => panic!("cross-tenant audience MUST reject"),
        Err(err) => err,
    };
    match err {
        CustodyError::AudienceMismatch { expected, found } => {
            assert_eq!(expected, "urn:chio:audience:tenant-b");
            assert_eq!(found, "urn:chio:audience:tenant-a");
        }
        other => panic!(
            "expected CustodyError::AudienceMismatch with both fields, \
             got {other:?}"
        ),
    }
}

#[test]
fn threat_audience_confusion_post_signing_audience_tamper_breaks_signature() {
    // covers: audience_confusion
    //
    // Attacker scenario: rewrite the audience inside a genuinely signed
    // capability so it names the attacker's target runtime. Audience is
    // part of the canonical signing message, so the original issuer
    // signature must no longer verify after the rewrite.
    let (mut capability, public_key) = signed_capability("urn:chio:audience:kernel");
    capability.audience = "urn:chio:audience:other".to_string();
    let message = match signing_message(&capability) {
        Ok(message) => message,
        Err(error) => panic!("tampered capability MUST remain encodable: {error}"),
    };
    let signature = match Signature::from_hex(&capability.signature) {
        Ok(signature) => signature,
        Err(error) => panic!("fixture signature MUST decode: {error}"),
    };
    assert!(
        !public_key.verify(&message, &signature),
        "post-signing audience rewrite MUST invalidate the issuer signature"
    );
}
