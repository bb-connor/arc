use chio_core::crypto::{Ed25519Backend, ExemptFormat, Keypair, SigningAlgorithm, SigningBackend};
use chio_core::receipt::authoritative_spend::PresentedNonceView;
use chio_core::receipt::body::ChioReceipt;
use chio_core::{canonical_json_bytes, message::SignedExecutionNonce};

use super::{
    build_evidence_receipts, signed_nonce, VerifiedFixPayload, VERIFIED_FIX_PAYLOAD_SCHEMA,
};

const ISSUED_AT: u64 = 1_800_000_000;

fn payload() -> VerifiedFixPayload {
    VerifiedFixPayload {
        schema: VERIFIED_FIX_PAYLOAD_SCHEMA.to_owned(),
        repository: "local/verified-fix".to_owned(),
        base_revision: "a".repeat(40),
        candidate_revision: "b".repeat(40),
        patch: "diff --git a/lib.rs b/lib.rs\n".to_owned(),
        baseline: Vec::new(),
        candidate: Vec::new(),
    }
}

fn sign_evidence(
    backend: &dyn SigningBackend,
) -> Result<(Vec<ChioReceipt>, Vec<SignedExecutionNonce>), String> {
    let receipts = build_evidence_receipts(backend, ISSUED_AT, &payload())?;
    let nonces = receipts
        .iter()
        .map(|receipt| signed_nonce(receipt, backend))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((receipts, nonces))
}

fn assert_signed_by(
    backend: &dyn SigningBackend,
    algorithm: SigningAlgorithm,
) -> Result<(), String> {
    let key = backend.public_key().map_err(|error| error.to_string())?;
    let (receipts, nonces) = sign_evidence(backend)?;
    assert_eq!(receipts.len(), 2);
    assert_eq!(nonces.len(), receipts.len());
    for (receipt, nonce) in receipts.iter().zip(&nonces) {
        assert_eq!(receipt.kernel_key, key);
        assert_eq!(receipt.signature.algorithm(), algorithm);
        assert!(receipt
            .verify_integrity_embedded_key()
            .map_err(|e| e.to_string())?);
        assert_eq!(nonce.signature.algorithm(), algorithm);
        assert!(nonce.verify_signed_by(&key));
    }
    Ok(())
}

#[test]
fn evidence_receipts_and_nonces_verify_under_the_production_backend_key() -> Result<(), String> {
    assert_signed_by(&Ed25519Backend::generate(), SigningAlgorithm::Ed25519)
}

#[test]
fn nonce_signing_refuses_a_backend_that_is_not_the_receipt_kernel() -> Result<(), String> {
    let (receipts, _) = sign_evidence(&Ed25519Backend::generate())?;
    let other = Ed25519Backend::generate();
    assert_eq!(
        signed_nonce(&receipts[0], &other).err(),
        Some(
            "invalid public key: signing backend identity does not match the requested key"
                .to_owned()
        )
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_production_backend_signs_hybrid_receipts_and_nonces() -> Result<(), String> {
    use chio_core::crypto::{HybridBackend, MlDsa65Backend};

    let backend = HybridBackend::new(
        Box::new(Ed25519Backend::generate()),
        MlDsa65Backend::generate().map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    assert_signed_by(&backend, SigningAlgorithm::Hybrid)
}

#[test]
fn nonce_signed_over_bare_canonical_bytes_is_refused() -> Result<(), String> {
    let seed = [7_u8; 32];
    let (_, nonces) = sign_evidence(&Ed25519Backend::new(Keypair::from_seed(&seed)))?;
    let signer = Keypair::from_seed(&seed);
    let mut bare = nonces[0].clone();
    assert!(bare.verify_signed_by(&signer.public_key()));
    let nonce_bytes = canonical_json_bytes(&bare.nonce).map_err(|e| e.to_string())?;
    bare.signature = signer.sign_exempt(ExemptFormat::JwsSigningInput, &nonce_bytes);
    assert!(!bare.verify_signed_by(&signer.public_key()));
    Ok(())
}
