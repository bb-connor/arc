use super::*;
use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_security_types::ports::{ActionId, TenantId};

#[test]
fn submission_proof_refuses_unwrapped_and_foreign_id_signatures() {
    let submitter = Keypair::from_seed(&[51; 32]);
    let body = ActiveResponseSubmissionProofBody::new(
        ActionId::new("action-wrapper-refusal").unwrap(),
        TenantId::new("tenant-wrapper-refusal").unwrap(),
        "a".repeat(64),
        "b".repeat(64),
        submitter.public_key(),
        1_792_234_800_000,
        1_792_234_845_000,
    )
    .unwrap();
    let proof = ActiveResponseSubmissionProof::sign_with_backend(
        body,
        &Ed25519Backend::new(submitter.clone()),
    )
    .unwrap();
    assert!(proof.verify_integrity_embedded_key().unwrap());
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&submitter, &proof.body) {
        let refused = ActiveResponseSubmissionProof {
            signature,
            ..proof.clone()
        };
        assert_eq!(
            refused.verify_integrity_embedded_key(),
            Ok(false),
            "{label}"
        );
    }
}
