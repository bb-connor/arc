use super::*;
use chio_core::crypto::{Ed25519Backend, Keypair};

#[test]
fn authority_attestation_refuses_unwrapped_and_foreign_id_signatures() {
    let authority = Keypair::from_seed(&[52; 32]);
    let body = ActiveResponseArtifactAuthorityAttestationBody::new(
        ActiveResponseArtifactAuthorityAttestationInput {
            artifact_ref: AdmissionArtifactRef::new("wrapper-refusal-artifacts").unwrap(),
            action_id: ActionId::new("action-wrapper-refusal").unwrap(),
            tenant_id: TenantId::new("tenant-wrapper-refusal").unwrap(),
            artifact_payload_digest: Digest32::new([1; 32]),
            submission_proof_digest: Digest32::new([2; 32]),
            plan_body_hash: Digest32::new([3; 32]),
            governed_intent_hash: Digest32::new([4; 32]),
            submitter: Keypair::from_seed(&[53; 32]).public_key(),
            authority: authority.public_key(),
            issued_at_unix_ms: 1_792_234_800_000,
            expires_at_unix_ms: 1_792_234_845_000,
        },
    )
    .unwrap();
    let attestation = ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        body,
        &Ed25519Backend::new(authority.clone()),
    )
    .unwrap();
    assert!(attestation.verify_integrity_embedded_key().unwrap());
    for (label, signature) in
        crate::wrapper_refusals::refused_signatures(&authority, &attestation.body)
    {
        let refused = ActiveResponseArtifactAuthorityAttestation {
            signature,
            ..attestation.clone()
        };
        assert_eq!(
            refused.verify_integrity_embedded_key(),
            Ok(false),
            "{label}"
        );
    }
}
