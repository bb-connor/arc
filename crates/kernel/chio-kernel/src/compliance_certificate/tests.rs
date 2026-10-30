use super::*;
use chio_core::crypto::{Ed25519Backend, Keypair};

#[test]
fn verification_refuses_unwrapped_and_foreign_id_signatures() {
    let key = Keypair::from_seed(&[7; 32]);
    let body = SessionComplianceCertificateBody {
        session_id: "sess-wrapper-refusal".to_string(),
        policy_hash: "policy-hash".to_string(),
        receipt_count: 3,
        all_signatures_valid: true,
        crypto_floor: KernelCryptoFloor::AllowClassical.as_str().to_string(),
        issued_at: 1_792_234_800,
    };
    let mut cert = issue_session_compliance_certificate(
        body,
        KernelCryptoFloor::AllowClassical,
        &Ed25519Backend::new(key.clone()),
    )
    .unwrap();
    verify_session_compliance_certificate(
        &cert,
        &key.public_key(),
        KernelCryptoFloor::AllowClassical,
    )
    .unwrap();
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&key, &cert.body) {
        cert.signature = signature;
        assert!(
            matches!(
                verify_session_compliance_certificate(
                    &cert,
                    &key.public_key(),
                    KernelCryptoFloor::AllowClassical
                ),
                Err(ComplianceCertificateError::SignatureVerificationFailed)
            ),
            "{label}"
        );
    }
}

#[test]
fn verification_refuses_a_certificate_from_an_unexpected_signer() {
    let key = Keypair::from_seed(&[7; 32]);
    let body = SessionComplianceCertificateBody {
        session_id: "sess-unexpected-signer".to_string(),
        policy_hash: "policy-hash".to_string(),
        receipt_count: 1,
        all_signatures_valid: true,
        crypto_floor: KernelCryptoFloor::AllowClassical.as_str().to_string(),
        issued_at: 1_792_234_800,
    };
    let cert = issue_session_compliance_certificate(
        body,
        KernelCryptoFloor::AllowClassical,
        &Ed25519Backend::new(key),
    )
    .unwrap();
    assert!(matches!(
        verify_session_compliance_certificate(
            &cert,
            &Keypair::from_seed(&[8; 32]).public_key(),
            KernelCryptoFloor::AllowClassical,
        ),
        Err(ComplianceCertificateError::UntrustedSigner)
    ));
}
