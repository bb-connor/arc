use super::*;

#[test]
fn otherwise_valid_event_from_untrusted_producer_is_rejected() {
    let trusted = Keypair::from_seed(&[72_u8; 32]);
    let untrusted = Keypair::from_seed(&[73_u8; 32]);
    let verifier = verifier(&trusted);
    assert!(verifier.verify(&signed_event(&untrusted)).is_err());
}
