use super::execution_nonce_coordinator_id;

#[test]
fn durable_nonce_identity_matches_independent_classical_vector(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = chio_core::Keypair::from_seed(&[73; 32]).public_key();
    assert_eq!(
        key.to_hex(),
        "772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef"
    );
    let identity = execution_nonce_coordinator_id(&key)?;
    assert_eq!(
        identity.as_str(),
        "kernel:a2766fcf82255578a2e29684bbe00d87e6bcc7d0336f3eb6cb7e73fd1e32926a"
    );
    assert_eq!(execution_nonce_coordinator_id(&key)?, identity);
    assert_eq!(identity.as_str().len(), 71);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn durable_nonce_identity_distinguishes_pq_components() -> Result<(), Box<dyn std::error::Error>> {
    use chio_core::crypto::{
        verify_exempt, Ed25519Backend, ExemptFormat, HybridBackend, MlDsa65Backend, SigningBackend,
        SigningMessage,
    };

    let classical = chio_core::Keypair::from_seed(&[73; 32]);
    let classical_id = execution_nonce_coordinator_id(&classical.public_key())?;
    let mut identities = Vec::new();
    for seed in [74, 75] {
        let backend = HybridBackend::new(
            Box::new(Ed25519Backend::new(classical.clone())),
            MlDsa65Backend::from_seed(&[seed; 32]),
        )?;
        let key = backend.public_key()?;
        let control = SigningMessage::exempt(ExemptFormat::JwsSigningInput, b"e30.e30");
        let signature = backend.sign_bytes(control)?;
        verify_exempt(&key, ExemptFormat::JwsSigningInput, b"e30.e30", &signature)?;
        let identity = execution_nonce_coordinator_id(&key)?;
        assert_eq!(identity.as_str().len(), 71);
        assert_ne!(identity, classical_id);
        identities.push(identity);
    }
    assert_ne!(identities.first(), identities.last());
    Ok(())
}
