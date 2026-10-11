use aws_lc_rs::{
    encoding::{AsDer, PublicKeyX509Der},
    rand::SystemRandom,
    rsa::KeySize,
    signature::{KeyPair as _, RsaEncoding, RsaKeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA256},
};
use sigstore_crypto::{sha256, verify_signature, verify_signature_prehashed, SigningScheme};
use sigstore_types::{DerPublicKey, SignatureBytes};

#[test]
fn rsa_prehashed_verification_must_not_hash_the_digest_again(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = RsaKeyPair::generate(KeySize::Rsa2048)?;
    let der: PublicKeyX509Der<'_> = key.public_key().as_der()?;
    let public = DerPublicKey::from_bytes(der.as_ref());
    let artifact = b"Chio dependency audit artifact";
    let digest = sha256(artifact);
    let schemes: [(&dyn RsaEncoding, SigningScheme); 2] = [
        (&RSA_PKCS1_SHA256, SigningScheme::RsaPkcs1Sha256),
        (&RSA_PSS_SHA256, SigningScheme::RsaPssSha256),
    ];
    let mut failures = Vec::new();
    for (padding, scheme) in schemes {
        let mut correct = vec![0; key.public_key().modulus_len()];
        key.sign(padding, &SystemRandom::new(), artifact, &mut correct)?;
        let correct = SignatureBytes::new(correct);
        verify_signature(&public, artifact, &correct, scheme)?;
        let correct_accepts =
            verify_signature_prehashed(&public, &digest, &correct, scheme).is_ok();
        let mut wrong_message = vec![0; key.public_key().modulus_len()];
        key.sign(
            padding,
            &SystemRandom::new(),
            digest.as_bytes(),
            &mut wrong_message,
        )?;
        let wrong_message = SignatureBytes::new(wrong_message);
        assert!(verify_signature(&public, artifact, &wrong_message, scheme).is_err());
        let wrong_accepts =
            verify_signature_prehashed(&public, &digest, &wrong_message, scheme).is_ok();
        println!("{scheme:?}: artifact signature accepted={correct_accepts}; digest-as-message signature accepted={wrong_accepts}");
        if !correct_accepts || wrong_accepts {
            failures.push(scheme.name());
        }
    }
    assert!(
        failures.is_empty(),
        "incorrect prehashed behavior: {failures:?}"
    );
    Ok(())
}

#[test]
fn ecdsa_prehashed_verification_preserves_artifact_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = sigstore_crypto::KeyPair::generate_ecdsa_p256()?;
    let public = key.public_key_der()?;
    let artifact = b"Chio ECDSA artifact";
    let digest = sha256(artifact);
    let signature = key.sign(artifact)?;
    verify_signature_prehashed(&public, &digest, &signature, key.default_scheme())?;
    assert!(verify_signature_prehashed(
        &public,
        &sha256(b"changed artifact"),
        &signature,
        key.default_scheme()
    )
    .is_err());
    let digest_as_message = key.sign(digest.as_bytes())?;
    assert!(
        verify_signature_prehashed(&public, &digest, &digest_as_message, key.default_scheme())
            .is_err()
    );
    Ok(())
}

#[test]
fn ed25519_signature_over_digest_bytes_is_not_a_prehashed_artifact_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    use aws_lc_rs::signature::Ed25519KeyPair;
    use der::{asn1::BitString, Encode};

    let private = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
    let key = Ed25519KeyPair::from_pkcs8(private.as_ref())?;
    let public = spki::SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None::<der::Any>,
        },
        subject_public_key: BitString::from_bytes(key.public_key().as_ref())?,
    };
    let public = DerPublicKey::new(public.to_der()?);
    let digest = sha256(b"Chio Ed25519 artifact");
    let signature = SignatureBytes::from_bytes(key.sign(digest.as_bytes()).as_ref());
    verify_signature(
        &public,
        digest.as_bytes(),
        &signature,
        SigningScheme::Ed25519,
    )?;
    assert!(matches!(
        verify_signature_prehashed(&public, &digest, &signature, SigningScheme::Ed25519),
        Err(sigstore_crypto::Error::UnsupportedAlgorithm(_))
    ));
    Ok(())
}

#[test]
fn sha256_digest_api_rejects_schemes_requiring_longer_digests(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = sigstore_crypto::KeyPair::generate_ecdsa_p256()?;
    let public = key.public_key_der()?;
    let digest = sha256(b"Chio algorithm boundary");
    let signature = key.sign(digest.as_bytes())?;
    for scheme in [
        SigningScheme::EcdsaP256Sha384,
        SigningScheme::EcdsaP384Sha384,
        SigningScheme::RsaPssSha384,
        SigningScheme::RsaPssSha512,
        SigningScheme::RsaPkcs1Sha384,
        SigningScheme::RsaPkcs1Sha512,
    ] {
        assert!(matches!(
            verify_signature_prehashed(&public, &digest, &signature, scheme),
            Err(sigstore_crypto::Error::UnsupportedAlgorithm(_))
        ));
    }
    Ok(())
}
