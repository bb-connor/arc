//! Keep byte-oriented encoding compatible with every public key wire family.

use chio_core_types::crypto::{
    sha256_hex, Keypair, PublicKey, HYBRID_ED25519_MLDSA65, HYBRID_P256_MLDSA65,
    HYBRID_P384_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN,
};
use sha2::{Digest, Sha256};

fn check_wire(key: &PublicKey, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(key.to_hex(), expected);
    key.with_hex_bytes(|bytes| assert_eq!(bytes, expected.as_bytes()));
    assert_eq!(
        serde_json::to_string(key)?,
        serde_json::to_string(expected)?
    );
    assert_eq!(PublicKey::from_hex(expected)?, *key);
    Ok(())
}

#[test]
fn every_key_family_preserves_hex_and_serialized_bytes() -> Result<(), Box<dyn std::error::Error>> {
    for seed in u8::MIN..=u8::MAX {
        let ed = Keypair::from_seed(&[seed; 32]).public_key();
        let mut p256 = [seed; 65];
        p256[0] = 4;
        let mut p384 = [seed; 97];
        p384[0] = 4;
        let cases = [
            (
                ed.clone(),
                hex::encode(ed.ed25519_bytes()?),
                HYBRID_ED25519_MLDSA65,
            ),
            (
                PublicKey::from_p256_sec1(&p256)?,
                format!("p256:{}", hex::encode(p256)),
                HYBRID_P256_MLDSA65,
            ),
            (
                PublicKey::from_p384_sec1(&p384)?,
                format!("p384:{}", hex::encode(p384)),
                HYBRID_P384_MLDSA65,
            ),
        ];
        let pq = [seed; ML_DSA_65_PUBLIC_KEY_LEN];
        for (key, expected, algorithm) in cases {
            check_wire(&key, &expected)?;
            let hybrid = PublicKey::from_hybrid_parts(key, &pq, algorithm)?;
            check_wire(
                &hybrid,
                &format!("hybrid:{expected}:{}:{algorithm}", hex::encode(pq)),
            )?;
        }
    }
    Ok(())
}

#[test]
fn digest_hex_preserves_all_byte_values_and_sha_block_boundaries() {
    let all_bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    for len in [
        0, 1, 31, 32, 55, 56, 63, 64, 65, 97, 127, 128, 129, 255, 256,
    ] {
        let input = &all_bytes[..len];
        assert_eq!(sha256_hex(input), hex::encode(Sha256::digest(input)));
    }
}
