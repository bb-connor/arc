//! Strict Ed25519 verification and trusted-key acceptance.

use super::*;

/// Canonical encodings of the eight small-order Ed25519 points.
const SMALL_ORDER_ED25519_KEYS: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// The identity point as public key, and the signature `(R = identity,
/// s = 0)` that satisfies the cofactorless equation for every message.
const IDENTITY_KEY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const IDENTITY_UNIVERSAL_SIGNATURE: &str =
    "0100000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000";

/// Ed25519 group order l, little-endian 64-bit limbs.
const GROUP_ORDER: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

fn at_least(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for index in (0..4).rev() {
        if a[index] != b[index] {
            return a[index] > b[index];
        }
    }
    true
}

fn add_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = 0;
    for index in 0..4 {
        let (sum, first) = a[index].overflowing_add(b[index]);
        let (sum, second) = sum.overflowing_add(carry);
        a[index] = sum;
        carry = u64::from(first || second);
    }
}

fn sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0;
    for index in 0..4 {
        let (difference, first) = a[index].overflowing_sub(b[index]);
        let (difference, second) = difference.overflowing_sub(borrow);
        a[index] = difference;
        borrow = u64::from(first || second);
    }
}

/// `2 * acc + bit (mod l)` for `acc < l`.
fn double_mod_l(acc: &mut [u64; 4], bit: bool) {
    let mut carry = u64::from(bit);
    for limb in acc.iter_mut() {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if at_least(acc, &GROUP_ORDER) {
        sub_assign(acc, &GROUP_ORDER);
    }
}

fn reduce_le_bytes_mod_l(bytes: &[u8]) -> [u64; 4] {
    let mut acc = [0; 4];
    for byte in bytes.iter().rev() {
        for bit in (0..8).rev() {
            double_mod_l(&mut acc, (byte >> bit) & 1 == 1);
        }
    }
    acc
}

fn mul_mod_l(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut acc = [0; 4];
    for limb in b.iter().rev() {
        for bit in (0..64).rev() {
            double_mod_l(&mut acc, false);
            if (limb >> bit) & 1 == 1 {
                add_assign(&mut acc, a);
                if at_least(&acc, &GROUP_ORDER) {
                    sub_assign(&mut acc, &GROUP_ORDER);
                }
            }
        }
    }
    acc
}

fn limbs_to_le_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// A signature by the holder of `seed` whose `R` is the identity point.
///
/// With `s = k * a (mod l)` the cofactorless equation `[s]B = R + [k]A`
/// holds, so only a verifier that rejects small-order `R` refuses it.
fn identity_r_signature(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use sha2::Sha512;
    let public_key = Keypair::from_seed(seed).public_key_bytes();
    let expanded = Sha512::digest(seed);
    let mut secret_scalar = [0; 32];
    secret_scalar.copy_from_slice(&expanded[..32]);
    secret_scalar[0] &= 248;
    secret_scalar[31] &= 127;
    secret_scalar[31] |= 64;
    let secret_scalar = reduce_le_bytes_mod_l(&secret_scalar);
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut challenge = Sha512::new();
    challenge.update(identity);
    challenge.update(public_key);
    challenge.update(message);
    let challenge = reduce_le_bytes_mod_l(&challenge.finalize());
    let response = mul_mod_l(&challenge, &secret_scalar);
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&identity);
    signature[32..].copy_from_slice(&limbs_to_le_bytes(&response));
    signature
}

fn loose_ed25519_accepts(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
        key.verify(message, &DalekSignature::from_bytes(signature))
            .is_ok()
    })
}

#[test]
fn verify_rejects_identity_key_universal_signature() -> Result<()> {
    let weak_key = PublicKey::from_hex(IDENTITY_KEY)?;
    let forged = Signature::from_hex(IDENTITY_UNIVERSAL_SIGNATURE)?;
    let message = b"message without a signer";
    assert!(loose_ed25519_accepts(
        weak_key.ed25519_bytes()?,
        message,
        &forged.to_bytes()
    ));

    assert!(weak_key.is_weak_ed25519());
    assert!(!weak_key.verify(message, &forged));
    let value = serde_json::json!({"authority": "forged"});
    assert!(!weak_key.verify_canonical(&value, &forged)?);
    assert!(!weak_key.verify_shared_canonical(&canonical_json_shared_bytes(&value)?, &forged));
    Ok(())
}

#[test]
fn verify_rejects_small_order_signature_point_from_honest_key() -> Result<()> {
    let seed = [77; 32];
    let keypair = Keypair::from_seed(&seed);
    let public_key = keypair.public_key();
    let message = b"small-order commitment";
    let forged = identity_r_signature(&seed, message);
    assert!(loose_ed25519_accepts(
        &keypair.public_key_bytes(),
        message,
        &forged
    ));

    assert!(!public_key.is_weak_ed25519());
    assert!(!public_key.verify(message, &Signature::from_bytes(&forged)));
    let trusted = TrustedPublicKey::new(public_key.clone())?;
    assert!(!trusted.verify(message, &Signature::from_bytes(&forged)));
    assert!(trusted.verify(message, &keypair.sign(message)));
    Ok(())
}

#[test]
fn verify_rejects_non_canonical_signature_scalar() -> Result<()> {
    let keypair = Keypair::from_seed(&[78; 32]);
    let message = b"malleated scalar";
    let mut encoded = keypair.sign(message).to_bytes();
    let mut scalar = [0; 4];
    for (limb, chunk) in scalar.iter_mut().zip(encoded[32..].chunks_exact(8)) {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(bytes);
    }
    add_assign(&mut scalar, &GROUP_ORDER);
    encoded[32..].copy_from_slice(&limbs_to_le_bytes(&scalar));

    assert!(keypair.public_key().verify(message, &keypair.sign(message)));
    assert!(!keypair
        .public_key()
        .verify(message, &Signature::from_bytes(&encoded)));
    Ok(())
}

#[test]
fn trusted_public_key_rejects_every_small_order_ed25519_key() -> Result<()> {
    for encoded in SMALL_ORDER_ED25519_KEYS {
        let key = PublicKey::from_hex(encoded)?;
        assert!(key.is_weak_ed25519(), "{encoded}");
        assert!(
            matches!(
                TrustedPublicKey::new(key.clone()),
                Err(Error::InvalidPublicKey(_))
            ),
            "{encoded}"
        );
        assert!(
            matches!(
                TrustedPublicKey::from_hex(encoded),
                Err(Error::InvalidPublicKey(_))
            ),
            "{encoded}"
        );
        assert!(
            matches!(
                TrustedPublicKey::try_from(key),
                Err(Error::InvalidPublicKey(_))
            ),
            "{encoded}"
        );
        let decoded = serde_json::from_str::<TrustedPublicKey>(&format!("\"{encoded}\""));
        assert!(
            decoded.is_err_and(|err| err.to_string().contains("weak")),
            "{encoded}"
        );
    }
    Ok(())
}

#[test]
fn trusted_public_key_rejects_hybrid_key_with_weak_classical_half() -> Result<()> {
    let weak_classical = PublicKey::from_hex(IDENTITY_KEY)?;
    let hybrid = PublicKey::from_hybrid_parts(
        weak_classical,
        &[0; ML_DSA_65_PUBLIC_KEY_LEN],
        HYBRID_ED25519_MLDSA65,
    )?;
    assert!(hybrid.is_weak_ed25519());
    assert!(matches!(
        TrustedPublicKey::new(hybrid),
        Err(Error::InvalidPublicKey(_))
    ));
    Ok(())
}

#[test]
fn trusted_public_key_accepts_honest_keys_and_preserves_encoding() -> Result<()> {
    let keypair = Keypair::from_seed(&[79; 32]);
    let trusted = TrustedPublicKey::new(keypair.public_key())?;
    assert_eq!(trusted.public_key(), &keypair.public_key());
    assert_eq!(trusted.to_hex(), keypair.public_key().to_hex());
    assert_eq!(trusted.algorithm(), SigningAlgorithm::Ed25519);
    assert_eq!(
        serde_json::to_string(&trusted)?,
        serde_json::to_string(&keypair.public_key())?
    );
    let decoded: TrustedPublicKey = serde_json::from_str(&serde_json::to_string(&trusted)?)?;
    assert_eq!(decoded, trusted);

    let value = serde_json::json!({"b": 2, "a": 1});
    let (signature, _) = keypair.sign_canonical(&value)?;
    assert!(trusted.verify_canonical(&value, &signature)?);
    assert!(!trusted.verify_canonical(&serde_json::json!({"a": 2}), &signature)?);
    assert_eq!(
        TrustedPublicKey::new_ed25519(keypair.public_key())?,
        trusted
    );
    assert_eq!(PublicKey::from(trusted.clone()), keypair.public_key());

    let mut p256_point = [0; 65];
    p256_point[0] = 0x04;
    let p256 = PublicKey::from_p256_sec1(&p256_point)?;
    assert!(TrustedPublicKey::new(p256.clone()).is_ok());
    assert!(matches!(
        TrustedPublicKey::new_ed25519(p256),
        Err(Error::InvalidPublicKey(_))
    ));
    Ok(())
}
