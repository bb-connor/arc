//! Untrusted crypto wire input must not control parser depth or decode allocation.

use chio_core_types::crypto::{
    HYBRID_ED25519_MLDSA65, HYBRID_P256_MLDSA65, HYBRID_P384_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN,
};
use chio_core_types::{Hash, Keypair, PublicKey, Signature};
use serde::Deserialize;
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_TEST: &str = "CHIO_CRYPTO_WIRE_BOUNDS_CHILD";

fn assert_deep_wire_rejected(
    test_name: &str,
    parse_rejects: impl FnOnce(&str) -> bool,
) -> TestResult {
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        // Short invalid inner components keep this below ordinary HTTP body
        // limits while exercising recursive parsing before semantic validation.
        let mut wire = "hybrid:".repeat(20_000);
        wire.push_str(&"00".repeat(64));
        wire.push_str(&":00:ed25519+mldsa65".repeat(20_000));
        assert!(parse_rejects(&wire));
        return Ok(());
    }
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_TEST, test_name)
        .output()?;
    assert!(
        output.status.success(),
        "crypto parser child terminated with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("running 1 test\n")
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"),
        "crypto parser child must execute its exact regression: {stdout}",
    );
    Ok(())
}

#[test]
fn deeply_nested_key_wire_returns_an_error_without_crashing() -> TestResult {
    assert_deep_wire_rejected(
        "deeply_nested_key_wire_returns_an_error_without_crashing",
        |wire| PublicKey::from_hex(wire).is_err(),
    )
}

#[test]
fn deeply_nested_signature_wire_returns_an_error_without_crashing() -> TestResult {
    assert_deep_wire_rejected(
        "deeply_nested_signature_wire_returns_an_error_without_crashing",
        |wire| Signature::from_hex(wire).is_err(),
    )
}

#[test]
fn deeply_nested_key_json_returns_an_error_without_crashing() -> TestResult {
    assert_deep_wire_rejected(
        "deeply_nested_key_json_returns_an_error_without_crashing",
        |wire| serde_json::from_str::<PublicKey>(&format!("\"{wire}\"")).is_err(),
    )
}

#[test]
fn deeply_nested_signature_json_returns_an_error_without_crashing() -> TestResult {
    assert_deep_wire_rejected(
        "deeply_nested_signature_json_returns_an_error_without_crashing",
        |wire| serde_json::from_str::<Signature>(&format!("\"{wire}\"")).is_err(),
    )
}

#[test]
fn nested_hybrids_reject_before_decoding_inner_material() {
    let wire = "hybrid:hybrid:zz:00:ed25519+mldsa65:00:ed25519+mldsa65";
    for error in [
        PublicKey::from_hex(wire).err(),
        Signature::from_hex(wire).err(),
    ] {
        assert!(
            error.is_some_and(|error| error.to_string().contains("nested")),
            "nested hybrid structure must reject before decoding its invalid inner hex",
        );
    }
}

#[test]
fn oversized_ecdsa_wire_signatures_are_rejected() {
    for (prefix, max_der_bytes) in [("p256:", 72), ("p384:", 104)] {
        let at_limit = format!("{prefix}{}", "00".repeat(max_der_bytes));
        assert!(Signature::from_hex(&at_limit).is_ok());
        let too_long = format!("{at_limit}00");
        assert!(Signature::from_hex(&too_long).is_err(), "{prefix}");
    }
}

#[test]
fn oversized_hex_rejects_before_decoding_invalid_digits() {
    let oversized = "g".repeat(100_000);
    for error in [
        Keypair::from_seed_hex(&oversized).err(),
        PublicKey::from_hex(&oversized).err(),
        Signature::from_hex(&oversized).err(),
    ] {
        assert!(
            error.is_some_and(|error| !matches!(error, chio_core_types::Error::InvalidHex(_))),
            "oversized inputs must fail their size check before hex decoding",
        );
    }
}

#[test]
fn valid_ed25519_and_hybrid_transport_encodings_round_trip() -> TestResult {
    let signer = Keypair::from_seed(&[7; 32]);
    let key = signer.public_key();
    let signature = signer.sign(b"wire contract");
    assert_eq!(PublicKey::from_hex(&key.to_hex())?, key);
    assert_eq!(Signature::from_hex(&signature.to_hex())?, signature);
    assert_eq!(PublicKey::from_hex(&key.to_hex().to_uppercase())?, key);
    assert_eq!(
        Signature::from_hex(&signature.to_hex().to_uppercase())?,
        signature
    );
    assert_eq!(PublicKey::from_hex(&format!("0x{}", key.to_hex()))?, key);
    assert_eq!(
        Signature::from_hex(&format!("0x{}", signature.to_hex()))?,
        signature
    );
    assert_eq!(
        Keypair::from_seed_hex(&format!("0x{}", signer.seed_hex()))?.public_key(),
        key,
    );

    // These are transport fixtures, not a claim of ML-DSA signature validity.
    let hybrid_key =
        PublicKey::from_hybrid_parts(key, &[7; ML_DSA_65_PUBLIC_KEY_LEN], HYBRID_ED25519_MLDSA65)?;
    let hybrid_signature = Signature::from_hybrid_parts(
        signature,
        &[7; ML_DSA_65_SIGNATURE_LEN],
        HYBRID_ED25519_MLDSA65,
    )?;
    assert_eq!(PublicKey::from_hex(&hybrid_key.to_hex())?, hybrid_key);
    assert_eq!(
        Signature::from_hex(&hybrid_signature.to_hex())?,
        hybrid_signature
    );
    assert_eq!(
        serde_json::from_str::<PublicKey>(&serde_json::to_string(&hybrid_key)?)?,
        hybrid_key,
    );
    assert_eq!(
        serde_json::from_str::<Signature>(&serde_json::to_string(&hybrid_signature)?)?,
        hybrid_signature,
    );
    Ok(())
}

fn maximal_der_signature(scalar_bytes: u8) -> Vec<u8> {
    // A SEQUENCE of two positive INTEGERs requiring leading sign octets.
    let mut der = vec![0x30, 2 * (scalar_bytes + 3)];
    for _ in 0..2 {
        der.extend_from_slice(&[0x02, scalar_bytes + 1, 0]);
        der.extend(std::iter::repeat_n(0x80, usize::from(scalar_bytes)));
    }
    der
}

#[test]
fn ecdsa_and_hybrid_wire_bounds_preserve_maximal_encodings() -> TestResult {
    // SEC1 transport fixtures exercise encoding shape, not curve membership.
    for (prefix, key, signature, alg_set) in [
        (
            "p256:",
            PublicKey::from_p256_sec1(&[4; 65])?,
            Signature::from_p256_der(&maximal_der_signature(32)),
            HYBRID_P256_MLDSA65,
        ),
        (
            "p384:",
            PublicKey::from_p384_sec1(&[4; 97])?,
            Signature::from_p384_der(&maximal_der_signature(48)),
            HYBRID_P384_MLDSA65,
        ),
    ] {
        let key_wire = key.to_hex();
        let signature_wire = signature.to_hex();
        let key_alias = key_wire.replacen(prefix, &format!("{prefix}0x"), 1);
        let signature_alias = signature_wire.replacen(prefix, &format!("{prefix}0x"), 1);
        assert_eq!(PublicKey::from_hex(&key_alias)?, key);
        assert_eq!(Signature::from_hex(&signature_alias)?, signature);
        let pq_key = "ab".repeat(ML_DSA_65_PUBLIC_KEY_LEN);
        let pq_signature = "ab".repeat(ML_DSA_65_SIGNATURE_LEN);
        let hybrid_key_wire = format!("hybrid:{key_alias}:{pq_key}:{alg_set}");
        let hybrid_signature_wire = format!("hybrid:{signature_alias}:{pq_signature}:{alg_set}");
        let hybrid_key = PublicKey::from_hex(&hybrid_key_wire)?;
        let hybrid_signature = Signature::from_hex(&hybrid_signature_wire)?;
        assert_eq!(
            hybrid_key.to_hex(),
            format!("hybrid:{key_wire}:{pq_key}:{alg_set}"),
        );
        assert_eq!(
            hybrid_signature.to_hex(),
            format!("hybrid:{signature_wire}:{pq_signature}:{alg_set}"),
        );
        for malformed in [
            format!("hybrid:{key_alias}:{pq_key}00:{alg_set}"),
            format!("hybrid:{key_alias}:{}:{alg_set}", &pq_key[2..]),
            format!("hybrid:{key_alias}:{pq_key}:ed25519+mldsa65"),
            format!("hybrid:{key_alias}:0x{pq_key}:{alg_set}"),
        ] {
            assert!(PublicKey::from_hex(&malformed).is_err());
        }
        assert!(Signature::from_hex(&format!(
            "hybrid:{signature_alias}00:{pq_signature}:{alg_set}",
        ))
        .is_err());
    }
    Ok(())
}

struct BorrowedStringOnly<'a>(&'a str);

impl<'de> serde::Deserializer<'de> for BorrowedStringOnly<'de> {
    type Error = serde::de::value::Error;

    fn deserialize_str<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(serde::de::Error::custom(
            "owned or non-string input was requested",
        ))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct
        enum identifier ignored_any
    }
}

#[test]
fn hash_wire_size_is_checked_before_hex_decoding() {
    assert!(matches!(
        Hash::from_hex(&"g".repeat(100_000)),
        Err(chio_core_types::Error::InvalidHashLength { .. }),
    ));
    for length in [0, 31, 33] {
        assert!(matches!(
            Hash::from_hex(&"00".repeat(length)),
            Err(chio_core_types::Error::InvalidHashLength { expected: 32, actual })
                if actual == length,
        ));
    }
    for wire in ["0".to_string(), "g".repeat(64)] {
        assert!(matches!(
            Hash::from_hex(&wire),
            Err(chio_core_types::Error::InvalidHex(_)),
        ));
    }
}

#[test]
fn hash_serde_borrows_input_and_preserves_prefixed_wire_format() -> TestResult {
    let hash = chio_core_types::sha256(b"hash wire contract");
    assert_eq!(
        Hash::deserialize(BorrowedStringOnly(&hash.to_hex_prefixed()))?,
        hash
    );
    assert_eq!(Hash::deserialize(BorrowedStringOnly(&hash.to_hex()))?, hash);
    assert_eq!(Hash::from_hex(&hash.to_hex().to_uppercase())?, hash);
    assert_eq!(
        serde_json::to_string(&hash)?,
        format!("\"{}\"", hash.to_hex_prefixed())
    );
    assert_eq!(
        serde_json::from_value::<Hash>(serde_json::json!(hash.to_hex_prefixed()))?,
        hash
    );
    Ok(())
}

#[test]
fn serde_accepts_borrowed_and_owned_strings_without_requesting_a_copy() -> TestResult {
    let signer = Keypair::from_seed(&[7; 32]);
    let key = signer.public_key();
    let signature = signer.sign(b"borrowed wire");
    assert_eq!(
        PublicKey::deserialize(BorrowedStringOnly(&key.to_hex()))?,
        key
    );
    assert_eq!(
        Signature::deserialize(BorrowedStringOnly(&signature.to_hex()))?,
        signature
    );
    assert_eq!(
        serde_json::from_value::<PublicKey>(serde_json::json!(key.to_hex()))?,
        key
    );
    assert_eq!(
        serde_json::from_value::<Signature>(serde_json::json!(signature.to_hex()))?,
        signature,
    );
    // Escaped JSON strings use the deserializer's scratch buffer rather than
    // borrowing the original input. They must retain the same key semantics.
    let escaped = key
        .to_hex()
        .bytes()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect::<String>();
    assert_eq!(
        serde_json::from_str::<PublicKey>(&format!("\"{escaped}\""))?,
        key
    );
    for json in ["null", "1", "[]", "{}", "true"] {
        assert!(serde_json::from_str::<PublicKey>(json).is_err());
        assert!(serde_json::from_str::<Signature>(json).is_err());
    }
    Ok(())
}

#[test]
fn malformed_unicode_and_prefixes_reject_without_panicking() {
    for wire in [
        "hybrid:",
        "hybrid:::",
        "hybrid:ed25519:00:00:ed25519+mldsa65",
        "hybrid:p521:00:00:p521+mldsa65",
        "p521:00",
        "HYBRID:00",
        "0X00",
        "💥",
        "hybrid:💥:💥:💥",
        "p256:💥",
        "p384:💥",
        "00\u{0000}",
    ] {
        assert!(PublicKey::from_hex(wire).is_err(), "{wire}");
        assert!(Signature::from_hex(wire).is_err(), "{wire}");
        assert!(Keypair::from_seed_hex(wire).is_err(), "{wire}");
    }
}

#[cfg(feature = "fips")]
#[test]
fn ecdsa_backend_signatures_verify_after_wire_and_json_round_trip() -> TestResult {
    use chio_core_types::{P256Backend, P384Backend, SigningBackend};

    for backend in [
        Box::new(P256Backend::generate()?) as Box<dyn SigningBackend>,
        Box::new(P384Backend::generate()?) as Box<dyn SigningBackend>,
    ] {
        assert_signed_round_trip(backend.as_ref())?;
    }
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_backend_signatures_verify_after_wire_and_json_round_trip() -> TestResult {
    use chio_core_types::{Ed25519Backend, HybridBackend, MlDsa65Backend, SigningBackend};

    let classical =
        Box::new(Ed25519Backend::new(Keypair::from_seed(&[7; 32]))) as Box<dyn SigningBackend>;
    assert_signed_round_trip(&HybridBackend::new(
        classical,
        MlDsa65Backend::from_seed(&[8; 32]),
    )?)?;
    #[cfg(feature = "fips")]
    for classical in [
        Box::new(chio_core_types::P256Backend::generate()?) as Box<dyn SigningBackend>,
        Box::new(chio_core_types::P384Backend::generate()?) as Box<dyn SigningBackend>,
    ] {
        assert_signed_round_trip(&HybridBackend::new(
            classical,
            MlDsa65Backend::from_seed(&[8; 32]),
        )?)?;
    }
    Ok(())
}

#[cfg(any(feature = "fips", feature = "pq"))]
fn assert_signed_round_trip(backend: &dyn chio_core_types::SigningBackend) -> TestResult {
    let message = b"bounded crypto wire verification";
    let key = backend.public_key();
    let signature = backend.sign_bytes(message)?;
    let key_wire = key.to_hex();
    let signature_wire = signature.to_hex();
    let decoded_key = PublicKey::from_hex(&key_wire)?;
    let decoded_signature = Signature::from_hex(&signature_wire)?;
    assert!(decoded_key.verify_strict(message, &decoded_signature));
    assert!(!decoded_key.verify_strict(b"changed message", &decoded_signature));
    let key_json = serde_json::to_string(&key)?;
    let signature_json = serde_json::to_string(&signature)?;
    assert_eq!(serde_json::from_str::<PublicKey>(&key_json)?, key);
    assert_eq!(
        serde_json::from_str::<Signature>(&signature_json)?,
        signature
    );
    assert_eq!(decoded_key.to_hex(), key_wire);
    assert_eq!(decoded_signature.to_hex(), signature_wire);
    assert_eq!(
        chio_core_types::canonical_json_bytes(&(decoded_key, decoded_signature))?,
        chio_core_types::canonical_json_bytes(&(key, signature))?,
    );
    Ok(())
}

proptest::proptest! {
    #[test]
    fn prefixed_hex_wire_round_trips_when_decoding_succeeds(
        prefix in proptest::sample::select(vec!["", "0x", "p256:", "p256:0x", "p384:", "hybrid:", "p521:"]),
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..220),
        suffix in proptest::sample::select(vec!["", ":00:ed25519+mldsa65", ":00:p256+mldsa65", ":00:p384+mldsa65"]),
    ) {
        let wire = format!("{prefix}{}{suffix}", hex::encode(bytes));
        if let Ok(key) = PublicKey::from_hex(&wire) {
            proptest::prop_assert_eq!(PublicKey::from_hex(&key.to_hex()).ok(), Some(key));
        }
        if let Ok(signature) = Signature::from_hex(&wire) {
            proptest::prop_assert_eq!(Signature::from_hex(&signature.to_hex()).ok(), Some(signature));
        }
    }
}
