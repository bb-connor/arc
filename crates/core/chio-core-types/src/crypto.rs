//! Signing and verification primitives for Chio artifacts.
//!
//! # Purpose and FIPS Posture
//!
//! Chio artifacts (capability tokens, receipts, DPoP proofs, governed approval
//! tokens) are signed with a cryptographic algorithm negotiated between the
//! kernel operator and its counterparties. The default algorithm is Ed25519
//! via `ed25519-dalek`, which is the baseline backend every Chio deployment
//! supports and the format every bare-hex on-wire artifact uses. To unblock
//! enterprise procurement in FIPS-constrained environments, this module also
//! exposes a [`SigningBackend`] abstraction with pluggable implementations for
//! NIST P-256 (secp256r1), P-384 (secp384r1), and hybrid classical plus
//! ML-DSA-65 signatures.
//!
//! The ECDSA backends are gated behind the `fips` Cargo feature and link to
//! `aws-lc-rs` through `aws-lc-sys`. This feature selects algorithm support;
//! enabling it alone is not a FIPS module-validation claim. The independent
//! `pq` feature adds ML-DSA-65 support. With `fips` enabled, callers may construct a
//! [`P256Backend`] or [`P384Backend`] and pass it to any Chio signing helper
//! that accepts `&dyn SigningBackend`.
//!
//! # Wire Encoding
//!
//! Ed25519 artifacts serialize byte-for-byte identically to the standard
//! format: a 64-character lowercase hex string for the public key and a
//! 128-character hex string for the signature. FIPS-algorithm artifacts use a
//! self-describing hex prefix (e.g. `p256:`, `p384:`, or `hybrid:`) so
//! verifiers that only understand bare hex recognise that the material is
//! non-Ed25519 and can reject with a clear error rather than misinterpreting
//! bytes.
//!
//! # Safety Notes
//!
//! - Private key material held by [`Keypair`] is zeroed on drop via
//!   `ed25519-dalek`'s `ZeroizeOnDrop` implementation.
//! - FIPS-backend private keys are held by `aws-lc-rs` owned types which zero
//!   their own key material.
//! - No `unsafe` code is introduced by this module.

use alloc::boxed::Box;
use alloc::format;
#[cfg(not(target_has_atomic = "ptr"))]
use alloc::rc::Rc as SharedCanonicalBytesInner;
use alloc::string::{String, ToString};
#[cfg(target_has_atomic = "ptr")]
use alloc::sync::Arc as SharedCanonicalBytesInner;
use alloc::vec::Vec;

use ed25519_dalek::{Signature as DalekSignature, Signer as DalekSigner, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalBytes, CanonicalJsonWitness};
use crate::error::{Error, Result};

mod ed25519_verification;
mod wire;

/// Shared canonical JSON bytes suitable for signing and verification.
pub type SharedCanonicalBytes = SharedCanonicalBytesInner<CanonicalBytes<CanonicalJsonWitness>>;

/// Wire algorithm-set suffix for Ed25519 plus ML-DSA-65 hybrid material.
pub const HYBRID_ED25519_MLDSA65: &str = "ed25519+mldsa65";
/// Wire algorithm-set suffix for P-256 plus ML-DSA-65 hybrid material.
pub const HYBRID_P256_MLDSA65: &str = "p256+mldsa65";
/// Wire algorithm-set suffix for P-384 plus ML-DSA-65 hybrid material.
pub const HYBRID_P384_MLDSA65: &str = "p384+mldsa65";
/// ML-DSA-65 public-key byte length from FIPS 204.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// ML-DSA-65 signature byte length from FIPS 204.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

// ---------------------------------------------------------------------------
// SigningAlgorithm
// ---------------------------------------------------------------------------

/// Enumerates the signature algorithms Chio knows how to produce and verify.
///
/// `Ed25519` is always available. `P256` and `P384` require the `fips`
/// Cargo feature on `chio-core-types` and route through `aws-lc-rs`.
/// `Hybrid` combines one classical signature with ML-DSA-65 and requires
/// the `pq` feature to produce or verify cryptographically.
///
/// This enum serializes as a short lowercase identifier:
/// `"ed25519"`, `"p256"`, `"p384"`, or `"hybrid"`. When absent from an
/// artifact's envelope, consumers MUST treat the algorithm as
/// [`SigningAlgorithm::Ed25519`] (the default algorithm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    /// Edwards-curve signature on Curve25519. Default, non-FIPS.
    #[default]
    Ed25519,
    /// ECDSA on NIST P-256 / secp256r1 with SHA-256. Requires `fips` feature.
    P256,
    /// ECDSA on NIST P-384 / secp384r1 with SHA-384. Requires `fips` feature.
    P384,
    /// Classical signature plus ML-DSA-65. Requires `pq` feature.
    Hybrid,
}

impl SigningAlgorithm {
    /// Returns true when this algorithm is the default (Ed25519).
    ///
    /// Useful for `#[serde(skip_serializing_if)]` helpers that keep Ed25519
    /// artifacts byte-identical to the bare-hex wire format.
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Ed25519)
    }

    /// Short lowercase identifier used as the hex prefix for non-Ed25519
    /// keys and signatures.
    #[must_use]
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Ed25519 => "",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Hybrid => "hybrid",
        }
    }
}

/// Returns `true` when `alg` equals the default algorithm. Free function
/// so it can be referenced from `#[serde(skip_serializing_if = "...")]`.
#[must_use]
pub fn is_default_algorithm(alg: &SigningAlgorithm) -> bool {
    alg.is_default()
}

/// Returns `true` when the optional algorithm is absent or is the default
/// (Ed25519). Used by `#[serde(skip_serializing_if)]` on envelope fields to
/// omit the algorithm field for standard Ed25519 artifacts.
#[must_use]
pub fn is_default_optional_algorithm(alg: &Option<SigningAlgorithm>) -> bool {
    match alg {
        None => true,
        Some(a) => a.is_default(),
    }
}

// ---------------------------------------------------------------------------
// Keypair (Ed25519 only; FIPS backends have their own types)
// ---------------------------------------------------------------------------

/// Ed25519 keypair for signing.
///
/// This is the default Chio signing identity. For FIPS-capable signing, see
/// [`SigningBackend`] and its implementations.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from raw seed bytes (32 bytes).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Create from hex-encoded seed bytes (with optional `0x` prefix).
    pub fn from_seed_hex(hex_str: &str) -> Result<Self> {
        Ok(Self::from_seed(&wire::seed_from_hex(hex_str)?))
    }

    /// Fixed-width public bytes of this Ed25519-only signing identity.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            material: PublicKeyMaterial::Ed25519 {
                verifying_key: self.signing_key.verifying_key(),
            },
        }
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature {
            material: SignatureMaterial::Ed25519 { inner: sig },
        }
    }

    /// Sign a serializable value by converting it to canonical JSON first.
    ///
    /// Returns the signature and the canonical bytes that were signed, so the
    /// caller can store or transmit them alongside the signature.
    pub fn sign_canonical<T: Serialize>(&self, value: &T) -> Result<(Signature, Vec<u8>)> {
        let canonical = CanonicalBytes::from_serializable(value)?;
        let signature = self.sign(canonical.as_bytes());
        Ok((signature, canonical.into_vec()))
    }

    /// Sign a serializable value after converting it to shared canonical JSON.
    ///
    /// The returned payload carries the exact canonical bytes behind an
    /// `Arc`, allowing downstream code to reuse the signed representation.
    pub fn sign_canonical_shared<T: Serialize>(&self, value: &T) -> Result<SignedCanonicalPayload> {
        let canonical = canonical_json_shared_bytes(value)?;
        Ok(self.sign_shared_canonical(canonical))
    }

    /// Sign shared canonical JSON bytes without reserializing the payload.
    #[must_use]
    pub fn sign_shared_canonical(&self, canonical: SharedCanonicalBytes) -> SignedCanonicalPayload {
        let signature = self.sign(canonical.as_bytes());
        SignedCanonicalPayload::new(signature, canonical)
    }

    #[must_use]
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    #[must_use]
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed_bytes())
    }
}

// ed25519-dalek's SigningKey implements ZeroizeOnDrop, so private key material
// is automatically zeroed when this struct is dropped.

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// Public key for verifying Chio signatures.
///
/// Internally this is a sum over the supported [`SigningAlgorithm`]s. The
/// common case (Ed25519) preserves the bare 32-byte encoding and bare
/// hex serialization. Non-Ed25519 variants use a self-describing hex prefix
/// (`p256:<hex>` / `p384:<hex>` / `hybrid:<classical>:<pq>:<alg_set>`) so the
/// wire format unambiguously identifies the algorithm without a separate
/// envelope field.
#[derive(Clone, Debug)]
pub struct PublicKey {
    material: PublicKeyMaterial,
}

#[derive(Clone, Debug)]
enum PublicKeyMaterial {
    Ed25519 {
        verifying_key: VerifyingKey,
    },
    /// Raw uncompressed SEC1 public key bytes (0x04 || X || Y).
    P256 {
        encoded_point: Vec<u8>,
    },
    /// Raw uncompressed SEC1 public key bytes (0x04 || X || Y).
    P384 {
        encoded_point: Vec<u8>,
    },
    /// Hybrid classical plus ML-DSA-65 public-key material.
    Hybrid {
        classical: Box<PublicKey>,
        pq: Vec<u8>,
        alg_set: String,
    },
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.material, &other.material) {
            (
                PublicKeyMaterial::Ed25519 { verifying_key: a },
                PublicKeyMaterial::Ed25519 { verifying_key: b },
            ) => a == b,
            (
                PublicKeyMaterial::P256 { encoded_point: a },
                PublicKeyMaterial::P256 { encoded_point: b },
            ) => a == b,
            (
                PublicKeyMaterial::P384 { encoded_point: a },
                PublicKeyMaterial::P384 { encoded_point: b },
            ) => a == b,
            (
                PublicKeyMaterial::Hybrid {
                    classical: classical_a,
                    pq: pq_a,
                    alg_set: alg_set_a,
                },
                PublicKeyMaterial::Hybrid {
                    classical: classical_b,
                    pq: pq_b,
                    alg_set: alg_set_b,
                },
            ) => classical_a == classical_b && pq_a == pq_b && alg_set_a == alg_set_b,
            _ => false,
        }
    }
}

impl Eq for PublicKey {}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        crate::wire_text::deserialize(
            deserializer,
            "an algorithm-aware public-key string",
            Self::from_hex,
        )
    }
}

impl PublicKey {
    /// Create from raw bytes (32 bytes). Produces an Ed25519 key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            material: PublicKeyMaterial::Ed25519 { verifying_key },
        })
    }

    /// Create a P-256 public key from uncompressed SEC1-encoded bytes
    /// (65 bytes beginning with `0x04`).
    ///
    /// The bytes are validated only for length and leading-byte format; full
    /// curve-point validation is delegated to the verifier at first use.
    pub fn from_p256_sec1(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 65-byte uncompressed P-256 SEC1 point, got {} bytes",
                bytes.len()
            )));
        }
        if bytes.first() != Some(&0x04) {
            return Err(Error::InvalidPublicKey(
                "P-256 SEC1 point must start with 0x04 (uncompressed)".to_string(),
            ));
        }
        Ok(Self {
            material: PublicKeyMaterial::P256 {
                encoded_point: bytes.to_vec(),
            },
        })
    }

    /// Create a P-384 public key from uncompressed SEC1-encoded bytes
    /// (97 bytes beginning with `0x04`).
    pub fn from_p384_sec1(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 97 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 97-byte uncompressed P-384 SEC1 point, got {} bytes",
                bytes.len()
            )));
        }
        if bytes.first() != Some(&0x04) {
            return Err(Error::InvalidPublicKey(
                "P-384 SEC1 point must start with 0x04 (uncompressed)".to_string(),
            ));
        }
        Ok(Self {
            material: PublicKeyMaterial::P384 {
                encoded_point: bytes.to_vec(),
            },
        })
    }

    /// Create a hybrid public key from a classical public key and ML-DSA-65
    /// public-key bytes.
    pub fn from_hybrid_parts(classical: PublicKey, pq: &[u8], alg_set: &str) -> Result<Self> {
        validate_hybrid_alg_set(classical.algorithm(), alg_set)?;
        validate_mldsa65_public_key_len(pq)?;
        Ok(Self {
            material: PublicKeyMaterial::Hybrid {
                classical: Box::new(classical),
                pq: pq.to_vec(),
                alg_set: alg_set.to_string(),
            },
        })
    }

    /// Create from hex-encoded bytes (with optional `0x` prefix).
    ///
    /// The string may carry a `p256:` or `p384:` prefix to select an ECDSA
    /// key. Bare hex strings are interpreted as Ed25519 (the default algorithm).
    /// Hybrid material may contain only one classical key. Encoded lengths are
    /// bounded before decoding; curve-point validation still occurs at use.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        wire::public_key_from_hex(hex_str)
    }

    /// Which algorithm this public key belongs to.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        match &self.material {
            PublicKeyMaterial::Ed25519 { .. } => SigningAlgorithm::Ed25519,
            PublicKeyMaterial::P256 { .. } => SigningAlgorithm::P256,
            PublicKeyMaterial::P384 { .. } => SigningAlgorithm::P384,
            PublicKeyMaterial::Hybrid { .. } => SigningAlgorithm::Hybrid,
        }
    }

    /// Whether this key carries weak, small-order Ed25519 material.
    ///
    /// Such a key validates forged signatures for arbitrary messages under
    /// cofactorless Ed25519 verification and never identifies a signer. A
    /// hybrid key is weak when its classical half is. P-256 and P-384 keys
    /// return `false`.
    #[must_use]
    pub fn is_weak_ed25519(&self) -> bool {
        match &self.material {
            PublicKeyMaterial::Ed25519 { verifying_key } => verifying_key.is_weak(),
            PublicKeyMaterial::Hybrid { classical, .. } => classical.is_weak_ed25519(),
            PublicKeyMaterial::P256 { .. } | PublicKeyMaterial::P384 { .. } => false,
        }
    }

    /// Verify a signature against a message.
    ///
    /// Ed25519 verification is strict: it rejects weak public keys,
    /// small-order signature points and non-canonical signature scalars.
    /// P-256 and P-384 use their standard verifiers. Hybrid signatures
    /// require both the strict classical signature and the ML-DSA-65
    /// signature. Returns `false` when algorithms differ between key and
    /// signature, or when the cryptographic check fails. Never panics.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (&self.material, &signature.material) {
            (
                PublicKeyMaterial::Ed25519 { verifying_key },
                SignatureMaterial::Ed25519 { inner },
            ) => ed25519_verification::verify(verifying_key, message, inner),
            (PublicKeyMaterial::P256 { encoded_point }, SignatureMaterial::P256 { der }) => {
                verify_ecdsa_p256(encoded_point, message, der)
            }
            (PublicKeyMaterial::P384 { encoded_point }, SignatureMaterial::P384 { der }) => {
                verify_ecdsa_p384(encoded_point, message, der)
            }
            (
                PublicKeyMaterial::Hybrid {
                    classical,
                    pq,
                    alg_set,
                },
                SignatureMaterial::Hybrid {
                    classical: classical_signature,
                    pq: pq_signature,
                    alg_set: signature_alg_set,
                },
            ) => {
                alg_set == signature_alg_set
                    && validate_hybrid_alg_set(classical.algorithm(), alg_set).is_ok()
                    && classical.verify(message, classical_signature)
                    && verify_mldsa65_signature(pq, message, pq_signature)
            }
            _ => false,
        }
    }

    /// Verify a signature over the canonical JSON form of a serializable value.
    ///
    /// Applies the strict rules of [`PublicKey::verify`].
    pub fn verify_canonical<T: Serialize>(&self, value: &T, signature: &Signature) -> Result<bool> {
        let canonical = canonical_json_shared_bytes(value)?;
        Ok(self.verify_shared_canonical(&canonical, signature))
    }

    /// Verify a signature over shared canonical JSON bytes.
    #[must_use]
    pub fn verify_shared_canonical(
        &self,
        canonical: &SharedCanonicalBytes,
        signature: &Signature,
    ) -> bool {
        self.verify_canonical_bytes(canonical.as_ref(), signature)
    }

    /// Verify a signature over canonical JSON bytes without reserializing.
    #[must_use]
    pub fn verify_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
        signature: &Signature,
    ) -> bool {
        self.verify(canonical.as_bytes(), signature)
    }

    /// Hex encoding, with algorithm prefix for non-Ed25519 keys.
    ///
    /// Ed25519 keys render as a bare 64-character lowercase hex string. P-256 keys render as
    /// `p256:<130-char hex>` (uncompressed SEC1). P-384 keys render as
    /// `p384:<194-char hex>`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        match &self.material {
            PublicKeyMaterial::Ed25519 { verifying_key } => hex::encode(verifying_key.to_bytes()),
            PublicKeyMaterial::P256 { encoded_point } => {
                format!("p256:{}", hex::encode(encoded_point))
            }
            PublicKeyMaterial::P384 { encoded_point } => {
                format!("p384:{}", hex::encode(encoded_point))
            }
            PublicKeyMaterial::Hybrid {
                classical,
                pq,
                alg_set,
            } => {
                format!(
                    "hybrid:{}:{}:{}",
                    classical.to_hex(),
                    hex::encode(pq),
                    alg_set
                )
            }
        }
    }

    /// Borrow the Ed25519 representation, refusing every other algorithm.
    /// Algorithm-polymorphic consumers must use an algorithm-tagged encoding.
    pub fn ed25519_bytes(&self) -> Result<&[u8; 32]> {
        match &self.material {
            PublicKeyMaterial::Ed25519 { verifying_key } => Ok(verifying_key.as_bytes()),
            PublicKeyMaterial::P256 { .. }
            | PublicKeyMaterial::P384 { .. }
            | PublicKeyMaterial::Hybrid { .. } => Err(Error::InvalidPublicKey(
                "Ed25519 public key required".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// TrustedPublicKey
// ---------------------------------------------------------------------------

/// A public key accepted as a signature verifier.
///
/// Construction rejects weak (small-order) Ed25519 material, including the
/// classical half of a hybrid key, with [`Error::InvalidPublicKey`]. A key
/// that identifies a trust anchor, pinned signer or artifact issuer is held
/// as this type so the rejection happens once, when the key is accepted,
/// rather than at each verifier. Verification applies the strict rules of
/// [`PublicKey::verify`]. Serialization is identical to [`PublicKey`];
/// deserialization rejects weak keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPublicKey {
    key: PublicKey,
}

impl TrustedPublicKey {
    /// Accept `key` as a verifier.
    ///
    /// Fails with [`Error::InvalidPublicKey`] when the key carries weak
    /// Ed25519 material.
    pub fn new(key: PublicKey) -> Result<Self> {
        if key.is_weak_ed25519() {
            return Err(Error::InvalidPublicKey(
                "weak (small-order) Ed25519 public key".to_string(),
            ));
        }
        Ok(Self { key })
    }

    /// Accept `key` as a verifier that must be an Ed25519 key.
    ///
    /// Fails with [`Error::InvalidPublicKey`] for any other algorithm or a
    /// weak key.
    pub fn new_ed25519(key: PublicKey) -> Result<Self> {
        if key.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(Error::InvalidPublicKey(
                "Ed25519 public key required".to_string(),
            ));
        }
        Self::new(key)
    }

    /// Parse a hex-encoded public key and accept it as a verifier.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        Self::new(PublicKey::from_hex(hex_str)?)
    }

    /// The accepted public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Unwrap the accepted public key.
    #[must_use]
    pub fn into_public_key(self) -> PublicKey {
        self.key
    }

    /// Which algorithm this public key belongs to.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.key.algorithm()
    }

    /// Hex encoding, identical to [`PublicKey::to_hex`].
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.key.to_hex()
    }

    /// Verify a signature against a message with [`PublicKey::verify`].
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.key.verify(message, signature)
    }

    /// Verify a signature over the canonical JSON form of `value`.
    pub fn verify_canonical<T: Serialize>(&self, value: &T, signature: &Signature) -> Result<bool> {
        self.key.verify_canonical(value, signature)
    }

    /// Verify a signature over shared canonical JSON bytes.
    #[must_use]
    pub fn verify_shared_canonical(
        &self,
        canonical: &SharedCanonicalBytes,
        signature: &Signature,
    ) -> bool {
        self.key.verify_shared_canonical(canonical, signature)
    }

    /// Verify a signature over canonical JSON bytes without reserializing.
    #[must_use]
    pub fn verify_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
        signature: &Signature,
    ) -> bool {
        self.key.verify_canonical_bytes(canonical, signature)
    }
}

impl TryFrom<PublicKey> for TrustedPublicKey {
    type Error = Error;

    fn try_from(key: PublicKey) -> Result<Self> {
        Self::new(key)
    }
}

impl From<TrustedPublicKey> for PublicKey {
    fn from(key: TrustedPublicKey) -> Self {
        key.key
    }
}

impl AsRef<PublicKey> for TrustedPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.key
    }
}

impl PartialEq<PublicKey> for TrustedPublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        &self.key == other
    }
}

impl PartialEq<TrustedPublicKey> for PublicKey {
    fn eq(&self, other: &TrustedPublicKey) -> bool {
        self == &other.key
    }
}

impl Serialize for TrustedPublicKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.key.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustedPublicKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = PublicKey::deserialize(deserializer)?;
        Self::new(key).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// Signature produced by a Chio [`SigningBackend`].
///
/// Algorithm-tagged signature type. Preserves byte-identical serialization
/// and construction helpers for the Ed25519 case; non-Ed25519 paths use
/// the same outer API.
#[derive(Clone, Debug)]
pub struct Signature {
    material: SignatureMaterial,
}

#[derive(Clone, Debug)]
enum SignatureMaterial {
    Ed25519 {
        inner: DalekSignature,
    },
    /// Raw ASN.1 DER-encoded ECDSA signature.
    P256 {
        der: Vec<u8>,
    },
    /// Raw ASN.1 DER-encoded ECDSA signature.
    P384 {
        der: Vec<u8>,
    },
    /// Hybrid classical plus ML-DSA-65 signature material.
    Hybrid {
        classical: Box<Signature>,
        pq: Vec<u8>,
        alg_set: String,
    },
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        match (&self.material, &other.material) {
            (SignatureMaterial::Ed25519 { inner: a }, SignatureMaterial::Ed25519 { inner: b }) => {
                a.to_bytes() == b.to_bytes()
            }
            (SignatureMaterial::P256 { der: a }, SignatureMaterial::P256 { der: b }) => a == b,
            (SignatureMaterial::P384 { der: a }, SignatureMaterial::P384 { der: b }) => a == b,
            (
                SignatureMaterial::Hybrid {
                    classical: classical_a,
                    pq: pq_a,
                    alg_set: alg_set_a,
                },
                SignatureMaterial::Hybrid {
                    classical: classical_b,
                    pq: pq_b,
                    alg_set: alg_set_b,
                },
            ) => classical_a == classical_b && pq_a == pq_b && alg_set_a == alg_set_b,
            _ => false,
        }
    }
}

impl Eq for Signature {}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        crate::wire_text::deserialize(
            deserializer,
            "an algorithm-aware signature string",
            Self::from_hex,
        )
    }
}

fn encoded_hex_text_len(bytes: usize, prefix: usize) -> Option<usize> {
    bytes.checked_mul(2)?.checked_add(prefix)
}

impl Signature {
    /// Create from raw 64-byte Ed25519 signature bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            material: SignatureMaterial::Ed25519 {
                inner: DalekSignature::from_bytes(bytes),
            },
        }
    }

    /// Create a P-256 ECDSA signature from DER-encoded bytes.
    pub fn from_p256_der(bytes: &[u8]) -> Self {
        Self {
            material: SignatureMaterial::P256 {
                der: bytes.to_vec(),
            },
        }
    }

    /// Create a P-384 ECDSA signature from DER-encoded bytes.
    pub fn from_p384_der(bytes: &[u8]) -> Self {
        Self {
            material: SignatureMaterial::P384 {
                der: bytes.to_vec(),
            },
        }
    }

    /// Create a hybrid signature from a classical signature and ML-DSA-65
    /// signature bytes.
    pub fn from_hybrid_parts(classical: Signature, pq: &[u8], alg_set: &str) -> Result<Self> {
        validate_hybrid_alg_set(classical.algorithm(), alg_set)?;
        validate_mldsa65_signature_len(pq)?;
        Ok(Self {
            material: SignatureMaterial::Hybrid {
                classical: Box::new(classical),
                pq: pq.to_vec(),
                alg_set: alg_set.to_string(),
            },
        })
    }

    /// Create from hex-encoded bytes (with optional `0x` prefix).
    ///
    /// Bare hex strings are interpreted as Ed25519 (the default algorithm).
    /// A `p256:` or `p384:` prefix selects ECDSA.
    /// Encoded lengths are bounded before decoding, and hybrid nesting rejects.
    /// DER structure and cryptographic validity remain the verifier's responsibility.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        wire::signature_from_hex(hex_str)
    }

    /// Length of the existing textual encoding without serializing or cloning material.
    ///
    /// This does not validate DER or cryptographic authority. Overflow returns
    /// `None`, so a caller can refuse before allocating the hexadecimal encoding.
    #[must_use]
    pub fn encoded_text_len(&self) -> Option<usize> {
        match &self.material {
            SignatureMaterial::Ed25519 { .. } => Some(128),
            SignatureMaterial::P256 { der } => encoded_hex_text_len(der.len(), "p256:".len()),
            SignatureMaterial::P384 { der } => encoded_hex_text_len(der.len(), "p384:".len()),
            SignatureMaterial::Hybrid {
                classical,
                pq,
                alg_set,
            } => "hybrid:"
                .len()
                .checked_add(alg_set.len())?
                .checked_add(1)?
                .checked_add(classical.encoded_text_len()?)?
                .checked_add(1)?
                .checked_add(pq.len().checked_mul(2)?),
        }
    }

    /// Hex encoding, with algorithm prefix for non-Ed25519 signatures.
    ///
    /// Ed25519 signatures render as a bare 128-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        match &self.material {
            SignatureMaterial::Ed25519 { inner } => hex::encode(inner.to_bytes()),
            SignatureMaterial::P256 { der } => format!("p256:{}", hex::encode(der)),
            SignatureMaterial::P384 { der } => format!("p384:{}", hex::encode(der)),
            SignatureMaterial::Hybrid {
                classical,
                pq,
                alg_set,
            } => {
                format!(
                    "hybrid:{}:{}:{}",
                    classical.to_hex(),
                    hex::encode(pq),
                    alg_set
                )
            }
        }
    }

    /// Raw 64-byte Ed25519 representation.
    ///
    /// For non-Ed25519 signatures returns an
    /// all-zero placeholder (such signatures never flow through 64-byte-only
    /// consumer paths because those paths are Ed25519-specific on-chain
    /// anchoring layers that never see FIPS artifacts).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        match &self.material {
            SignatureMaterial::Ed25519 { inner } => inner.to_bytes(),
            _ => [0u8; 64],
        }
    }

    /// Which algorithm produced this signature.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        match &self.material {
            SignatureMaterial::Ed25519 { .. } => SigningAlgorithm::Ed25519,
            SignatureMaterial::P256 { .. } => SigningAlgorithm::P256,
            SignatureMaterial::P384 { .. } => SigningAlgorithm::P384,
            SignatureMaterial::Hybrid { .. } => SigningAlgorithm::Hybrid,
        }
    }
}

/// Detached signature paired with the shared canonical bytes that were signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCanonicalPayload {
    signature: Signature,
    canonical: SharedCanonicalBytes,
}

impl SignedCanonicalPayload {
    /// Build a signed canonical payload from a signature and shared bytes.
    #[must_use]
    pub fn new(signature: Signature, canonical: SharedCanonicalBytes) -> Self {
        Self {
            signature,
            canonical,
        }
    }

    /// Borrow the detached signature.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Borrow the shared canonical JSON bytes.
    #[must_use]
    pub fn canonical(&self) -> &SharedCanonicalBytes {
        &self.canonical
    }

    /// Borrow the signed canonical JSON byte slice.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Consume the payload into its signature and shared canonical bytes.
    #[must_use]
    pub fn into_parts(self) -> (Signature, SharedCanonicalBytes) {
        (self.signature, self.canonical)
    }

    /// Consume the payload into the compatibility tuple shape.
    #[must_use]
    pub fn into_signature_and_bytes(self) -> (Signature, Vec<u8>) {
        let (signature, canonical) = self.into_parts();
        (signature, canonical.as_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// SigningBackend
// ---------------------------------------------------------------------------

/// One signing identity and detached signature captured as a single backend
/// operation.
///
/// Rotating backends override the bound signing methods so the public key,
/// algorithm, and signature are observed under the same selector lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningOutcome {
    /// Public key that produced `signature`.
    pub public_key: PublicKey,
    /// Algorithm selected for this operation.
    pub algorithm: SigningAlgorithm,
    /// Detached signature over the requested bytes.
    pub signature: Signature,
}

/// Abstraction over Chio signing algorithms.
///
/// Every Chio artifact that requires a signature delegates to a
/// `SigningBackend` implementation. The default backend is [`Ed25519Backend`],
/// which wraps the existing [`Keypair`] and preserves byte-identical
/// serialization. Under the `fips` feature, [`P256Backend`] and
/// [`P384Backend`] are available and route through `aws-lc-rs`.
///
/// Backends are expected to be cheap to clone; implementations should store
/// private key material behind reference counting or copy-on-sign semantics
/// as appropriate. The trait is deliberately dyn-compatible so it can be
/// passed as `&dyn SigningBackend` through artifact signing helpers.
pub trait SigningBackend: Send + Sync {
    /// Algorithm this backend produces.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Public half of this backend's signing identity.
    fn public_key(&self) -> PublicKey;

    /// Produce a detached signature over `message`.
    fn sign_bytes(&self, message: &[u8]) -> Result<Signature>;

    /// Capture identity and signature as one validated operation.
    ///
    /// A rotating backend must override this method and retain its selector
    /// lease through signature creation and durable signing evidence.
    fn sign_bytes_with_identity(&self, message: &[u8]) -> Result<SigningOutcome> {
        let public_key = self.public_key();
        let algorithm = self.algorithm();
        if public_key.algorithm() != algorithm {
            return Err(Error::InvalidSignature(
                "signing backend algorithm does not match public key".to_string(),
            ));
        }
        let signature = self.sign_bytes(message)?;
        if signature.algorithm() != algorithm || !public_key.verify(message, &signature) {
            return Err(Error::InvalidSignature(
                "signing backend returned a signature from a different identity".to_string(),
            ));
        }
        Ok(SigningOutcome {
            public_key,
            algorithm,
            signature,
        })
    }

    /// Sign only when the atomic backend identity equals `expected_key`.
    ///
    /// A rotating backend should override this method so it checks the key
    /// before signing while the same selector lease remains held.
    fn sign_bytes_for_identity(
        &self,
        expected_key: &PublicKey,
        message: &[u8],
    ) -> Result<SigningOutcome> {
        let outcome = self.sign_bytes_with_identity(message)?;
        if &outcome.public_key != expected_key {
            return Err(Error::InvalidPublicKey(
                "signing backend identity does not match the requested key".to_string(),
            ));
        }
        Ok(outcome)
    }

    /// Produce a detached signature over canonical JSON bytes.
    fn sign_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<Signature> {
        self.sign_bytes_with_identity(canonical.as_bytes())
            .map(|outcome| outcome.signature)
    }
}

/// Sign the canonical JSON form of `value` with the given backend.
///
/// Returns the produced signature and the canonical byte sequence that was
/// signed (so callers can store or retransmit the exact bytes used). This is
/// a free function rather than a trait method so [`SigningBackend`] remains
/// dyn-compatible.
pub fn sign_canonical_with_backend<T: Serialize>(
    backend: &dyn SigningBackend,
    value: &T,
) -> Result<(Signature, Vec<u8>)> {
    let canonical = CanonicalBytes::from_serializable(value)?;
    let outcome = backend.sign_bytes_with_identity(canonical.as_bytes())?;
    Ok((outcome.signature, canonical.into_vec()))
}

/// Sign canonical JSON while binding the operation to an embedded public key.
pub fn sign_canonical_with_backend_for_identity<T: Serialize>(
    backend: &dyn SigningBackend,
    expected_key: &PublicKey,
    value: &T,
) -> Result<(SigningOutcome, Vec<u8>)> {
    let canonical = CanonicalBytes::from_serializable(value)?;
    let outcome = backend.sign_bytes_for_identity(expected_key, canonical.as_bytes())?;
    Ok((outcome, canonical.into_vec()))
}

/// Sign shared canonical JSON bytes with the given backend.
///
/// The returned payload keeps the exact bytes behind an `Arc` so callers can
/// share the signed representation without copying or reserializing.
pub fn sign_shared_canonical_with_backend(
    backend: &dyn SigningBackend,
    canonical: SharedCanonicalBytes,
) -> Result<SignedCanonicalPayload> {
    let outcome = backend.sign_bytes_with_identity(canonical.as_ref().as_bytes())?;
    Ok(SignedCanonicalPayload::new(outcome.signature, canonical))
}

/// Sign the canonical JSON form of `value` with the given backend and keep the
/// canonical byte sequence shareable.
pub fn sign_canonical_with_backend_shared<T: Serialize>(
    backend: &dyn SigningBackend,
    value: &T,
) -> Result<SignedCanonicalPayload> {
    let canonical = canonical_json_shared_bytes(value)?;
    sign_shared_canonical_with_backend(backend, canonical)
}

/// Ed25519 [`SigningBackend`] wrapping a [`Keypair`].
///
/// Always available regardless of feature flags.
#[derive(Clone)]
pub struct Ed25519Backend {
    keypair: Keypair,
}

impl Ed25519Backend {
    /// Construct from an existing keypair.
    #[must_use]
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Generate a fresh Ed25519 keypair.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate(),
        }
    }

    /// Borrow the underlying keypair.
    #[must_use]
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

impl SigningBackend for Ed25519Backend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.keypair.sign(message))
    }
}

// ---------------------------------------------------------------------------
// FIPS backends (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "fips")]
mod fips_backends {
    use super::{PublicKey, PublicKeyMaterial, Result, Signature, SignatureMaterial};
    use crate::crypto::{Error, SigningAlgorithm, SigningBackend};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
    };

    /// ECDSA P-256 signing backend using `aws-lc-rs` (`fips` feature).
    pub struct P256Backend {
        keypair: EcdsaKeyPair,
        rng: SystemRandom,
        public_sec1: Vec<u8>,
    }

    impl P256Backend {
        /// Generate a fresh P-256 keypair.
        pub fn generate() -> Result<Self> {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .map_err(|e| {
                    Error::InvalidPublicKey(format!("aws-lc-rs P-256 pkcs8 generation: {e}"))
                })?;
            let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                .map_err(|e| Error::InvalidPublicKey(format!("aws-lc-rs P-256 parse: {e}")))?;
            let public_sec1 = keypair.public_key().as_ref().to_vec();
            Ok(Self {
                keypair,
                rng,
                public_sec1,
            })
        }

        /// Import from PKCS#8 v1 DER-encoded private key bytes.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
            let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
                .map_err(|e| {
                    Error::InvalidPublicKey(format!("aws-lc-rs P-256 pkcs8 import: {e}"))
                })?;
            let public_sec1 = keypair.public_key().as_ref().to_vec();
            Ok(Self {
                keypair,
                rng: SystemRandom::new(),
                public_sec1,
            })
        }
    }

    impl SigningBackend for P256Backend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::P256
        }

        fn public_key(&self) -> PublicKey {
            PublicKey {
                material: PublicKeyMaterial::P256 {
                    encoded_point: self.public_sec1.clone(),
                },
            }
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            let sig = self
                .keypair
                .sign(&self.rng, message)
                .map_err(|e| Error::InvalidSignature(format!("aws-lc-rs P-256 sign: {e}")))?;
            Ok(Signature {
                material: SignatureMaterial::P256 {
                    der: sig.as_ref().to_vec(),
                },
            })
        }
    }

    /// ECDSA P-384 signing backend using `aws-lc-rs` (`fips` feature).
    pub struct P384Backend {
        keypair: EcdsaKeyPair,
        rng: SystemRandom,
        public_sec1: Vec<u8>,
    }

    impl P384Backend {
        /// Generate a fresh P-384 keypair.
        pub fn generate() -> Result<Self> {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                .map_err(|e| {
                    Error::InvalidPublicKey(format!("aws-lc-rs P-384 pkcs8 generation: {e}"))
                })?;
            let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref())
                .map_err(|e| Error::InvalidPublicKey(format!("aws-lc-rs P-384 parse: {e}")))?;
            let public_sec1 = keypair.public_key().as_ref().to_vec();
            Ok(Self {
                keypair,
                rng,
                public_sec1,
            })
        }

        /// Import from PKCS#8 v1 DER-encoded private key bytes.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
            let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8)
                .map_err(|e| {
                    Error::InvalidPublicKey(format!("aws-lc-rs P-384 pkcs8 import: {e}"))
                })?;
            let public_sec1 = keypair.public_key().as_ref().to_vec();
            Ok(Self {
                keypair,
                rng: SystemRandom::new(),
                public_sec1,
            })
        }
    }

    impl SigningBackend for P384Backend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::P384
        }

        fn public_key(&self) -> PublicKey {
            PublicKey {
                material: PublicKeyMaterial::P384 {
                    encoded_point: self.public_sec1.clone(),
                },
            }
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            let sig = self
                .keypair
                .sign(&self.rng, message)
                .map_err(|e| Error::InvalidSignature(format!("aws-lc-rs P-384 sign: {e}")))?;
            Ok(Signature {
                material: SignatureMaterial::P384 {
                    der: sig.as_ref().to_vec(),
                },
            })
        }
    }
}

#[cfg(feature = "fips")]
pub use fips_backends::{P256Backend, P384Backend};

#[cfg(feature = "pq")]
pub use crate::pq::{HybridBackend, MlDsa65Backend};

// ---------------------------------------------------------------------------
// Verification helpers (always compiled; use aws-lc-rs under fips feature,
// otherwise return false)
// ---------------------------------------------------------------------------

#[cfg(feature = "fips")]
fn verify_ecdsa_p256(public_sec1: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_sec1);
    verifier.verify(message, signature_der).is_ok()
}

#[cfg(not(feature = "fips"))]
fn verify_ecdsa_p256(_public_sec1: &[u8], _message: &[u8], _signature_der: &[u8]) -> bool {
    // Without the `fips` feature we cannot verify ECDSA signatures. Fail-closed.
    false
}

#[cfg(feature = "fips")]
fn verify_ecdsa_p384(public_sec1: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_ASN1};
    let verifier = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_sec1);
    verifier.verify(message, signature_der).is_ok()
}

#[cfg(not(feature = "fips"))]
fn verify_ecdsa_p384(_public_sec1: &[u8], _message: &[u8], _signature_der: &[u8]) -> bool {
    false
}

#[cfg(feature = "pq")]
fn verify_mldsa65_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    crate::pq::verify_mldsa65_signature(public_key, message, signature)
}

#[cfg(not(feature = "pq"))]
fn verify_mldsa65_signature(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
    false
}

fn expected_hybrid_alg_set(algorithm: SigningAlgorithm) -> Result<&'static str> {
    match algorithm {
        SigningAlgorithm::Ed25519 => Ok(HYBRID_ED25519_MLDSA65),
        SigningAlgorithm::P256 => Ok(HYBRID_P256_MLDSA65),
        SigningAlgorithm::P384 => Ok(HYBRID_P384_MLDSA65),
        SigningAlgorithm::Hybrid => Err(Error::InvalidSignature(
            "hybrid signatures cannot be nested".to_string(),
        )),
    }
}

fn validate_hybrid_alg_set(algorithm: SigningAlgorithm, alg_set: &str) -> Result<()> {
    let expected = expected_hybrid_alg_set(algorithm)?;
    if alg_set != expected {
        return Err(Error::InvalidSignature(format!(
            "hybrid alg_set {alg_set} does not match expected {expected}"
        )));
    }
    Ok(())
}

fn validate_mldsa65_public_key_len(bytes: &[u8]) -> Result<()> {
    if bytes.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(Error::InvalidPublicKey(format!(
            "expected {ML_DSA_65_PUBLIC_KEY_LEN}-byte ML-DSA-65 public key, got {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

fn validate_mldsa65_signature_len(bytes: &[u8]) -> Result<()> {
    if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
        return Err(Error::InvalidSignature(format!(
            "expected {ML_DSA_65_SIGNATURE_LEN}-byte ML-DSA-65 signature, got {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256 of the given bytes, returning the hash as lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Serialize a value to canonical JSON bytes (RFC 8785 / JCS).
///
/// Uses the full RFC 8785 implementation from `crate::canonical`. Object keys
/// are sorted by UTF-16 code unit comparison, numbers follow ECMAScript
/// `JSON.stringify()` rules, and strings use minimal escaping.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    crate::canonical::canonical_json_bytes(value)
}

/// Serialize a value to shared canonical JSON bytes.
pub fn canonical_json_shared_bytes<T: Serialize>(value: &T) -> Result<SharedCanonicalBytes> {
    Ok(SharedCanonicalBytes::new(
        CanonicalBytes::from_serializable(value)?,
    ))
}

/// Serialize a value to a canonical JSON string (RFC 8785 / JCS).
pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    crate::canonical::canonical_json_string(value)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;

    #[test]
    fn signature_encoded_text_len_matches_existing_encoding() -> Result<()> {
        let ed25519 = Keypair::from_seed(&[31; 32]).sign(b"encoding-length");
        let p256 = Signature::from_p256_der(&[0x30; 72]);
        let p384 = Signature::from_p384_der(&[0x30; 104]);
        let pq = alloc::vec![0; ML_DSA_65_SIGNATURE_LEN];
        let signatures = [
            ed25519.clone(),
            p256.clone(),
            p384.clone(),
            Signature::from_hybrid_parts(ed25519, &pq, HYBRID_ED25519_MLDSA65)?,
            Signature::from_hybrid_parts(p256, &pq, HYBRID_P256_MLDSA65)?,
            Signature::from_hybrid_parts(p384, &pq, HYBRID_P384_MLDSA65)?,
        ];
        for signature in signatures {
            assert_eq!(signature.encoded_text_len(), Some(signature.to_hex().len()));
        }
        Ok(())
    }

    #[test]
    fn signature_encoded_text_len_overflow_refuses() {
        assert_eq!(encoded_hex_text_len(usize::MAX, 5), None);
        assert_eq!(encoded_hex_text_len(usize::MAX / 2, 5), None);
        assert_eq!(encoded_hex_text_len(0, 5), Some(5));
    }

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate();
        let msg = b"hello chio";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello chio");
        assert!(!kp.public_key().verify(b"wrong", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"hello chio");
        assert!(!kp2.public_key().verify(b"hello chio", &sig));
    }

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
        assert_eq!(trusted, keypair.public_key());
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

    #[test]
    fn deterministic_from_seed() {
        let seed = [42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.public_key().to_hex(), kp2.public_key().to_hex());
    }

    #[test]
    fn keypair_seed_hex_roundtrip() {
        let kp = Keypair::generate();
        let restored = Keypair::from_seed_hex(&kp.seed_hex()).unwrap();
        assert_eq!(kp.public_key().to_hex(), restored.public_key().to_hex());
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let kp = Keypair::generate();
        let hex = kp.public_key().to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(kp.public_key(), restored);
    }

    #[test]
    fn pubkey_hex_with_0x_prefix() {
        let kp = Keypair::generate();
        let hex = format!("0x{}", kp.public_key().to_hex());
        let restored = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(kp.public_key(), restored);
    }

    #[test]
    fn signature_hex_roundtrip() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"test");
        let hex = sig.to_hex();
        let restored = Signature::from_hex(&hex).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn pubkey_serde_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let json = serde_json::to_string(&pk).unwrap();
        let restored: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"test");
        let json = serde_json::to_string(&sig).unwrap();
        let restored: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn sign_canonical_roundtrip() {
        let kp = Keypair::generate();
        let value = serde_json::json!({"b": 2, "a": 1});
        let (sig, _bytes) = kp.sign_canonical(&value).unwrap();
        let valid = kp.public_key().verify_canonical(&value, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn sign_canonical_shared_returns_shared_canonical_bytes() -> Result<()> {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let value = serde_json::json!({"b": 2, "a": 1});
        let signed = kp.sign_canonical_shared(&value)?;

        assert_eq!(signed.canonical_bytes(), br#"{"a":1,"b":2}"#);
        assert!(kp
            .public_key()
            .verify_shared_canonical(signed.canonical(), signed.signature()));

        let shared = signed.canonical().clone();
        assert!(SharedCanonicalBytes::ptr_eq(signed.canonical(), &shared));

        let (legacy_signature, legacy_bytes) = kp.sign_canonical(&value)?;
        assert_eq!(&legacy_signature, signed.signature());
        assert_eq!(legacy_bytes, signed.canonical_bytes());

        Ok(())
    }

    #[test]
    fn backend_signing_reuses_supplied_shared_canonical_bytes() -> Result<()> {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[9u8; 32]));
        let value = serde_json::json!({"z": 0, "a": [true]});
        let canonical = canonical_json_shared_bytes(&value)?;
        let signed = sign_shared_canonical_with_backend(&backend, canonical.clone())?;

        assert!(SharedCanonicalBytes::ptr_eq(&canonical, signed.canonical()));
        assert!(backend
            .public_key()
            .verify_shared_canonical(signed.canonical(), signed.signature()));

        let (legacy_signature, legacy_bytes) = sign_canonical_with_backend(&backend, &value)?;
        assert_eq!(&legacy_signature, signed.signature());
        assert_eq!(legacy_bytes, signed.canonical_bytes());

        Ok(())
    }

    #[test]
    fn canonical_json_key_order() {
        let value = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let s = canonical_json_string(&value).unwrap();
        let a_pos = s.find("\"a\"").unwrap();
        let m_pos = s.find("\"m\"").unwrap();
        let z_pos = s.find("\"z\"").unwrap();
        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256("hello") is well-known
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn ed25519_backend_round_trip() {
        let backend = Ed25519Backend::generate();
        assert_eq!(backend.algorithm(), SigningAlgorithm::Ed25519);
        let msg = b"hello chio";
        let sig = backend.sign_bytes(msg).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::Ed25519);
        assert!(backend.public_key().verify(msg, &sig));
    }

    #[test]
    fn atomic_signing_outcome_binds_identity_algorithm_and_signature() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[21_u8; 32]));
        let outcome = backend
            .sign_bytes_with_identity(b"atomic identity")
            .unwrap();

        assert_eq!(outcome.public_key, backend.public_key());
        assert_eq!(outcome.algorithm, SigningAlgorithm::Ed25519);
        assert!(outcome
            .public_key
            .verify(b"atomic identity", &outcome.signature));

        let wrong = Ed25519Backend::new(Keypair::from_seed(&[22_u8; 32])).public_key();
        assert!(backend
            .sign_bytes_for_identity(&wrong, b"wrong identity")
            .is_err());
    }

    #[test]
    fn atomic_signing_rejects_a_signature_from_another_identity() {
        struct MismatchedBackend {
            advertised: Ed25519Backend,
            signer: Ed25519Backend,
        }

        impl SigningBackend for MismatchedBackend {
            fn algorithm(&self) -> SigningAlgorithm {
                SigningAlgorithm::Ed25519
            }

            fn public_key(&self) -> PublicKey {
                self.advertised.public_key()
            }

            fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
                self.signer.sign_bytes(message)
            }
        }

        let backend = MismatchedBackend {
            advertised: Ed25519Backend::new(Keypair::from_seed(&[23_u8; 32])),
            signer: Ed25519Backend::new(Keypair::from_seed(&[24_u8; 32])),
        };
        assert!(backend
            .sign_bytes_with_identity(b"identity substitution")
            .is_err());
    }

    #[test]
    fn ed25519_hex_is_bare_64_chars() {
        // Ed25519 keys and signatures serialize as plain hex with no algorithm prefix.
        let kp = Keypair::generate();
        let pk_hex = kp.public_key().to_hex();
        assert_eq!(pk_hex.len(), 64);
        assert!(!pk_hex.contains(':'));
        let sig = kp.sign(b"x");
        let sig_hex = sig.to_hex();
        assert_eq!(sig_hex.len(), 128);
        assert!(!sig_hex.contains(':'));
    }

    #[test]
    fn algorithm_enum_defaults_to_ed25519() {
        assert_eq!(SigningAlgorithm::default(), SigningAlgorithm::Ed25519);
        assert!(SigningAlgorithm::default().is_default());
    }

    #[test]
    fn rejects_non_matching_algorithm_pair() {
        // Pairing a P-256 signature against an Ed25519 key (or vice versa)
        // must return false rather than panic.
        let kp = Keypair::generate();
        let fake_p256_sig = Signature::from_p256_der(&[0x30, 0x02, 0x02, 0x01]);
        assert!(!kp.public_key().verify(b"x", &fake_p256_sig));
    }

    #[test]
    fn non_ed25519_byte_access_fails_closed() {
        let p256_generator = PublicKey::from_hex(
            "p256:046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();

        assert!(matches!(
            p256_generator.ed25519_bytes(),
            Err(Error::InvalidPublicKey(_))
        ));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn p256_backend_round_trip() {
        let backend = P256Backend::generate().unwrap();
        assert_eq!(backend.algorithm(), SigningAlgorithm::P256);
        let msg = b"hello fips";
        let sig = backend.sign_bytes(msg).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::P256);
        assert!(backend.public_key().verify(msg, &sig));
        // Serde round-trips.
        let json_pk = serde_json::to_string(&backend.public_key()).unwrap();
        assert!(json_pk.contains("p256:"));
        let restored_pk: PublicKey = serde_json::from_str(&json_pk).unwrap();
        assert_eq!(restored_pk.algorithm(), SigningAlgorithm::P256);
        let json_sig = serde_json::to_string(&sig).unwrap();
        assert!(json_sig.contains("p256:"));
        let restored_sig: Signature = serde_json::from_str(&json_sig).unwrap();
        assert!(restored_pk.verify(msg, &restored_sig));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn p384_backend_round_trip() {
        let backend = P384Backend::generate().unwrap();
        assert_eq!(backend.algorithm(), SigningAlgorithm::P384);
        let msg = b"hello fips 384";
        let sig = backend.sign_bytes(msg).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::P384);
        assert!(backend.public_key().verify(msg, &sig));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn p256_wrong_message_fails() {
        let backend = P256Backend::generate().unwrap();
        let sig = backend.sign_bytes(b"original").unwrap();
        assert!(!backend.public_key().verify(b"tampered", &sig));
    }
}
