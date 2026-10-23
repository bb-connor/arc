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
use crate::signed_artifact::registered_wrapper_schema;

mod ed25519_verification;
mod encoding;
mod wire;
mod wrapper;

pub use wrapper::{
    assemble_wrapper, ExemptFormat, SigningMessage, SigningWrapper, SIGNING_WRAPPER_LEN,
    SIGNING_WRAPPER_PREFIX,
};

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
/// `"ed25519"`, `"p256"`, `"p384"`, or `"hybrid"`. A verifier takes the
/// algorithm only from the pinned key, never from an artifact member.
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
    pub(crate) fn sign(&self, message: SigningMessage<'_>) -> Signature {
        let sig = self.signing_key.sign(message.as_bytes());
        Signature {
            material: SignatureMaterial::Ed25519 { inner: sig },
        }
    }

    /// Sign the wrapper over `canonical` under `schema_id`; refuses an
    /// unregistered id before signing.
    pub fn sign_wrapped(
        &self,
        schema_id: &str,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<Signature> {
        let wrapper = SigningWrapper::new(schema_id, canonical)?;
        Ok(self.sign(SigningMessage::wrapper(&wrapper)))
    }

    /// Sign bytes whose layout an external standard fixes.
    #[must_use]
    pub fn sign_exempt(&self, format: ExemptFormat, bytes: &[u8]) -> Signature {
        self.sign(SigningMessage::exempt(format, bytes))
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

    /// Whether this is a weak, low-order Ed25519 public key.
    ///
    /// Such keys can validate signatures for almost every message under
    /// loose Ed25519 verification and must not identify artifact issuers.
    /// Non-Ed25519 keys return `false`.
    #[must_use]
    pub fn is_weak_ed25519(&self) -> bool {
        match &self.material {
            PublicKeyMaterial::Ed25519 { verifying_key } => verifying_key.is_weak(),
            _ => false,
        }
    }

    /// Verify a signature against a message.
    ///
    /// Returns `false` when algorithms differ between key and signature, or
    /// when the cryptographic check fails. Never panics.
    #[must_use]
    pub(crate) fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match (&self.material, &signature.material) {
            (
                PublicKeyMaterial::Ed25519 { verifying_key },
                SignatureMaterial::Ed25519 { inner },
            ) => ed25519_verification::verify(verifying_key, message, inner, false),
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

    /// Strictly verify a signature against a message.
    ///
    /// Ed25519 verification rejects weak public keys and small-order
    /// signature points. Other algorithms retain their normal verifier;
    /// hybrid signatures apply strict verification to the classical part.
    #[must_use]
    pub(crate) fn verify_strict(&self, message: &[u8], signature: &Signature) -> bool {
        match (&self.material, &signature.material) {
            (
                PublicKeyMaterial::Ed25519 { verifying_key },
                SignatureMaterial::Ed25519 { inner },
            ) => ed25519_verification::verify(verifying_key, message, inner, true),
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
                    && classical.verify_strict(message, classical_signature)
                    && verify_mldsa65_signature(pq, message, pq_signature)
            }
            _ => false,
        }
    }

    /// Hex encoding, with algorithm prefix for non-Ed25519 keys.
    ///
    /// Ed25519 keys render as a bare 64-character lowercase hex string. P-256 keys render as
    /// `p256:<130-char hex>` (uncompressed SEC1). P-384 keys render as
    /// `p384:<194-char hex>`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        match &self.material {
            PublicKeyMaterial::Ed25519 { verifying_key } => {
                encoding::prefixed_hex("", verifying_key.as_bytes())
            }
            PublicKeyMaterial::P256 { encoded_point } => {
                encoding::prefixed_hex("p256:", encoded_point)
            }
            PublicKeyMaterial::P384 { encoded_point } => {
                encoding::prefixed_hex("p384:", encoded_point)
            }
            PublicKeyMaterial::Hybrid {
                classical,
                pq,
                alg_set,
            } => {
                format!(
                    "hybrid:{}:{}:{}",
                    classical.to_hex(),
                    encoding::prefixed_hex("", pq),
                    alg_set
                )
            }
        }
    }

    /// Lend the exact [`Self::to_hex`] wire bytes to a synchronous consumer.
    ///
    /// P-256 uses a fixed stack buffer; other key families keep their established
    /// rendering. The consumer cannot retain a borrow of the temporary buffer.
    pub fn with_hex_bytes<R>(&self, consume: impl FnOnce(&[u8]) -> R) -> R {
        if let PublicKeyMaterial::P256 { encoded_point } = &self.material {
            let mut encoded = [0; 135];
            if encoding::fill_prefixed_hex("p256:", encoded_point, &mut encoded).is_some() {
                return consume(&encoded);
            }
            #[cfg(kani)]
            panic!("bounded P-256 hex encoding must succeed");
        }
        // Prove that the bounded P-256 fixture never needs compatibility
        // rendering. Every other algorithm must fail this additional Kani
        // obligation; production retains its established rendering below.
        #[cfg(kani)]
        panic!("bounded hex-byte consumer must use P-256");
        #[cfg(not(kani))]
        {
            let encoded = self.to_hex();
            consume(encoded.as_bytes())
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
    /// The identity this backend signs with now.
    ///
    /// An unreadable identity is an error. The algorithm is
    /// `public_key()?.algorithm()`.
    fn public_key(&self) -> Result<PublicKey>;

    /// Produce a detached signature over `message`.
    fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature>;

    /// Capture identity and signature as one validated operation.
    ///
    /// A rotating backend must override this method and retain its selector
    /// lease through signature creation and durable signing evidence.
    fn sign_bytes_with_identity(&self, message: SigningMessage<'_>) -> Result<SigningOutcome> {
        let public_key = self.public_key()?;
        let algorithm = public_key.algorithm();
        let signature = self.sign_bytes(message)?;
        if signature.algorithm() != algorithm || !public_key.verify(message.as_bytes(), &signature)
        {
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
        message: SigningMessage<'_>,
    ) -> Result<SigningOutcome> {
        let outcome = self.sign_bytes_with_identity(message)?;
        if &outcome.public_key != expected_key {
            return Err(Error::InvalidPublicKey(
                "signing backend identity does not match the requested key".to_string(),
            ));
        }
        Ok(outcome)
    }

    /// Build the wrapper and sign it; refuses an unregistered id before any
    /// signing call.
    fn sign_wrapped(
        &self,
        schema_id: &str,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<SigningOutcome> {
        let wrapper = SigningWrapper::new(schema_id, canonical)?;
        self.sign_bytes_with_identity(SigningMessage::wrapper(&wrapper))
    }

    /// [`SigningBackend::sign_wrapped`] bound to `expected_key`.
    fn sign_wrapped_for_identity(
        &self,
        expected_key: &PublicKey,
        schema_id: &str,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
    ) -> Result<SigningOutcome> {
        let wrapper = SigningWrapper::new(schema_id, canonical)?;
        self.sign_bytes_for_identity(expected_key, SigningMessage::wrapper(&wrapper))
    }
}

/// Sign the wrapper over the canonical JSON of `value` under `schema_id`.
///
/// Returns the outcome and the canonical body the wrapper hashed.
pub fn sign_wrapped<T: Serialize>(
    backend: &dyn SigningBackend,
    schema_id: &str,
    value: &T,
) -> Result<(SigningOutcome, CanonicalBytes<CanonicalJsonWitness>)> {
    let canonical = CanonicalBytes::from_serializable(value)?;
    let outcome = backend.sign_wrapped(schema_id, &canonical)?;
    Ok((outcome, canonical))
}

/// [`sign_wrapped`] bound to `expected_key`.
pub fn sign_wrapped_for_identity<T: Serialize>(
    backend: &dyn SigningBackend,
    expected_key: &PublicKey,
    schema_id: &str,
    value: &T,
) -> Result<(SigningOutcome, CanonicalBytes<CanonicalJsonWitness>)> {
    let canonical = CanonicalBytes::from_serializable(value)?;
    let outcome = backend.sign_wrapped_for_identity(expected_key, schema_id, &canonical)?;
    Ok((outcome, canonical))
}

/// Sign the wrapper over shared canonical bytes without reserializing them.
pub fn sign_shared_wrapped(
    backend: &dyn SigningBackend,
    schema_id: &str,
    canonical: SharedCanonicalBytes,
) -> Result<SignedCanonicalPayload> {
    let outcome = backend.sign_wrapped(schema_id, canonical.as_ref())?;
    Ok(SignedCanonicalPayload::new(outcome.signature, canonical))
}

/// Verify `signature` over the wrapper of the canonical JSON of `value`.
///
/// `pinned` is the key the caller trusts; its encoding alone selects the
/// algorithm. `schema_id` is the type the call site expects. Order: id
/// registered, signature algorithm equals `pinned.algorithm()`, strict
/// cryptographic check.
pub fn verify_wrapped<T: Serialize>(
    pinned: &PublicKey,
    schema_id: &str,
    value: &T,
    signature: &Signature,
) -> Result<()> {
    if !registered_wrapper_schema(schema_id) {
        return Err(Error::UnregisteredSchemaId(schema_id.to_string()));
    }
    let canonical = CanonicalBytes::from_serializable(value)?;
    verify_wrapped_bytes(pinned, schema_id, &canonical, signature)
}

/// [`verify_wrapped`] over canonical bytes the caller already holds.
pub fn verify_wrapped_bytes(
    pinned: &PublicKey,
    schema_id: &str,
    canonical: &CanonicalBytes<CanonicalJsonWitness>,
    signature: &Signature,
) -> Result<()> {
    let wrapper = SigningWrapper::new(schema_id, canonical)?;
    verify_message(pinned, wrapper.as_bytes(), signature)
}

/// Verify a signature over a wrapper the caller already holds.
pub fn verify_wrapper(
    pinned: &PublicKey,
    wrapper: &SigningWrapper,
    signature: &Signature,
) -> Result<()> {
    verify_message(pinned, wrapper.as_bytes(), signature)
}

/// Verify a signature over bytes whose layout `format` fixes.
pub fn verify_exempt(
    pinned: &PublicKey,
    _format: ExemptFormat,
    bytes: &[u8],
    signature: &Signature,
) -> Result<()> {
    verify_message(pinned, bytes, signature)
}

/// Maps a wrapper verification to the boolean artifact verifiers return: a
/// rejected signature is `Ok(false)`; every other refusal stays an error.
pub(crate) fn wrapped_verdict(result: Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(Error::SignatureRejected) => Ok(false),
        Err(error) => Err(error),
    }
}

fn verify_message(pinned: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let key = pinned.algorithm();
    let signed = signature.algorithm();
    if key != signed {
        return Err(Error::SignatureAlgorithmMismatch {
            key,
            signature: signed,
        });
    }
    if pinned.verify_strict(message, signature) {
        Ok(())
    } else {
        Err(Error::SignatureRejected)
    }
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
    fn public_key(&self) -> Result<PublicKey> {
        Ok(self.keypair.public_key())
    }

    fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature> {
        Ok(self.keypair.sign(message))
    }
}

// ---------------------------------------------------------------------------
// FIPS backends (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "fips")]
mod fips_backends {
    use super::{
        PublicKey, PublicKeyMaterial, Result, Signature, SignatureMaterial, SigningMessage,
    };
    use crate::crypto::{Error, SigningBackend};
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
        fn public_key(&self) -> Result<PublicKey> {
            Ok(PublicKey {
                material: PublicKeyMaterial::P256 {
                    encoded_point: self.public_sec1.clone(),
                },
            })
        }

        fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature> {
            let sig = self
                .keypair
                .sign(&self.rng, message.as_bytes())
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
        fn public_key(&self) -> Result<PublicKey> {
            Ok(PublicKey {
                material: PublicKeyMaterial::P384 {
                    encoded_point: self.public_sec1.clone(),
                },
            })
        }

        fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature> {
            let sig = self
                .keypair
                .sign(&self.rng, message.as_bytes())
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
    encoding::prefixed_hex("", &hasher.finalize())
}

/// Write the exact lowercase ASCII bytes of [`sha256_hex`] into a fixed buffer.
#[must_use]
pub fn sha256_hex_bytes(data: &[u8]) -> Option<[u8; 64]> {
    let mut encoded = [0; 64];
    encoding::fill_prefixed_hex("", &Sha256::digest(data), &mut encoded)?;
    Some(encoded)
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

    fn raw(bytes: &[u8]) -> SigningMessage<'_> {
        SigningMessage::exempt(ExemptFormat::JwsSigningInput, bytes)
    }

    #[test]
    fn signature_encoded_text_len_matches_existing_encoding() -> Result<()> {
        let ed25519 = Keypair::from_seed(&[31; 32]).sign(raw(b"encoding-length"));
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
        let sig = kp.sign(raw(msg));
        assert!(kp.public_key().verify(msg, &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = Keypair::generate();
        let sig = kp.sign(raw(b"hello chio"));
        assert!(!kp.public_key().verify(b"wrong", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(raw(b"hello chio"));
        assert!(!kp2.public_key().verify(b"hello chio", &sig));
    }

    #[test]
    fn strict_verification_rejects_weak_ed25519_key() {
        let weak_key = match PublicKey::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ) {
            Ok(key) => key,
            Err(err) => panic!("weak Ed25519 test key construction failed: {err}"),
        };
        let forged_signature = match Signature::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
        ) {
            Ok(signature) => signature,
            Err(err) => panic!("weak Ed25519 test signature construction failed: {err}"),
        };

        assert!(weak_key.is_weak_ed25519());
        assert!(!weak_key.verify_strict(b"message without a signer", &forged_signature));
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
        let sig = kp.sign(raw(b"test"));
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
        let sig = kp.sign(raw(b"test"));
        let json = serde_json::to_string(&sig).unwrap();
        let restored: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn sign_wrapped_roundtrip() -> Result<()> {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let canonical = CanonicalBytes::from_serializable(&serde_json::json!({"b": 2, "a": 1}))?;
        let sig = kp.sign_wrapped("chio.receipt.v1", &canonical)?;
        verify_wrapped_bytes(&kp.public_key(), "chio.receipt.v1", &canonical, &sig)?;
        let wrapper = SigningWrapper::new("chio.receipt.v1", &canonical)?;
        assert!(kp.public_key().verify_strict(wrapper.as_bytes(), &sig));
        assert!(!kp.public_key().verify(canonical.as_bytes(), &sig));
        Ok(())
    }

    #[test]
    fn backend_signing_reuses_supplied_shared_canonical_bytes() -> Result<()> {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[9u8; 32]));
        let value = serde_json::json!({"z": 0, "a": [true]});
        let canonical = canonical_json_shared_bytes(&value)?;
        let signed = sign_shared_wrapped(&backend, "chio.receipt.v1", canonical.clone())?;

        assert!(SharedCanonicalBytes::ptr_eq(&canonical, signed.canonical()));
        verify_wrapped(
            &backend.public_key()?,
            "chio.receipt.v1",
            &value,
            signed.signature(),
        )?;
        let (outcome, bytes) = sign_wrapped(&backend, "chio.receipt.v1", &value)?;
        assert_eq!(&outcome.signature, signed.signature());
        assert_eq!(bytes.as_bytes(), signed.canonical_bytes());
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
    fn sha256_hex_bytes_are_the_sha256_hex_wire_bytes() {
        for data in [&b""[..], b"hello", &[0xff; 200]] {
            let encoded = sha256_hex_bytes(data);
            assert_eq!(
                encoded.as_ref().map(|bytes| &bytes[..]),
                Some(sha256_hex(data).as_bytes())
            );
        }
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
        assert_eq!(
            backend.public_key().unwrap().algorithm(),
            SigningAlgorithm::Ed25519
        );
        let msg = b"hello chio";
        let sig = backend.sign_bytes(raw(msg)).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::Ed25519);
        assert!(backend.public_key().unwrap().verify(msg, &sig));
    }

    #[test]
    fn atomic_signing_outcome_binds_identity_algorithm_and_signature() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[21_u8; 32]));
        let outcome = backend
            .sign_bytes_with_identity(raw(b"atomic identity"))
            .unwrap();

        assert_eq!(outcome.public_key, backend.public_key().unwrap());
        assert_eq!(outcome.algorithm, SigningAlgorithm::Ed25519);
        assert!(outcome
            .public_key
            .verify(b"atomic identity", &outcome.signature));

        let wrong = Ed25519Backend::new(Keypair::from_seed(&[22_u8; 32]))
            .public_key()
            .unwrap();
        assert!(backend
            .sign_bytes_for_identity(&wrong, raw(b"wrong identity"))
            .is_err());
    }

    #[test]
    fn atomic_signing_rejects_a_signature_from_another_identity() {
        struct MismatchedBackend {
            advertised: Ed25519Backend,
            signer: Ed25519Backend,
        }

        impl SigningBackend for MismatchedBackend {
            fn public_key(&self) -> crate::Result<PublicKey> {
                self.advertised.public_key()
            }

            fn sign_bytes(&self, message: SigningMessage<'_>) -> Result<Signature> {
                self.signer.sign_bytes(message)
            }
        }

        let backend = MismatchedBackend {
            advertised: Ed25519Backend::new(Keypair::from_seed(&[23_u8; 32])),
            signer: Ed25519Backend::new(Keypair::from_seed(&[24_u8; 32])),
        };
        assert!(backend
            .sign_bytes_with_identity(raw(b"identity substitution"))
            .is_err());
    }

    #[test]
    fn ed25519_hex_is_bare_64_chars() {
        // Ed25519 keys and signatures serialize as plain hex with no algorithm prefix.
        let kp = Keypair::generate();
        let pk_hex = kp.public_key().to_hex();
        assert_eq!(pk_hex.len(), 64);
        assert!(!pk_hex.contains(':'));
        let sig = kp.sign(raw(b"x"));
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
        assert_eq!(
            backend.public_key().unwrap().algorithm(),
            SigningAlgorithm::P256
        );
        let msg = b"hello fips";
        let sig = backend.sign_bytes(raw(msg)).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::P256);
        assert!(backend.public_key().unwrap().verify(msg, &sig));
        // Serde round-trips.
        let json_pk = serde_json::to_string(&backend.public_key().unwrap()).unwrap();
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
        assert_eq!(
            backend.public_key().unwrap().algorithm(),
            SigningAlgorithm::P384
        );
        let msg = b"hello fips 384";
        let sig = backend.sign_bytes(raw(msg)).unwrap();
        assert_eq!(sig.algorithm(), SigningAlgorithm::P384);
        assert!(backend.public_key().unwrap().verify(msg, &sig));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn p256_wrong_message_fails() {
        let backend = P256Backend::generate().unwrap();
        let sig = backend.sign_bytes(raw(b"original")).unwrap();
        assert!(!backend.public_key().unwrap().verify(b"tampered", &sig));
    }
}
