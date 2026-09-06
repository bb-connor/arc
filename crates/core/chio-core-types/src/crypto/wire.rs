//! Bounded, non-recursive decoding of cryptographic text encodings.
//!
//! A hybrid contains exactly one classical value, not another wire envelope.
//! Check encoded lengths before hex decoding. This bounds allocations performed
//! here; enclosing transport/deserializer input limits remain the caller's job.

use alloc::string::ToString;
use alloc::vec::Vec;

use super::{
    expected_hybrid_alg_set, Error, PublicKey, Result, Signature, SignatureMaterial,
    SigningAlgorithm, HYBRID_ED25519_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

// DER SEQUENCE header plus two INTEGER headers, each with an optional sign
// octet. Both supported curves fit the short-form DER length encoding:
// 2 + 2 * (2 + 1 + scalar_bytes), yielding 72 and 104 bytes respectively.
const P256_MAX_DER_BYTES: usize = 2 + 2 * (2 + 1 + 32);
const P384_MAX_DER_BYTES: usize = 2 + 2 * (2 + 1 + 48);
const MAX_CLASSICAL_KEY_WIRE_BYTES: usize = "p384:0x".len() + 2 * 97;
const MAX_CLASSICAL_SIGNATURE_WIRE_BYTES: usize = "p384:0x".len() + 2 * P384_MAX_DER_BYTES;
const HYBRID_OVERHEAD: usize = "hybrid:".len() + 2 + HYBRID_ED25519_MLDSA65.len();
const MAX_KEY_WIRE_BYTES: usize =
    HYBRID_OVERHEAD + MAX_CLASSICAL_KEY_WIRE_BYTES + 2 * ML_DSA_65_PUBLIC_KEY_LEN;
const MAX_SIGNATURE_WIRE_BYTES: usize =
    HYBRID_OVERHEAD + MAX_CLASSICAL_SIGNATURE_WIRE_BYTES + 2 * ML_DSA_65_SIGNATURE_LEN;

#[derive(Clone, Copy)]
enum Material {
    Key,
    Signature,
    Seed,
}

impl Material {
    fn invalid(self, message: &str) -> Error {
        match self {
            Self::Key => Error::InvalidPublicKey(message.into()),
            Self::Signature | Self::Seed => Error::InvalidSignature(message.into()),
        }
    }
}

enum ClassicalWire<'a> {
    Ed25519(&'a str),
    P256(&'a str),
    P384(&'a str),
}

impl<'a> ClassicalWire<'a> {
    fn parse(wire: &'a str, material: Material) -> Result<Self> {
        match wire.split_once(':') {
            Some(("p256", hex)) => Ok(Self::P256(strip_hex_prefix(hex))),
            Some(("p384", hex)) => Ok(Self::P384(strip_hex_prefix(hex))),
            Some(("hybrid", _)) => {
                Err(material.invalid("hybrid keys and signatures cannot be nested"))
            }
            Some(_) => Err(material.invalid("unknown classical crypto wire algorithm")),
            None => Ok(Self::Ed25519(strip_hex_prefix(wire))),
        }
    }

    fn algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Ed25519(_) => SigningAlgorithm::Ed25519,
            Self::P256(_) => SigningAlgorithm::P256,
            Self::P384(_) => SigningAlgorithm::P384,
        }
    }

    fn public_key(self) -> Result<PublicKey> {
        match self {
            Self::Ed25519(hex) => PublicKey::from_bytes(&decode_fixed::<32>(hex, Material::Key)?),
            Self::P256(hex) => PublicKey::from_p256_sec1(&decode_fixed::<65>(hex, Material::Key)?),
            Self::P384(hex) => PublicKey::from_p384_sec1(&decode_fixed::<97>(hex, Material::Key)?),
        }
    }

    fn signature(self) -> Result<Signature> {
        let material = match self {
            Self::Ed25519(hex) => {
                return Ok(Signature::from_bytes(&decode_fixed::<64>(
                    hex,
                    Material::Signature,
                )?));
            }
            Self::P256(hex) => SignatureMaterial::P256 {
                der: decode_bounded(hex, P256_MAX_DER_BYTES, Material::Signature)?,
            },
            Self::P384(hex) => SignatureMaterial::P384 {
                der: decode_bounded(hex, P384_MAX_DER_BYTES, Material::Signature)?,
            },
        };
        Ok(Signature { material })
    }
}

enum Wire<'a> {
    Classical(ClassicalWire<'a>),
    Hybrid {
        classical: ClassicalWire<'a>,
        pq_hex: &'a str,
        alg_set: &'static str,
    },
}

impl<'a> Wire<'a> {
    fn parse(wire: &'a str, max_bytes: usize, material: Material) -> Result<Self> {
        if wire.len() > max_bytes {
            return Err(material.invalid("crypto wire input exceeds its encoded size limit"));
        }
        let Some(rest) = wire.strip_prefix("hybrid:") else {
            return ClassicalWire::parse(wire, material).map(Self::Classical);
        };
        // Split from the end because a classical ECDSA value has its own prefix.
        let mut parts = rest.rsplitn(3, ':');
        let (Some(alg_set), Some(pq_hex), Some(classical_hex)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(material.invalid("hybrid wire input is missing a component"));
        };
        if classical_hex.is_empty() || pq_hex.is_empty() || alg_set.is_empty() {
            return Err(material.invalid("hybrid wire input contains an empty component"));
        }
        let classical = ClassicalWire::parse(classical_hex, material)?;
        let expected_alg_set = expected_hybrid_alg_set(classical.algorithm())?;
        if alg_set != expected_alg_set {
            return Err(material.invalid("hybrid algorithm set does not match its classical half"));
        }
        Ok(Self::Hybrid {
            classical,
            pq_hex,
            alg_set: expected_alg_set,
        })
    }
}

pub(super) fn public_key_from_hex(wire: &str) -> Result<PublicKey> {
    match Wire::parse(wire, MAX_KEY_WIRE_BYTES, Material::Key)? {
        Wire::Classical(classical) => classical.public_key(),
        Wire::Hybrid {
            classical,
            pq_hex,
            alg_set,
        } => PublicKey::from_hybrid_parts(
            classical.public_key()?,
            &decode_fixed::<ML_DSA_65_PUBLIC_KEY_LEN>(pq_hex, Material::Key)?,
            alg_set,
        ),
    }
}

pub(super) fn signature_from_hex(wire: &str) -> Result<Signature> {
    match Wire::parse(wire, MAX_SIGNATURE_WIRE_BYTES, Material::Signature)? {
        Wire::Classical(classical) => classical.signature(),
        Wire::Hybrid {
            classical,
            pq_hex,
            alg_set,
        } => Signature::from_hybrid_parts(
            classical.signature()?,
            &decode_fixed::<ML_DSA_65_SIGNATURE_LEN>(pq_hex, Material::Signature)?,
            alg_set,
        ),
    }
}

pub(super) fn seed_from_hex(wire: &str) -> Result<[u8; 32]> {
    decode_fixed(strip_hex_prefix(wire), Material::Seed)
}

fn strip_hex_prefix(wire: &str) -> &str {
    wire.strip_prefix("0x").unwrap_or(wire)
}

/// Within the size bound, text that was never hex is a hex error before it is a
/// material error, so callers keep one stable classification for malformed
/// input. Oversized input is rejected by its size alone and is never inspected.
fn reject_non_hex(wire: &str) -> Result<()> {
    if wire.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidHex(
            "crypto hex input contains non-hex characters".to_owned(),
        ));
    }
    Ok(())
}

fn decode_fixed<const N: usize>(wire: &str, material: Material) -> Result<[u8; N]> {
    if wire.len() > 2 * N {
        return Err(material.invalid("crypto hex input exceeds its encoded size limit"));
    }
    reject_non_hex(wire)?;
    if wire.len() != 2 * N {
        return Err(material.invalid("crypto hex input has an incorrect encoded length"));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(wire, &mut bytes).map_err(|error| Error::InvalidHex(error.to_string()))?;
    Ok(bytes)
}

fn decode_bounded(wire: &str, max_bytes: usize, material: Material) -> Result<Vec<u8>> {
    if wire.len() > 2 * max_bytes {
        return Err(material.invalid("crypto hex input exceeds its encoded size limit"));
    }
    reject_non_hex(wire)?;
    hex::decode(wire).map_err(|error| Error::InvalidHex(error.to_string()))
}
