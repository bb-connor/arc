//! Compact JWS parsing and signature verification against pinned JWKs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core::crypto::{PublicKey, Signature as ChioSignature};
use chio_core::root_authority::{
    Identifier, Jwk, JwkCurve, JwkKeyType, JwsAlgorithm, Sha256Digest,
};
use chio_core::sha256;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use rsa::pkcs1v15::{Signature as Pkcs1v15Signature, VerifyingKey as Pkcs1v15VerifyingKey};
use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPublicKey};
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};

use super::error::RootExchangeError;

/// Upper bound on a compact JWS and on each decoded JSON part.
pub const MAX_JWS_BYTES: usize = 16 * 1024;

/// Smallest admitted RSA modulus.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

const FORBIDDEN_HEADER_MEMBERS: [&str; 5] = ["jku", "x5u", "jwk", "x5c", "crit"];

/// The protected header members the exchange reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsHeader {
    pub alg: JwsAlgorithm,
    pub kid: Identifier,
    pub typ: Option<String>,
}

/// A parsed compact JWS whose signature is not yet verified.
#[derive(Debug, Clone)]
pub struct CompactJws {
    pub header: JwsHeader,
    pub claims: Map<String, Value>,
    signing_input: String,
    signature: Vec<u8>,
    /// SHA-256 of the exact compact bytes received.
    pub artifact_digest: Sha256Digest,
}

fn decode_part(part: &str, what: &'static str) -> Result<Map<String, Value>, RootExchangeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| RootExchangeError::MalformedJws(what))?;
    let value: Value = crate::input::decode(&bytes, MAX_JWS_BYTES)
        .map_err(|_| RootExchangeError::MalformedJws(what))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(RootExchangeError::MalformedJws(what)),
    }
}

impl CompactJws {
    /// Parse `token`, refusing key-location and `crit` header members and
    /// any `alg` outside the asymmetric set.
    pub fn parse(token: &str) -> Result<Self, RootExchangeError> {
        if token.len() > MAX_JWS_BYTES {
            return Err(RootExchangeError::MalformedJws(
                "token exceeds the size bound",
            ));
        }
        let mut parts = token.split('.');
        let (Some(header_part), Some(payload_part), Some(signature_part), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(RootExchangeError::MalformedJws("token is not three parts"));
        };
        let header = decode_part(header_part, "header")?;
        for member in FORBIDDEN_HEADER_MEMBERS {
            if header.contains_key(member) {
                return Err(RootExchangeError::ForbiddenHeaderMember(member));
            }
        }
        let alg = header
            .get("alg")
            .cloned()
            .and_then(|alg| serde_json::from_value::<JwsAlgorithm>(alg).ok())
            .ok_or(RootExchangeError::AlgorithmNotAdmitted)?;
        let kid = match header.get("kid") {
            Some(Value::String(kid)) => Identifier::new(kid.as_str())
                .map_err(|_| RootExchangeError::MalformedJws("kid is not an identifier"))?,
            Some(_) => return Err(RootExchangeError::MalformedJws("kid is not an identifier")),
            None => return Err(RootExchangeError::KidMissing),
        };
        let typ = match header.get("typ") {
            Some(Value::String(typ)) => Some(typ.clone()),
            Some(_) => return Err(RootExchangeError::MalformedJws("typ is not a string")),
            None => None,
        };
        let claims = decode_part(payload_part, "payload")?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| RootExchangeError::MalformedJws("signature"))?;
        Ok(Self {
            header: JwsHeader { alg, kid, typ },
            claims,
            signing_input: format!("{header_part}.{payload_part}"),
            signature,
            artifact_digest: Sha256Digest::from_hash(sha256(token.as_bytes())),
        })
    }

    /// Verify the signature with `key`, which must admit the header `alg`.
    pub fn verify_with(&self, key: &VerifyingKey) -> Result<(), RootExchangeError> {
        if !key.admits(self.header.alg) {
            return Err(RootExchangeError::KeyAlgorithmMismatch);
        }
        if key.verify(
            self.header.alg,
            self.signing_input.as_bytes(),
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(RootExchangeError::SignatureInvalid)
        }
    }
}

#[derive(Debug, Clone)]
enum KeyMaterial {
    Rsa(RsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
    Ed25519(PublicKey),
}

/// A JWK decoded into verification material.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    material: KeyMaterial,
    alg: Option<JwsAlgorithm>,
}

fn component(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).ok()
}

fn fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    component(value)?.try_into().ok()
}

impl VerifyingKey {
    /// Decode `jwk`. `None` when the key is unusable: an unsupported curve,
    /// undecodable material or an RSA modulus under 2048 bits.
    #[must_use]
    pub fn from_jwk(jwk: &Jwk) -> Option<Self> {
        let material = match (jwk.kty, jwk.crv) {
            (JwkKeyType::Rsa, None) => {
                let n = BigUint::from_bytes_be(&component(jwk.n.as_ref()?.as_str())?);
                let e = BigUint::from_bytes_be(&component(jwk.e.as_ref()?.as_str())?);
                let key = RsaPublicKey::new(n, e).ok()?;
                if key.n().bits() < MIN_RSA_MODULUS_BITS {
                    return None;
                }
                KeyMaterial::Rsa(key)
            }
            (JwkKeyType::Ec, Some(JwkCurve::P256)) => {
                let point = sec1_point::<32, 65>(jwk)?;
                KeyMaterial::P256(P256VerifyingKey::from_sec1_bytes(&point).ok()?)
            }
            (JwkKeyType::Ec, Some(JwkCurve::P384)) => {
                let point = sec1_point::<48, 97>(jwk)?;
                KeyMaterial::P384(P384VerifyingKey::from_sec1_bytes(&point).ok()?)
            }
            (JwkKeyType::Okp, Some(JwkCurve::Ed25519)) => {
                let x = fixed::<32>(jwk.x.as_ref()?.as_str())?;
                KeyMaterial::Ed25519(PublicKey::from_bytes(&x).ok()?)
            }
            _ => return None,
        };
        Some(Self {
            material,
            alg: jwk.alg,
        })
    }

    /// Whether this key verifies `alg`, honouring the JWK's own `alg`.
    #[must_use]
    pub fn admits(&self, alg: JwsAlgorithm) -> bool {
        if self.alg.is_some_and(|pinned| pinned != alg) {
            return false;
        }
        matches!(
            (&self.material, alg),
            (
                KeyMaterial::Rsa(_),
                JwsAlgorithm::RS256
                    | JwsAlgorithm::RS384
                    | JwsAlgorithm::RS512
                    | JwsAlgorithm::PS256
                    | JwsAlgorithm::PS384
                    | JwsAlgorithm::PS512
            ) | (KeyMaterial::P256(_), JwsAlgorithm::ES256)
                | (KeyMaterial::P384(_), JwsAlgorithm::ES384)
                | (KeyMaterial::Ed25519(_), JwsAlgorithm::EdDSA)
        )
    }

    fn verify(&self, alg: JwsAlgorithm, input: &[u8], signature: &[u8]) -> bool {
        match (&self.material, alg) {
            (KeyMaterial::Rsa(key), JwsAlgorithm::RS256) => {
                pkcs1v15::<Sha256>(key, input, signature)
            }
            (KeyMaterial::Rsa(key), JwsAlgorithm::RS384) => {
                pkcs1v15::<Sha384>(key, input, signature)
            }
            (KeyMaterial::Rsa(key), JwsAlgorithm::RS512) => {
                pkcs1v15::<Sha512>(key, input, signature)
            }
            (KeyMaterial::Rsa(key), JwsAlgorithm::PS256) => pss::<Sha256>(key, input, signature),
            (KeyMaterial::Rsa(key), JwsAlgorithm::PS384) => pss::<Sha384>(key, input, signature),
            (KeyMaterial::Rsa(key), JwsAlgorithm::PS512) => pss::<Sha512>(key, input, signature),
            (KeyMaterial::P256(key), JwsAlgorithm::ES256) => P256Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(input, &signature).is_ok()),
            (KeyMaterial::P384(key), JwsAlgorithm::ES384) => P384Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(input, &signature).is_ok()),
            (KeyMaterial::Ed25519(key), JwsAlgorithm::EdDSA) => <[u8; 64]>::try_from(signature)
                .is_ok_and(|bytes| key.verify_strict(input, &ChioSignature::from_bytes(&bytes))),
            _ => false,
        }
    }
}

fn sec1_point<const COORD: usize, const POINT: usize>(jwk: &Jwk) -> Option<[u8; POINT]> {
    let x = fixed::<COORD>(jwk.x.as_ref()?.as_str())?;
    let y = fixed::<COORD>(jwk.y.as_ref()?.as_str())?;
    let mut point = [0_u8; POINT];
    let (tag, coordinates) = point.split_first_mut()?;
    *tag = 0x04;
    let (x_out, y_out) = coordinates.split_at_mut(COORD);
    x_out.copy_from_slice(&x);
    y_out.copy_from_slice(&y);
    Some(point)
}

fn pkcs1v15<D>(key: &RsaPublicKey, input: &[u8], signature: &[u8]) -> bool
where
    D: sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    Pkcs1v15Signature::try_from(signature).is_ok_and(|signature| {
        Pkcs1v15VerifyingKey::<D>::new(key.clone())
            .verify(input, &signature)
            .is_ok()
    })
}

fn pss<D>(key: &RsaPublicKey, input: &[u8], signature: &[u8]) -> bool
where
    D: sha2::Digest + sha2::digest::FixedOutputReset,
{
    PssSignature::try_from(signature).is_ok_and(|signature| {
        PssVerifyingKey::<D>::new(key.clone())
            .verify(input, &signature)
            .is_ok()
    })
}
