//! The issued token's container: a JWS in compact serialization.
//!
//! RFC 8693 returns the exchanged credential in `access_token` and says nothing
//! about its encoding beyond the token type identifier; with
//! `urn:ietf:params:oauth:token-type:jwt` the credential is a JWT, which is a
//! JWS over the claim set. That is what this module builds and parses: three
//! base64url segments, the signature computed over the ASCII of the first two
//! joined by a dot, exactly as RFC 7515 section 5 defines the signing input.
//!
//! The signature algorithm is Ed25519, registered for JOSE as `EdDSA`. Both
//! sides of the comparison then sign with one implementation, so a latency
//! difference between them is a difference in what they check.

use chio_core_types::crypto::{Keypair, PublicKey, Signature};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoseError {
    /// The token is not three dot-separated segments.
    Segments,
    /// A segment carries a character outside the base64url alphabet, or a
    /// length no base64url encoding produces.
    Alphabet,
    /// The signature segment does not decode to an Ed25519 signature.
    SignatureLength,
}

impl std::fmt::Display for JoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoseError::Segments => write!(f, "a compact JWS has three segments"),
            JoseError::Alphabet => write!(f, "segment is not base64url"),
            JoseError::SignatureLength => write!(f, "signature segment is not 64 bytes"),
        }
    }
}

impl std::error::Error for JoseError {}

pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let packed = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[((packed >> 18) & 63) as usize]));
        encoded.push(char::from(ALPHABET[((packed >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            encoded.push(char::from(ALPHABET[((packed >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[(packed & 63) as usize]));
        }
    }
    encoded
}

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub fn base64url_decode(text: &str) -> Result<Vec<u8>, JoseError> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return Err(JoseError::Alphabet);
        }
        let mut packed = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = sextet(*byte).ok_or(JoseError::Alphabet)?;
            packed |= value << (18 - 6 * index);
        }
        decoded.push(((packed >> 16) & 0xff) as u8);
        if chunk.len() > 2 {
            decoded.push(((packed >> 8) & 0xff) as u8);
        }
        if chunk.len() > 3 {
            decoded.push((packed & 0xff) as u8);
        }
    }
    Ok(decoded)
}

/// A token in compact serialization, split but not yet interpreted.
#[derive(Debug, Clone)]
pub struct CompactJws {
    pub header_segment: String,
    pub payload_segment: String,
    pub signature_segment: String,
}

impl CompactJws {
    pub fn parse(token: &str) -> Result<Self, JoseError> {
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(JoseError::Segments);
        };
        if header.is_empty() || payload.is_empty() || signature.is_empty() {
            return Err(JoseError::Segments);
        }
        Ok(Self {
            header_segment: header.to_string(),
            payload_segment: payload.to_string(),
            signature_segment: signature.to_string(),
        })
    }

    /// The JWS signing input: the two encoded segments joined by a dot.
    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.header_segment, self.payload_segment)
    }

    pub fn header_bytes(&self) -> Result<Vec<u8>, JoseError> {
        base64url_decode(&self.header_segment)
    }

    /// The exact bytes the issuer signed, which is what the receiver parses.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, JoseError> {
        base64url_decode(&self.payload_segment)
    }

    pub fn verify(&self, key: &PublicKey) -> Result<bool, JoseError> {
        let raw = base64url_decode(&self.signature_segment)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| JoseError::SignatureLength)?;
        let signature = Signature::from_bytes(&bytes);
        Ok(key.verify_strict(self.signing_input().as_bytes(), &signature))
    }
}

/// Build a token from a header and a payload already encoded as bytes. The
/// caller passes the exact bytes so a case can transmit a payload that is not
/// the canonical encoding of what it parses to.
pub fn sign_compact(header_json: &[u8], payload_json: &[u8], key: &Keypair) -> String {
    let header_segment = base64url_encode(header_json);
    let payload_segment = base64url_encode(payload_json);
    let signing_input = format!("{header_segment}.{payload_segment}");
    let signature = key.sign(signing_input.as_bytes());
    let signature_segment = base64url_encode(&signature.to_bytes());
    format!("{signing_input}.{signature_segment}")
}
