//! The `chio.receipt-disclosure.v1` document and the commitment opener.
//!
//! A disclosure is unsigned and self-verifying: each opening carries the salt of one
//! commitment, and a verifier recomputes the commitment over its own copy of the preimage.
//! The commitment domain comes from the commitment's position in the receipt, never from the
//! opening.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use super::commitment::{
    CommitmentDomain, ContentPreimage, ReceiptCommitment, Salt, CONTENT_SALT_REF, PARAMS_SALT_REF,
    SALT_LEN,
};
use crate::canonical::canonical_json_bytes;
use crate::root_authority::SaltRef;

pub const CHIO_RECEIPT_DISCLOSURE_SCHEMA: &str = "chio.receipt-disclosure.v1";
pub const MAX_DISCLOSURE_OPENINGS: usize = 64;

const SALT_WIRE_PREFIX: &str = "b64u:";
const SALT_WIRE_CHARS: usize = 43;
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn sextet(character: u8) -> Option<u8> {
    match character {
        b'A'..=b'Z' => Some(character - b'A'),
        b'a'..=b'z' => Some(character - b'a' + 26),
        b'0'..=b'9' => Some(character - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn base64url_char(index: u32) -> char {
    usize::try_from(index & 0x3f)
        .ok()
        .and_then(|index| BASE64URL.get(index))
        .map_or('A', |byte| char::from(*byte))
}

impl Salt {
    /// `b64u:` followed by the canonical unpadded base64url form of the 32 bytes.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let mut text = String::with_capacity(SALT_WIRE_PREFIX.len() + SALT_WIRE_CHARS);
        text.push_str(SALT_WIRE_PREFIX);
        let mut bits = 0_u32;
        let mut width = 0_u32;
        for byte in self.as_bytes() {
            bits = (bits << 8) | u32::from(*byte);
            width += 8;
            while width >= 6 {
                width -= 6;
                text.push(base64url_char(bits >> width));
            }
            bits &= (1 << width) - 1;
        }
        if width > 0 {
            text.push(base64url_char(bits << (6 - width)));
        }
        text
    }

    /// Decodes the canonical wire form only: no padding, exactly 43 characters and zero
    /// trailing bits, so exactly one string decodes to each salt.
    pub fn from_wire(text: &str) -> Result<Self, SaltWireError> {
        let encoded = text
            .strip_prefix(SALT_WIRE_PREFIX)
            .ok_or(SaltWireError)?
            .as_bytes();
        if encoded.len() != SALT_WIRE_CHARS {
            return Err(SaltWireError);
        }
        let mut bytes = [0_u8; SALT_LEN];
        let mut filled = 0;
        let mut bits = 0_u32;
        let mut width = 0_u32;
        for character in encoded {
            bits = ((bits << 6) | u32::from(sextet(*character).ok_or(SaltWireError)?)) & 0xfff;
            width += 6;
            if width >= 8 {
                width -= 8;
                let slot = bytes.get_mut(filled).ok_or(SaltWireError)?;
                *slot = u8::try_from((bits >> width) & 0xff).map_err(|_| SaltWireError)?;
                filled += 1;
            }
        }
        if filled != SALT_LEN || bits & ((1 << width) - 1) != 0 {
            return Err(SaltWireError);
        }
        Ok(Self::from_bytes(bytes))
    }
}

impl Serialize for Salt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for Salt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_wire(&text).map_err(de::Error::custom)
    }
}

/// A salt string that is not the canonical `b64u:` form of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaltWireError;

impl fmt::Display for SaltWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("salt is not the canonical b64u form of 32 bytes")
    }
}

impl core::error::Error for SaltWireError {}

/// The closed `schema` member of a disclosure document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureSchema {
    V1,
}

impl Serialize for DisclosureSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(CHIO_RECEIPT_DISCLOSURE_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for DisclosureSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == CHIO_RECEIPT_DISCLOSURE_SCHEMA {
            Ok(Self::V1)
        } else {
            Err(de::Error::custom(
                "schema is not chio.receipt-disclosure.v1",
            ))
        }
    }
}

/// One opening. `payload` is opaque to the opener; `None` is a salt-only opening and
/// serializes as `null`. The member is required on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub salt_ref: SaltRef,
    pub salt: Salt,
    #[serde(deserialize_with = "required_nullable")]
    pub payload: Option<serde_json::Value>,
}

fn required_nullable<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    Option::<serde_json::Value>::deserialize(deserializer)
}

/// `chio.receipt-disclosure.v1`, unsigned. `receipt_id` is bare lowercase hex.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReceiptDisclosure {
    pub schema: DisclosureSchema,
    pub receipt_id: String,
    pub openings: Vec<Opening>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptDisclosureWire {
    schema: DisclosureSchema,
    receipt_id: String,
    openings: Vec<Opening>,
}

impl<'de> Deserialize<'de> for ReceiptDisclosure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ReceiptDisclosureWire::deserialize(deserializer)?;
        let bare_hex = wire.receipt_id.len() == 64
            && wire
                .receipt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !bare_hex {
            return Err(de::Error::custom(
                "receipt_id is not 64 lowercase hex characters",
            ));
        }
        if wire.openings.is_empty() || wire.openings.len() > MAX_DISCLOSURE_OPENINGS {
            return Err(de::Error::custom("openings must hold 1 to 64 entries"));
        }
        Ok(Self {
            schema: wire.schema,
            receipt_id: wire.receipt_id,
            openings: wire.openings,
        })
    }
}

/// The verdict for one committed field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldVerdict {
    Verified,
    Rejected,
    Unverifiable,
}

/// `disclosure_valid` is false exactly when the document is tampered disclosure: a structural
/// fault or any field `Rejected`. A reader accepts a disclosure only when it is true. An absent
/// opening or an absent own preimage leaves its field `Unverifiable`. The report covers only
/// the parameter and content commitments: the delegation-context anchor commitments
/// (`anchor_subject`, `anchor_tenant`) are outside it, and a disclosure that opens them is
/// accepted only after they are judged separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningReport {
    pub parameters: FieldVerdict,
    pub content: FieldVerdict,
    pub disclosure_valid: bool,
}

fn structurally_valid(receipt_id: &str, disclosure: &ReceiptDisclosure) -> bool {
    if disclosure.receipt_id != receipt_id {
        return false;
    }
    let openings = &disclosure.openings;
    for (index, opening) in openings.iter().enumerate() {
        for other in openings.iter().skip(index + 1) {
            if opening.salt_ref.as_str() == other.salt_ref.as_str() || opening.salt == other.salt {
                return false;
            }
        }
    }
    true
}

fn open_field(
    disclosure: &ReceiptDisclosure,
    commitment: &ReceiptCommitment,
    position: &str,
    domain: CommitmentDomain<'_>,
    preimage: Option<crate::Result<Vec<u8>>>,
) -> FieldVerdict {
    if commitment.salt_ref.as_str() != position {
        return FieldVerdict::Rejected;
    }
    let Some(opening) = disclosure
        .openings
        .iter()
        .find(|opening| opening.salt_ref.as_str() == position)
    else {
        return FieldVerdict::Unverifiable;
    };
    match preimage {
        None => FieldVerdict::Unverifiable,
        Some(Err(_)) => FieldVerdict::Rejected,
        Some(Ok(bytes)) if commitment.opens_to(domain, &opening.salt, &bytes) => {
            FieldVerdict::Verified
        }
        Some(Ok(_)) => FieldVerdict::Rejected,
    }
}

/// Opens a receipt's parameter and content commitments with `disclosure` over the caller's own
/// arguments and output; `payload` never supplies a preimage. A document for another receipt,
/// a duplicate `salt_ref` or a salt shared by two openings marks every field `Rejected` and the
/// disclosure invalid. A commitment that does not recompute, or one found in the other
/// commitment's position, marks that field `Rejected` and the disclosure invalid; the other
/// field keeps its own verdict.
#[must_use]
pub fn open_commitments(
    receipt_id: &str,
    parameter_commitment: &ReceiptCommitment,
    content_commitment: &ReceiptCommitment,
    disclosure: &ReceiptDisclosure,
    own_parameters: Option<&serde_json::Value>,
    own_output: Option<ContentPreimage<'_>>,
) -> OpeningReport {
    if !structurally_valid(receipt_id, disclosure) {
        return OpeningReport {
            parameters: FieldVerdict::Rejected,
            content: FieldVerdict::Rejected,
            disclosure_valid: false,
        };
    }
    let parameters = open_field(
        disclosure,
        parameter_commitment,
        PARAMS_SALT_REF,
        CommitmentDomain::Parameters,
        own_parameters.map(canonical_json_bytes),
    );
    let content = open_field(
        disclosure,
        content_commitment,
        CONTENT_SALT_REF,
        CommitmentDomain::Content,
        own_output.map(|output| output.to_bytes()),
    );
    OpeningReport {
        parameters,
        content,
        disclosure_valid: parameters != FieldVerdict::Rejected && content != FieldVerdict::Rejected,
    }
}
