//! Return authorities cannot substitute disclosure signatures for endorsement.
use super::authority::{invalid, signed_authority};
use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, Keypair, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};
use alloc::vec::Vec;
use chio_security_types::confinement::*;
use serde::{Deserialize, Serialize};

pub const CONFINED_DISCLOSURE_SIGNATURE_DOMAIN: &str = "chio:confined-disclosure:v1";
pub const CONFINED_ENDORSEMENT_SIGNATURE_DOMAIN: &str = "chio:confined-endorsement:v1";
/// Hash the complete signed confined capability under its own domain.
/// This identity cannot be substituted for a capability body digest.
///
/// ```compile_fail
/// use chio_core_types::capability::token::CapabilityToken;
/// use chio_core_types::recovery::confined_capability_digest;
/// use chio_security_types::recovery::CapabilityBodyDigest;
/// fn require_body(_: CapabilityBodyDigest) {}
/// fn confuse_domains(cap: &CapabilityToken) -> chio_core_types::Result<()> {
///     require_body(confined_capability_digest(cap)?);
///     Ok(())
/// }
/// ```
pub fn confined_capability_digest(
    cap: &crate::capability::token::CapabilityToken,
) -> Result<chio_security_types::recovery::ConfinedCapabilityDigest> {
    super::knowledge_digest(super::RecoveryDigestDomain::ConfinedCapability, cap)
        .map(chio_security_types::recovery::ConfinedCapabilityDigest::from_bytes)
}
/// Cage measurements use lowercase SHA-256 hex; portable contracts use Digest32.
/// A measured executable or configuration is not canonical payload identity.
///
/// ```compile_fail
/// use chio_core_types::recovery::parse_cage_digest;
/// use chio_security_types::recovery::CanonicalPayloadDigest;
/// fn require_payload(_: CanonicalPayloadDigest) {}
/// fn confuse_domains() -> chio_core_types::Result<()> {
///     require_payload(parse_cage_digest(
///         "0000000000000000000000000000000000000000000000000000000000000000",
///     )?);
///     Ok(())
/// }
/// ```
pub fn parse_cage_digest(
    value: &str,
) -> Result<chio_security_types::recovery::CageMeasurementDigest> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let bytes = hex::decode(value).map_err(|_| invalid())?;
    Ok(
        chio_security_types::recovery::CageMeasurementDigest::from_bytes(
            bytes.try_into().map_err(|_| invalid())?,
        ),
    )
}
signed_authority!(
    SignedConfinedDisclosureV1,
    ConfinedReturnEvidenceV1,
    CONFINED_DISCLOSURE_SIGNATURE_DOMAIN,
    |b: &ConfinedReturnEvidenceV1| b.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedConfinedEndorsementV1,
    ConfinedReturnEvidenceV1,
    CONFINED_ENDORSEMENT_SIGNATURE_DOMAIN,
    |b: &ConfinedReturnEvidenceV1| b.validate().map_err(|_| invalid())
);

pub fn isolation_boundary_digest(
    boundary: &IsolationBoundaryV1,
) -> Result<chio_security_types::recovery::CanonicalPayloadDigest> {
    boundary.validate().map_err(|_| invalid())?;
    super::knowledge_digest(super::RecoveryDigestDomain::IsolationBoundary, boundary)
        .map(chio_security_types::recovery::CanonicalPayloadDigest::from_bytes)
}

/// Exact canonical boolean projection, independently recomputed by the host.
pub fn project_confined_boolean(input: &[u8], field: &str) -> Result<Vec<u8>> {
    if input.len() > MAX_CONFINED_INPUT_BYTES as usize {
        return Err(invalid());
    }
    let value: serde_json::Value = serde_json::from_slice(input).map_err(|_| invalid())?;
    if canonical_json_bytes(&value)?.as_slice() != input {
        return Err(invalid());
    }
    let boolean = value
        .as_object()
        .and_then(|v| v.get(field))
        .and_then(|v| v.as_bool())
        .ok_or_else(invalid)?;
    canonical_json_bytes(&boolean)
}

pub fn encode_confined_input(
    field: &str,
    observation: &[u8],
    seeds: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if field.is_empty() || field.len() > 128 || seeds.len() > 8 {
        return Err(invalid());
    }
    let mut out = Vec::from(b"CHIOCF1\0".as_slice());
    append_frame(&mut out, field.as_bytes())?;
    append_frame(&mut out, observation)?;
    out.extend_from_slice(&(seeds.len() as u32).to_be_bytes());
    for seed in seeds {
        append_frame(&mut out, seed)?;
    }
    if out.len() > MAX_CONFINED_INPUT_BYTES as usize {
        return Err(invalid());
    }
    Ok(out)
}
fn append_frame(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if out.len().saturating_add(value.len()).saturating_add(4) > MAX_CONFINED_INPUT_BYTES as usize {
        return Err(invalid());
    }
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}
/// Bounded views borrow the private packet, avoiding another observation copy.
pub struct DecodedConfinedInput<'a> {
    pub field: &'a str,
    pub observation: &'a [u8],
    pub seeds: Vec<&'a [u8]>,
}
impl core::fmt::Debug for DecodedConfinedInput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DecodedConfinedInput([redacted])")
    }
}
pub fn decode_confined_input(mut bytes: &[u8]) -> Result<DecodedConfinedInput<'_>> {
    if bytes.len() > MAX_CONFINED_INPUT_BYTES as usize || !bytes.starts_with(b"CHIOCF1\0") {
        return Err(invalid());
    }
    bytes = &bytes[8..];
    let field = core::str::from_utf8(take_frame(&mut bytes)?).map_err(|_| invalid())?;
    if field.is_empty() || field.len() > 128 {
        return Err(invalid());
    }
    let observation = take_frame(&mut bytes)?;
    let n = take_u32(&mut bytes)? as usize;
    if n > 8 {
        return Err(invalid());
    }
    let mut seeds = Vec::with_capacity(n);
    for _ in 0..n {
        seeds.push(take_frame(&mut bytes)?);
    }
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(DecodedConfinedInput {
        field,
        observation,
        seeds,
    })
}
fn take_u32(bytes: &mut &[u8]) -> Result<u32> {
    let prefix = bytes.get(..4).ok_or_else(invalid)?;
    let number = u32::from_be_bytes(prefix.try_into().map_err(|_| invalid())?);
    *bytes = &bytes[4..];
    Ok(number)
}
fn take_frame<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = take_u32(bytes)? as usize;
    let value = bytes.get(..n).ok_or_else(invalid)?;
    *bytes = &bytes[n..];
    Ok(value)
}
