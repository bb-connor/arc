use super::*;

/// What the co-signing side knows about itself and its peer before it agrees
/// to sign a DSSE preimage: the two kernel ids of the exchange and the two
/// passport keys the statement must name.
#[derive(Debug, Clone, Copy)]
pub struct DssePreimageBinding<'a> {
    /// The co-signing (origin) kernel's own id.
    pub org_a_kernel_id: &'a str,
    /// The co-signing kernel's own passport key.
    pub org_a_public_key: &'a PublicKey,
    /// The requesting (tool-host) kernel's id, as authenticated by the caller.
    pub org_b_kernel_id: &'a str,
    /// The requesting kernel's passport key, as resolved by the caller.
    pub org_b_public_key: &'a PublicKey,
}

/// Rebuild the DSSE pre-authentication encoding a peer asked to have signed
/// from the content those bytes carry, and refuse anything that does not
/// rebuild byte-for-byte.
///
/// A kernel's co-signing key also signs receipts and canonical
/// [`crate::bilateral::CoSigningBody`] preimages, and the three families are
/// separated by structure alone. Signing unparsed bytes therefore turns this
/// endpoint into an oracle for the other two: the caller can present the
/// canonical receipt signing preimage of a receipt it invented, attributed to
/// the co-signing kernel, and the reply is that kernel's signature over it.
///
/// The reconstruction is exact. The bytes must frame as DSSE v1 PAE under the
/// in-toto payload type, the payload must be canonical JSON of a
/// [`DsseStatement`] carrying one of the two bilateral predicate types, and
/// re-encoding that statement and re-applying [`pae`] must reproduce the
/// presented bytes. The statement must also name this kernel, with this
/// kernel's passport key, as `tool_server_a`, and the requesting peer with its
/// directory-bound passport key as `tool_server_b`.
///
/// # Errors
///
/// Fails closed on any framing, encoding, type or identity disagreement.
pub fn reconstruct_dsse_pae(
    signed_bytes: &[u8],
    binding: DssePreimageBinding<'_>,
) -> Result<DsseStatement, BilateralCoSigningError> {
    let (payload_type, payload) = split_pae(signed_bytes)?;
    if payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: payloadType {payload_type:?} is not {PAYLOAD_TYPE_IN_TOTO:?}"
        )));
    }
    let statement: DsseStatement = serde_json::from_slice(payload)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("statement.malformed: {e}")))?;
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.schema_invalid: _type {:?} is not {STATEMENT_TYPE_V1:?}",
            statement.statement_type
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL
        && statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
    {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.type_unrecognised: {:?}",
            statement.predicate_type
        )));
    }
    let server_a = &statement.predicate.tool_server_a;
    let server_b = &statement.predicate.tool_server_b;
    if server_a.kernel_id != binding.org_a_kernel_id
        || server_b.kernel_id != binding.org_b_kernel_id
        || server_a.passport_key_fingerprint != Keyid::from_public_key(binding.org_a_public_key)
        || server_b.passport_key_fingerprint != Keyid::from_public_key(binding.org_b_public_key)
    {
        return Err(BilateralCoSigningError::PeerIdentityMismatch);
    }
    if pae(&payload_type, &statement.canonical_bytes()?) != signed_bytes {
        return Err(BilateralCoSigningError::CanonicalJson(
            "statement.malformed: the payload is not the canonical encoding of the statement it \
             decodes to"
                .to_string(),
        ));
    }
    Ok(statement)
}

/// Split DSSE v1 PAE bytes back into `(payloadType, payload)`.
///
/// The framing is `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` with
/// decimal ASCII lengths. Every length must be present, in range, and consume
/// the buffer exactly; a trailing byte is a refusal, not a truncation.
fn split_pae(bytes: &[u8]) -> Result<(String, &[u8]), BilateralCoSigningError> {
    let rest = bytes
        .strip_prefix(PAE_PREFIX.as_bytes())
        .and_then(|rest| rest.strip_prefix(b" "))
        .ok_or_else(|| {
            BilateralCoSigningError::CanonicalJson(
                "dsse.malformed: the bytes do not carry the DSSE pre-authentication prefix"
                    .to_string(),
            )
        })?;
    let (type_len, rest) = take_length(rest)?;
    if rest.len() < type_len {
        return Err(malformed_pae("payloadType runs past the end of the bytes"));
    }
    let (type_bytes, rest) = rest.split_at(type_len);
    let payload_type = core::str::from_utf8(type_bytes)
        .map_err(|_| malformed_pae("payloadType is not UTF-8"))?
        .to_string();
    let rest = rest
        .strip_prefix(b" ")
        .ok_or_else(|| malformed_pae("payloadType is not followed by a separator"))?;
    let (payload_len, payload) = take_length(rest)?;
    if payload.len() != payload_len {
        return Err(malformed_pae(
            "the declared payload length does not span the remaining bytes exactly",
        ));
    }
    Ok((payload_type, payload))
}

/// Read one decimal ASCII length and the single separator that closes it.
fn take_length(bytes: &[u8]) -> Result<(usize, &[u8]), BilateralCoSigningError> {
    let separator = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| malformed_pae("a length field is not terminated"))?;
    let digits = core::str::from_utf8(&bytes[..separator])
        .map_err(|_| malformed_pae("a length field is not UTF-8"))?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed_pae("a length field is not decimal ASCII"));
    }
    let length: usize = digits
        .parse()
        .map_err(|_| malformed_pae("a length field does not fit this platform"))?;
    Ok((length, &bytes[separator + 1..]))
}

fn malformed_pae(detail: &str) -> BilateralCoSigningError {
    BilateralCoSigningError::CanonicalJson(format!("dsse.malformed: {detail}"))
}
