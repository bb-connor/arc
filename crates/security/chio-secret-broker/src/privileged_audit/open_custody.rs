//! Private Open custody using existing native Serde and direct byte writer.
use super::*;
use crate::proof::RequestProof;
use crate::protocol::{
    BrokerDestination, BrokerRequest, CallerOptions, HeaderField, SignedBrokerCapability,
    MAX_HEADER_VALUE_BYTES,
};
use crate::service::{BoundedZeroizingByteArray, BoundedZeroizingString, SensitiveJsonParser};
use serde::de::{DeserializeOwned, DeserializeSeed, IgnoredAny};
#[path = "open_custody/private_decode.rs"]
mod private_decode;
use private_decode::{
    ByteBound, BytesSeed, ExecuteSeed, PrivateBytes, PrivateExecute, SeedFailure,
};

#[cfg(test)]
std::thread_local! {
    static PRIVATE_BYTE_SERIALIZATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn reset_private_byte_serialization_observer() {
    PRIVATE_BYTE_SERIALIZATIONS.with(|value| value.set(0));
}
#[cfg(test)]
pub(crate) fn private_byte_serialization_observation() -> usize {
    PRIVATE_BYTE_SERIALIZATIONS.with(std::cell::Cell::get)
}

struct PrivateOpen {
    schema: String,
    audit_id: String,
    reference_source: String,
    revocation_authority_domain: String,
    request: PrivateExecute,
    salt: BoundedZeroizingString<MAX_AUDIT_OPEN_FRAME_BYTES>,
    commitment: String,
    head: PrivateBytes<MAX_WIRE_BYTES>,
    body: PrivateBytes<MAX_BODY_BYTES>,
}

impl PrivateOpen {
    fn into_public(self) -> BrokerPrivilegedAuditOpenRequest {
        BrokerPrivilegedAuditOpenRequest {
            schema: self.schema,
            audit_id: self.audit_id,
            reference_source: self.reference_source,
            revocation_authority_domain: self.revocation_authority_domain,
            request: BrokerExecuteRequest {
                schema: self.request.schema,
                invocation_id: self.request.invocation_id,
                capability: self.request.capability,
                proof: self.request.proof,
                request: BrokerRequest {
                    destination: self.request.request.destination,
                    headers: self
                        .request
                        .request
                        .headers
                        .into_iter()
                        .map(|header| HeaderField {
                            name: header.name,
                            value: header.value.into_vec(),
                        })
                        .collect(),
                    body: self.request.request.body.into_vec(),
                    approved_preview_sha256: self.request.request.approved_preview_sha256,
                    options: self.request.request.options,
                },
            },
            reference_commitment_salt: self.salt.into_string(),
            reference_commitment_sha256: self.commitment,
            reference_request_head: self.head.into_vec(),
            reference_request_body: self.body.into_vec(),
        }
    }
}

fn invalid(offset: usize, rule: &'static str) -> BrokerError {
    BrokerError::AuditInput(super::AuditInputError::rule(offset, rule))
}

struct Fields<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Fields<'a> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.position += 1;
        }
    }
    fn delimiter(&mut self, byte: u8) -> Result<()> {
        self.whitespace();
        if self.input.get(self.position) != Some(&byte) {
            return Err(invalid(self.position, "delimiter"));
        }
        self.position += 1;
        Ok(())
    }
    fn typed<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.whitespace();
        let rest = self
            .input
            .get(self.position..)
            .ok_or_else(|| invalid(self.position, "offset"))?;
        let mut values = serde_json::Deserializer::from_slice(rest).into_iter::<T>();
        let value = values
            .next()
            .ok_or_else(|| invalid(self.position, "missing value"))?
            .map_err(|error| {
                BrokerError::UntrustedInput(chio_core_types::canonical::UntrustedJsonError::Decode(
                    error,
                ))
            })?;
        self.position = self
            .position
            .checked_add(values.byte_offset())
            .ok_or_else(|| invalid(self.position, "offset"))?;
        Ok(value)
    }
    fn token(&mut self) -> Result<&'a [u8]> {
        self.whitespace();
        let start = self.position;
        self.typed::<IgnoredAny>()?;
        self.input
            .get(start..self.position)
            .ok_or_else(|| invalid(start, "token range"))
    }
    fn seeded<S: DeserializeSeed<'a>>(&mut self, seed: S) -> Result<S::Value> {
        self.whitespace();
        let rest = self
            .input
            .get(self.position..)
            .ok_or_else(|| invalid(self.position, "offset"))?;
        let mut deserializer = serde_json::Deserializer::from_slice(rest);
        let value = seed.deserialize(&mut deserializer).map_err(|error| {
            BrokerError::UntrustedInput(chio_core_types::canonical::UntrustedJsonError::Decode(
                error,
            ))
        })?;
        // Serde's public seeded interface has no byte-offset accessor. After a
        // successful seed, native IgnoredAny measures the same borrowed token.
        // Failed seeds return first, retaining their real error and live owners.
        self.typed::<IgnoredAny>()?;
        Ok(value)
    }
    fn private_bytes<const MAXIMUM: usize>(&mut self) -> Result<PrivateBytes<MAXIMUM>> {
        let mut failure = None;
        let value = self.seeded(BytesSeed::<MAXIMUM> {
            failure: &mut failure,
            bound: ByteBound::Reference,
        });
        seed_result(value, failure)
    }
    fn request(&mut self) -> Result<PrivateExecute> {
        let mut failure = None;
        let value = self.seeded(ExecuteSeed {
            failure: &mut failure,
        });
        seed_result(value, failure)
    }
    fn salt(&mut self) -> Result<BoundedZeroizingString<MAX_AUDIT_OPEN_FRAME_BYTES>> {
        self.whitespace();
        if self.input.get(self.position) != Some(&b'"') {
            return match self.typed::<String>() {
                Err(error) => Err(error),
                Ok(_) => Err(invalid(self.position, "salt type")),
            };
        }
        // A string token reaches IgnoredAny, whose ignore_str checks syntax
        // without copying its content into the native Serde string scratch.
        let start = self.position;
        let raw = self.token()?;
        validate_salt_scalars(raw, start)?;
        let mut parser = SensitiveJsonParser::new(raw);
        let salt = parser
            .parse_string_with_capacity::<MAX_AUDIT_OPEN_FRAME_BYTES>(raw.len())
            .map_err(|source| match source {
                BrokerError::Storage(_) | BrokerError::Invariant(_) | BrokerError::Custody(_) => {
                    source
                }
                _ => BrokerError::UntrustedInput(
                    chio_core_types::canonical::UntrustedJsonError::NonCanonical,
                ),
            })?;
        parser.finish().map_err(|source| {
            BrokerError::AuditInput(super::AuditInputError::caused_by(
                self.position,
                "salt suffix",
                source,
            ))
        })?;
        Ok(salt)
    }
}

// Native IgnoredAny validates escapes without decoding string content, but
// deliberately permits lone UTF-16 surrogates. Match String's shape rejection
// before the existing canonical parser copies any private salt prefix.
fn validate_salt_scalars(raw: &[u8], start: usize) -> Result<()> {
    let mut position = 1_usize;
    while let Some(byte) = raw.get(position) {
        if *byte != b'\\' {
            position += 1;
            continue;
        }
        if raw.get(position + 1) != Some(&b'u') {
            position += 2;
            continue;
        }
        let scalar = salt_hex(raw.get(position + 2..position + 6))
            .ok_or_else(|| invalid(start + position, "salt unicode escape"))?;
        if (0xdc00..=0xdfff).contains(&scalar) {
            return Err(invalid(start + position, "salt unicode scalar"));
        }
        if (0xd800..=0xdbff).contains(&scalar) {
            let paired = raw.get(position + 6..position + 8) == Some(b"\\u")
                && salt_hex(raw.get(position + 8..position + 12))
                    .is_some_and(|scalar| (0xdc00..=0xdfff).contains(&scalar));
            if !paired {
                return Err(invalid(start + position, "salt unicode scalar"));
            }
            position += 12;
        } else {
            position += 6;
        }
    }
    Ok(())
}
fn salt_hex(digits: Option<&[u8]>) -> Option<u16> {
    digits?.iter().try_fold(0_u16, |word, digit| {
        let digit = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        word.checked_mul(16)?.checked_add(u16::from(digit))
    })
}

fn seed_result<T>(value: Result<T>, failure: Option<SeedFailure>) -> Result<T> {
    match (value, failure) {
        (Err(_), Some(failure)) => Err(failure.into_error()),
        (value, None) => value,
        (Ok(_), Some(_)) => Err(BrokerError::Invariant(
            "privileged audit seed retained an unused cause".to_owned(),
        )),
    }
}

fn parse_open_object(fields: &mut Fields<'_>) -> Result<PrivateOpen> {
    fields.delimiter(b'{')?;
    let (
        mut schema,
        mut audit_id,
        mut reference_source,
        mut domain,
        mut request,
        mut salt,
        mut commitment,
        mut head,
        mut body,
    ) = (None, None, None, None, None, None, None, None, None);
    loop {
        fields.whitespace();
        if fields.input.get(fields.position) == Some(&b'}') {
            fields.position += 1;
            break;
        }
        let key: String = fields.typed()?;
        fields.delimiter(b':')?;
        match key.as_str() {
            "schema" if schema.is_none() => schema = Some(fields.typed()?),
            "auditId" if audit_id.is_none() => audit_id = Some(fields.typed()?),
            "referenceSource" if reference_source.is_none() => {
                reference_source = Some(fields.typed()?)
            }
            "revocationAuthorityDomain" if domain.is_none() => domain = Some(fields.typed()?),
            "request" if request.is_none() => request = Some(fields.request()?),
            "referenceCommitmentSha256" if commitment.is_none() => {
                commitment = Some(fields.typed()?)
            }
            "referenceRequestHead" if head.is_none() => {
                head = Some(fields.private_bytes::<MAX_WIRE_BYTES>()?)
            }
            "referenceRequestBody" if body.is_none() => {
                body = Some(fields.private_bytes::<MAX_BODY_BYTES>()?)
            }
            "referenceCommitmentSalt" if salt.is_none() => salt = Some(fields.salt()?),
            "schema"
            | "auditId"
            | "referenceSource"
            | "revocationAuthorityDomain"
            | "request"
            | "referenceCommitmentSha256"
            | "referenceRequestHead"
            | "referenceRequestBody"
            | "referenceCommitmentSalt" => return Err(invalid(fields.position, "duplicate field")),
            _ => return Err(invalid(fields.position, "unknown field")),
        }
        fields.whitespace();
        match fields.input.get(fields.position) {
            Some(b',') => {
                fields.position += 1;
                fields.whitespace();
                if fields.input.get(fields.position) == Some(&b'}') {
                    return Err(invalid(fields.position, "trailing comma"));
                }
            }
            Some(b'}') => {
                fields.position += 1;
                break;
            }
            _ => return Err(invalid(fields.position, "object separator")),
        }
    }
    Ok(PrivateOpen {
        schema: schema.ok_or_else(|| invalid(fields.position, "missing schema"))?,
        audit_id: audit_id.ok_or_else(|| invalid(fields.position, "missing auditId"))?,
        reference_source: reference_source
            .ok_or_else(|| invalid(fields.position, "missing referenceSource"))?,
        revocation_authority_domain: domain
            .ok_or_else(|| invalid(fields.position, "missing domain"))?,
        request: request.ok_or_else(|| invalid(fields.position, "missing request"))?,
        salt: salt.ok_or_else(|| invalid(fields.position, "missing salt"))?,
        commitment: commitment.ok_or_else(|| invalid(fields.position, "missing commitment"))?,
        head: head.ok_or_else(|| invalid(fields.position, "missing head"))?,
        body: body.ok_or_else(|| invalid(fields.position, "missing body"))?,
    })
}

fn parse_open_sequence(fields: &mut Fields<'_>) -> Result<PrivateOpen> {
    fields.delimiter(b'[')?;
    let schema = fields.typed()?;
    fields.delimiter(b',')?;
    let audit_id = fields.typed()?;
    fields.delimiter(b',')?;
    let reference_source = fields.typed()?;
    fields.delimiter(b',')?;
    let revocation_authority_domain = fields.typed()?;
    fields.delimiter(b',')?;
    let request = fields.request()?;
    fields.delimiter(b',')?;
    let salt = fields.salt()?;
    fields.delimiter(b',')?;
    let commitment = fields.typed()?;
    fields.delimiter(b',')?;
    let head = fields.private_bytes::<MAX_WIRE_BYTES>()?;
    fields.delimiter(b',')?;
    let body = fields.private_bytes::<MAX_BODY_BYTES>()?;
    fields.delimiter(b']')?;
    Ok(PrivateOpen {
        schema,
        audit_id,
        reference_source,
        revocation_authority_domain,
        request,
        salt,
        commitment,
        head,
        body,
    })
}

pub(crate) fn decode_open_wire(input: &[u8]) -> Result<BrokerPrivilegedAuditOpenRequest> {
    chio_core_types::canonical::UntrustedJsonText::from_wire(input, MAX_AUDIT_OPEN_FRAME_BYTES)
        .map_err(BrokerError::UntrustedInput)?;
    let mut fields = Fields { input, position: 0 };
    fields.whitespace();
    let value = match fields.input.get(fields.position) {
        Some(b'[') => parse_open_sequence(&mut fields)?,
        Some(b'{') => parse_open_object(&mut fields)?,
        _ => return Err(invalid(fields.position, "open request type")),
    };
    fields.whitespace();
    if fields.position != input.len() {
        return Err(invalid(fields.position, "trailing data"));
    }
    let canonical = encode_private_open(&value)?;
    if canonical.as_slice() != input {
        return Err(BrokerError::UntrustedInput(
            chio_core_types::canonical::UntrustedJsonError::NonCanonical,
        ));
    }
    Ok(value.into_public())
}

use crate::private_request_wire::{OpenRef, RequestRef};

fn encode_private_open(open: &PrivateOpen) -> Result<Zeroizing<Vec<u8>>> {
    let request = &open.request;
    crate::private_request_wire::canonical_open_bytes(
        OpenRef {
            schema: &open.schema,
            audit_id: &open.audit_id,
            source: &open.reference_source,
            domain: &open.revocation_authority_domain,
            salt: open.salt.as_str(),
            commitment: &open.commitment,
            head: open.head.as_slice(),
            body: open.body.as_slice(),
            request: RequestRef {
                schema: &request.schema,
                invocation: &request.invocation_id,
                capability: &request.capability,
                proof: &request.proof,
                destination: &request.request.destination,
                options: &request.request.options,
                body: request.request.body.as_slice(),
                preview: &request.request.approved_preview_sha256,
                headers: request
                    .request
                    .headers
                    .iter()
                    .map(|header| (header.name.as_str(), header.value.as_slice()))
                    .collect(),
            },
        },
        MAX_AUDIT_OPEN_FRAME_BYTES,
    )
}

pub(crate) fn encode_open_wire(
    open: &BrokerPrivilegedAuditOpenRequest,
) -> Result<Zeroizing<Vec<u8>>> {
    let request = &open.request;
    crate::private_request_wire::canonical_open_bytes(
        OpenRef {
            schema: &open.schema,
            audit_id: &open.audit_id,
            source: &open.reference_source,
            domain: &open.revocation_authority_domain,
            salt: &open.reference_commitment_salt,
            commitment: &open.reference_commitment_sha256,
            head: &open.reference_request_head,
            body: &open.reference_request_body,
            request: RequestRef {
                schema: &request.schema,
                invocation: &request.invocation_id,
                capability: &request.capability,
                proof: &request.proof,
                destination: &request.request.destination,
                options: &request.request.options,
                body: &request.request.body,
                preview: &request.request.approved_preview_sha256,
                headers: request
                    .request
                    .headers
                    .iter()
                    .map(|header| (header.name.as_str(), header.value.as_slice()))
                    .collect(),
            },
        },
        MAX_AUDIT_OPEN_FRAME_BYTES,
    )
}
