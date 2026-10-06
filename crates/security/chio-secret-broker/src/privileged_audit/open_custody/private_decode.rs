//! Audit-only owned Serde seeds for the fixed request wire schemas.
use super::*;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use std::fmt;

#[derive(Clone, Copy)]
pub(super) enum ByteBound {
    Reference,
    Request,
    HeaderValue,
}

pub(super) enum SeedFailure {
    Cause(BrokerError),
    Bound(ByteBound),
}

impl SeedFailure {
    fn record<E: serde::de::Error>(self, slot: &mut Option<Self>) -> E {
        *slot = Some(self);
        E::custom("privileged audit private field refused")
    }
    pub(super) fn into_error(self) -> BrokerError {
        match self {
            Self::Cause(error) => error,
            Self::Bound(bound) => BrokerError::InvalidRequest(
                match bound {
                    ByteBound::Reference => {
                        "privileged audit reference request is malformed or oversized"
                    }
                    ByteBound::Request => "request body or header count exceeds broker limit",
                    ByteBound::HeaderValue => "header value is invalid or oversized",
                }
                .to_owned(),
            ),
        }
    }
}

pub(super) struct PrivateBytes<const MAXIMUM: usize>(BoundedZeroizingByteArray<MAXIMUM>);
impl<const MAXIMUM: usize> PrivateBytes<MAXIMUM> {
    pub(super) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub(super) fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

pub(super) struct BytesSeed<'a, const MAXIMUM: usize> {
    pub(super) failure: &'a mut Option<SeedFailure>,
    pub(super) bound: ByteBound,
}
impl<'de, const MAXIMUM: usize> DeserializeSeed<'de> for BytesSeed<'_, MAXIMUM> {
    type Value = PrivateBytes<MAXIMUM>;
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}
impl<'de, const MAXIMUM: usize> Visitor<'de> for BytesSeed<'_, MAXIMUM> {
    type Value = PrivateBytes<MAXIMUM>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence")
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = BoundedZeroizingByteArray::copy_from_slice(&[])
            .map_err(|error| SeedFailure::Cause(error).record(self.failure))?;
        loop {
            if bytes.as_slice().len() == MAXIMUM {
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(SeedFailure::Bound(self.bound).record(self.failure));
                }
                return Ok(PrivateBytes(bytes));
            }
            let Some(byte) = sequence.next_element::<u8>()? else {
                return Ok(PrivateBytes(bytes));
            };
            if !bytes.push_bounded(byte) {
                return Err(SeedFailure::Bound(self.bound).record(self.failure));
            }
        }
    }
}

struct HeadersSeed<'a> {
    failure: &'a mut Option<SeedFailure>,
}
impl<'de> DeserializeSeed<'de> for HeadersSeed<'_> {
    type Value = Vec<PrivateHeader>;
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for HeadersSeed<'_> {
    type Value = Vec<PrivateHeader>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence")
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(crate::protocol::MAX_HEADER_COUNT)
            .map_err(|error| {
                SeedFailure::Cause(BrokerError::Storage(format!(
                    "privileged audit header capacity failed: {error}"
                )))
                .record(self.failure)
            })?;
        loop {
            if headers.len() == crate::protocol::MAX_HEADER_COUNT {
                if sequence
                    .next_element_seed(ExtraHeaderSeed {
                        failure: self.failure,
                    })?
                    .is_some()
                {
                    return Err(SeedFailure::Bound(ByteBound::Request).record(self.failure));
                }
                return Ok(headers);
            }
            let Some(header) = sequence.next_element_seed(HeaderSeed {
                failure: self.failure,
            })?
            else {
                return Ok(headers);
            };
            headers.push(header);
        }
    }
}

// The existing header-count boundary refuses a 65th header before its values
// enter any private buffer. Native Serde still reports wrong outer types.
struct ExtraHeaderSeed<'a> {
    failure: &'a mut Option<SeedFailure>,
}
impl<'de> DeserializeSeed<'de> for ExtraHeaderSeed<'_> {
    type Value = ();
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("HeaderField", &["name", "value"], self)
    }
}
impl<'de> Visitor<'de> for ExtraHeaderSeed<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("struct HeaderField")
    }
    fn visit_seq<A>(self, _sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(SeedFailure::Bound(ByteBound::Request).record(self.failure))
    }
    fn visit_map<A>(self, _map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(SeedFailure::Bound(ByteBound::Request).record(self.failure))
    }
}

fn required<T, E: serde::de::Error>(
    value: Option<T>,
    field: &'static str,
) -> std::result::Result<T, E> {
    match value {
        Some(value) => Ok(value),
        None => Err(E::missing_field(field)),
    }
}

pub(super) struct PrivateHeader {
    pub(super) name: String,
    pub(super) value: PrivateBytes<MAX_HEADER_VALUE_BYTES>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum HeaderKey {
    #[serde(rename = "name")]
    Field0,
    #[serde(rename = "value")]
    Field1,
}

pub(super) struct HeaderSeed<'a> {
    pub(super) failure: &'a mut Option<SeedFailure>,
}
impl<'de> DeserializeSeed<'de> for HeaderSeed<'_> {
    type Value = PrivateHeader;
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("HeaderField", &["name", "value"], self)
    }
}
impl<'de> Visitor<'de> for HeaderSeed<'_> {
    type Value = PrivateHeader;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("struct HeaderField")
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let name = sequence
            .next_element::<String>()?
            .ok_or_else(|| A::Error::invalid_length(0, &self))?;
        let value = sequence
            .next_element_seed(BytesSeed::<MAX_HEADER_VALUE_BYTES> {
                failure: self.failure,
                bound: ByteBound::HeaderValue,
            })?
            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
        Ok(PrivateHeader { name, value })
    }
    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut name = None;
        let mut value = None;
        while let Some(key) = map.next_key::<HeaderKey>()? {
            match key {
                HeaderKey::Field0 => {
                    if name.is_some() {
                        return Err(A::Error::duplicate_field("name"));
                    }
                    name = Some(map.next_value::<String>()?);
                }
                HeaderKey::Field1 => {
                    if value.is_some() {
                        return Err(A::Error::duplicate_field("value"));
                    }
                    value = Some(map.next_value_seed(BytesSeed::<MAX_HEADER_VALUE_BYTES> {
                        failure: self.failure,
                        bound: ByteBound::HeaderValue,
                    })?);
                }
            }
        }
        Ok(PrivateHeader {
            name: required(name, "name")?,
            value: required(value, "value")?,
        })
    }
}

pub(super) struct PrivateRequest {
    pub(super) destination: BrokerDestination,
    pub(super) headers: Vec<PrivateHeader>,
    pub(super) body: PrivateBytes<MAX_BODY_BYTES>,
    pub(super) approved_preview_sha256: Option<String>,
    pub(super) options: CallerOptions,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum RequestKey {
    #[serde(rename = "destination")]
    Field0,
    #[serde(rename = "headers")]
    Field1,
    #[serde(rename = "body")]
    Field2,
    #[serde(rename = "approvedPreviewSha256")]
    Field3,
    #[serde(rename = "options")]
    Field4,
}

pub(super) struct RequestSeed<'a> {
    pub(super) failure: &'a mut Option<SeedFailure>,
}
impl<'de> DeserializeSeed<'de> for RequestSeed<'_> {
    type Value = PrivateRequest;
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "BrokerRequest",
            &[
                "destination",
                "headers",
                "body",
                "approvedPreviewSha256",
                "options",
            ],
            self,
        )
    }
}
impl<'de> Visitor<'de> for RequestSeed<'_> {
    type Value = PrivateRequest;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("struct BrokerRequest")
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let destination = sequence
            .next_element::<BrokerDestination>()?
            .ok_or_else(|| A::Error::invalid_length(0, &self))?;
        let headers = sequence
            .next_element_seed(HeadersSeed {
                failure: self.failure,
            })?
            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
        let body = sequence
            .next_element_seed(BytesSeed::<MAX_BODY_BYTES> {
                failure: self.failure,
                bound: ByteBound::Request,
            })?
            .ok_or_else(|| A::Error::invalid_length(2, &self))?;
        let approved_preview_sha256 = sequence
            .next_element::<Option<String>>()?
            .ok_or_else(|| A::Error::invalid_length(3, &self))?;
        let options = sequence
            .next_element::<CallerOptions>()?
            .ok_or_else(|| A::Error::invalid_length(4, &self))?;
        Ok(PrivateRequest {
            destination,
            headers,
            body,
            approved_preview_sha256,
            options,
        })
    }
    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut destination = None;
        let mut headers = None;
        let mut body = None;
        let mut approved_preview_sha256 = None;
        let mut options = None;
        while let Some(key) = map.next_key::<RequestKey>()? {
            match key {
                RequestKey::Field0 => {
                    if destination.is_some() {
                        return Err(A::Error::duplicate_field("destination"));
                    }
                    destination = Some(map.next_value::<BrokerDestination>()?);
                }
                RequestKey::Field1 => {
                    if headers.is_some() {
                        return Err(A::Error::duplicate_field("headers"));
                    }
                    headers = Some(map.next_value_seed(HeadersSeed {
                        failure: self.failure,
                    })?);
                }
                RequestKey::Field2 => {
                    if body.is_some() {
                        return Err(A::Error::duplicate_field("body"));
                    }
                    body = Some(map.next_value_seed(BytesSeed::<MAX_BODY_BYTES> {
                        failure: self.failure,
                        bound: ByteBound::Request,
                    })?);
                }
                RequestKey::Field3 => {
                    if approved_preview_sha256.is_some() {
                        return Err(A::Error::duplicate_field("approvedPreviewSha256"));
                    }
                    approved_preview_sha256 = Some(map.next_value::<Option<String>>()?);
                }
                RequestKey::Field4 => {
                    if options.is_some() {
                        return Err(A::Error::duplicate_field("options"));
                    }
                    options = Some(map.next_value::<CallerOptions>()?);
                }
            }
        }
        Ok(PrivateRequest {
            destination: required(destination, "destination")?,
            headers: required(headers, "headers")?,
            body: required(body, "body")?,
            approved_preview_sha256: match approved_preview_sha256 {
                Some(value) => value,
                None => None,
            },
            options: required(options, "options")?,
        })
    }
}

pub(super) struct PrivateExecute {
    pub(super) schema: String,
    pub(super) invocation_id: String,
    pub(super) capability: SignedBrokerCapability,
    pub(super) proof: RequestProof,
    pub(super) request: PrivateRequest,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ExecuteKey {
    #[serde(rename = "schema")]
    Field0,
    #[serde(rename = "invocationId")]
    Field1,
    #[serde(rename = "capability")]
    Field2,
    #[serde(rename = "proof")]
    Field3,
    #[serde(rename = "request")]
    Field4,
}

pub(super) struct ExecuteSeed<'a> {
    pub(super) failure: &'a mut Option<SeedFailure>,
}
impl<'de> DeserializeSeed<'de> for ExecuteSeed<'_> {
    type Value = PrivateExecute;
    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "BrokerExecuteRequest",
            &["schema", "invocationId", "capability", "proof", "request"],
            self,
        )
    }
}
impl<'de> Visitor<'de> for ExecuteSeed<'_> {
    type Value = PrivateExecute;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("struct BrokerExecuteRequest")
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let schema = sequence
            .next_element::<String>()?
            .ok_or_else(|| A::Error::invalid_length(0, &self))?;
        let invocation_id = sequence
            .next_element::<String>()?
            .ok_or_else(|| A::Error::invalid_length(1, &self))?;
        let capability = sequence
            .next_element::<SignedBrokerCapability>()?
            .ok_or_else(|| A::Error::invalid_length(2, &self))?;
        let proof = sequence
            .next_element::<RequestProof>()?
            .ok_or_else(|| A::Error::invalid_length(3, &self))?;
        let request = sequence
            .next_element_seed(RequestSeed {
                failure: self.failure,
            })?
            .ok_or_else(|| A::Error::invalid_length(4, &self))?;
        Ok(PrivateExecute {
            schema,
            invocation_id,
            capability,
            proof,
            request,
        })
    }
    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema = None;
        let mut invocation_id = None;
        let mut capability = None;
        let mut proof = None;
        let mut request = None;
        while let Some(key) = map.next_key::<ExecuteKey>()? {
            match key {
                ExecuteKey::Field0 => {
                    if schema.is_some() {
                        return Err(A::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value::<String>()?);
                }
                ExecuteKey::Field1 => {
                    if invocation_id.is_some() {
                        return Err(A::Error::duplicate_field("invocationId"));
                    }
                    invocation_id = Some(map.next_value::<String>()?);
                }
                ExecuteKey::Field2 => {
                    if capability.is_some() {
                        return Err(A::Error::duplicate_field("capability"));
                    }
                    capability = Some(map.next_value::<SignedBrokerCapability>()?);
                }
                ExecuteKey::Field3 => {
                    if proof.is_some() {
                        return Err(A::Error::duplicate_field("proof"));
                    }
                    proof = Some(map.next_value::<RequestProof>()?);
                }
                ExecuteKey::Field4 => {
                    if request.is_some() {
                        return Err(A::Error::duplicate_field("request"));
                    }
                    request = Some(map.next_value_seed(RequestSeed {
                        failure: self.failure,
                    })?);
                }
            }
        }
        Ok(PrivateExecute {
            schema: required(schema, "schema")?,
            invocation_id: required(invocation_id, "invocationId")?,
            capability: required(capability, "capability")?,
            proof: required(proof, "proof")?,
            request: required(request, "request")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn f053_codec_seed_retains_actual_capacity_failure_as_fatal_storage() {
        // Capacity overflow is the real fallible constructor failure, without
        // allocating a huge buffer or probing an allocator's freed storage.
        let mut fields = super::super::Fields {
            input: b"[]",
            position: 0,
        };
        let mut failure = None;
        let result = fields.seeded(BytesSeed::<{ usize::MAX }> {
            failure: &mut failure,
            bound: ByteBound::Reference,
        });
        let Err(error) = super::super::seed_result(result, failure) else {
            panic!("native oversized capacity must fail");
        };
        assert!(matches!(&error, BrokerError::Storage(_)));
        assert_eq!(error.diagnostic_code(), "storage");
        assert!(error.is_service_fault());
    }
}
