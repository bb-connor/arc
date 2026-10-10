//! Direct canonical bytes for the private fields on the audit request path.
use crate::proof::RequestProof;
use crate::protocol::{
    BrokerDestination, BrokerExecuteRequest, BrokerRequest, CallerOptions, HeaderField,
    SignedBrokerCapability,
};
use crate::{BrokerError, Result};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

enum Segment<'a> {
    Literal(&'static [u8]),
    String(&'a str),
    Bytes(&'a [u8]),
    Canonical(&'a [u8]),
}
fn finish_segments(segments: &[Segment<'_>], maximum: Option<usize>) -> Result<Zeroizing<Vec<u8>>> {
    use crate::service::{
        canonical_json_byte_array_length, canonical_json_string_length, checked_canonical_length,
        ZeroizingCanonicalJsonWriter,
    };
    let mut length = 0;
    for segment in segments {
        let size = match segment {
            Segment::Literal(value) | Segment::Canonical(value) => value.len(),
            Segment::String(value) => canonical_json_string_length(value)?,
            Segment::Bytes(value) => canonical_json_byte_array_length(value)?,
        };
        length = checked_canonical_length(length, size)?;
    }
    if maximum.is_some_and(|maximum| length > maximum) {
        return Err(BrokerError::Invariant(
            "privileged audit response frame is empty or oversized".to_owned(),
        ));
    }
    let mut output = ZeroizingCanonicalJsonWriter::with_exact_length(length)?;
    for segment in segments {
        match segment {
            Segment::Literal(value) | Segment::Canonical(value) => {
                output.extend_from_slice(value)?
            }
            Segment::String(value) => output.write_string(value)?,
            Segment::Bytes(value) => output.write_byte_array(value)?,
        }
    }
    output.finish()
}

fn public_bytes<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    chio_core_types::canonical::canonical_json_bytes_zeroizing(value).map_err(|error| {
        BrokerError::UntrustedInput(
            chio_core_types::canonical::UntrustedJsonError::Canonicalization(error),
        )
    })
}

pub(crate) struct RequestRef<'a> {
    pub(crate) schema: &'a str,
    pub(crate) invocation: &'a str,
    pub(crate) capability: &'a SignedBrokerCapability,
    pub(crate) proof: &'a RequestProof,
    pub(crate) destination: &'a BrokerDestination,
    pub(crate) options: &'a CallerOptions,
    pub(crate) body: &'a [u8],
    pub(crate) preview: &'a Option<String>,
    pub(crate) headers: Vec<(&'a str, &'a [u8])>,
}

#[cfg(unix)]
pub(crate) struct OpenRef<'a> {
    pub(crate) schema: &'a str,
    pub(crate) audit_id: &'a str,
    pub(crate) source: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) salt: &'a str,
    pub(crate) commitment: &'a str,
    pub(crate) head: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) request: RequestRef<'a>,
}
#[cfg(unix)]
pub(crate) fn canonical_open_bytes(
    open: OpenRef<'_>,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let OpenRef {
        schema,
        audit_id,
        source,
        domain,
        salt,
        commitment,
        head,
        body,
        request,
    } = open;
    let capability = public_bytes(request.capability)?;
    let proof = public_bytes(request.proof)?;
    let destination = public_bytes(request.destination)?;
    let options = public_bytes(request.options)?;
    use Segment::{Bytes as B, Canonical as C, Literal as L, String as S};
    let mut parts = vec![
        L(b"{\"auditId\":"),
        S(audit_id),
        L(b",\"referenceCommitmentSalt\":"),
        S(salt),
        L(b",\"referenceCommitmentSha256\":"),
        S(commitment),
        L(b",\"referenceRequestBody\":"),
        B(body),
        L(b",\"referenceRequestHead\":"),
        B(head),
        L(b",\"referenceSource\":"),
        S(source),
        L(b",\"request\":{\"capability\":"),
        C(&capability),
        L(b",\"invocationId\":"),
        S(request.invocation),
        L(b",\"proof\":"),
        C(&proof),
        L(b",\"request\":"),
    ];
    append_request(&mut parts, &request, &destination, &options);
    parts.extend([
        L(b",\"schema\":"),
        S(request.schema),
        L(b"},\"revocationAuthorityDomain\":"),
        S(domain),
        L(b",\"schema\":"),
        S(schema),
        L(b"}"),
    ]);
    finish_segments(&parts, Some(maximum))
}

fn append_headers<'a>(parts: &mut Vec<Segment<'a>>, headers: &[(&'a str, &'a [u8])]) {
    use Segment::{Bytes as B, Literal as L, String as S};
    parts.push(L(b"["));
    for (index, (name, value)) in headers.iter().enumerate() {
        if index != 0 {
            parts.push(L(b","));
        }
        parts.extend([
            L(b"{\"name\":"),
            S(name),
            L(b",\"value\":"),
            B(value),
            L(b"}"),
        ]);
    }
    parts.push(L(b"]"));
}

fn append_request<'a>(
    parts: &mut Vec<Segment<'a>>,
    request: &RequestRef<'a>,
    destination: &'a [u8],
    options: &'a [u8],
) {
    use Segment::{Bytes as B, Canonical as C, Literal as L, String as S};
    parts.push(L(b"{\"approvedPreviewSha256\":"));
    match request.preview {
        Some(value) => parts.push(S(value)),
        None => parts.push(L(b"null")),
    }
    parts.extend([
        L(b",\"body\":"),
        B(request.body),
        L(b",\"destination\":"),
        C(destination),
        L(b",\"headers\":"),
    ]);
    append_headers(parts, &request.headers);
    parts.extend([L(b",\"options\":"), C(options), L(b"}")]);
}

fn execute_ref(request: &BrokerExecuteRequest) -> RequestRef<'_> {
    RequestRef {
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
    }
}

pub(crate) fn canonical_execute_bytes(
    request: &BrokerExecuteRequest,
) -> Result<Zeroizing<Vec<u8>>> {
    let request = execute_ref(request);
    let capability = public_bytes(request.capability)?;
    let proof = public_bytes(request.proof)?;
    let destination = public_bytes(request.destination)?;
    let options = public_bytes(request.options)?;
    use Segment::{Canonical as C, Literal as L, String as S};
    let mut parts = vec![
        L(b"{\"capability\":"),
        C(&capability),
        L(b",\"invocationId\":"),
        S(request.invocation),
        L(b",\"proof\":"),
        C(&proof),
        L(b",\"request\":"),
    ];
    append_request(&mut parts, &request, &destination, &options);
    parts.extend([L(b",\"schema\":"), S(request.schema), L(b"}")]);
    finish_segments(&parts, None)
}

pub(crate) fn canonical_header_bytes(headers: &[HeaderField]) -> Result<Zeroizing<Vec<u8>>> {
    let headers = headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_slice()))
        .collect::<Vec<_>>();
    let mut parts = Vec::new();
    append_headers(&mut parts, &headers);
    finish_segments(&parts, None)
}

pub(crate) fn zeroize_caller_bytes(headers: &mut [HeaderField], body: &mut Vec<u8>) {
    body.zeroize();
    for header in headers {
        header.value.zeroize();
    }
}

pub(crate) fn zeroize_request_bytes(request: &mut BrokerRequest) {
    zeroize_caller_bytes(&mut request.headers, &mut request.body);
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum CallerOwner {
    Open,
    Provider,
    Pinned,
}
#[cfg(test)]
std::thread_local! {
    static CALLER_DROPS: std::cell::Cell<[usize; 3]> = const { std::cell::Cell::new([0; 3]) };
}
#[cfg(test)]
pub(crate) fn reset_caller_drop_observer() {
    CALLER_DROPS.with(|counts| counts.set([0; 3]));
}
#[cfg(test)]
pub(crate) fn caller_drop_observation() -> [usize; 3] {
    CALLER_DROPS.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(crate) fn observe_caller_drop(owner: CallerOwner, populated: bool, cleared: bool) {
    assert!(
        cleared,
        "owned caller bytes are cleared before owner drop completes"
    );
    if !populated {
        return;
    }
    CALLER_DROPS.with(|counts| {
        let mut next = counts.get();
        let index = match owner {
            CallerOwner::Open => 0,
            CallerOwner::Provider => 1,
            CallerOwner::Pinned => 2,
        };
        let Some(count) = next.get_mut(index) else {
            panic!("caller owner observer index")
        };
        let Some(value) = count.checked_add(1) else {
            panic!("caller owner observer overflow")
        };
        *count = value;
        counts.set(next);
    });
}
