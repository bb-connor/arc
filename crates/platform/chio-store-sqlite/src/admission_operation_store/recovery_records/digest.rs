//! Protected record and store event digests: SHA-256 of the canonical JSON
//! array that names the shared domain followed by the bound fields.
//!
//! The record array binds the payload by `sha256_hex(payload)`, never by its
//! bytes. Canonical JSON writes each character of a string in at most six
//! bytes (a `\u00XX` control escape), so a 512-character key and a
//! 256-character native request bound either array to a few kilobytes
//! whatever the payload size.

use chio_core::canonical::canonical_json_bytes;
use chio_core::recovery::RecoveryDigestDomain;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use serde::Serialize;

use super::invariant;
use super::record::{NativeIdentity, RecordKind};

pub(super) struct RecordDigestInput<'a> {
    pub key: &'a str,
    pub scope: &'a str,
    pub kind: RecordKind,
    pub version: u64,
    pub payload: &'a [u8],
    pub native: Option<&'a NativeIdentity>,
}

pub(super) struct EventDigestInput<'a> {
    pub sequence: u64,
    pub key: &'a str,
    pub version: u64,
    pub record_digest: &'a str,
    pub previous_digest: &'a str,
    pub observed_at: u64,
}

/// `[domain, key, scope, kind, version, sha256_hex(payload), namespace, request]`.
pub(super) fn record_digest(
    input: &RecordDigestInput<'_>,
) -> Result<String, AdmissionOperationStoreError> {
    array_digest(&(
        RecoveryDigestDomain::ProtectedRecord.name(),
        input.key,
        input.scope,
        input.kind.as_str(),
        input.version,
        sha256_hex(input.payload),
        input.native.map(|native| native.namespace.as_str()),
        input.native.map(|native| native.request.as_str()),
    ))
}

/// `[domain, sequence, key, version, record_digest, previous_digest, observed_at]`.
pub(super) fn event_digest(
    input: &EventDigestInput<'_>,
) -> Result<String, AdmissionOperationStoreError> {
    array_digest(&(
        RecoveryDigestDomain::StoreEvent.name(),
        input.sequence,
        input.key,
        input.version,
        input.record_digest,
        input.previous_digest,
        input.observed_at,
    ))
}

/// Stored digests and scope keys are lowercase hexadecimal SHA-256 values.
pub(super) fn is_digest_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn array_digest<T: Serialize>(array: &T) -> Result<String, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(array)
        .map_err(|_| invariant("recovery record digest input was refused"))?;
    Ok(sha256_hex(&bytes))
}
