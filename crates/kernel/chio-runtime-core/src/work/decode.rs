//! Bounded decoding of `chio.work.v1` frames. Every bound is charged before
//! the typed decoder allocates, and decoding authenticates nothing.

use std::collections::BTreeSet;

use chio_security_types::recovery::SafeInteger;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::error::{WorkContractError, WorkRejectionCodeV1};
use super::wire::*;

/// Request body bytes, excluding the frame's terminating newline.
pub const MAX_WORK_REQUEST_BYTES: usize = 2_097_151;
/// Response bytes including framing.
pub const MAX_WORK_RESPONSE_BYTES: usize = 8_388_608;
pub const MAX_WORK_DEPTH: usize = 32;
pub const MAX_WORK_NODES: usize = 16_384;
/// Collection entries across the whole decoded frame, not per container.
pub const MAX_WORK_ENTRIES: usize = 8_192;
pub const MAX_WORK_NEW_TASKS: usize = 16;
pub const MAX_WORK_DEPENDENCIES: usize = 64;
pub const MAX_WORK_JOIN_DRAFTS: usize = 16;
pub const MAX_WORK_JOIN_PARENTS: usize = 16;
pub const MAX_WORK_CATALOG_ENTRIES: usize = 64;
pub const MAX_WORK_EVIDENCE: usize = 16;
pub const MAX_WORK_RECOVERY_OPERATIONS: usize = 8;
pub const MAX_WORK_CONDITIONS: usize = 64;

/// Decode and validate one request frame.
pub fn decode_work_request(input: &[u8]) -> Result<WorkRequestV1, WorkContractError> {
    let request: WorkRequestV1 = decode(input, MAX_WORK_REQUEST_BYTES)?;
    request.validate()?;
    Ok(request)
}

/// Decode and validate one response frame.
pub fn decode_work_response(input: &[u8]) -> Result<WorkResponseV1, WorkContractError> {
    let response: WorkResponseV1 = decode(input, MAX_WORK_RESPONSE_BYTES)?;
    response.validate()?;
    Ok(response)
}

/// Decode and validate one join-input manifest.
pub fn decode_work_join_inputs(input: &[u8]) -> Result<WorkJoinInputsV1, WorkContractError> {
    let manifest: WorkJoinInputsV1 = decode(input, MAX_WORK_REQUEST_BYTES)?;
    manifest.validate()?;
    Ok(manifest)
}

fn decode<T: DeserializeOwned>(input: &[u8], bytes: usize) -> Result<T, WorkContractError> {
    preflight(input, bytes)?;
    let value: Value = chio_core_types::canonical::UntrustedJsonText::from_wire(input, bytes)
        .and_then(|text| text.decode_document())
        .map_err(|error| match error {
            chio_core_types::canonical::UntrustedJsonError::SignedInput(_) => {
                reject(WorkRejectionCodeV1::DuplicateKey)
            }
            chio_core_types::canonical::UntrustedJsonError::TooLarge { .. } => {
                reject(WorkRejectionCodeV1::Bounds)
            }
            _ => reject(WorkRejectionCodeV1::Malformed),
        })?;
    check_schema_fields(&value)?;
    serde_json::from_value(value).map_err(|error| {
        let message = error.to_string();
        [
            WorkRejectionCodeV1::Identifier,
            WorkRejectionCodeV1::UnsafeInteger,
            WorkRejectionCodeV1::Bounds,
        ]
        .into_iter()
        .find(|code| message.starts_with(code.as_str()))
        .map_or_else(|| reject(WorkRejectionCodeV1::Malformed), reject)
    })
}

const fn reject(code: WorkRejectionCodeV1) -> WorkContractError {
    WorkContractError::new(code)
}

/// A wrong `schema` or `version` on any Work-owned record is a schema
/// rejection, distinct from an unknown field or variant.
fn check_schema_fields(value: &Value) -> Result<(), WorkContractError> {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(schema)) = map.get("schema") {
                if schema.starts_with("chio.work.") {
                    let known = [
                        "chio.work.request.v1",
                        "chio.work.response.v1",
                        "chio.work.preparation.v1",
                        "chio.work.command.v1",
                        "chio.work.join-inputs.v1",
                    ];
                    if !known.contains(&schema.as_str())
                        || map.get("version") != Some(&Value::from(1))
                    {
                        return Err(reject(WorkRejectionCodeV1::Schema));
                    }
                }
            }
            map.values().try_for_each(check_schema_fields)
        }
        Value::Array(items) => items.iter().try_for_each(check_schema_fields),
        _ => Ok(()),
    }
}

/// Allocation-free resource accounting before the parser builds a value.
fn preflight(input: &[u8], bytes: usize) -> Result<(), WorkContractError> {
    if input.is_empty() {
        return Err(reject(WorkRejectionCodeV1::Malformed));
    }
    if input.len() > bytes {
        return Err(reject(WorkRejectionCodeV1::Bounds));
    }
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut entries = 0usize;
    let mut cursor = 0usize;
    let charge = |used: &mut usize, ceiling: usize| -> Result<(), WorkContractError> {
        *used += 1;
        if *used > ceiling {
            return Err(reject(WorkRejectionCodeV1::Bounds));
        }
        Ok(())
    };
    while let Some(&byte) = input.get(cursor) {
        match byte {
            b' ' | b'\n' | b'\r' | b'\t' | b':' => cursor += 1,
            b'{' | b'[' => {
                charge(&mut nodes, MAX_WORK_NODES)?;
                charge(&mut entries, MAX_WORK_ENTRIES)?;
                depth += 1;
                if depth > MAX_WORK_DEPTH {
                    return Err(reject(WorkRejectionCodeV1::Bounds));
                }
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(reject(WorkRejectionCodeV1::Malformed))?;
                cursor += 1;
            }
            b',' => {
                charge(&mut entries, MAX_WORK_ENTRIES)?;
                cursor += 1;
            }
            b'"' => {
                charge(&mut nodes, MAX_WORK_NODES)?;
                cursor += 1;
                loop {
                    match input.get(cursor) {
                        Some(b'"') => break,
                        Some(b'\\') => cursor += 2,
                        Some(_) => cursor += 1,
                        None => return Err(reject(WorkRejectionCodeV1::Malformed)),
                    }
                }
                cursor += 1;
            }
            _ => {
                charge(&mut nodes, MAX_WORK_NODES)?;
                let start = cursor;
                while input.get(cursor).is_some_and(|byte| {
                    !matches!(byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t')
                }) {
                    cursor += 1;
                }
                let token = input
                    .get(start..cursor)
                    .ok_or(reject(WorkRejectionCodeV1::Malformed))?;
                check_integer(token)?;
            }
        }
    }
    if depth != 0 {
        return Err(reject(WorkRejectionCodeV1::Malformed));
    }
    Ok(())
}

/// Integers outside the interoperable range are refused anywhere in the
/// frame. Fractional and exponent forms are left to the typed decoder.
fn check_integer(token: &[u8]) -> Result<(), WorkContractError> {
    let digits = token.strip_prefix(b"-").unwrap_or(token);
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || matches!(token, b"true" | b"false" | b"null")
    {
        return Ok(());
    }
    let mut value = 0u64;
    for byte in digits {
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
            .filter(|n| *n <= SafeInteger::MAX)
            .ok_or(reject(WorkRejectionCodeV1::UnsafeInteger))?;
    }
    Ok(())
}

fn bounded<T>(items: &[T], ceiling: usize) -> Result<(), WorkContractError> {
    if items.len() > ceiling {
        return Err(reject(WorkRejectionCodeV1::Bounds));
    }
    Ok(())
}

fn unique<T: Ord>(items: impl IntoIterator<Item = T>) -> Result<(), WorkContractError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(reject(WorkRejectionCodeV1::Conflict));
        }
    }
    Ok(())
}

impl WorkRequestV1 {
    /// Structural checks every transport applies before an owner sees it.
    pub fn validate(&self) -> Result<(), WorkContractError> {
        match &self.body {
            WorkRequestBodyV1::Prepare { preparation } => preparation.proposal.validate(),
            WorkRequestBodyV1::Submit { command } => command.action.validate(),
            WorkRequestBodyV1::Query { .. } => Ok(()),
        }
    }
}

impl WorkProposalV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        match self {
            Self::Extend {
                new_work,
                dependencies,
                join_draft_refs,
                ..
            } => {
                bounded(new_work, MAX_WORK_NEW_TASKS)?;
                bounded(dependencies, MAX_WORK_DEPENDENCIES)?;
                bounded(join_draft_refs, MAX_WORK_JOIN_DRAFTS)?;
                unique(new_work.iter().map(|task| task.task_id.as_str()))?;
                unique(join_draft_refs.iter().map(|draft| draft.draft_id.as_str()))
            }
            Self::Join { parents, .. } => {
                bounded(parents, MAX_WORK_JOIN_PARENTS)?;
                unique(parents.iter().map(|parent| parent.request_id.as_str()))
            }
            Self::Agreement { commitment, terms } => {
                commitment.validate()?;
                match terms {
                    WorkAgreementTermsV1::Unpaid { .. } => Ok(()),
                    WorkAgreementTermsV1::Funded { .. } => {
                        Err(reject(WorkRejectionCodeV1::UnsupportedProfile))
                    }
                }
            }
            Self::Delegate { .. } | Self::Offer { .. } | Self::Select { .. } => Ok(()),
        }
    }
}

impl WorkCommitmentV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        if self.handle.slot_id.as_str() != self.permit.body.slot.id {
            return Err(WorkContractError::binding(
                super::error::WorkBindingFieldV1::SlotId,
            ));
        }
        if self.handle.allocation_hash.as_str() != self.permit.body.allocation_hash {
            return Err(WorkContractError::binding(
                super::error::WorkBindingFieldV1::AllocationHash,
            ));
        }
        if self.handle.request_id.as_str() != self.permit.body.selection.body.request_id {
            return Err(WorkContractError::binding(
                super::error::WorkBindingFieldV1::RequestId,
            ));
        }
        Ok(())
    }
}

impl WorkActionV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        match self {
            Self::Submit { commitment } => commitment.validate(),
            _ => Ok(()),
        }
    }
}

impl WorkResponseV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        match &self.body {
            WorkResponseBodyV1::Prepared { .. } | WorkResponseBodyV1::Command { .. } => Ok(()),
            WorkResponseBodyV1::Query { result } => result.validate(),
        }
    }
}

impl WorkQueryResultV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        match self {
            Self::Catalog { page } => {
                bounded(&page.entries, MAX_WORK_CATALOG_ENTRIES)?;
                unique(
                    page.entries
                        .iter()
                        .map(|entry| entry.catalog_entry.as_str()),
                )
            }
            Self::Profile { profile } => {
                bounded(&profile.recovery_operations, MAX_WORK_RECOVERY_OPERATIONS)?;
                bounded(&profile.conditions, MAX_WORK_CONDITIONS)?;
                unique(profile.recovery_operations.iter())
            }
            Self::Work { view } => view.validate(),
            Self::Command { .. } | Self::Preparation { .. } | Self::Unavailable { .. } => Ok(()),
        }
    }
}

impl WorkViewV1 {
    pub fn validate(&self) -> Result<(), WorkContractError> {
        if let WorkObservationV1::Available { value, .. } = &self.acceptance {
            bounded(&value.evidence, MAX_WORK_EVIDENCE)?;
        }
        if let WorkObservationV1::Available { value, .. } = &self.recovery {
            bounded(&value.available, MAX_WORK_RECOVERY_OPERATIONS)?;
            unique(value.available.iter())?;
        }
        Ok(())
    }
}

impl WorkJoinInputsV1 {
    /// Parents are unique, strictly sorted by task id and at most 16.
    pub fn validate(&self) -> Result<(), WorkContractError> {
        if self.parents.is_empty() {
            return Err(reject(WorkRejectionCodeV1::Bounds));
        }
        bounded(&self.parents, MAX_WORK_JOIN_PARENTS)?;
        unique(self.parents.iter().map(|parent| parent.receipt_id.as_str()))?;
        if !self
            .parents
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.task_id < right.task_id))
        {
            return Err(reject(WorkRejectionCodeV1::Conflict));
        }
        Ok(())
    }
}
