//! Preallocation bounds for closed, borrowed certificate inputs.
//!
//! Typed callers already own their inputs, so this is not an original-wire or
//! fixed-RSS promise. Before cloning or authority checks, a receipt is limited
//! to 1 MiB of raw string bytes, 1,048,576 structural nodes and nesting depth 128.
//! Signature text length is checked without allocation before serde can render
//! it. The counting serializer then enforces the logical canonical 1 MiB per
//! receipt and 128 MiB aggregate limits. It emits no receipt buffer; only bounded
//! crypto strings and canonical numeric scalar temporaries are rendered.
//!
//! Object ordering changes no byte lengths. Float lengths come from the core
//! canonicalizer, avoiding raw-serde or sequence-wrapper boundary exclusions.

use super::{
    ComplianceBundleError, ComplianceCertificateError, ComplianceCoverage, ComplianceReceiptEntry,
    MAX_CERTIFICATE_RECEIPTS, MAX_RECEIPT_BYTES, MAX_RECEIPT_SET_BYTES,
};
use chio_core::{canonical::canonical_json_bytes, crypto::Signature, receipt::decision::Decision};
use serde::Serialize;
use serde_json::{ser::Formatter, Value};
use std::io::{self, Write};

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_NODES: usize = 1_048_576;

struct ShapeBudget {
    string_bytes: usize,
    nodes: usize,
}

impl ShapeBudget {
    fn new() -> Self {
        Self {
            string_bytes: MAX_RECEIPT_BYTES,
            nodes: MAX_JSON_NODES,
        }
    }

    fn string(&mut self, value: &str) -> Result<(), ComplianceBundleError> {
        self.string_bytes = self
            .string_bytes
            .checked_sub(value.len())
            .ok_or(ComplianceBundleError::CapacityExceeded)?;
        Ok(())
    }

    fn nodes(&mut self, count: usize) -> Result<(), ComplianceBundleError> {
        self.nodes = self
            .nodes
            .checked_sub(count)
            .ok_or(ComplianceBundleError::CapacityExceeded)?;
        Ok(())
    }

    fn json(&mut self, value: &Value, depth: usize) -> Result<(), ComplianceBundleError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ComplianceBundleError::CapacityExceeded);
        }
        self.nodes(1)?;
        match value {
            Value::String(value) => self.string(value)?,
            Value::Array(values) => {
                for value in values {
                    self.json(value, depth + 1)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    self.string(key)?;
                    self.json(value, depth + 1)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }
}

fn signature(signature: &Signature) -> Result<(), ComplianceBundleError> {
    if signature
        .encoded_text_len()
        .is_none_or(|length| length > MAX_RECEIPT_BYTES)
    {
        return Err(ComplianceBundleError::CapacityExceeded);
    }
    Ok(())
}

fn receipt_shape(entry: &ComplianceReceiptEntry) -> Result<(), ComplianceBundleError> {
    let receipt = &entry.receipt;
    signature(&receipt.signature)?;
    let mut budget = ShapeBudget::new();
    for value in [
        &receipt.id,
        &receipt.capability_id,
        &receipt.tool_server,
        &receipt.tool_name,
        &receipt.action.parameter_hash,
        &receipt.content_hash,
        &receipt.policy_hash,
    ] {
        budget.string(value)?;
    }
    for value in receipt
        .tenant_id
        .iter()
        .chain(receipt.bbs_projection_version.iter())
    {
        budget.string(value)?;
    }
    budget.nodes(receipt.actor_chain.len())?;
    for actor in &receipt.actor_chain {
        budget.string(&actor.actor_id)?;
        if let Some(kind) = &actor.actor_kind {
            budget.string(kind)?;
        }
    }
    budget.nodes(receipt.evidence.len())?;
    for evidence in &receipt.evidence {
        budget.string(&evidence.guard_name)?;
        if let Some(details) = &evidence.details {
            budget.string(details)?;
        }
    }
    match receipt.decision.as_ref() {
        Some(Decision::Deny { reason, guard }) => {
            budget.string(reason)?;
            budget.string(guard)?;
        }
        Some(Decision::Cancelled { reason } | Decision::Incomplete { reason }) => {
            budget.string(reason)?
        }
        None | Some(Decision::Allow) => {}
    }
    if let Some(bbs) = &receipt.bbs_signature {
        for value in [
            &bbs.schema,
            &bbs.projection_version,
            &bbs.algorithm,
            &bbs.ciphersuite,
            &bbs.issuer_fingerprint,
            &bbs.issuer_public_key_hex,
            &bbs.signature_hex,
        ] {
            budget.string(value)?;
        }
    }
    budget.json(&receipt.action.parameters, 0)?;
    if let Some(metadata) = &receipt.metadata {
        budget.json(metadata, 0)?;
    }
    Ok(())
}

fn coverage_shape(
    coverage: &ComplianceCoverage,
    budget: &mut ShapeBudget,
) -> Result<(), ComplianceBundleError> {
    if let ComplianceCoverage::RetainedSnapshotReference {
        session_id,
        tenant_id,
        checkpoint,
        ..
    } = coverage
    {
        signature(&checkpoint.signature)?;
        budget.string(session_id)?;
        if let Some(tenant) = tenant_id {
            budget.string(tenant)?;
        }
        budget.string(&checkpoint.body.schema)?;
        if let Some(previous) = &checkpoint.body.previous_checkpoint_sha256 {
            budget.string(previous)?;
        }
    }
    Ok(())
}

pub(super) fn preflight_set(
    session_id: &str,
    entries: &[ComplianceReceiptEntry],
    coverage: &ComplianceCoverage,
) -> Result<(), ComplianceCertificateError> {
    if session_id.len() > 1024 || entries.len() > MAX_CERTIFICATE_RECEIPTS {
        return Err(ComplianceBundleError::CapacityExceeded.into());
    }
    coverage_shape(coverage, &mut ShapeBudget::new())?;
    canonical_size(coverage)?;
    let mut bytes = 0usize;
    for entry in entries {
        receipt_shape(entry)?;
        bytes = bytes
            .checked_add(canonical_size(&entry.receipt)?)
            .ok_or(ComplianceBundleError::CapacityExceeded)?;
        if bytes > MAX_RECEIPT_SET_BYTES {
            return Err(ComplianceBundleError::CapacityExceeded.into());
        }
    }
    Ok(())
}

pub(crate) fn preflight_certificate(
    cert: &crate::ComplianceCertificate,
) -> Result<(), ComplianceCertificateError> {
    signature(&cert.signature)?;
    preflight_body(&cert.body)
}

pub(crate) fn preflight_body(
    body: &crate::ComplianceCertificateBody,
) -> Result<(), ComplianceCertificateError> {
    let mut budget = ShapeBudget::new();
    budget.string(&body.schema)?;
    budget.string(&body.session_id)?;
    for value in body
        .receipt_set_digest
        .iter()
        .chain(body.compliance_profile_digest.iter())
    {
        budget.string(value)?;
    }
    budget.nodes(body.anomalies.len())?;
    for anomaly in &body.anomalies {
        budget.string(anomaly)?;
    }
    if let Some(coverage) = &body.coverage {
        coverage_shape(coverage, &mut budget)?;
    }
    canonical_size(body)?;
    Ok(())
}

struct CountWriter {
    bytes: usize,
    exhausted: bool,
}

impl Write for CountWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self
            .bytes
            .checked_add(buffer.len())
            .filter(|bytes| *bytes <= MAX_RECEIPT_BYTES)
        {
            Some(bytes) => {
                self.bytes = bytes;
                Ok(buffer.len())
            }
            None => {
                self.exhausted = true;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "certificate preflight byte budget exhausted",
                ))
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CanonicalLengthFormatter;

impl Formatter for CanonicalLengthFormatter {
    fn write_f32<W: ?Sized + Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        self.write_f64(writer, f64::from(value))
    }
    fn write_f64<W: ?Sized + Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        let number = serde_json::Number::from_f64(value).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "nonfinite certificate number")
        })?;
        // The input is one finite scalar, never a caller-sized document.
        let bytes = canonical_json_bytes(&number).map_err(io::Error::other)?;
        writer.write_all(&bytes)
    }
}

fn canonical_size(value: &impl Serialize) -> Result<usize, ComplianceCertificateError> {
    let mut writer = CountWriter {
        bytes: 0,
        exhausted: false,
    };
    let result = value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut writer,
        CanonicalLengthFormatter,
    ));
    if let Err(error) = result {
        return Err(if writer.exhausted {
            ComplianceBundleError::CapacityExceeded.into()
        } else {
            chio_core::error::Error::CanonicalJson(error.to_string()).into()
        });
    }
    Ok(writer.bytes)
}
