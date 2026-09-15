//! Conservative Finding artifacts backed by the original retained native return.
//! These checks do not assert settled-spend, bond, status or runtime assurance.
use super::{agreement::Policy, journal::Journal, native::CURRENCY};
use crate::common::{digest, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chio_core_types::{
    canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex, Keypair, Signature,
};
use chio_finding::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub allocation_id: String,
    pub agreement_sha256: String,
    pub authority_uuid: String,
    pub operation_id: String,
    pub hold_id: String,
    pub authorization_id: String,
    pub request_sha256: String,
    pub outcome_id: String,
    pub raw_outcome_sha256: String,
    pub expires_at: u64,
}

pub struct Evidence {
    pub binding: Binding,
    pub input: String,
    pub output: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionBody {
    pub schema: String,
    pub binding: Binding,
    pub input_sha256: String,
    pub output_sha256: String,
    pub finding: Finding,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signature: Signature,
}

pub type Submission = Signed<SubmissionBody>;

pub fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    if raw.len() > 256 * 1024 {
        return Err("artifact exceeds bounded profile".into());
    }
    let canonical = canonical_json_bytes_from_str(std::str::from_utf8(raw)?)?;
    let value: T = serde_json::from_slice(raw)?;
    if canonical != raw || canonical_json_bytes(&value)? != raw {
        return Err("artifact must have exact canonical typed bytes".into());
    }
    Ok(value)
}

pub(super) fn read<T: DeserializeOwned + Serialize>(
    path: impl AsRef<std::path::Path>,
) -> Result<T> {
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(super::wire::MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    decode(&raw)
}

pub fn sign<T: Serialize>(body: T, key: &Keypair) -> Result<Signed<T>> {
    let signature = key.sign(&canonical_json_bytes(&body)?);
    Ok(Signed { body, signature })
}

fn reveal(bytes: &[u8]) -> Value {
    serde_json::json!({"media_type":"application/json","payload_b64":STANDARD.encode(bytes)})
}

pub fn submit(
    original: &Evidence,
    output: &Value,
    key: &Keypair,
    custody: &Journal,
) -> Result<Submission> {
    let output = canonical_json_bytes(output)?;
    let input_sha256 = custody.put_blob(original.input.as_bytes())?;
    let output_sha256 = custody.put_blob(&output)?;
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.into(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "security:openapi:authentication-declarations".into(),
            context_sha256: digest(&original.binding)?,
            outcome_class: FindingOutcomeClass::PositiveResult,
        },
        guarantee_class: FindingGuaranteeClass::Asserted,
        payload_sha256: digest(&reveal(&output))?,
        payload_media_type: "application/json".into(),
        evidence_receipt_ids: Vec::new(),
        evidence_checkpoint_ref: "unavailable:pre-settlement".into(),
        evidence_cost: chio_core_types::capability::scope::MonetaryAmount {
            units: 100,
            currency: CURRENCY.into(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Asserted,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "unbacked:experimental-funded-w0".into(),
        status_feed_ref: "unavailable:experimental-funded-w0".into(),
        license_ref: None,
        price_hint_ref: None,
        issuer: key.public_key(),
        issued_at: crate::common::now()?,
        expires_at: original.binding.expires_at,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    let body = SubmissionBody {
        schema: "chio.experimental.native-funded-submission.v1".into(),
        binding: original.binding.clone(),
        input_sha256,
        output_sha256,
        finding: sign_finding(finding, key)?,
    };
    sign(body, key)
}

/// `false` is a retrieved, authenticated result contradicting the original
/// native output. Invalid authority, missing evidence and malformed artifacts
/// remain errors; callers must never turn them into financial decisions.
pub fn verify(raw: &[u8], original: &Evidence, policy: &Policy, custody: &Journal) -> Result<bool> {
    let submission: Submission = decode(raw)?;
    super::wire::submission(&submission)?;
    let body = &submission.body;
    if body.schema != "chio.experimental.native-funded-submission.v1"
        || body.binding != original.binding
        || body.binding.authority_uuid != policy.authority_uuid
        || !policy
            .provider_key
            .verify_strict(&canonical_json_bytes(body)?, &submission.signature)
    {
        return Err("submission changed original authority or native binding".into());
    }
    let finding = &body.finding;
    verify_finding(finding)?;
    if finding.issuer != policy.provider_key
        || finding.descriptor.context_sha256 != digest(&original.binding)?
        || finding.descriptor.topic != "security:openapi:authentication-declarations"
        || finding.descriptor.outcome_class != FindingOutcomeClass::PositiveResult
        || finding.guarantee_class != FindingGuaranteeClass::Asserted
        || finding.evidence_class != FindingEvidenceClass::Asserted
        || !finding.evidence_receipt_ids.is_empty()
        || finding.evidence_checkpoint_ref != "unavailable:pre-settlement"
        || finding.runtime_assurance_tier.is_some()
        || finding.replay_recipe_sha256.is_some()
        || finding.intent_commitment_receipt_id.is_some()
        || finding.bond_ref != "unbacked:experimental-funded-w0"
        || finding.status_feed_ref != "unavailable:experimental-funded-w0"
        || finding.license_ref.is_some()
        || finding.price_hint_ref.is_some()
        || finding.evidence_cost.units != 100
        || finding.evidence_cost.currency != CURRENCY
        || finding.expires_at != original.binding.expires_at
        || finding.issued_at > crate::common::now()?
        || crate::common::now()? >= finding.expires_at
        || finding.payload_media_type != "application/json"
    {
        return Err("Finding exceeds supported pre-settlement assurance profile".into());
    }
    let input = custody.blob(&body.input_sha256)?;
    let output = custody.blob(&body.output_sha256)?;
    if input != original.input.as_bytes()
        || body.input_sha256 != sha256_hex(original.input.as_bytes())
        || finding.payload_sha256 != digest(&reveal(&output))?
    {
        return Err("Finding custody or original input binding changed".into());
    }
    Ok(output == canonical_json_bytes(&original.output)?)
}
