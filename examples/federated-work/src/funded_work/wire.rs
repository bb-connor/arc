//! Strict parsing and structural bounds for the registered funded-work profile.
//! Parsing establishes neither signer authority nor payment eligibility.
use super::{agreement::SignedAgreement, child::Dependency, evidence, verification::Decision};
use crate::common::Result;
use chio_core_types::canonical_json_bytes;
use chio_finding::FindingFacetKind;
use serde_json::Value;

pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024;

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("work identifier exceeds the registered profile".into());
    }
    Ok(())
}

fn hex(value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("work hex value has noncanonical encoding".into());
    }
    Ok(())
}

fn sha256(value: &str) -> Result<()> {
    hex(value, 64)
}

fn key(value: &chio_core_types::PublicKey) -> Result<()> {
    if value.algorithm() != chio_core_types::crypto::SigningAlgorithm::Ed25519 {
        return Err("registered funded work requires Ed25519 keys".into());
    }
    hex(&value.to_hex(), 64)
}

fn signature(value: &chio_core_types::Signature) -> Result<()> {
    if value.algorithm() != chio_core_types::crypto::SigningAlgorithm::Ed25519 {
        return Err("registered funded work requires Ed25519 signatures".into());
    }
    hex(&value.to_hex(), 128)
}

fn safe_integer(value: u64) -> Result<()> {
    if value > super::allocation::MAX_UNITS {
        return Err("work integer exceeds the I-JSON bound".into());
    }
    Ok(())
}

pub(super) fn requirements(facets: &[FindingFacetKind]) -> Result<()> {
    if facets.len() > FindingFacetKind::ALL.len()
        || !facets.contains(&FindingFacetKind::ArtifactIntegrity)
        || !facets.contains(&FindingFacetKind::GuaranteeConsistency)
        || facets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("work facet requirements must retain the floor in canonical order".into());
    }
    Ok(())
}

pub(super) fn agreement(signed: &SignedAgreement) -> Result<()> {
    let b = &signed.body;
    key(&b.buyer_key)?;
    key(&b.provider_key)?;
    signature(&signed.buyer_signature)?;
    signature(&signed.provider_signature)?;
    if b.schema != super::agreement::AGREEMENT_SCHEMA {
        return Err("unsupported registered work agreement".into());
    }
    for id in [&b.authority_uuid, &b.request_id] {
        identifier(id)?;
    }
    for hash in [
        &b.policy_sha256,
        &b.request_sha256,
        &b.finding_context_sha256,
    ] {
        sha256(hash)?;
    }
    requirements(&b.required_finding_facets)?;
    b.domain.validate()?;
    b.terms()?.abi(&b.domain.escrow)?;
    if let Some(waiver) = &b.capture_waiver_terms {
        signature(&waiver.receiver_signature)?;
        signature(&waiver.counterparty_signature)?;
        let t = &waiver.body;
        if t.schema != chio_kernel::payment::CONTRACTUAL_CAPTURE_WAIVER_SCHEMA {
            return Err("unsupported original capture waiver".into());
        }
        for hash in [
            &t.policy_digest,
            &t.contract_context_digest,
            &t.capability_digest,
        ] {
            sha256(hash)?;
        }
        identifier(&t.request_id)?;
        safe_integer(t.issued_at_unix_ms)?;
        safe_integer(t.expires_at_unix_ms)?;
        if t.issued_at_unix_ms == 0
            || t.expires_at_unix_ms <= t.issued_at_unix_ms
            || t.expires_at_unix_ms - t.issued_at_unix_ms > 86_400_000
        {
            return Err("invalid capture waiver lifetime".into());
        }
    }
    Ok(())
}

fn binding(b: &evidence::Binding) -> Result<()> {
    super::allocation::hash(&b.allocation_id)?;
    for hash in [
        &b.agreement_sha256,
        &b.request_sha256,
        &b.raw_outcome_sha256,
    ] {
        sha256(hash)?;
    }
    for id in [
        &b.authority_uuid,
        &b.operation_id,
        &b.hold_id,
        &b.authorization_id,
        &b.outcome_id,
    ] {
        identifier(id)?;
    }
    safe_integer(b.expires_at)
}

pub(super) fn submission(signed: &evidence::Submission) -> Result<()> {
    let b = &signed.body;
    signature(&signed.signature)?;
    key(&b.finding.issuer)?;
    if b.schema != chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_SUBMISSION_V1_SCHEMA {
        return Err("unsupported registered work submission".into());
    }
    binding(&b.binding)?;
    sha256(&b.input_sha256)?;
    sha256(&b.output_sha256)?;
    hex(&b.finding.signature, 128)?;
    b.finding.validate()?;
    Ok(())
}

pub(super) fn dependency(signed: &evidence::Signed<Dependency>) -> Result<()> {
    let b = &signed.body;
    signature(&signed.signature)?;
    if b.schema != chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_DEPENDENCY_V1_SCHEMA {
        return Err("unsupported registered work dependency".into());
    }
    for hash in [
        &b.parent_agreement,
        &b.child_agreement,
        &b.parent_request,
        &b.child_request,
        &b.input_sha256,
    ] {
        sha256(hash)?;
    }
    identifier(&b.parent_authority)?;
    identifier(&b.child_authority)?;
    if b.parent_authority == b.child_authority {
        return Err("funded dependency requires separate authorities".into());
    }
    Ok(())
}

pub(super) fn decision(signed: &Decision) -> Result<()> {
    let b = &signed.body;
    signature(&signed.signature)?;
    if b.schema != chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_DECISION_V2_SCHEMA {
        return Err("unsupported registered work decision".into());
    }
    binding(&b.binding)?;
    for hash in [
        &b.commitment,
        &b.claim_transaction_hash,
        &b.claim_block_hash,
    ] {
        super::allocation::hash(hash)?;
    }
    for hash in [&b.finding_id, &b.checker_sha256] {
        sha256(hash)?;
    }
    let a = &b.finding_assessment;
    if a.schema != super::finding_acceptance::ASSESSMENT_SCHEMA
        || a.facets.iter().map(|f| f.facet).collect::<Vec<_>>() != FindingFacetKind::ALL
    {
        return Err("work decision lacks a canonical complete assessment".into());
    }
    for hash in [
        &a.context_sha256,
        &a.finding_artifact_sha256,
        &a.resolved_evidence_bundle_sha256,
    ] {
        sha256(hash)?;
    }
    safe_integer(a.evaluated_at)?;
    requirements(&a.required_facets)?;
    for facet in &a.facets {
        if facet.reason.trim().is_empty()
            || facet.reason.len() > chio_finding::MAX_FINDING_TEXT_BYTES
            || facet.evidence_refs.len() > chio_finding::MAX_FINDING_ARTIFACT_ITEMS
        {
            return Err("work facet explanation exceeds registered bounds".into());
        }
        for reference in &facet.evidence_refs {
            identifier(reference)?;
        }
    }
    Ok(())
}

/// Parse one of the registered signed shapes without claiming authority.
pub fn parse(raw: &[u8]) -> Result<Value> {
    let value: Value = evidence::decode(raw)?;
    let schema = value["body"]["schema"]
        .as_str()
        .ok_or("work artifact schema missing")?;
    match schema {
        chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_AGREEMENT_V2_SCHEMA => {
            let signed: SignedAgreement = evidence::decode(raw)?;
            agreement(&signed)?;
        }
        chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_SUBMISSION_V1_SCHEMA => {
            let signed: evidence::Submission = evidence::decode(raw)?;
            submission(&signed)?;
        }
        chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_DEPENDENCY_V1_SCHEMA => {
            let signed: evidence::Signed<Dependency> = evidence::decode(raw)?;
            dependency(&signed)?;
        }
        chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_DECISION_V2_SCHEMA => {
            let signed: Decision = evidence::decode(raw)?;
            decision(&signed)?;
        }
        _ => return Err("unregistered or unsupported work artifact".into()),
    }
    Ok(
        serde_json::json!({"schema":schema,"sha256":chio_core_types::sha256_hex(&canonical_json_bytes(&value)?),"authorityVerified":false}),
    )
}
