//! Pre-agreement fixture trust and actual Finding evidence assessment.
//! Pre-agreement standing covers governance. Execution contexts additionally
//! evaluate the exact retained receipt, checkpoint and signer standing bundle.
use crate::common::{digest, Result};
use chio_core_types::{
    canonical_json_bytes, receipt::lineage::SignedExportEnvelope, Keypair, PublicKey,
};
use chio_finding::*;
use chio_finding_verifier::{
    verify_finding_evidence, FindingCheckpointSignerStatusTrust, FindingEvidenceBundle,
    FindingVerifierTrustRoots, NoNonceEvidence, ResolvedReceiptEvidence,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONTEXT_SCHEMA: &str = "chio.experimental.funded-finding-context.v1";
pub const ASSESSMENT_SCHEMA: &str = "chio.experimental.funded-finding-assessment.v1";

pub const EXECUTION_CONTEXT_SCHEMA: &str = "chio.experimental.funded-finding-context.v2";

#[path = "finding_context.rs"]
mod context_bootstrap;
pub use context_bootstrap::{
    fixture_context, fixture_execution_context, signed_execution_context, ContextSigners,
};

/// Persist before agreement signing. The independently loaded agreement policy
/// pins the digest of this complete context, including every authority key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceContext {
    pub schema: String,
    pub governance_authority: FindingAuthorityKeyPolicy,
    pub profile: SignedFindingChallengeVerifierProfile,
    pub governance_standing: FindingCheckpointSignerStatusTrust,
    pub admitted_kernel_key: PublicKey,
    pub collateral_authority: FindingAuthorityKeyPolicy,
}

/// Derived exclusively from the verifier's immutable draft. This local
/// assessment is carried inside the funding verifier's signed decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assessment {
    pub schema: String,
    pub context_sha256: String,
    pub finding_artifact_sha256: String,
    pub resolved_evidence_bundle_sha256: String,
    pub evaluated_at: u64,
    pub required_facets: Vec<FindingFacetKind>,
    pub facets: Vec<FindingFacetResult>,
    pub outcome: Outcome,
}

/// The pin and requirements must come from the original signed agreement's
/// policy, never from the submission. Raw Finding bytes are checked canonically
/// by the actual verifier before any facet is evaluated.
#[cfg(test)]
pub fn evaluate(
    raw_finding: &[u8],
    context: &AcceptanceContext,
    pinned_context_sha256: &str,
    requirements: &[FindingFacetKind],
    now: u64,
) -> Result<Assessment> {
    evaluate_with_evidence(
        raw_finding,
        context,
        pinned_context_sha256,
        requirements,
        now,
        None,
    )
}

/// Evaluate the original retained evidence under the agreement-pinned context.
pub fn evaluate_with_evidence(
    raw_finding: &[u8],
    context: &AcceptanceContext,
    pinned_context_sha256: &str,
    requirements: &[FindingFacetKind],
    now: u64,
    evidence: Option<&super::execution_evidence::Bundle>,
) -> Result<Assessment> {
    if digest(context)? != pinned_context_sha256 {
        return Err("Finding verifier context differs from the pre-agreement pin".into());
    }
    validate_context(
        context,
        &context.profile.body.verifier_report_signer.key,
        &context.admitted_kernel_key,
        now,
    )?;
    let mut required: BTreeSet<_> = requirements.iter().copied().collect();
    if required.len() != requirements.len() {
        return Err("Finding facet requirements contain duplicates".into());
    }
    let mut standing = context.governance_standing.clone();
    if let Some(evidence) = evidence {
        validate_execution_bundle(context, evidence)?;
        standing
            .signed_statuses
            .extend(evidence.signer_statuses.iter().cloned());
    }
    let trust = FindingVerifierTrustRoots {
        governance_authority: context.governance_authority.key.clone(),
        governance_authority_policy: context.governance_authority.clone(),
        profile: context.profile.clone(),
        admitted_kernel_keys: vec![context.admitted_kernel_key.clone()],
        collateral_authority: context.collateral_authority.clone(),
        fee_schedule_authorities: Vec::new(),
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        status_operator_authorization: None,
        status_freshness_policy: None,
        checkpoint_signer_status: Some(standing),
        trusted_time: now,
        trust_root_snapshot_sha256: pinned_context_sha256.into(),
        resolver_policy_sha256: digest(&context.profile.body.resolver_policy_ref)?,
        trusted_time_input_sha256: digest(&("funded-w0-local-clock-v1", now))?,
    };
    let bundle = FindingEvidenceBundle {
        receipts: evidence
            .map(|evidence| -> Result<_> {
                Ok(vec![ResolvedReceiptEvidence {
                    receipt: evidence.receipt.clone(),
                    canonical_receipt_bytes: canonical_json_bytes(&evidence.receipt)?,
                    inclusion_proof: evidence.inclusion.clone(),
                }])
            })
            .transpose()?
            .unwrap_or_default(),
        checkpoints: evidence
            .map(|evidence| evidence.checkpoints.clone())
            .unwrap_or_default(),
        checkpoint_transparency: evidence
            .map(|evidence| evidence.transparency.clone())
            .unwrap_or_default(),
        finding_delivery: None,
        recipe_preimage: None,
        status_proof_input: None,
        runtime_attestation: None,
        runtime_appraisal: None,
        bond_snapshot: None,
        nonce_resolver: &NoNonceEvidence,
    };
    let draft = verify_finding_evidence(std::str::from_utf8(raw_finding)?, &trust, &bundle)?;
    required.extend(draft.required_facets(&context.profile.body));
    Ok(Assessment {
        schema: ASSESSMENT_SCHEMA.into(),
        context_sha256: pinned_context_sha256.into(),
        finding_artifact_sha256: draft.finding_artifact_sha256().into(),
        resolved_evidence_bundle_sha256: draft.resolved_evidence_bundle_sha256().into(),
        evaluated_at: draft.evaluation_time(),
        required_facets: required.iter().copied().collect(),
        facets: draft.facets().to_vec(),
        outcome: classify(
            draft.facets(),
            &required.iter().copied().collect::<Vec<_>>(),
        ),
    })
}

/// Convenience for trusted typed Finding values already decoded at ingress.
#[cfg(test)]
pub fn evaluate_finding(
    finding: &Finding,
    context: &AcceptanceContext,
    pin: &str,
    requirements: &[FindingFacetKind],
    now: u64,
) -> Result<Assessment> {
    evaluate(
        &canonical_json_bytes(finding)?,
        context,
        pin,
        requirements,
        now,
    )
}

#[cfg(test)]
#[path = "finding_acceptance_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Accepted,
    Rejected,
    Unavailable,
    Unsupported,
}

fn classify(facets: &[FindingFacetResult], required: &[FindingFacetKind]) -> Outcome {
    if facets
        .iter()
        .any(|f| f.outcome == FindingFacetOutcome::Failed)
    {
        return Outcome::Rejected;
    }
    if required.iter().any(|f| {
        matches!(
            f,
            FindingFacetKind::KernelAndRevocationTrust
                | FindingFacetKind::IssuerLineage
                | FindingFacetKind::IntentBinding
        )
    }) {
        return Outcome::Unsupported;
    }
    if required.iter().any(|kind| {
        !facets
            .iter()
            .any(|f| f.facet == *kind && f.outcome == FindingFacetOutcome::Verified)
    }) {
        return Outcome::Unavailable;
    }
    Outcome::Accepted
}

/// Check the signed assessment's shape and Finding/policy bindings at ingress.
/// This does not authenticate its enclosing verifier signature.
#[cfg(test)]
pub fn validate_assessment(
    assessment: &Assessment,
    finding: &Finding,
    context: &AcceptanceContext,
    requirements: &[FindingFacetKind],
) -> Result<()> {
    validate_assessment_with_evidence(assessment, finding, context, requirements, None)
}

/// Replay the exact assessment at its original time using original evidence.
pub fn validate_assessment_with_evidence(
    assessment: &Assessment,
    finding: &Finding,
    context: &AcceptanceContext,
    requirements: &[FindingFacetKind],
    evidence: Option<&super::execution_evidence::Bundle>,
) -> Result<()> {
    validate_context(
        context,
        &context.profile.body.verifier_report_signer.key,
        &context.admitted_kernel_key,
        assessment.evaluated_at,
    )?;
    let mut required: BTreeSet<_> = requirements.iter().copied().collect();
    if required.len() != requirements.len() {
        return Err("Finding facet requirements contain duplicates".into());
    }
    required.extend(required_finding_facets(finding, &context.profile.body));
    if assessment.schema != ASSESSMENT_SCHEMA
        || assessment.context_sha256 != digest(context)?
        || assessment.finding_artifact_sha256 != digest(finding)?
        || assessment.evaluated_at < finding.issued_at
        || assessment.evaluated_at >= finding.expires_at
        || assessment
            .facets
            .iter()
            .map(|f| f.facet)
            .collect::<Vec<_>>()
            != FindingFacetKind::ALL
        || assessment.required_facets != required.into_iter().collect::<Vec<_>>()
        || assessment.facets.iter().any(|facet| {
            facet.reason.trim().is_empty()
                || facet.reason.len() > MAX_FINDING_TEXT_BYTES
                || facet.evidence_refs.len() > MAX_FINDING_ARTIFACT_ITEMS
                || facet
                    .evidence_refs
                    .iter()
                    .any(|r| r.is_empty() || r.len() > MAX_FINDING_IDENTIFIER_BYTES)
        })
        || assessment.outcome != classify(&assessment.facets, &assessment.required_facets)
        || assessment.resolved_evidence_bundle_sha256.len() != 64
        || !assessment
            .resolved_evidence_bundle_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Finding assessment structure, binding or outcome invalid".into());
    }
    // Re-derive the original draft so even a freshly signed row cannot invent
    // optional backing, reasons or a different resolved evidence commitment.
    let derived = evaluate_with_evidence(
        &canonical_json_bytes(finding)?,
        context,
        &digest(context)?,
        requirements,
        assessment.evaluated_at,
        evidence,
    )?;
    if canonical_json_bytes(assessment)? != canonical_json_bytes(&derived)? {
        return Err("Finding assessment differs from derived evidence verification".into());
    }
    Ok(())
}

/// Validate persisted fixture authority before admitting a new agreement.
/// Governance standing uses the existing verifier lifecycle helper; despite
/// its exported historical name, it checks any independently pinned authority.
pub fn validate_context(
    context: &AcceptanceContext,
    verifier_key: &PublicKey,
    kernel_key: &PublicKey,
    now: u64,
) -> Result<()> {
    let profile = &context.profile.body;
    let execution = match context.schema.as_str() {
        CONTEXT_SCHEMA if profile.required_receipt_semantics == "chio.mediated_spend.v1" => false,
        EXECUTION_CONTEXT_SCHEMA if profile.required_receipt_semantics == chio_core_types::receipt::execution_evidence::PRE_SETTLEMENT_EXECUTION_PROFILE => true,
        _ => return Err("Finding context schema and receipt semantics disagree".into()),
    };
    if profile.verifier_report_signer.key != *verifier_key
        || context.admitted_kernel_key != *kernel_key
        || profile.governance_authority != context.governance_authority.key
        || profile.required_facets != context_floor(execution)
        || now < profile.issued_at
        || now >= profile.expires_at
        || now < profile.verifier_report_signer.valid_from
        || now >= profile.verifier_report_signer.valid_until
        || profile.expires_at.saturating_sub(profile.issued_at) > 86400
        || context.governance_standing.signed_statuses.len() != 1
        || context.governance_standing.status_authority.key == *verifier_key
        || context.collateral_authority.key == *verifier_key
        || !profile
            .receipt_signers
            .iter()
            .any(|r| r.role == FindingReceiptRole::Production && r.policy.key == *kernel_key)
    {
        return Err("Finding fixture context changes pinned roles, floor or validity".into());
    }
    if execution {
        let status_key = &context.governance_standing.status_authority.key;
        if profile.checkpoint_logs.len() != 1
            || profile
                .receipt_signers
                .iter()
                .filter(|r| r.role == FindingReceiptRole::Production)
                .count()
                != 1
            || profile
                .receipt_signers
                .iter()
                .any(|r| r.policy.key == *status_key)
            || profile
                .checkpoint_logs
                .iter()
                .any(|c| c.signer.key == *status_key)
            || [
                &context.governance_authority.key,
                &context.collateral_authority.key,
                &profile.purchase_authority.key,
                &profile.failed_delivery_authority.key,
            ]
            .contains(&status_key)
            || profile.resource_caps.max_evidence_receipts != 1
        {
            return Err(
                "Execution context requires independent bounded receipt and checkpoint authorities"
                    .into(),
            );
        }
    }
    verify_signed_profile(&context.profile, &context.governance_authority.key)?;
    chio_finding_verifier::validate_supported_finding_verifier_profile(profile)?;
    chio_finding_verifier::verify_status_operator_standing(
        &context.governance_authority,
        profile.issued_at,
        now,
        Some(&context.governance_standing),
    )
    .map_err(|reason| format!("Finding governance standing invalid: {reason}"))?;
    Ok(())
}

fn context_floor(execution: bool) -> Vec<FindingFacetKind> {
    if execution {
        vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::GuaranteeConsistency,
        ]
    } else {
        vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::GuaranteeConsistency,
        ]
    }
}

/// Enforce the local one-receipt profile before general cryptographic checks.
pub(super) fn validate_execution_bundle(
    context: &AcceptanceContext,
    evidence: &super::execution_evidence::Bundle,
) -> Result<()> {
    if context.schema != EXECUTION_CONTEXT_SCHEMA
        || evidence.schema != super::execution_evidence::BUNDLE_SCHEMA
        || evidence.checkpoints.len() != 1
        || evidence.signer_statuses.len() != 2
        || canonical_json_bytes(evidence)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("Execution evidence is outside the agreement-pinned bounded profile".into());
    }
    let checkpoint = &evidence.checkpoints[0];
    if checkpoint.body.checkpoint_seq != 1
        || checkpoint.body.batch_start_seq != 1
        || checkpoint.body.batch_end_seq != 1
        || checkpoint.body.tree_size != 1
        || evidence.inclusion.checkpoint_seq != 1
        || evidence.inclusion.receipt_seq != 1
        || evidence.inclusion.leaf_index != 0
    {
        return Err("Execution checkpoint does not cover the original single receipt".into());
    }
    let production = context
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|r| r.role == FindingReceiptRole::Production)
        .ok_or("Execution profile production signer missing")?;
    let checkpoint_policy = context
        .profile
        .body
        .checkpoint_logs
        .first()
        .ok_or("Execution profile checkpoint signer missing")?;
    for ((policy, acted_at), signed) in [
        (&production.policy, evidence.receipt.timestamp),
        (&checkpoint_policy.signer, checkpoint.body.issued_at),
    ]
    .into_iter()
    .zip(&evidence.signer_statuses)
    {
        let status = &signed.body;
        if status.authority_id != policy.authority_id
            || status.key != policy.key
            || status.key_epoch != policy.key_epoch
            || status.status_ref != policy.revocation_status_ref
            || status.observed_at < acted_at
        {
            return Err("Execution signer standing does not match the pre-agreement role".into());
        }
    }
    Ok(())
}
