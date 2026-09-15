//! Pre-agreement fixture trust and actual Finding evidence assessment.
//! Fixture authority standing covers profile governance only. It supplies no
//! receipt, collateral, Finding status, or runtime-assurance evidence.
use crate::common::{digest, Result};
use chio_core_types::{
    canonical_json_bytes, receipt::lineage::SignedExportEnvelope, Keypair, PublicKey,
};
use chio_finding::*;
use chio_finding_verifier::{
    verify_finding_evidence, FindingCheckpointSignerStatusTrust, FindingEvidenceBundle,
    FindingVerifierTrustRoots, NoNonceEvidence,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONTEXT_SCHEMA: &str = "chio.experimental.funded-finding-context.v1";
pub const ASSESSMENT_SCHEMA: &str = "chio.experimental.funded-finding-assessment.v1";

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

fn authority(key: PublicKey, role: &str, now: u64, expires_at: u64) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("funded-w0-fixture/{role}"),
        key,
        key_epoch: 1,
        valid_from: now,
        valid_until: expires_at,
        rotation_policy_ref: format!("funded-w0-fixture/rotation/{role}"),
        revocation_status_ref: format!("funded-w0-fixture/status/{role}"),
    }
}

/// Local fixture bootstrap, called once before buyer/provider agreement.
/// Distinct generated signers authenticate governance and its standing. Their
/// private keys are discarded; the persisted context cannot refresh itself.
pub fn fixture_context(
    verifier_key: &PublicKey,
    kernel_key: &PublicKey,
    now: u64,
    expires_at: u64,
) -> Result<AcceptanceContext> {
    if now >= expires_at || expires_at - now > 86400 {
        return Err("Finding fixture trust requires a bounded one-day window".into());
    }
    let governance = Keypair::generate();
    let status = Keypair::generate();
    let new_authority = |role| authority(Keypair::generate().public_key(), role, now, expires_at);
    let governance_authority = authority(governance.public_key(), "governance", now, expires_at);
    let checkpoint = new_authority("checkpoint");
    let mut body = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.into(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "funded-w0-fixture".into(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: authority(kernel_key.clone(), "production", now, expires_at),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: new_authority("delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: new_authority("replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: finding_checkpoint_log_id(&checkpoint.key),
            signer: checkpoint,
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "unavailable:funded-w0-fixture".into(),
            key_hex: "00".repeat(32),
            registry_ref: "unavailable:funded-w0-fixture".into(),
            key_epoch: 1,
            valid_from: now,
            valid_until: expires_at,
            revocation_status_ref: "unavailable:funded-w0-fixture".into(),
        },
        allowed_runner_manifests: vec![digest(&"funded-w0-no-replay-runner")?],
        required_receipt_semantics: "chio.mediated_spend.v1".into(),
        resolver_policy_ref: "funded-w0-empty-evidence-v1".into(),
        retention_policy_ref: "funded-w0-journal-v1".into(),
        resource_caps: FindingResourceCaps {
            max_recipe_bytes: 262144,
            max_evidence_receipts: 1,
            max_runtime_secs: 60,
            max_memory_bytes: 16777216,
        },
        predicate_engine: FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1.into(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: authority(verifier_key.clone(), "verifier", now, expires_at),
        purchase_authority: new_authority("purchase"),
        failed_delivery_authority: new_authority("failed-delivery"),
        issued_at: now,
        expires_at,
    };
    body.profile_id = compute_profile_id(&body)?;
    let profile = SignedExportEnvelope::sign(body, &governance)?;
    let standing = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.into(),
            status_ref: governance_authority.revocation_status_ref.clone(),
            authority_id: governance_authority.authority_id.clone(),
            key: governance.public_key(),
            key_epoch: 1,
            revoked_from: None,
            observed_at: now,
        },
        &status,
    )?;
    Ok(AcceptanceContext {
        schema: CONTEXT_SCHEMA.into(),
        governance_authority,
        profile,
        governance_standing: FindingCheckpointSignerStatusTrust {
            signed_statuses: vec![standing],
            status_authority: authority(status.public_key(), "authority-status", now, expires_at),
            max_age_secs: expires_at - now,
        },
        admitted_kernel_key: kernel_key.clone(),
        collateral_authority: new_authority("collateral"),
    })
}

/// The pin and requirements must come from the original signed agreement's
/// policy, never from the submission. Raw Finding bytes are checked canonically
/// by the actual verifier before any facet is evaluated.
pub fn evaluate(
    raw_finding: &[u8],
    context: &AcceptanceContext,
    pinned_context_sha256: &str,
    requirements: &[FindingFacetKind],
    now: u64,
) -> Result<Assessment> {
    if context.schema != CONTEXT_SCHEMA || digest(context)? != pinned_context_sha256 {
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
        checkpoint_signer_status: Some(context.governance_standing.clone()),
        trusted_time: now,
        trust_root_snapshot_sha256: pinned_context_sha256.into(),
        resolver_policy_sha256: digest(&context.profile.body.resolver_policy_ref)?,
        trusted_time_input_sha256: digest(&("funded-w0-local-clock-v1", now))?,
    };
    let bundle = FindingEvidenceBundle {
        receipts: Vec::new(),
        checkpoints: Vec::new(),
        checkpoint_transparency: Default::default(),
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
pub fn validate_assessment(
    assessment: &Assessment,
    finding: &Finding,
    context: &AcceptanceContext,
    requirements: &[FindingFacetKind],
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
    // This profile resolves no external evidence. Re-derive the exact retained
    // draft at its original evaluation instant so even a freshly signed row
    // cannot invent optional backing, reasons, or resolved evidence digests.
    let derived = evaluate_finding(
        finding,
        context,
        &digest(context)?,
        requirements,
        assessment.evaluated_at,
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
    if context.schema != CONTEXT_SCHEMA
        || profile.verifier_report_signer.key != *verifier_key
        || context.admitted_kernel_key != *kernel_key
        || profile.governance_authority != context.governance_authority.key
        || profile.required_facets
            != [
                FindingFacetKind::ArtifactIntegrity,
                FindingFacetKind::GuaranteeConsistency,
            ]
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
