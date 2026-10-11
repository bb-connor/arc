//! Authenticate authority-signed evidence before allowing local policy to promote assurance.

use crate::capability::{
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    trust_policy::{canonicalize_attestation_verifier, AttestationTrustPolicy},
};
use crate::crypto::PublicKey;
use crate::derive_runtime_attestation_appraisal;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::types::*;

/// Validate normalized caller evidence as an observation, without granting assurance.
///
/// Matching schema, verifier and claim strings does not authenticate evidence. A
/// configured policy therefore cannot promote this unsigned input. Callers with a
/// separately pinned attestation authority must use the signed-envelope boundary.
pub fn verify_runtime_attestation_record(
    evidence: &RuntimeAttestationEvidence,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, RuntimeAttestationVerificationError> {
    let record = build_runtime_attestation_record(evidence, trust_policy, now)?;
    if record.is_locally_accepted() {
        return Err(RuntimeAttestationVerificationError::UnauthenticatedEvidence);
    }
    Ok(record)
}

/// Authenticate an attestation authority's signed assertions against a local key pin.
///
/// The caller owns the authority's authorization, subject scope and revocation
/// standing. The key must come from local trust configuration, not the envelope.
/// This authenticates the authority's assertions; it does not verify a hardware
/// quote or supply the nonce/audience binding needed for fresh live admission.
/// Historical finding verification also checks the signed producing receipts.
pub fn verify_signed_runtime_attestation_record(
    envelope: &SignedExportEnvelope<RuntimeAttestationEvidence>,
    trusted_authority: &PublicKey,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, RuntimeAttestationVerificationError> {
    if &envelope.signer_key != trusted_authority {
        return Err(RuntimeAttestationVerificationError::UntrustedSigner);
    }
    if !envelope.verify_signature().map_err(|error| {
        RuntimeAttestationVerificationError::SignatureVerification(std::sync::Arc::new(error))
    })? {
        return Err(RuntimeAttestationVerificationError::InvalidSignature);
    }
    build_runtime_attestation_record(&envelope.body, trust_policy, now)
}

fn build_runtime_attestation_record(
    evidence: &RuntimeAttestationEvidence,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, RuntimeAttestationVerificationError> {
    let appraisal = derive_runtime_attestation_appraisal(evidence)?;
    let subject = verified_runtime_attestation_subject(evidence)?;
    let policy_outcome = verify_runtime_attestation_policy_outcome(evidence, trust_policy, now)?;
    Ok(VerifiedRuntimeAttestationRecord {
        evidence: evidence.clone(),
        provenance: VerifiedRuntimeAttestationProvenance {
            verifier_family: appraisal.verifier_family,
            verifier_adapter: appraisal.adapter.clone(),
            canonical_verifier: canonicalize_attestation_verifier(&evidence.verifier),
            matched_trust_rule: policy_outcome.matched_trust_rule.clone(),
        },
        appraisal,
        policy_outcome: policy_outcome.outcome,
        subject,
        verified_at: now,
    })
}

fn verified_runtime_attestation_subject(
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisalResultSubject, RuntimeAttestationVerificationError> {
    Ok(RuntimeAttestationAppraisalResultSubject {
        runtime_identity: evidence.runtime_identity.clone(),
        workload_identity: evidence.normalized_workload_identity()?,
    })
}

#[derive(Debug, Clone)]
struct VerifiedRuntimeAttestationPolicyVerification {
    outcome: RuntimeAttestationPolicyOutcome,
    matched_trust_rule: Option<String>,
}

fn verify_runtime_attestation_policy_outcome(
    evidence: &RuntimeAttestationEvidence,
    trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationPolicyVerification, RuntimeAttestationVerificationError> {
    let trust_policy_configured = trust_policy.is_some_and(|policy| !policy.rules.is_empty());
    if trust_policy_configured {
        let resolved = evidence
            .resolve_effective_runtime_assurance(trust_policy, now)
            .map_err(RuntimeAttestationVerificationError::TrustPolicy)?;
        let matched_trust_rule = resolved.matched_rule.clone();
        return Ok(VerifiedRuntimeAttestationPolicyVerification {
            outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: true,
                accepted: true,
                effective_tier: resolved.effective_tier,
                reason: matched_trust_rule
                    .as_ref()
                    .map(|rule| format!("matched attestation trust rule `{rule}`")),
            },
            matched_trust_rule,
        });
    }

    evidence.validate_workload_identity_binding()?;
    if !evidence.is_valid_at(now) {
        return Err(RuntimeAttestationVerificationError::StaleEvidence {
            now,
            issued_at: evidence.issued_at,
            expires_at: evidence.expires_at,
        });
    }

    Ok(VerifiedRuntimeAttestationPolicyVerification {
        outcome: RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: false,
            effective_tier: RuntimeAssuranceTier::None,
            reason: Some(
                "runtime attestation evidence did not cross a local verified trust boundary"
                    .to_string(),
            ),
        },
        matched_trust_rule: None,
    })
}
