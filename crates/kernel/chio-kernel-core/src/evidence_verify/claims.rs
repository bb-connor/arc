//! Audit and transparency-preview claims derived from a verified bundle.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::receipt::checkpoint::{
    CheckpointPublication, CheckpointPublicationIdentityKind, CheckpointTransparencySummary,
};
use chio_core_types::receipt::evidence::{
    EvidenceAuditClaims, EvidenceExportBundle, EvidencePublicationState,
    EvidenceTransparencyClaims, EvidenceTransparencyPreviewClaim,
    EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
};

#[derive(Default)]
struct EvidenceTransparencyLogStats {
    checkpoint_count: u64,
    witness_count: u64,
    consistency_proof_count: u64,
    log_tree_size: u64,
}

fn trusted_publication_anchor(
    publications: &[CheckpointPublication],
    requested_trust_anchor: Option<&str>,
) -> Option<String> {
    let requested_trust_anchor = requested_trust_anchor
        .map(str::trim)
        .filter(|trust_anchor| !trust_anchor.is_empty());
    if publications.is_empty() {
        return None;
    }

    let mut shared_trust_anchor = None::<String>;
    for publication in publications {
        let binding = publication.trust_anchor_binding.as_ref()?;
        if binding.validate().is_err() {
            return None;
        }
        if binding.publication_identity.kind == CheckpointPublicationIdentityKind::LocalLog
            && binding.publication_identity.identity != publication.log_id
        {
            return None;
        }
        match shared_trust_anchor.as_deref() {
            Some(existing) if existing != binding.trust_anchor_ref => return None,
            None => shared_trust_anchor = Some(binding.trust_anchor_ref.clone()),
            Some(_) => {}
        }
    }

    match (shared_trust_anchor, requested_trust_anchor) {
        (Some(shared), Some(requested)) if shared == requested => Some(shared),
        (Some(_), Some(_)) => None,
        (Some(_), None) => None,
        (None, _) => None,
    }
}

#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "These conversions only widen collection lengths on the supported 32-bit and 64-bit targets."
)]
pub fn build_evidence_transparency_claims(
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
    trust_anchor: Option<&str>,
) -> EvidenceTransparencyClaims {
    let trust_anchor = trusted_publication_anchor(&transparency.publications, trust_anchor);
    let mut by_log = BTreeMap::<String, EvidenceTransparencyLogStats>::new();

    for publication in &transparency.publications {
        let stats = by_log.entry(publication.log_id.clone()).or_default();
        stats.checkpoint_count += 1;
        stats.log_tree_size = stats.log_tree_size.max(publication.log_tree_size);
    }
    for witness in &transparency.witnesses {
        by_log
            .entry(witness.log_id.clone())
            .or_default()
            .witness_count += 1;
    }
    for proof in &transparency.consistency_proofs {
        let stats = by_log.entry(proof.log_id.clone()).or_default();
        stats.consistency_proof_count += 1;
        stats.log_tree_size = stats.log_tree_size.max(proof.to_log_tree_size);
    }

    let checkpoint_logs = by_log.keys().cloned().collect::<Vec<_>>();
    let transparency_preview = if trust_anchor.is_some() {
        Vec::new()
    } else {
        by_log
            .into_iter()
            .map(|(log_id, stats)| EvidenceTransparencyPreviewClaim {
                log_id,
                claim: "append_only_local_checkpoint_log".to_string(),
                reason: "no trust anchor is attached, so log identity and prefix growth remain transparency-preview claims".to_string(),
                checkpoint_count: stats.checkpoint_count,
                witness_count: stats.witness_count,
                consistency_proof_count: stats.consistency_proof_count,
                log_tree_size: stats.log_tree_size,
            })
            .collect()
    };

    EvidenceTransparencyClaims {
        schema: EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
        publication_state: if trust_anchor.is_some() {
            EvidencePublicationState::TrustAnchored
        } else {
            EvidencePublicationState::TransparencyPreview
        },
        trust_anchor,
        audit: EvidenceAuditClaims {
            checkpoint_logs,
            signed_checkpoints: bundle.checkpoints.len() as u64,
            checkpoint_publications: transparency.publications.len() as u64,
            checkpoint_witnesses: transparency.witnesses.len() as u64,
            checkpoint_consistency_proofs: transparency.consistency_proofs.len() as u64,
            inclusion_proofs: bundle.inclusion_proofs.len() as u64,
            capability_lineage_records: bundle.capability_lineage.len() as u64,
        },
        transparency_preview,
    }
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
