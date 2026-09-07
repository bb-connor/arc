use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    CorrelatedFindingReceiptBody, DetectorHealthReceiptBody, MAX_ACTIVE_DEFENSE_JSON_INTEGER,
};
use chio_core::{canonical_json_bytes, sha256};
use chio_kernel::{
    ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
    AuthoritativeCorrelatedFindingEvidence,
};
use chio_quarantine::{CorrelationOutcome, CorrelationStatus};
use chio_security_types::ports::{
    CanonicalBody, Digest32, PortError, PortResult, ReceiptAppendRequest, RecordId,
    SecurityReceiptSink,
};
use chio_security_types::{
    CorrelatedFinding, DetectorGroupBindingEvidence, DetectorHealthEvidence, DetectorHealthKind,
    DetectorWatermarkEvidence,
};

const FINDING_HASH_DOMAIN: &[u8] = b"chio.attested-correlated-finding.v1\0";
const FINDING_TRANSITION_DOMAIN: &[u8] = b"chio.attested-correlated-finding-transition.v1\0";
const DETECTOR_HEALTH_EVIDENCE_DOMAIN: &[u8] = b"chio.detector-health-evidence.v1\0";
const DETECTOR_HEALTH_TRANSITION_DOMAIN: &[u8] = b"chio.detector-health-transition.v1\0";

/// Converts raw temporal-correlation output into signed, indexed evidence.
///
/// The returned values are the only finding values intended for response
/// planning. Raw `CorrelatedFinding` values are never returned from this API.
pub struct AttestedCorrelationWriter {
    receipt_sink: Arc<dyn SecurityReceiptSink>,
    finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
    policy_hashes: BTreeMap<RecordId, Digest32>,
}

impl AttestedCorrelationWriter {
    #[must_use]
    pub fn new(
        receipt_sink: Arc<dyn SecurityReceiptSink>,
        finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
        policy_hashes: BTreeMap<RecordId, Digest32>,
    ) -> Self {
        Self {
            receipt_sink,
            finding_authority,
            policy_hashes,
        }
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        self.receipt_sink.ensure_receipts_ready()?;
        self.finding_authority
            .ensure_ready()
            .map_err(map_authority_error)
    }

    pub fn attest_outcome(
        &self,
        outcome: &CorrelationOutcome,
    ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
        if !outcome.findings.is_empty()
            && !matches!(
                outcome.status,
                CorrelationStatus::Matched | CorrelationStatus::Suppressed
            )
        {
            return Err(PortError::integrity_failure());
        }
        if matches!(outcome.status, CorrelationStatus::Suppressed)
            && !outcome.automatic_response_suppressed
        {
            return Err(PortError::integrity_failure());
        }
        if !outcome.detector_health.is_empty()
            && (!matches!(outcome.status, CorrelationStatus::Suppressed)
                || !outcome.automatic_response_suppressed)
        {
            return Err(PortError::integrity_failure());
        }
        for health in &outcome.detector_health {
            self.exact_policy_hash(&health.policy_version)?;
        }
        for finding in &outcome.findings {
            self.exact_policy_hash(&finding.policy_version)?;
        }
        self.ensure_ready()?;
        for health in &outcome.detector_health {
            self.attest_detector_health(health)?;
        }
        let authoritative = outcome
            .findings
            .iter()
            .map(|finding| self.attest_finding(finding))
            .collect::<PortResult<Vec<_>>>()?;
        if outcome.automatic_response_suppressed {
            Ok(Vec::new())
        } else {
            Ok(authoritative)
        }
    }

    fn attest_detector_health(&self, health: &DetectorHealthEvidence) -> PortResult<()> {
        if health.observed_at_unix_ms == 0
            || health.observed_at_unix_ms > MAX_ACTIVE_DEFENSE_JSON_INTEGER
            || health
                .rule_version_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::invalid_data());
        }
        if matches!(
            health.group_binding,
            DetectorGroupBindingEvidence::Resolved { group_key_hash }
                if group_key_hash.as_bytes().iter().all(|byte| *byte == 0)
        ) {
            return Err(PortError::invalid_data());
        }
        let watermark_valid = match &health.watermark {
            DetectorWatermarkEvidence::Unknown => true,
            DetectorWatermarkEvidence::Committed { unix_ms } => {
                *unix_ms != 0
                    && *unix_ms <= health.observed_at_unix_ms
                    && *unix_ms <= MAX_ACTIVE_DEFENSE_JSON_INTEGER
            }
            DetectorWatermarkEvidence::Contradictory { claimed_unix_ms } => {
                parse_canonical_u64(claimed_unix_ms).is_some_and(|claimed| {
                    health.kind == DetectorHealthKind::CorruptState
                        && (claimed == 0
                            || claimed > health.observed_at_unix_ms
                            || claimed > MAX_ACTIVE_DEFENSE_JSON_INTEGER)
                })
            }
        };
        if !watermark_valid
            || (matches!(
                health.group_binding,
                DetectorGroupBindingEvidence::Unresolved
            ) && !matches!(&health.watermark, DetectorWatermarkEvidence::Unknown))
        {
            return Err(PortError::invalid_data());
        }
        let policy_hash = self.exact_policy_hash(&health.policy_version)?;
        let evidence_hash = domain_hash(DETECTOR_HEALTH_EVIDENCE_DOMAIN, health)?;
        let transition_digest = domain_hash(
            DETECTOR_HEALTH_TRANSITION_DOMAIN,
            &(&health.policy_version, health, evidence_hash),
        )?;
        let transition_id = RecordId::new(format!(
            "detector-health-attestation-{}",
            hex::encode(transition_digest.as_bytes())
        ))
        .map_err(PortError::from)?;
        let header = ActiveDefenseReceiptHeader::new(
            health.observed_at_unix_ms,
            health.tenant_id.clone(),
            transition_id.clone(),
            Vec::new(),
        )
        .map_err(|_| PortError::invalid_data())?;
        let body = ActiveDefenseReceiptBody::DetectorHealth(DetectorHealthReceiptBody {
            header,
            policy: ActiveDefensePolicyBinding {
                policy_version: health.policy_version.clone(),
                policy_hash,
            },
            rule_id: health.rule_id.clone(),
            rule_version_hash: health.rule_version_hash,
            group_binding: health.group_binding,
            event_id: health.event_id.clone(),
            health_kind: health.kind,
            watermark: health.watermark.clone(),
            evidence_hash,
        });
        body.validate().map_err(|_| PortError::invalid_data())?;
        let evidence_id = body.evidence_id().map_err(|_| PortError::invalid_data())?;
        let canonical_body = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        let request = ReceiptAppendRequest {
            tenant_id: health.tenant_id.clone(),
            evidence_type: RecordId::new(body.kind().as_str()).map_err(PortError::from)?,
            evidence_id: evidence_id.clone(),
            canonical_body: CanonicalBody::new(canonical_body)
                .map_err(|_| PortError::invalid_data())?,
            body_hash: body.body_digest().map_err(|_| PortError::invalid_data())?,
            transition_id,
            occurred_at_unix_ms: health.observed_at_unix_ms,
        };
        let appended = self.receipt_sink.sign_and_append(&request)?;
        if appended != evidence_id {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn attest_finding(
        &self,
        finding: &CorrelatedFinding,
    ) -> PortResult<AuthoritativeCorrelatedFindingEvidence> {
        finding.validate().map_err(|_| PortError::invalid_data())?;
        let policy_hash = self.exact_policy_hash(&finding.policy_version)?;
        let finding_hash = domain_hash(FINDING_HASH_DOMAIN, finding)?;
        let transition_hash = domain_hash(FINDING_TRANSITION_DOMAIN, &finding_hash)?;
        let transition_id = RecordId::new(format!(
            "correlated-finding-attestation-{}",
            hex::encode(transition_hash.as_bytes())
        ))
        .map_err(PortError::from)?;
        let mut prior_receipt_ids = finding.ordered_source_receipt_ids.as_slice().to_vec();
        prior_receipt_ids.sort();
        prior_receipt_ids.dedup();
        let header = ActiveDefenseReceiptHeader::new(
            finding.last_event_time_unix_ms,
            finding.tenant_id.clone(),
            transition_id.clone(),
            prior_receipt_ids,
        )
        .map_err(|_| PortError::invalid_data())?;
        let body = ActiveDefenseReceiptBody::CorrelatedFinding(CorrelatedFindingReceiptBody {
            header,
            policy: ActiveDefensePolicyBinding {
                policy_version: finding.policy_version.clone(),
                policy_hash,
            },
            finding_id: finding.finding_id.clone(),
            finding_hash,
            rule_id: finding.rule_id.clone(),
            rule_version_hash: finding.rule_version_hash,
            group_key_hash: finding.group_key_hash,
            ordered_event_ids: finding.ordered_event_ids.clone(),
            ordered_evidence_digests: finding.ordered_evidence_digests.clone(),
            ordered_source_receipt_ids: finding.ordered_source_receipt_ids.clone(),
            first_event_time_unix_ms: finding.first_event_time_unix_ms,
            last_event_time_unix_ms: finding.last_event_time_unix_ms,
            lineage_seed: finding.lineage_seed.clone(),
        });
        body.validate().map_err(|_| PortError::invalid_data())?;
        let evidence_id = body.evidence_id().map_err(|_| PortError::invalid_data())?;
        let canonical_body = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        let request = ReceiptAppendRequest {
            tenant_id: finding.tenant_id.clone(),
            evidence_type: RecordId::new(body.kind().as_str()).map_err(PortError::from)?,
            evidence_id: evidence_id.clone(),
            canonical_body: CanonicalBody::new(canonical_body)
                .map_err(|_| PortError::invalid_data())?,
            body_hash: body.body_digest().map_err(|_| PortError::invalid_data())?,
            transition_id,
            occurred_at_unix_ms: finding.last_event_time_unix_ms,
        };
        let appended = self.receipt_sink.sign_and_append(&request)?;
        if appended != evidence_id {
            return Err(PortError::integrity_failure());
        }
        let authoritative = self
            .finding_authority
            .load_correlated_finding(&evidence_id)
            .map_err(map_authority_error)?
            .ok_or_else(PortError::integrity_failure)?;
        let ActiveDefenseReceiptBody::CorrelatedFinding(expected) = body else {
            return Err(PortError::integrity_failure());
        };
        if authoritative.evidence_id() != &evidence_id || authoritative.body() != &expected {
            return Err(PortError::integrity_failure());
        }
        Ok(authoritative)
    }

    fn exact_policy_hash(&self, policy_version: &RecordId) -> PortResult<Digest32> {
        let policy_hash = self
            .policy_hashes
            .get(policy_version)
            .copied()
            .ok_or_else(PortError::integrity_failure)?;
        if policy_hash.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(PortError::integrity_failure());
        }
        Ok(policy_hash)
    }
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn domain_hash<T: serde::Serialize>(domain: &[u8], value: &T) -> PortResult<Digest32> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&preimage).as_bytes()))
}

fn map_authority_error(error: ActiveResponseFindingAuthorityError) -> PortError {
    match error {
        ActiveResponseFindingAuthorityError::Unavailable(_) => PortError::unavailable(),
        ActiveResponseFindingAuthorityError::Integrity(_) => PortError::integrity_failure(),
    }
}
