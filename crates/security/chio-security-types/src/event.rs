use crate::ports::{
    BoundedVec, Digest32, EventId, LineageId, OpaqueReceiptRef, ProducerId, ProducerTrustClass,
    RecordId, RuleId, SessionId, TenantId,
};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

pub const MAX_EVENT_EVIDENCE_REFERENCES: usize = 64;
pub const MAX_FINDING_EVENTS: usize = 64;

pub type EventEvidenceReferences = BoundedVec<OpaqueReceiptRef, MAX_EVENT_EVIDENCE_REFERENCES>;
pub type FindingEventIds = BoundedVec<EventId, MAX_FINDING_EVENTS>;
pub type FindingEvidenceDigests = BoundedVec<Digest32, MAX_FINDING_EVENTS>;
pub type FindingSourceReceiptIds = BoundedVec<OpaqueReceiptRef, MAX_FINDING_EVENTS>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    CanaryInvocation,
    CredentialAccess,
    DeclassificationAttempt,
    DetectorHealth,
    EgressAttempt,
    FlowDenial,
    ToolInvocation,
    TripwireObservation,
    WatermarkObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySubject {
    pub subject_id: RecordId,
    pub agent_id: RecordId,
    pub session_id: SessionId,
    pub capability_id: RecordId,
    pub lineage_seed: LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventBody {
    pub event_id: EventId,
    pub event_time_unix_ms: u64,
    pub ingest_time_unix_ms: u64,
    pub tenant_id: TenantId,
    pub subject: SecuritySubject,
    pub source_receipt_id: OpaqueReceiptRef,
    pub event_kind: SecurityEventKind,
    pub severity: SecuritySeverity,
    pub evidence_references: EventEvidenceReferences,
    pub producer_id: ProducerId,
    pub producer_key_id: RecordId,
    pub trust_class: ProducerTrustClass,
    pub policy_version: RecordId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityEventBodyInput {
    pub event_id: EventId,
    pub event_time_unix_ms: u64,
    pub ingest_time_unix_ms: u64,
    pub tenant_id: TenantId,
    pub subject: SecuritySubject,
    pub source_receipt_id: OpaqueReceiptRef,
    pub event_kind: SecurityEventKind,
    pub severity: SecuritySeverity,
    pub evidence_references: Vec<OpaqueReceiptRef>,
    pub producer_id: ProducerId,
    pub producer_key_id: RecordId,
    pub trust_class: ProducerTrustClass,
    pub policy_version: RecordId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityEventValidationError {
    EventAfterIngest,
    MissingEvidence,
    TooManyEvidenceReferences,
}

impl fmt::Display for SecurityEventValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EventAfterIngest => "event time is after ingest time",
            Self::MissingEvidence => "verified security event has no evidence reference",
            Self::TooManyEvidenceReferences => {
                "security event exceeds the evidence-reference limit"
            }
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for SecurityEventValidationError {}

impl SecurityEventBody {
    pub fn new(input: SecurityEventBodyInput) -> Result<Self, SecurityEventValidationError> {
        let evidence_references = EventEvidenceReferences::new(input.evidence_references)
            .map_err(|_| SecurityEventValidationError::TooManyEvidenceReferences)?;
        let body = Self {
            event_id: input.event_id,
            event_time_unix_ms: input.event_time_unix_ms,
            ingest_time_unix_ms: input.ingest_time_unix_ms,
            tenant_id: input.tenant_id,
            subject: input.subject,
            source_receipt_id: input.source_receipt_id,
            event_kind: input.event_kind,
            severity: input.severity,
            evidence_references,
            producer_id: input.producer_id,
            producer_key_id: input.producer_key_id,
            trust_class: input.trust_class,
            policy_version: input.policy_version,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), SecurityEventValidationError> {
        if self.event_time_unix_ms > self.ingest_time_unix_ms {
            return Err(SecurityEventValidationError::EventAfterIngest);
        }
        if self.evidence_references.is_empty() {
            return Err(SecurityEventValidationError::MissingEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedFinding {
    pub finding_id: RecordId,
    pub tenant_id: TenantId,
    pub rule_id: RuleId,
    pub rule_version_hash: Digest32,
    pub policy_version: RecordId,
    pub group_key_hash: Digest32,
    pub ordered_event_ids: FindingEventIds,
    pub ordered_evidence_digests: FindingEvidenceDigests,
    pub ordered_source_receipt_ids: FindingSourceReceiptIds,
    pub first_event_time_unix_ms: u64,
    pub last_event_time_unix_ms: u64,
    pub lineage_seed: LineageId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelatedFindingInput {
    pub finding_id: RecordId,
    pub tenant_id: TenantId,
    pub rule_id: RuleId,
    pub rule_version_hash: Digest32,
    pub policy_version: RecordId,
    pub group_key_hash: Digest32,
    pub ordered_event_ids: Vec<EventId>,
    pub ordered_evidence_digests: Vec<Digest32>,
    pub ordered_source_receipt_ids: Vec<OpaqueReceiptRef>,
    pub first_event_time_unix_ms: u64,
    pub last_event_time_unix_ms: u64,
    pub lineage_seed: LineageId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrelatedFindingValidationError {
    EmptySequence,
    MismatchedEvidence,
    NonMonotonicTime,
    TooManyEvents,
}

impl fmt::Display for CorrelatedFindingValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySequence => "correlated finding has no contributing events",
            Self::MismatchedEvidence => {
                "correlated finding event, evidence, and source receipt cardinalities differ"
            }
            Self::NonMonotonicTime => "correlated finding time range is not monotonic",
            Self::TooManyEvents => "correlated finding exceeds the event limit",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for CorrelatedFindingValidationError {}

impl CorrelatedFinding {
    pub fn new(input: CorrelatedFindingInput) -> Result<Self, CorrelatedFindingValidationError> {
        if input.ordered_event_ids.is_empty() {
            return Err(CorrelatedFindingValidationError::EmptySequence);
        }
        if input.ordered_event_ids.len() != input.ordered_evidence_digests.len()
            || input.ordered_event_ids.len() != input.ordered_source_receipt_ids.len()
        {
            return Err(CorrelatedFindingValidationError::MismatchedEvidence);
        }
        if input.first_event_time_unix_ms > input.last_event_time_unix_ms {
            return Err(CorrelatedFindingValidationError::NonMonotonicTime);
        }
        let ordered_event_ids = FindingEventIds::new(input.ordered_event_ids)
            .map_err(|_| CorrelatedFindingValidationError::TooManyEvents)?;
        let ordered_evidence_digests = FindingEvidenceDigests::new(input.ordered_evidence_digests)
            .map_err(|_| CorrelatedFindingValidationError::TooManyEvents)?;
        let ordered_source_receipt_ids =
            FindingSourceReceiptIds::new(input.ordered_source_receipt_ids)
                .map_err(|_| CorrelatedFindingValidationError::TooManyEvents)?;
        Ok(Self {
            finding_id: input.finding_id,
            tenant_id: input.tenant_id,
            rule_id: input.rule_id,
            rule_version_hash: input.rule_version_hash,
            policy_version: input.policy_version,
            group_key_hash: input.group_key_hash,
            ordered_event_ids,
            ordered_evidence_digests,
            ordered_source_receipt_ids,
            first_event_time_unix_ms: input.first_event_time_unix_ms,
            last_event_time_unix_ms: input.last_event_time_unix_ms,
            lineage_seed: input.lineage_seed,
        })
    }

    pub fn validate(&self) -> Result<(), CorrelatedFindingValidationError> {
        if self.ordered_event_ids.is_empty() {
            return Err(CorrelatedFindingValidationError::EmptySequence);
        }
        if self.ordered_event_ids.len() != self.ordered_evidence_digests.len()
            || self.ordered_event_ids.len() != self.ordered_source_receipt_ids.len()
        {
            return Err(CorrelatedFindingValidationError::MismatchedEvidence);
        }
        if self.first_event_time_unix_ms > self.last_event_time_unix_ms {
            return Err(CorrelatedFindingValidationError::NonMonotonicTime);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorHealthKind {
    CorruptEvent,
    CorruptState,
    StateOverflow,
    StoreConflict,
    StoreUnavailable,
    TruncatedScan,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorWatermarkEvidence {
    Unknown,
    Committed { unix_ms: u64 },
    Contradictory { claimed_unix_ms: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorGroupBindingEvidence {
    Unresolved,
    Resolved { group_key_hash: Digest32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorHealthEvidence {
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
    pub rule_id: RuleId,
    pub rule_version_hash: Digest32,
    pub group_binding: DetectorGroupBindingEvidence,
    pub kind: DetectorHealthKind,
    pub event_id: EventId,
    pub observed_at_unix_ms: u64,
    pub watermark: DetectorWatermarkEvidence,
}
