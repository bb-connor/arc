# [cfg (feature = "std")]
use super::format;
use super::String;
# [cfg (feature = "std")]
use super::vec;
use super::Vec;
use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::TenantId;
use super::RecordId;
use super::RequestId;
use super::EventId;
use super::GrantId;
use super::ErrorCode;
use super::OpaqueReceiptRef;
use super::PortError;
use super::PortResult;
use super::ReceiptAppendRequest;

pub const DECLASSIFICATION_EVIDENCE_SCHEMA_VERSION: u8 = 2;
pub const DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS: u64 = 1_000;
pub const DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS: u64 = 3_600_000;
pub const DECLASSIFICATION_EVIDENCE_RETENTION_MS: u64 = 7_776_000_000;
pub const DECLASSIFICATION_CONSUMPTION_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.consumption.v1\0";
pub const DECLASSIFICATION_RELEASED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.released.v1\0";
pub const DECLASSIFICATION_DISPATCH_FAILED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.dispatch-failed.v1\0";
pub const DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.outcome-unknown-after-dispatch.v1\0";
pub const DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.receipt-persistence-failed.v1\0";
pub const DECLASSIFICATION_RECOVERY_UNDELIVERED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.recovery-undelivered-consumption.v1\0";
pub const DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.recovery-outcome-unknown.v1\0";
pub const DECLASSIFICATION_CONSUMPTION_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.consumption.v1\0";
pub const DECLASSIFICATION_RELEASED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.released.v1\0";
pub const DECLASSIFICATION_DISPATCH_FAILED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.dispatch-failed.v1\0";
pub const DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.outcome-unknown-after-dispatch.v1\0";
pub const DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.receipt-persistence-failed.v1\0";
pub const DECLASSIFICATION_RECOVERY_UNDELIVERED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.recovery-undelivered-consumption.v1\0";
pub const DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.recovery-outcome-unknown.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumeRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub consumed_at_unix_ms: u64,
    pub grant_expires_at_unix_ms: u64,
}

pub fn declassification_retain_until_unix_ms(grant_expires_at_unix_ms: u64) -> PortResult<u64> {
    grant_expires_at_unix_ms
        .checked_add(DECLASSIFICATION_EVIDENCE_RETENTION_MS)
        .ok_or_else(PortError::invalid_data)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationUseState {
    ConsumedPendingDispatch,
    Released,
    DispatchFailed,
    OutcomeUnknown,
}

/// Closed, bounded input to declassification transition and event identity.
///
/// Each identity preimage starts with its fixed variant domain and then the
/// listed fields in declaration order. Every field is encoded as an unsigned
/// 64-bit big-endian byte length followed by the exact field bytes. Digests
/// contribute their 32 raw bytes. Callers cannot supply a domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum DeclassificationTransitionBinding {
    Consumption {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
    },
    Released {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    DispatchFailed {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    OutcomeUnknownAfterDispatch {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    ReceiptPersistenceFailed {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    RecoveryUndeliveredConsumption {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        predecessor_evidence_id: OpaqueReceiptRef,
        predecessor_transition_id: RecordId,
    },
    RecoveryOutcomeUnknown {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        predecessor_evidence_id: OpaqueReceiptRef,
        predecessor_transition_id: RecordId,
    },
}

impl DeclassificationTransitionBinding {
    #[must_use]
    pub const fn terminal_state(&self) -> Option<DeclassificationUseState> {
        match self {
            Self::Consumption { .. } => None,
            Self::Released { .. } => Some(DeclassificationUseState::Released),
            Self::DispatchFailed { .. }
            | Self::ReceiptPersistenceFailed { .. }
            | Self::RecoveryUndeliveredConsumption { .. } => {
                Some(DeclassificationUseState::DispatchFailed)
            }
            Self::OutcomeUnknownAfterDispatch { .. } | Self::RecoveryOutcomeUnknown { .. } => {
                Some(DeclassificationUseState::OutcomeUnknown)
            }
        }
    }

    #[must_use]
    pub const fn is_live_dispatch_binding(&self) -> bool {
        matches!(
            self,
            Self::Released { .. }
                | Self::DispatchFailed { .. }
                | Self::OutcomeUnknownAfterDispatch { .. }
                | Self::ReceiptPersistenceFailed { .. }
        )
    }

    #[must_use]
    pub const fn is_consumption(&self) -> bool {
        matches!(self, Self::Consumption { .. })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Consumption { tenant_id, .. }
            | Self::Released { tenant_id, .. }
            | Self::DispatchFailed { tenant_id, .. }
            | Self::OutcomeUnknownAfterDispatch { tenant_id, .. }
            | Self::ReceiptPersistenceFailed { tenant_id, .. }
            | Self::RecoveryUndeliveredConsumption { tenant_id, .. }
            | Self::RecoveryOutcomeUnknown { tenant_id, .. } => tenant_id,
        }
    }

    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        match self {
            Self::Consumption { grant_id, .. }
            | Self::Released { grant_id, .. }
            | Self::DispatchFailed { grant_id, .. }
            | Self::OutcomeUnknownAfterDispatch { grant_id, .. }
            | Self::ReceiptPersistenceFailed { grant_id, .. }
            | Self::RecoveryUndeliveredConsumption { grant_id, .. }
            | Self::RecoveryOutcomeUnknown { grant_id, .. } => grant_id,
        }
    }

    #[must_use]
    pub const fn request_hash(&self) -> Digest32 {
        match self {
            Self::Consumption { request_hash, .. }
            | Self::Released { request_hash, .. }
            | Self::DispatchFailed { request_hash, .. }
            | Self::OutcomeUnknownAfterDispatch { request_hash, .. }
            | Self::ReceiptPersistenceFailed { request_hash, .. }
            | Self::RecoveryUndeliveredConsumption { request_hash, .. }
            | Self::RecoveryOutcomeUnknown { request_hash, .. } => *request_hash,
        }
    }

    #[must_use]
    pub const fn recovery_predecessor(&self) -> Option<(&OpaqueReceiptRef, &RecordId)> {
        match self {
            Self::RecoveryUndeliveredConsumption {
                predecessor_evidence_id,
                predecessor_transition_id,
                ..
            }
            | Self::RecoveryOutcomeUnknown {
                predecessor_evidence_id,
                predecessor_transition_id,
                ..
            } => Some((predecessor_evidence_id, predecessor_transition_id)),
            Self::Consumption { .. }
            | Self::Released { .. }
            | Self::DispatchFailed { .. }
            | Self::OutcomeUnknownAfterDispatch { .. }
            | Self::ReceiptPersistenceFailed { .. } => None,
        }
    }

    #[cfg(feature = "std")]
    const fn transition_domain(&self) -> &'static [u8] {
        match self {
            Self::Consumption { .. } => DECLASSIFICATION_CONSUMPTION_TRANSITION_DOMAIN,
            Self::Released { .. } => DECLASSIFICATION_RELEASED_TRANSITION_DOMAIN,
            Self::DispatchFailed { .. } => DECLASSIFICATION_DISPATCH_FAILED_TRANSITION_DOMAIN,
            Self::OutcomeUnknownAfterDispatch { .. } => {
                DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_TRANSITION_DOMAIN
            }
            Self::ReceiptPersistenceFailed { .. } => {
                DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_TRANSITION_DOMAIN
            }
            Self::RecoveryUndeliveredConsumption { .. } => {
                DECLASSIFICATION_RECOVERY_UNDELIVERED_TRANSITION_DOMAIN
            }
            Self::RecoveryOutcomeUnknown { .. } => {
                DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_TRANSITION_DOMAIN
            }
        }
    }

    #[cfg(feature = "std")]
    const fn event_domain(&self) -> &'static [u8] {
        match self {
            Self::Consumption { .. } => DECLASSIFICATION_CONSUMPTION_EVENT_DOMAIN,
            Self::Released { .. } => DECLASSIFICATION_RELEASED_EVENT_DOMAIN,
            Self::DispatchFailed { .. } => DECLASSIFICATION_DISPATCH_FAILED_EVENT_DOMAIN,
            Self::OutcomeUnknownAfterDispatch { .. } => {
                DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_EVENT_DOMAIN
            }
            Self::ReceiptPersistenceFailed { .. } => {
                DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_EVENT_DOMAIN
            }
            Self::RecoveryUndeliveredConsumption { .. } => {
                DECLASSIFICATION_RECOVERY_UNDELIVERED_EVENT_DOMAIN
            }
            Self::RecoveryOutcomeUnknown { .. } => {
                DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_EVENT_DOMAIN
            }
        }
    }

    #[cfg(feature = "std")]
    fn fields(&self) -> Vec<&[u8]> {
        match self {
            Self::Consumption {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                request_id.as_str().as_bytes(),
            ],
            Self::Released {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::DispatchFailed {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::OutcomeUnknownAfterDispatch {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::ReceiptPersistenceFailed {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                request_id.as_str().as_bytes(),
                dispatch_commitment_id.as_str().as_bytes(),
            ],
            Self::RecoveryUndeliveredConsumption {
                tenant_id,
                grant_id,
                request_hash,
                predecessor_evidence_id,
                predecessor_transition_id,
            }
            | Self::RecoveryOutcomeUnknown {
                tenant_id,
                grant_id,
                request_hash,
                predecessor_evidence_id,
                predecessor_transition_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                predecessor_evidence_id.as_str().as_bytes(),
                predecessor_transition_id.as_str().as_bytes(),
            ],
        }
    }
}

#[cfg(feature = "std")]
fn declassification_binding_digest(
    domain: &[u8],
    binding: &DeclassificationTransitionBinding,
) -> PortResult<[u8; 32]> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in binding.fields() {
        let length = u64::try_from(field.len()).map_err(|_| PortError::invalid_data())?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

#[cfg(feature = "std")]
fn declassification_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(feature = "std")]
#[must_use = "derived transition IDs must be persisted or verified"]
pub fn derive_declassification_transition_id(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<RecordId> {
    let digest = declassification_binding_digest(binding.transition_domain(), binding)?;
    RecordId::new(format!(
        "declassification-transition:{}",
        declassification_hex(&digest)
    ))
    .map_err(PortError::from)
}

#[cfg(feature = "std")]
#[must_use = "derived event IDs must be persisted or verified"]
pub fn derive_declassification_event_id(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<EventId> {
    let digest = declassification_binding_digest(binding.event_domain(), binding)?;
    EventId::new(format!(
        "declassification-event:{}",
        declassification_hex(&digest)
    ))
    .map_err(PortError::from)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum DeclassificationConsume {
    Consumed,
    AlreadyConsumed {
        request_hash: Digest32,
        state: DeclassificationUseState,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub expected_state: DeclassificationUseState,
    pub new_state: DeclassificationUseState,
    pub transition_id: RecordId,
}

pub const MAX_DECLASSIFICATION_EVIDENCE_BATCH: u32 = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationEvidencePhase {
    Consumption,
    Outcome,
}

impl DeclassificationEvidencePhase {
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Consumption => 0,
            Self::Outcome => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumptionEvidenceCommit {
    pub consumption: DeclassificationConsumeRequest,
    pub transition_binding: DeclassificationTransitionBinding,
    pub receipt: ReceiptAppendRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeEvidenceCommit {
    pub outcome: DeclassificationOutcomeRequest,
    pub transition_binding: DeclassificationTransitionBinding,
    pub predecessor_evidence_id: OpaqueReceiptRef,
    pub receipt: ReceiptAppendRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationUseQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationUseRecord {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub state: DeclassificationUseState,
    pub consumed_at_unix_ms: u64,
    pub grant_expires_at_unix_ms: u64,
    pub retain_until_unix_ms: u64,
    pub consumption_binding: DeclassificationTransitionBinding,
    pub outcome_binding: Option<DeclassificationTransitionBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidencePendingQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub now_unix_ms: u64,
    pub max_records: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceRecord {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub request_hash: Digest32,
    pub state: DeclassificationUseState,
    pub transition_binding: DeclassificationTransitionBinding,
    pub predecessor_evidence_id: Option<OpaqueReceiptRef>,
    pub receipt: ReceiptAppendRequest,
    pub acknowledged: bool,
    pub durable_sink_record_hash: Option<Digest32>,
    pub attempts: u32,
    pub next_attempt_at_unix_ms: u64,
    pub last_error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceAckRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub evidence_id: OpaqueReceiptRef,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub durable_sink_record_hash: Digest32,
    pub verified_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceRetryRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub evidence_id: OpaqueReceiptRef,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub failed_at_unix_ms: u64,
    pub error_code: ErrorCode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionQuery {
    pub readiness_cursor: RecordId,
    pub now_unix_ms: u64,
    pub after_tenant_id: Option<TenantId>,
    pub after_grant_id: Option<GrantId>,
    pub max_records: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionCandidate {
    pub readiness_cursor: RecordId,
    pub use_record: DeclassificationUseRecord,
    pub consumption: DeclassificationEvidenceRecord,
    pub outcome: DeclassificationEvidenceRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionRequest {
    pub readiness_cursor: RecordId,
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub terminal_state: DeclassificationUseState,
    pub consumption_evidence_id: OpaqueReceiptRef,
    pub consumption_body_hash: Digest32,
    pub consumption_transition_id: RecordId,
    pub consumption_occurred_at_unix_ms: u64,
    pub consumption_sink_record_hash: Digest32,
    pub outcome_evidence_id: OpaqueReceiptRef,
    pub outcome_body_hash: Digest32,
    pub outcome_transition_id: RecordId,
    pub outcome_occurred_at_unix_ms: u64,
    pub outcome_sink_record_hash: Digest32,
    pub policy_hash: Digest32,
    pub compacted_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceTombstone {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub terminal_state: DeclassificationUseState,
    pub consumption_evidence_id: OpaqueReceiptRef,
    pub consumption_body_hash: Digest32,
    pub consumption_transition_id: RecordId,
    pub consumption_occurred_at_unix_ms: u64,
    pub consumption_sink_record_hash: Digest32,
    pub outcome_evidence_id: OpaqueReceiptRef,
    pub outcome_body_hash: Digest32,
    pub outcome_transition_id: RecordId,
    pub outcome_occurred_at_unix_ms: u64,
    pub outcome_sink_record_hash: Digest32,
    pub policy_hash: Digest32,
    pub compacted_at_unix_ms: u64,
}

#[cfg(feature = "std")]
pub fn declassification_retry_deadline_unix_ms(
    failed_at_unix_ms: u64,
    attempts_after_failure: u32,
) -> PortResult<u64> {
    if attempts_after_failure == 0 {
        return Err(PortError::invalid_data());
    }
    let exponent = attempts_after_failure.saturating_sub(1).min(63);
    let multiplier = 1_u64
        .checked_shl(exponent)
        .ok_or_else(PortError::integrity_failure)?;
    let backoff = match DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS.checked_mul(multiplier) {
        Some(value) => value.min(DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS),
        None => DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS,
    };
    failed_at_unix_ms
        .checked_add(backoff)
        .ok_or_else(PortError::integrity_failure)
}

#[cfg(feature = "std")]
pub trait DeclassificationUseStore: Send + Sync {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume>;
    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait DeclassificationEvidenceCommitStore: Send + Sync {
    fn ensure_declassification_evidence_ready(&self) -> PortResult<()>;
    fn declassification_evidence_readiness_cursor(&self) -> PortResult<RecordId>;
    fn begin_declassification_reconciliation(&self) -> PortResult<()>;
    fn end_declassification_reconciliation(&self) -> PortResult<()>;
    fn seal_declassification_live_dispatch(&self) -> PortResult<()>;
    /// Fresh consumption must check grant expiry against the store's trusted
    /// clock after acquiring its write transaction. Request timestamps are not
    /// a replacement for that clock. Exact retained use/evidence replay returns
    /// `AlreadyConsumed` without acquiring new authority, including after expiry.
    fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
    ) -> PortResult<DeclassificationConsume>;
    fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()>;
    fn load_declassification_use(
        &self,
        query: &DeclassificationUseQuery,
    ) -> PortResult<Option<DeclassificationUseRecord>>;
    fn load_declassification_evidence(
        &self,
        query: &DeclassificationEvidenceQuery,
    ) -> PortResult<Option<DeclassificationEvidenceRecord>>;
    fn load_pending_declassification_evidence(
        &self,
        query: &DeclassificationEvidencePendingQuery,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn load_pending_declassification_evidence_batch(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn load_stranded_declassification_consumptions_batch(
        &self,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()>;
    fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord>;
    fn count_pending_declassification_evidence(&self) -> PortResult<u64>;
    fn count_stranded_declassification_consumptions(&self) -> PortResult<u64>;
    fn load_declassification_compaction_candidates(
        &self,
        query: &DeclassificationCompactionQuery,
    ) -> PortResult<Vec<DeclassificationCompactionCandidate>>;
    fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone>;
}
