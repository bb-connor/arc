//! Recovery bookkeeping never grants dispatch, nonce, or monetary authority.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRecoveryFailureKind {
    Unavailable,
    Fenced,
    NotFound,
    Conflict,
    Invariant,
    OutcomeUnknown,
}

/// New recovery ports retain native client causes without changing the legacy
/// store error's Clone/Eq contract or pretending a remote server object is local.
pub enum AdmissionRecoveryPortError {
    Local(AdmissionOperationStoreError),
    Remote {
        kind: RemoteRecoveryFailureKind,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl AdmissionRecoveryPortError {
    #[must_use]
    pub fn remote(
        kind: RemoteRecoveryFailureKind,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Remote {
            kind,
            source: Box::new(source),
        }
    }

    #[must_use]
    pub fn kind(&self) -> RemoteRecoveryFailureKind {
        match self {
            Self::Remote { kind, .. } => *kind,
            Self::Local(error) => match error {
                AdmissionOperationStoreError::Unavailable(_) => {
                    RemoteRecoveryFailureKind::Unavailable
                }
                AdmissionOperationStoreError::Fenced => RemoteRecoveryFailureKind::Fenced,
                AdmissionOperationStoreError::NotFound => RemoteRecoveryFailureKind::NotFound,
                AdmissionOperationStoreError::OutcomeUnknown(_) => {
                    RemoteRecoveryFailureKind::OutcomeUnknown
                }
                AdmissionOperationStoreError::Invariant(_)
                | AdmissionOperationStoreError::Operation(_) => {
                    RemoteRecoveryFailureKind::Invariant
                }
            },
        }
    }
}

impl std::fmt::Display for AdmissionRecoveryPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "recovery port failed ({:?})", self.kind())
    }
}

impl std::fmt::Debug for AdmissionRecoveryPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionRecoveryPortError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl std::error::Error for AdmissionRecoveryPortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Local(error) => error,
            Self::Remote { source, .. } => source.as_ref(),
        })
    }
}

impl From<AdmissionOperationStoreError> for AdmissionRecoveryPortError {
    fn from(error: AdmissionOperationStoreError) -> Self {
        Self::Local(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRecoveryPhase {
    Inspection,
    BeforeDispatch,
    Returned,
    CommittedUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRecoveryFailureKind {
    ContractChanged,
    ParticipantUnavailable,
    PaymentPending,
    RecoveryRequestAbsent,
    OutputDenied,
    UnsupportedState,
    LegacyPaymentAmountAbsent,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionRecoveryError {
    #[error(transparent)]
    Port(#[from] AdmissionRecoveryPortError),
    #[error(transparent)]
    Store(#[from] AdmissionOperationStoreError),
    #[error(transparent)]
    Outcome(#[from] crate::tool_outcome::ToolOutcomeStoreError),
    #[error(transparent)]
    PaymentJournal(#[from] crate::receipt_store::AdmissionPaymentJournalError),
    #[error(transparent)]
    PaymentRecord(#[from] crate::payment::PaymentJournalError),
    #[error("payment participant failed ({kind:?})")]
    Payment {
        kind: AdmissionRecoveryFailureKind,
        #[source]
        source: crate::payment::PaymentError,
    },
    #[error(transparent)]
    Operation(#[from] AdmissionOperationError),
    #[error("{kind:?}: {detail}")]
    Item {
        kind: AdmissionRecoveryFailureKind,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionRecoveryDeferralV1 {
    pub operation_id: AdmissionOperationId,
    pub operation_version: u64,
    pub phase: AdmissionRecoveryPhase,
    pub failure_kind: AdmissionRecoveryFailureKind,
    pub attempt_count: u32,
    pub last_failure_unix_ms: u64,
    pub retry_not_before_unix_ms: u64,
    pub diagnostic_digest: AdmissionDigest,
}

impl AdmissionRecoveryDeferralV1 {
    pub fn after_failure(
        operation: &AdmissionOperationV1,
        previous: Option<&Self>,
        phase: AdmissionRecoveryPhase,
        failure_kind: AdmissionRecoveryFailureKind,
        diagnostic_digest: AdmissionDigest,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if let Some(previous) = previous {
            previous.validate_for(operation)?;
            if now < previous.last_failure_unix_ms {
                return Err(AdmissionOperationStoreError::Invariant(
                    "recovery deferral time regressed".into(),
                ));
            }
        }
        let attempt_count = previous.map_or(Ok(1), |previous| {
            previous.attempt_count.checked_add(1).ok_or_else(|| {
                AdmissionOperationStoreError::Invariant("recovery attempt count overflowed".into())
            })
        })?;
        let delay = retry_delay(attempt_count);
        let retry_not_before_unix_ms = now.checked_add(delay).ok_or_else(|| {
            AdmissionOperationStoreError::Invariant("recovery retry deadline overflowed".into())
        })?;
        let value = Self {
            operation_id: operation.binding().operation_id().clone(),
            operation_version: operation.version(),
            phase,
            failure_kind,
            attempt_count,
            last_failure_unix_ms: now,
            retry_not_before_unix_ms,
            diagnostic_digest,
        };
        value.validate_for(operation)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if &self.operation_id != operation.binding().operation_id()
            || self.operation_version == 0
            || self.operation_version > operation.version()
            || self.attempt_count == 0
            || self.last_failure_unix_ms == 0
            || self.retry_not_before_unix_ms > I_JSON_MAX_SAFE_INTEGER
            || self
                .last_failure_unix_ms
                .checked_add(retry_delay(self.attempt_count))
                != Some(self.retry_not_before_unix_ms)
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "recovery deferral binding or retry schedule is invalid".into(),
            ));
        }
        Ok(())
    }
}

fn retry_delay(attempt: u32) -> u64 {
    60_000_u64
        .saturating_mul(1_u64 << attempt.saturating_sub(1).min(3))
        .min(300_000)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionRecoveryStatusV1 {
    pub quarantined: bool,
    pub deferral: AdmissionRecoveryDeferralV1,
}

pub struct AdmissionRecoveryPageQuery<'a> {
    pub not_after_unix_ms: u64,
    pub candidate_limit: usize,
    pub after_operation_id: Option<&'a AdmissionOperationId>,
    pub fence: &'a StoreMutationFence,
}

pub struct AdmissionRecoveryPageV1 {
    pub operations: Vec<AdmissionOperationV1>,
    pub scanned_candidates: usize,
    pub next_cursor: Option<AdmissionOperationId>,
}

pub struct AdmissionRecoveryDeferralWrite<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub lease: &'a AdmissionRecoveryLease,
    pub expected: Option<&'a AdmissionRecoveryStatusV1>,
    pub deferral: &'a AdmissionRecoveryDeferralV1,
    pub fence: &'a StoreMutationFence,
    pub trusted_now_unix_ms: u64,
}

pub struct AdmissionRecoveryDeferralClear<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub lease: Option<&'a AdmissionRecoveryLease>,
    pub expected: &'a AdmissionRecoveryStatusV1,
    pub fence: &'a StoreMutationFence,
    pub trusted_now_unix_ms: u64,
}
