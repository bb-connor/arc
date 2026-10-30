#[cfg(feature = "std")]
use alloc::collections::{BTreeMap, BTreeSet};

use super::identifiers::MAX_ID_BYTES;
use super::{fmt, Deserialize, Digest32, RecordId, Serialize, String, TenantId};
#[cfg(feature = "std")]
use super::{PortResult, Vec};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAlert {
    pub tenant_id: TenantId,
    pub event_id: RecordId,
    pub idempotency_key: RecordId,
    pub occurred_at_unix_ms: u64,
    pub alert_type: RecordId,
    pub finding_id_hash: Digest32,
    pub action_id_hash: Option<Digest32>,
    pub evidence_hash: Digest32,
}

/// Largest canonical JSON encoding of a [`SecurityAlert`]: four identifiers
/// whose every byte escapes to two, three digests of 32 three-digit bytes and a
/// 20-digit timestamp.
pub const SECURITY_ALERT_MAX_CANONICAL_BYTES: usize = {
    const ID: usize = 2 + 2 * MAX_ID_BYTES;
    const DIGEST: usize = 2 + 32 * 3 + 31;
    const FRAME: &str = r#"{"action_id_hash":,"alert_type":,"event_id":,"evidence_hash":,"finding_id_hash":,"idempotency_key":,"occurred_at_unix_ms":,"tenant_id":}"#;
    FRAME.len() + 4 * ID + 3 * DIGEST + 20
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertDeliveryQuery {
    pub alert: SecurityAlert,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum AlertDeliveryStatus {
    Pending {
        attempts: u32,
        next_attempt_at_unix_ms: u64,
    },
    Delivered {
        attempts: u32,
        delivered_at_unix_ms: u64,
    },
    /// Delivery attempts are exhausted. The alert is never dispatched again
    /// and stays parked until an operator resolves it.
    Parked { attempts: u32 },
}

/// Name of one alert backend as the outbox records it: not empty, without
/// surrounding whitespace and without NUL.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BackendName(String);

/// Why a string is not a [`BackendName`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendNameError {
    Empty,
    Untrimmed,
    ContainsNul,
}

impl BackendName {
    pub fn new(name: &str) -> Result<Self, BackendNameError> {
        if name.is_empty() {
            return Err(BackendNameError::Empty);
        }
        if name.trim() != name {
            return Err(BackendNameError::Untrimmed);
        }
        if name.contains('\0') {
            return Err(BackendNameError::ContainsNul);
        }
        Ok(Self(name.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::borrow::Borrow<str> for BackendName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "alert backend name is empty",
            Self::Untrimmed => "alert backend name has surrounding whitespace",
            Self::ContainsNul => "alert backend name contains NUL",
        })
    }
}

impl core::error::Error for BackendNameError {}

/// Outcome of one dispatch of a paged alert to one backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertBackendOutcome {
    Confirmed,
    Refused,
}

#[cfg(feature = "std")]
pub trait SecurityAlertPort: Send + Sync {
    fn ensure_alerts_ready(&self) -> PortResult<()>;
    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus>;
    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>>;
}

/// Undelivered rows of the security paging outbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecurityAlertOutboxBacklog {
    /// Rows that are due now or will be retried under backoff.
    pub pending: u64,
    /// Rows in [`AlertDeliveryStatus::Parked`].
    pub parked: u64,
}

/// A pending outbox row as read for delivery: the exact paged alert, the
/// digest of its canonical bytes and the attempts recorded so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueSecurityAlert {
    pub alert: SecurityAlert,
    pub command_hash: Digest32,
    pub attempts: u32,
}

/// Durable paging outbox. Every method is one atomic unit. Writes that name a
/// [`DueSecurityAlert`] apply only while the row still holds that command and
/// attempt count, and refuse otherwise.
#[cfg(feature = "std")]
pub trait SecurityAlertOutboxStore: Send + Sync {
    fn ensure_ready(&self) -> PortResult<()>;
    /// Admits `alert` as a pending row due at its occurrence time, or returns
    /// the stored status of the identical command.
    fn admit(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus>;
    fn load_status(&self, alert: &SecurityAlert) -> PortResult<Option<AlertDeliveryStatus>>;
    /// The stored command under `idempotency_key`, verified against its
    /// canonical bytes and digest.
    fn load_command(
        &self,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>>;
    /// Per-backend outcome of a paged alert, keyed by backend name. A backend
    /// appears once it has been dispatched to: `Delivered` after it confirmed
    /// the alert, otherwise `Pending` with its dispatch count and the row's next
    /// attempt time while the row is pending, and `Parked` once the row is no
    /// longer retried.
    fn load_backend_deliveries(
        &self,
        alert: &SecurityAlert,
    ) -> PortResult<Option<BTreeMap<BackendName, AlertDeliveryStatus>>>;
    fn backlog(&self) -> PortResult<SecurityAlertOutboxBacklog>;
    /// Up to `limit` pending rows due at `now_unix_ms`, earliest first.
    fn load_due(&self, now_unix_ms: u64, limit: usize) -> PortResult<Vec<DueSecurityAlert>>;
    fn confirmed_backends(&self, row: &DueSecurityAlert) -> PortResult<BTreeSet<BackendName>>;
    fn record_backend_outcome(
        &self,
        row: &DueSecurityAlert,
        backend: &BackendName,
        outcome: AlertBackendOutcome,
        now_unix_ms: u64,
    ) -> PortResult<()>;
    /// Counts one failed attempt and schedules the row at
    /// `next_attempt_at_unix_ms`.
    fn record_failure(
        &self,
        row: &DueSecurityAlert,
        next_attempt_at_unix_ms: u64,
    ) -> PortResult<()>;
    /// Counts the final attempt and marks the row delivered. Refuses unless
    /// every backend in `backends` has confirmed the row.
    fn record_delivery(
        &self,
        row: &DueSecurityAlert,
        backends: &[BackendName],
        now_unix_ms: u64,
    ) -> PortResult<()>;
    /// Moves the pending row to [`AlertDeliveryStatus::Parked`] with
    /// `attempts`: the row's recorded attempts when it is parked unsent, or
    /// one more when its final attempt failed. Refuses any other count. A
    /// parked row is never due again.
    fn record_parked(&self, row: &DueSecurityAlert, attempts: u32) -> PortResult<()>;
}
