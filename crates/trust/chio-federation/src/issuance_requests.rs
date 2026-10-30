//! Federated-issuance requests awaiting an operator decision, and the
//! repository port that persists them.

use serde::{Deserialize, Serialize};

/// Open requests (`pending` or `deciding`) one store holds at a time.
pub const MAX_PENDING_ISSUANCE_REQUESTS: usize = 256;

/// Summaries returned by one listing page.
pub const MAX_ISSUANCE_LIST_PAGE: usize = 50;

/// Decision reason recorded when a pending request outlives its challenge.
pub const EXPIRED_REASON: &str = "expired";

/// Closed refusal classes of an [`IssuanceRequestRepository`]. A backend
/// failure it cannot classify is `Unavailable`; stored state that fails
/// decoding is `Integrity` and never carries row data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuanceStoreError {
    #[error("an issuance request was already submitted for challenge {0}")]
    AlreadySubmitted(String),
    #[error("issuance request {0} expired before it was submitted")]
    Expired(String),
    #[error("too many pending issuance requests")]
    Full,
    #[error("issuance request {0} not found")]
    NotFound(String),
    #[error("issuance request {0} is not pending")]
    NotPending(String),
    #[error("issuance request {0} is not claimed by a decision")]
    NotClaimed(String),
    #[error("issuance timestamp is out of range")]
    InvalidTimestamp,
    #[error("issuance list limit {0} is outside 1..=50")]
    InvalidPageLimit(usize),
    #[error("issuance request store is busy")]
    Busy,
    #[error("issuance request store is unavailable")]
    Unavailable,
    #[error("issuance request store failed an integrity check")]
    Integrity,
}

/// `deciding` means one approve or deny call has claimed the request; only
/// that call may finish or release it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssuanceRequestStatus {
    Pending,
    Deciding,
    Approved,
    Denied,
}

impl IssuanceRequestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Deciding => "deciding",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "deciding" => Some(Self::Deciding),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// The terminal state a claimed request finishes in. An approval always
/// names the capability it issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceDecision {
    Approved { capability_id: String },
    Denied,
}

impl IssuanceDecision {
    #[must_use]
    pub const fn status(&self) -> IssuanceRequestStatus {
        match self {
            Self::Approved { .. } => IssuanceRequestStatus::Approved,
            Self::Denied => IssuanceRequestStatus::Denied,
        }
    }

    #[must_use]
    pub fn capability_id(&self) -> Option<&str> {
        match self {
            Self::Approved { capability_id } => Some(capability_id),
            Self::Denied => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRequestRecord {
    pub challenge_id: String,
    pub subject: String,
    pub verifier: String,
    pub presentation_json: String,
    pub challenge_json: String,
    pub submitted_at: u64,
    pub expires_at: u64,
    pub status: IssuanceRequestStatus,
    pub decided_at: Option<u64>,
    pub capability_id: Option<String>,
    pub decision_reason: Option<String>,
}

/// A listing row: the record without its presentation and challenge payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRequestSummary {
    pub challenge_id: String,
    pub subject: String,
    pub verifier: String,
    pub submitted_at: u64,
    pub expires_at: u64,
    pub status: IssuanceRequestStatus,
    pub decided_at: Option<u64>,
    pub capability_id: Option<String>,
    pub decision_reason: Option<String>,
}

/// Summaries one listing page may hold, in `1..=MAX_ISSUANCE_LIST_PAGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuancePageLimit(usize);

impl IssuancePageLimit {
    pub const MAX: Self = Self(MAX_ISSUANCE_LIST_PAGE);

    /// Refuses zero and any limit above [`MAX_ISSUANCE_LIST_PAGE`].
    pub const fn new(limit: usize) -> Result<Self, IssuanceStoreError> {
        if limit == 0 || limit > MAX_ISSUANCE_LIST_PAGE {
            return Err(IssuanceStoreError::InvalidPageLimit(limit));
        }
        Ok(Self(limit))
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// One listing request. `after` names the last request of the previous page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceListQuery<'a> {
    pub status: Option<IssuanceRequestStatus>,
    pub after: Option<&'a str>,
    pub limit: IssuancePageLimit,
}

/// One listing page in `(submitted_at, challenge_id)` order. `next_after`
/// names the last row when more rows follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRequestPage {
    pub requests: Vec<IssuanceRequestSummary>,
    pub next_after: Option<String>,
}

/// Durable home of federated-issuance requests.
///
/// Every implementation holds these invariants:
/// - capacity counts `pending` and `deciding` requests, and concurrent
///   submissions never exceed it;
/// - a pending request whose challenge expired by `now` is retired to
///   `denied` with reason [`EXPIRED_REASON`] before every capacity check,
///   claim and listing; a `deciding` request is never retired, because its
///   decision may already have issued authority;
/// - only the caller that won [`IssuanceRequestRepository::claim`] may
///   finish or release the request;
/// - each method is one atomic unit.
pub trait IssuanceRequestRepository: Send + Sync {
    /// Store a new pending request. Refuses a record whose challenge expired
    /// by `now`, a challenge already submitted and a store at capacity.
    fn submit(&self, record: &IssuanceRequestRecord, now: u64) -> Result<(), IssuanceStoreError>;

    fn get(&self, challenge_id: &str) -> Result<Option<IssuanceRequestRecord>, IssuanceStoreError>;

    /// One page of summaries. An unknown `after` is `NotFound`.
    fn list(
        &self,
        query: IssuanceListQuery<'_>,
        now: u64,
    ) -> Result<IssuanceRequestPage, IssuanceStoreError>;

    /// Move a pending request to `deciding` and return it. A request that is
    /// not pending, including one just retired as expired, is `NotPending`.
    fn claim(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<IssuanceRequestRecord, IssuanceStoreError>;

    /// Finish a claimed request. A request that is not `deciding` is
    /// `NotClaimed`.
    fn finish(
        &self,
        challenge_id: &str,
        decision: &IssuanceDecision,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), IssuanceStoreError>;

    /// Return a claimed request to `pending` after a decision that had no
    /// effect. A request that is not `deciding` is `NotClaimed`.
    fn release(&self, challenge_id: &str) -> Result<(), IssuanceStoreError>;
}

#[cfg(any(test, feature = "test-support"))]
pub mod conformance;
#[cfg(any(test, feature = "test-support"))]
pub mod memory;

#[cfg(test)]
#[path = "issuance_requests_tests.rs"]
mod tests;
