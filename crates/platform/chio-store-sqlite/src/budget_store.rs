use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{
    AuthorizedBudgetHold, BudgetAdmissionOperationBinding, BudgetAuthorityProfile,
    BudgetAuthorizeHoldDecision, BudgetCaptureHoldDecision, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetCommitMetadata, BudgetEventAuthority,
    BudgetGuaranteeLevel, BudgetHoldDispositionView, BudgetHoldMutationDecision,
    BudgetHoldSnapshot, BudgetInvocationQuota, BudgetInvocationQuotaUsage,
    BudgetInvocationReservationState, BudgetMeteringProfile, BudgetMonetaryHoldState,
    BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldRequest, BudgetReleaseHoldRequest, BudgetReverseHoldRequest,
    DeniedBudgetHold, ReservedHoldEnvelope, MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{
    BudgetStore, BudgetStoreError, BudgetStoreProfile, BudgetUsageRecord,
    MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

mod composite;
mod model;
mod reaper;
mod replication;
mod rows;
mod schema;
mod store;
mod trait_impl;

#[cfg(test)]
#[path = "budget_store/tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

use model::{HoldDisposition, SqliteBudgetHold};
use replication::*;
use rows::*;
use schema::*;

pub use reaper::ReapSummary;

pub struct SqliteBudgetStore {
    connection: Mutex<Connection>,
    authority_profile: BudgetStoreProfile,
    database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
}

/// Replicated projection of one legacy grant's structured invocation authority.
///
/// Compatibility mutations still maintain [`BudgetUsageRecord`] for existing
/// readers, but this record is the authoritative source for the immutable
/// invocation maximum. It is deliberately limited to the one-grant legacy path:
/// composite reserved state is replicated by admission consensus together with
/// its authorization, hold, revocation, and evidence records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetInvocationQuotaUsageRecord {
    pub usage: BudgetInvocationQuotaUsage,
    pub updated_at: i64,
    pub seq: u64,
}

impl BudgetInvocationQuotaUsageRecord {
    pub fn validate_compatibility_projection(&self) -> Result<(), BudgetStoreError> {
        self.usage.validate()?;
        if self.usage.quota.key().profile() != BudgetQuotaProfile::GrantInvocation
            || self.usage.quota.key().grant_index().is_none()
            || self.usage.reserved_invocations_after != 0
        {
            return Err(BudgetStoreError::Invariant(
                "replicated compatibility quota must be a captured-only grant quota".to_string(),
            ));
        }
        Ok(())
    }
}

/// Trusted backend input for a kernel-verified composite budget admission.
///
/// The kernel remains responsible for deriving these descriptors from signed
/// capability evidence. SQLite revalidates and durably binds every field before
/// mutating counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteCompositeAuthorizeInput {
    pub operation_id: String,
    pub request_binding_hash: String,
    pub capability_id: String,
    pub grant_index: usize,
    pub requested_exposure_units: u64,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub hold_id: String,
    pub event_id: String,
    pub authority: Option<BudgetEventAuthority>,
    pub invocation_quotas: Vec<BudgetInvocationQuota>,
    pub revocation_set: CanonicalRevocationSet,
    pub authorization_artifact_digests: Vec<String>,
}

/// Authenticated aggregate-family identity bound to a composite authorization.
///
/// This value is accepted only alongside an aggregate-family quota. Both fields
/// are persisted with the authorization and must match on every exact replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteAggregateFamilyEvidence {
    pub root_capability_id: String,
    pub root_binding_digest: String,
}

/// Immutable input reconstructed from a persisted composite authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteStoredCompositeAuthorizeInput {
    pub authorization: SqliteCompositeAuthorizeInput,
    pub aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
}

/// Result of one durable SQLite authorization attempt.
///
/// `event_created` is decided inside the same `BEGIN IMMEDIATE` transaction as
/// the mutation. Callers use it to compensate only provisional writes created by
/// their own attempt, never an exact retry that merely re-read a persisted event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteBudgetAuthorizationOutcome {
    pub allowed: bool,
    pub event_created: bool,
    pub authority: Option<BudgetEventAuthority>,
}

/// Frozen result of one invocation increment in the admission transaction.
///
/// Consensus callers persist the operation ID as the mutation event ID. An
/// exact replay therefore returns this original result without consuming a
/// second invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteBudgetIncrementOutcome {
    pub allowed: bool,
    pub invocation_count: u32,
    pub event_seq: u64,
}

/// Authority source for an authorization request before its write transaction.
///
/// Exact persisted retries must retain their frozen authority. A genuinely
/// compensated authorization must instead use the server's current fenced
/// authority so the transaction can perform its typed rollback rebind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteBudgetAuthorizationAuthority {
    Persisted(Option<BudgetEventAuthority>),
    Current,
}

/// Server-resolved authority candidate for a new or compensated authorization.
///
/// `Unavailable` is distinct from `Resolved(None)`: the latter is the valid
/// standalone authority state, while the former lets an exact persisted retry
/// proceed without silently downgrading a compensated HA claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteBudgetCurrentAuthority {
    Resolved(Option<BudgetEventAuthority>),
    Unavailable,
}

pub(super) enum SqliteBudgetAuthorizationAuthorityMode {
    CallerPinned(Option<BudgetEventAuthority>),
    ServerCurrent(SqliteBudgetCurrentAuthority),
}
