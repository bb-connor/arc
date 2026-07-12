use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{
    AuthorizedBudgetHold, BudgetAuthorityProfile, BudgetAuthorizeHoldDecision,
    BudgetCaptureHoldDecision, BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest,
    BudgetCommitMetadata, BudgetEventAuthority, BudgetGuaranteeLevel, BudgetHoldMutationDecision,
    BudgetInvocationQuota, BudgetInvocationQuotaUsage, BudgetInvocationReservationState,
    BudgetMeteringProfile, BudgetMonetaryHoldState, BudgetMutationKind, BudgetMutationRecord,
    BudgetQuotaKey, BudgetQuotaProfile, DeniedBudgetHold, MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

mod composite;
mod model;
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

pub struct SqliteBudgetStore {
    connection: Mutex<Connection>,
}

/// Trusted backend input for a kernel-verified composite budget admission.
///
/// The kernel remains responsible for deriving these descriptors from signed
/// capability evidence. SQLite revalidates and durably binds every field before
/// mutating counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteCompositeAuthorizeInput {
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
