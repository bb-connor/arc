use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{
    BudgetCaptureHoldDecision, BudgetCaptureHoldRequest, BudgetCommitMetadata,
    BudgetEventAuthority, BudgetHoldMutationDecision, BudgetInvocationReservationState,
    BudgetMonetaryHoldState, BudgetMutationKind, BudgetMutationRecord,
};
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

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
