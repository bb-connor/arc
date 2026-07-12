use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use chio_kernel::budget_store::BudgetReconcileHoldRequest;
use chio_kernel::budget_store::{
    AuthorizedBudgetHold, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetCommitMetadata, BudgetEventAuthority,
    BudgetHoldMutationDecision, BudgetInvocationCaptureDecision, BudgetMutationKind,
    BudgetMutationRecord, DeniedBudgetHold,
};
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

mod authorization;
mod authorization_fences;
mod import_hold_state;
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
