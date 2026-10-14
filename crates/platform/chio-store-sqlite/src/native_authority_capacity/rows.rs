//! Retained cardinality bounds for the authority's physical B-trees.
//!
//! A table bounds the entry count of each of its indexes, including partial
//! indexes. The preupdate hook includes WITHOUT ROWID tables and trigger
//! effects. Only positive insertions are counted inside a transaction: deletes
//! and statement/savepoint rollback cannot manufacture reservation credit.
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

mod writes;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeTableRowLoan {
    pub(crate) table: String,
    pub(crate) ceiling: u64,
    pub(crate) insertions: u64,
}

impl NativeTableRowLoan {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !supported_table(&self.table) || self.ceiling == 0 || self.insertions > self.ceiling {
            return Err("native table row loan is invalid".into());
        }
        Ok(())
    }
}

/// Aggregate of authenticated, outstanding loans for one physical table.
#[derive(Clone, Debug, Default)]
pub(crate) struct NativeTableRowDebt {
    pub(crate) ceiling: u64,
    pub(crate) insertions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeTableRowReservation {
    pub(crate) loan: NativeTableRowLoan,
    pub(crate) references: u64,
}

pub(crate) fn replace_loans(
    reservations: &mut Vec<NativeTableRowReservation>,
    old: &[NativeTableRowLoan],
    new: &[NativeTableRowLoan],
) -> Result<(), String> {
    for loan in old {
        let position = reservations
            .iter()
            .position(|entry| entry.loan.table == loan.table && entry.loan.ceiling == loan.ceiling)
            .ok_or("native bank lost a table row loan")?;
        let entry = &mut reservations[position];
        entry.references = entry
            .references
            .checked_sub(1)
            .ok_or("native bank row reference underflow")?;
        entry.loan.insertions = entry
            .loan
            .insertions
            .checked_sub(loan.insertions)
            .ok_or("native bank insertion underflow")?;
        if entry.references == 0 {
            if entry.loan.insertions != 0 {
                return Err("native bank released a table with outstanding inserts".into());
            }
            reservations.remove(position);
        }
    }
    for loan in new {
        loan.validate()?;
        match reservations
            .iter_mut()
            .find(|entry| entry.loan.table == loan.table && entry.loan.ceiling == loan.ceiling)
        {
            Some(entry) => {
                entry.references = entry
                    .references
                    .checked_add(1)
                    .ok_or("native bank row reference overflow")?;
                entry.loan.insertions = entry
                    .loan
                    .insertions
                    .checked_add(loan.insertions)
                    .ok_or("native bank insertion overflow")?;
                entry.loan.validate()?;
            }
            None => reservations.push(NativeTableRowReservation {
                loan: loan.clone(),
                references: 1,
            }),
        }
    }
    reservations.sort_by(|left, right| {
        (&left.loan.table, left.loan.ceiling).cmp(&(&right.loan.table, right.loan.ceiling))
    });
    Ok(())
}

pub(crate) fn aggregate(
    loans: impl IntoIterator<Item = NativeTableRowLoan>,
) -> Result<BTreeMap<String, NativeTableRowDebt>, String> {
    let mut debts = BTreeMap::<String, NativeTableRowDebt>::new();
    for loan in loans {
        loan.validate()?;
        let debt = debts.entry(loan.table).or_insert(NativeTableRowDebt {
            ceiling: loan.ceiling,
            insertions: 0,
        });
        debt.ceiling = debt.ceiling.min(loan.ceiling);
        debt.insertions = debt
            .insertions
            .checked_add(loan.insertions)
            .ok_or("native table insertion debt exhausted")?;
        if debt.insertions > debt.ceiling {
            return Err("native table insertion debt exceeds its ceiling".into());
        }
    }
    Ok(debts)
}

pub(crate) fn count(connection: &Connection, table: &str) -> Result<u64, String> {
    if !supported_table(table) {
        return Err("native row reservation names an unsupported table".into());
    }
    let count: i64 = connection
        .query_row(
            &format!("SELECT COUNT(*) FROM main.\"{table}\" NOT INDEXED"),
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    u64::try_from(count).map_err(|_| "native table count is invalid".into())
}

// Closed maintained producers. A name cannot supply a SQL fragment or expand
// this policy to arbitrary application tables.
fn supported_table(table: &str) -> bool {
    matches!(
        table,
        "tool_outcome_blobs"
            | "tool_outcomes"
            | "post_return_evaluations"
            | "admission_operations"
            | "admission_operation_commits"
            | "admission_operation_commit_meta"
            | "authority_global_commits"
            | "authority_global_commit_meta"
            | "tool_outcome_security_releases"
            | "admission_operation_terminal_projections"
            | "admission_operation_terminal_records"
            | "admission_operation_observer_attempts"
            | "admission_operation_recovery_records"
            | "admission_operation_recovery_events"
            | "security_participant_output_events"
            | "security_participant_state_flow_contexts"
            | "security_participant_state_flow_sequences"
            | "security_participant_state_isolation_epochs"
            | "security_participant_state_lineage_flow_state"
            | "security_participant_state_principal_flow_state"
            | "security_participant_state_session_flow_state"
            | "security_participant_state_session_memberships"
            | "security_participant_state_transitions"
            | "security_participant_state_declassification_uses"
            | "security_participant_state_declassification_evidence_identity"
            | "security_participant_state_declassification_receipt_outbox"
            | "payment_journal"
            | "payment_release_evidence"
            | "capability_grant_budgets"
            | "budget_authorization_holds"
            | "budget_mutation_events"
            | "budget_event_quota_members"
            | "budget_event_revocation_members"
            | "budget_event_authorization_artifacts"
            | "budget_event_revocation_commits"
            | "budget_event_cumulative_approval"
            | "budget_replication_meta"
            | "budget_invocation_quotas"
            | "budget_cumulative_approval_accounts"
            | "budget_cumulative_approval_operations"
    )
}

struct TableCounter {
    /// Snapshot plus positive insertions, never decreased within a transaction.
    rows: u64,
    permitted: u64,
    ceiling: u64,
}

#[derive(Default)]
pub(super) struct RowLedger {
    tables: BTreeMap<String, TableCounter>,
    authorized: BTreeSet<String>,
    failed: bool,
    writes: writes::WriteLedger,
}

impl RowLedger {
    pub(super) fn snapshot(
        connection: &Connection,
        debts: &BTreeMap<String, NativeTableRowDebt>,
    ) -> Result<Self, String> {
        let mut ledger = Self::default();
        ledger.tighten(connection, debts)?;
        Ok(ledger)
    }

    /// Publication can introduce stricter loans. Never reset an existing
    /// counter inside its transaction, even after a failed statement.
    pub(super) fn tighten(
        &mut self,
        connection: &Connection,
        debts: &BTreeMap<String, NativeTableRowDebt>,
    ) -> Result<(), String> {
        for (table, debt) in debts {
            let permitted = debt
                .ceiling
                .checked_sub(debt.insertions)
                .ok_or("native table row debt exceeds its ceiling")?;
            if let Some(counter) = self.tables.get_mut(table) {
                counter.permitted = counter.permitted.min(permitted);
                counter.ceiling = counter.ceiling.min(debt.ceiling);
            } else {
                self.tables.insert(
                    table.clone(),
                    TableCounter {
                        rows: count(connection, table)?,
                        permitted,
                        ceiling: debt.ceiling,
                    },
                );
            }
        }
        self.check()
    }

    pub(super) fn authorize(
        &mut self,
        identity: &str,
        loans: &[NativeTableRowLoan],
    ) -> Result<(), String> {
        if self.authorized.contains(identity) {
            return Ok(());
        }
        self.check()?;
        let mut grants = BTreeMap::<String, u64>::new();
        for loan in loans {
            loan.validate()?;
            let counter = self
                .tables
                .get(&loan.table)
                .ok_or("native funded table has no retained row loan")?;
            let permitted = grants
                .get(&loan.table)
                .copied()
                .unwrap_or(counter.permitted)
                .checked_add(loan.insertions)
                .filter(|permitted| *permitted <= counter.ceiling)
                .ok_or("native funded rows exceed their retained ceiling")?;
            grants.insert(loan.table.clone(), permitted);
        }
        // Validate the entire grant before changing any counter. A caller
        // handling an error cannot retain a partially authorized allowance.
        for (table, permitted) in grants {
            if let Some(counter) = self.tables.get_mut(&table) {
                counter.permitted = permitted;
            }
        }
        self.authorized.insert(identity.into());
        self.check()
    }

    pub(super) fn inserted(&mut self, database: &str, table: &str) {
        if database != "main" {
            return;
        }
        if let Some(counter) = self.tables.get_mut(table) {
            match counter.rows.checked_add(1) {
                Some(rows) => counter.rows = rows,
                None => self.failed = true,
            }
        }
    }

    pub(super) fn changed(
        &mut self,
        database: &str,
        table: &str,
        change: &rusqlite::hooks::PreUpdateCase,
    ) {
        self.writes.changed(database, table, change);
    }

    pub(super) fn current_write_shape(
        &self,
        source: &Connection,
    ) -> Result<Option<chio_sqlite_file_identity::SqliteTransactionWriteShapeData>, String> {
        self.writes.shape(source)
    }

    pub(super) fn fail(&mut self) {
        self.failed = true;
    }

    pub(super) fn check(&self) -> Result<(), String> {
        if self.failed
            || self
                .tables
                .values()
                .any(|table| table.rows > table.permitted)
        {
            return Err("authority write would consume an owed native table row".into());
        }
        Ok(())
    }

    pub(super) fn protects_schema(&self) -> bool {
        !self.tables.is_empty()
    }
}
