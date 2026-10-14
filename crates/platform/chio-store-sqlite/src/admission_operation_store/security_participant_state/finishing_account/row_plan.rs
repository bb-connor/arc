//! One lifetime row budget for all writers of the original native program.
use super::*;
use crate::admission_operation_store::tool_outcome_liability::{
    describe_native_tool_outcome_transactions, ToolOutcomeTransactionEnvelopeData,
};
use crate::native_authority_capacity::rows::{count, NativeTableRowLoan};
use std::collections::BTreeMap;

pub(super) const RECORDS: &str = "admission_operation_recovery_records";
pub(super) const EVENTS: &str = "admission_operation_recovery_events";
pub(super) const GLOBAL: &str = "authority_global_commits";
pub(super) const GLOBAL_META: &str = "authority_global_commit_meta";
pub(super) const CONTEXTS: &str = "security_participant_state_flow_contexts";

pub(super) const OUTPUT_TABLES: &[&str] = &[
    "security_participant_output_events",
    CONTEXTS,
    "security_participant_state_flow_sequences",
    "security_participant_state_isolation_epochs",
    "security_participant_state_lineage_flow_state",
    "security_participant_state_principal_flow_state",
    "security_participant_state_session_flow_state",
    "security_participant_state_session_memberships",
    "security_participant_state_transitions",
    "security_participant_state_declassification_uses",
    "security_participant_state_declassification_evidence_identity",
    "security_participant_state_declassification_receipt_outbox",
];

pub(super) struct NativeRowPlan {
    ceilings: BTreeMap<String, u64>,
}

impl NativeRowPlan {
    pub(super) fn prepare(
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        source: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let mut insertions = BTreeMap::<String, u64>::new();
        let mut add = |table: &str, rows: u64| -> Result<(), AdmissionOperationStoreError> {
            let total = insertions.entry(table.into()).or_default();
            *total = total
                .checked_add(rows)
                .ok_or_else(|| invalid("native row plan exhausted"))?;
            Ok(())
        };
        let transactions = describe_native_tool_outcome_transactions(source)?;
        for transaction in &transactions {
            for row in transaction.rows() {
                add(row.table().table_name(), row.maximum_insertions())?;
            }
        }
        for table in OUTPUT_TABLES {
            add(table, 1)?;
        }
        add(GLOBAL, 1)?;
        add(GLOBAL_META, 0)?;
        // One possible journal seal. Each protected command also publishes its
        // real recovery event and global commit. No history is omitted.
        add(RECORDS, 1)?;
        add(EVENTS, 1)?;
        add(GLOBAL, 1)?;
        // Confirmed, each native purpose, and Settled each rewrite account and bank.
        let transitions = u64::try_from(transactions.len()).map_err(invalid)? + 4;
        add(
            EVENTS,
            transitions
                .checked_mul(2)
                .ok_or_else(|| invalid("native transition rows exhausted"))?,
        )?;
        add(
            GLOBAL,
            transitions
                .checked_mul(2)
                .ok_or_else(|| invalid("native transition rows exhausted"))?,
        )?;
        let debts = crate::admission_operation_store::native_authority_table_row_debt(
            tx,
            &owner.fence.store_uuid,
        )?;
        let mut ceilings = BTreeMap::new();
        for (table, own) in insertions {
            let current = count(tx, &table).map_err(invalid)?;
            let debt = debts.get(&table);
            let needed = current
                .checked_add(debt.map_or(0, |debt| debt.insertions))
                .and_then(|rows| rows.checked_add(own))
                .ok_or_else(|| invalid("native row ceiling exhausted"))?;
            let ceiling = match debt {
                Some(debt) if needed <= debt.ceiling => debt.ceiling,
                Some(_) => return Err(invalid("native intake would consume an owed table row")),
                // Space for concurrent intake is separate from owed rows. Its
                // consumption cannot reduce any account's retained insertions.
                None => needed
                    .checked_add(64)
                    .and_then(u64::checked_next_power_of_two)
                    .ok_or_else(|| invalid("native row ceiling exhausted"))?,
            };
            ceilings.insert(table, ceiling);
        }
        Ok(Self { ceilings })
    }

    pub(super) fn ceilings(&self) -> &BTreeMap<String, u64> {
        &self.ceilings
    }

    pub(super) fn ceiling(&self, table: &str) -> Result<u64, AdmissionOperationStoreError> {
        self.ceilings
            .get(table)
            .copied()
            .ok_or_else(|| invalid("native writer is absent from the row roster"))
    }

    pub(super) fn loans(
        &self,
        rows: impl IntoIterator<Item = (&'static str, u64)>,
    ) -> Result<Vec<NativeTableRowLoan>, AdmissionOperationStoreError> {
        let mut combined = BTreeMap::<String, u64>::new();
        for (table, insertions) in rows {
            let total = combined.entry(table.into()).or_default();
            *total = total
                .checked_add(insertions)
                .ok_or_else(|| invalid("native row loan exhausted"))?;
        }
        combined
            .into_iter()
            .map(|(table, insertions)| {
                Ok(NativeTableRowLoan {
                    ceiling: self.ceiling(&table)?,
                    table,
                    insertions,
                })
            })
            .collect()
    }

    pub(super) fn tool_outcome_loans(
        &self,
        transaction: &ToolOutcomeTransactionEnvelopeData,
    ) -> Result<Vec<NativeTableRowLoan>, AdmissionOperationStoreError> {
        self.loans(
            transaction
                .rows()
                .iter()
                .map(|row| (row.table().table_name(), row.maximum_insertions())),
        )
    }

    pub(super) fn command_loans(
        &self,
        commands: u64,
        fresh: bool,
    ) -> Result<Vec<NativeTableRowLoan>, AdmissionOperationStoreError> {
        self.loans([
            (RECORDS, if fresh { commands } else { 0 }),
            (EVENTS, commands),
            (GLOBAL, commands),
            (GLOBAL_META, 0),
        ])
    }
}
