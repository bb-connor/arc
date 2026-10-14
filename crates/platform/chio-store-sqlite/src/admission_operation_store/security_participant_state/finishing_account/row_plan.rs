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

/// Rows the Prepared publication itself commits under these ceilings: the
/// account, the Process source alias and the bank record, each with its
/// recovery event and global commit. They are this transaction's own writes,
/// never a loan, so they widen the ceiling without being reserved.
fn prepared_publication_rows(table: &str) -> u64 {
    match table {
        RECORDS | EVENTS | GLOBAL => 3,
        _ => 0,
    }
}

/// The established ordinary intake allowance every new reserved ceiling keeps
/// for the stores' other protected writers.
const ORDINARY_INTAKE_ROWS: u64 = 64;

/// Rows this original's own ordinary writers insert after the Prepared
/// publication and before its effect, into tables the roster reserves. Each
/// count is the writer's actual insertion for the authenticated original:
/// the executable hold's authorization and dispatch capture and, for a nonce
/// original, its preflight hold's authorization and reversal, each one
/// composite event with the members `PaymentHoldInventory` binds; the hold,
/// usage, quota and cumulative rows those holds create; the journal row the
/// executable hold authorization inserts; at most one row per flow table for
/// each of the two pre-effect joins (Input and Nonce); and the declassification
/// consumption a declassified egress records. None is a loan: these rows are
/// written before any external authorization, under ordinary intake.
struct PreparatoryRows {
    payment: bool,
    executable:
        Option<crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory>,
    preflight:
        Option<crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory>,
    declassifies: bool,
}

impl PreparatoryRows {
    fn of(
        source: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let requirements = source.operation().binding().participant_requirements();
        let executable = if requirements.payment {
            Some(
                crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory::executable(
                    source.request(),
                    requirements.supplemental_authorization,
                )?,
            )
        } else {
            None
        };
        Ok(Self {
            payment: requirements.payment,
            preflight: executable
                .filter(|_| requirements.execution_nonce)
                .map(|hold| hold.preflight()),
            executable,
            declassifies: source.request().declassification_grant.is_some(),
        })
    }

    fn rows(&self, table: &str) -> u64 {
        // Two composite events per hold: authorize and capture for the
        // executable hold, authorize and reversal for the preflight hold.
        let per_event = |member: fn(
            &crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory,
        ) -> u64| {
            [self.executable, self.preflight]
                .into_iter()
                .flatten()
                .map(|hold| 2 * member(&hold))
                .sum::<u64>()
        };
        let holds = u64::from(self.executable.is_some()) + u64::from(self.preflight.is_some());
        let cumulative = self.executable.is_some_and(|hold| hold.cumulative);
        match table {
            "payment_journal" => u64::from(self.payment),
            "budget_authorization_holds" => holds,
            "budget_mutation_events" => 2 * holds,
            "budget_event_quota_members" => per_event(|hold| hold.quotas),
            "budget_event_revocation_members" => per_event(|hold| hold.revocations),
            "budget_event_authorization_artifacts" => per_event(|hold| hold.artifacts),
            "budget_event_revocation_commits" => {
                per_event(|hold| u64::from(hold.revocation_commit))
            }
            "budget_event_cumulative_approval" => 2 * u64::from(cumulative),
            "capability_grant_budgets" => u64::from(self.payment),
            "budget_invocation_quotas" => self.executable.map_or(0, |hold| hold.quotas),
            "budget_cumulative_approval_accounts" | "budget_cumulative_approval_operations" => {
                u64::from(cumulative)
            }
            _ if OUTPUT_TABLES[1..9].contains(&table) => super::roster::PRE_EFFECT_JOIN_SLOTS,
            _ if OUTPUT_TABLES[9..].contains(&table) => u64::from(self.declassifies),
            _ => 0,
        }
    }
}

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
        let preparation = PreparatoryRows::of(source)?;
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
                .and_then(|rows| rows.checked_add(prepared_publication_rows(&table)))
                .and_then(|rows| rows.checked_add(preparation.rows(&table)))
                .ok_or_else(|| invalid("native row ceiling exhausted"))?;
            let ceiling = match debt {
                Some(debt) if needed <= debt.ceiling => debt.ceiling,
                Some(_) => return Err(invalid("native intake would consume an owed table row")),
                // The smallest power of two holding every present row, every
                // owed insertion, this original's whole roster and the
                // established ordinary intake allowance. Intake may never
                // consume an owed row.
                None => needed
                    .checked_add(ORDINARY_INTAKE_ROWS)
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
