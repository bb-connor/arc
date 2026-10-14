//! Every original custody transaction retains an independent full WAL amount.
//! A quoted amount cannot create or consume a native bank purpose.
use super::*;
use crate::admission_operation_store::security_participant_state::finishing_plan::VerifiedNativeInitialFinishingPlan;
use crate::admission_operation_store::tool_outcome_liability::{
    describe_native_tool_outcome_transactions, ToolOutcomeTransactionEnvelopeData,
    ToolOutcomeTransactionPurposeData, ToolOutcomeWriteTableData,
};
use crate::serving_owner::{NativeSourceTransactionOrigin, SqliteServingOwner};
use chio_sqlite_file_identity::{
    SqliteFramePriceProfileData, SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData,
};
use std::collections::BTreeMap;

pub(in crate::admission_operation_store) struct ToolOutcomeTransactionPriceData {
    purpose: ToolOutcomeTransactionPurposeData,
    physical: PhysicalLiabilityData,
    profile: String,
    page_growth: u64,
}

impl ToolOutcomeTransactionPriceData {
    pub(in crate::admission_operation_store) fn purpose(
        &self,
    ) -> ToolOutcomeTransactionPurposeData {
        self.purpose
    }

    pub(in crate::admission_operation_store) fn physical(&self) -> &PhysicalLiabilityData {
        &self.physical
    }

    pub(in crate::admission_operation_store) fn page_growth(&self) -> u64 {
        self.page_growth
    }

    pub(in crate::admission_operation_store) fn profile(&self) -> &str {
        &self.profile
    }
}

pub(in crate::admission_operation_store) fn tool_outcome_price_algorithm_fingerprint(
) -> Result<String, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.tool-outcome-frame-price.v1",
        (
            CURSOR_LEVELS,
            BALANCE_PAGES_PER_LEVEL,
            NEW_BALANCE_WALKS,
            EXISTING_BALANCE_WALKS,
            ALLOCATION_OR_FREE_FRAME_MULTIPLIER,
        ),
        (
            FRAME_HEADER_BYTES,
            WAL_HEADER_BYTES,
            MAX_WAL_SECTOR_BYTES,
            SERVING_ANCHOR_FILE_BYTES,
        ),
        "possible before and maximum intermediate overflow; no future blob existence credit",
        "independent transactions retain independent WAL and history amounts",
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// The owning bank must add its real funding/account/phase writes to each
/// transaction and preserve every other native, recovery and second-DB debt.
/// These component prices alone never enable pre-rail payment or capture.
pub(in crate::admission_operation_store) fn price_native_tool_outcome_phases(
    tx: &Transaction<'_>,
    writer: (&SqliteServingOwner, &NativeSourceTransactionOrigin<'_>),
    source: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    row_ceilings: &BTreeMap<String, u64>,
) -> Result<Vec<ToolOutcomeTransactionPriceData>, AdmissionOperationStoreError> {
    source.verify_before(tx, writer.0, writer.1)?;
    let profile = source.physical_write_profile();
    let page_size = profile.page_size();
    // This exact full native profile must already authenticate UTF-8, FULL WAL,
    // auto-vacuum=0, current and pending reserved bytes=0, actual supported VFS,
    // whole source/index/trigger catalog and the original producing program.
    let transactions = describe_native_tool_outcome_transactions(source)?;
    transactions
        .iter()
        .map(|transaction| {
            let profile = SqliteFramePriceProfileData::checked(page_size, 0).map_err(invariant)?;
            let shape = transaction_shape(transaction, row_ceilings)?;
            // The native authority writer retains cache_spill=0 and denies
            // changes to it. Its verified profile also excludes auto-vacuum.
            let price = shape.price_without_spill(&profile).map_err(invariant)?;
            Ok(ToolOutcomeTransactionPriceData {
                purpose: transaction.purpose(),
                physical: PhysicalLiabilityData::native_transaction(
                    price.wal_bytes(),
                    price.disk_bytes(),
                    0,
                    transaction.global_appends(),
                )?,
                profile: transaction_profile(source, transaction, row_ceilings)?,
                page_growth: shape.maximum_page_growth(&profile).map_err(invariant)?,
            })
        })
        .collect()
}

fn transaction_profile(
    source: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    transaction: &ToolOutcomeTransactionEnvelopeData,
    row_ceilings: &BTreeMap<String, u64>,
) -> Result<String, AdmissionOperationStoreError> {
    let rows = transaction
        .rows()
        .iter()
        .map(|row| {
            (
                row.table().table_name(),
                row.possible_before_record_bytes(),
                row.maximum_after_record_bytes(),
                row.mutations(),
                row.index_record_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let purpose = match transaction.purpose() {
        ToolOutcomeTransactionPurposeData::RawCustody => ("raw", 0),
        ToolOutcomeTransactionPurposeData::EvaluationBegin => ("evaluation_begin", 0),
        ToolOutcomeTransactionPurposeData::Finalization { pure_prefix } => {
            ("finalization", pure_prefix)
        }
        ToolOutcomeTransactionPurposeData::SecurityRelease => ("security_release", 0),
        ToolOutcomeTransactionPurposeData::TerminalProjection { observer, payment } => (
            "terminal_projection",
            u64::from(observer) + 2 * u64::from(payment),
        ),
        ToolOutcomeTransactionPurposeData::PaymentAuthorization => ("payment_authorization", 0),
        ToolOutcomeTransactionPurposeData::PaymentCompensation => ("payment_compensation", 0),
        ToolOutcomeTransactionPurposeData::PaymentSettlement => ("payment_settlement", 0),
        ToolOutcomeTransactionPurposeData::PaymentCompletion => ("payment_completion", 0),
    };
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.original-tool-outcome-transaction-envelope.v3",
        "retained_table_rows; unchanged_table_keys; mutable_indexes_separate; each_transaction_complete",
        row_ceilings,
        chio_sqlite_file_identity::write_price_algorithm_descriptor(),
        SqliteTransactionWriteShapeData::page_bounded_descriptor(),
        SqliteTransactionWriteShapeData::no_spill_descriptor(),
        source.physical_write_profile().fingerprint(),
        sha256_hex(source.original().canonical_bytes()),
        tool_outcome_price_algorithm_fingerprint()?,
        purpose,
        rows,
        transaction.admission_appends(),
        transaction.global_appends(),
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn transaction_shape(
    transaction: &ToolOutcomeTransactionEnvelopeData,
    row_ceilings: &BTreeMap<String, u64>,
) -> Result<SqliteTransactionWriteShapeData, AdmissionOperationStoreError> {
    let mut trees = Vec::new();
    for row in transaction.rows() {
        let ceiling = row_ceilings
            .get(row.table().table_name())
            .copied()
            .ok_or_else(|| invariant("original custody tree lacks its retained row ceiling"))?;
        let shape = if matches!(
            row.table(),
            ToolOutcomeWriteTableData::AdmissionMeta
                | ToolOutcomeWriteTableData::GlobalMeta
                | ToolOutcomeWriteTableData::BudgetReplicationMeta
        ) {
            SqliteTreeWriteShapeData::singleton_root(
                row.maximum_after_record_bytes(),
                row.mutations(),
            )
        } else if let Some(before) = row.possible_before_record_bytes() {
            // UPDATE leaves the table key unchanged. Blob rehydration may
            // instead insert a fresh record: its one insertion balance and new
            // image are both covered by the same-key old-plus-new shape.
            let images = before
                .max(row.maximum_after_record_bytes())
                .checked_mul(row.mutations())
                .ok_or_else(|| invariant("original custody image bound exhausted"))?;
            SqliteTreeWriteShapeData::same_key_rewrites(row.mutations(), images)
        } else {
            SqliteTreeWriteShapeData::fresh_insertions(
                row.maximum_after_record_bytes(),
                row.mutations(),
            )
        }
        .map_err(invariant)?;
        trees.push(shape.within_retained_rows(ceiling).map_err(invariant)?);
        for &bytes in row.index_record_bytes() {
            let index = if row.possible_before_record_bytes().is_some()
                && !matches!(row.table(), ToolOutcomeWriteTableData::Blobs)
            {
                // A rewritten row lists exactly the indexes whose key its
                // writer changes (the operation recovery index, the journal
                // state index, the usage time and sequence indexes and the
                // hold disposition index). Retain deletion and reinsertion
                // walks for each.
                SqliteTreeWriteShapeData::record(Some(bytes), bytes, row.mutations())
            } else {
                // The content-addressed blob's PK index is inserted only for a
                // fresh blob. Rehydration preserves it. Other indexed rows here
                // are insert-only; immutable outcome/evaluation indexes are
                // deliberately absent from their later rewrite descriptors.
                SqliteTreeWriteShapeData::fresh_insertions(bytes, row.mutations())
            }
            .map_err(invariant)?;
            trees.push(index.within_retained_rows(ceiling).map_err(invariant)?);
        }
    }
    SqliteTransactionWriteShapeData::checked(trees).map_err(invariant)
}
