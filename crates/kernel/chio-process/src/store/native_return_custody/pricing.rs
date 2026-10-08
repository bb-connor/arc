//! Price every side-database transaction from its actual Process source cut.
use super::*;
use chio_sqlite_file_identity::{
    price_transaction_write_shape, SqliteFramePriceProfileData, SqliteTransactionWriteShapeData,
    SqliteTreeWriteShapeData,
};

pub struct ProcessFinishingTransactionPriceData {
    purpose: ProcessReturnTransactionData,
    wal_bytes: u64,
    disk_bytes: u64,
    wal_frames: u64,
}
impl ProcessFinishingTransactionPriceData {
    pub fn purpose(&self) -> ProcessReturnTransactionData {
        self.purpose
    }
    pub fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }
    pub fn wal_frames(&self) -> u64 {
        self.wal_frames
    }
}

/// This returns price DATA only. The native owning account separately verifies
/// all purposes, physical preservation, exact funding and Process enrollment.
pub(super) fn price_future_finishing_transactions(
    tx: &Transaction<'_>,
    source: &PreparedProcessReturnSource,
) -> Result<Vec<ProcessFinishingTransactionPriceData>, ProcessError> {
    require_complete_process_return_bank(tx)?;
    source::verify_prepared_pricing_cut(tx, source)?;
    let profile = SqliteFramePriceProfileData::checked(
        source.profile().page_size(),
        source.profile().reserved_bytes(),
    )
    .map_err(|_| unavailable())?;
    let mut purposes = vec![
        ProcessReturnTransactionData::Enrollment,
        ProcessReturnTransactionData::UnavailableNotice,
        ProcessReturnTransactionData::FinalNativeCustody,
        ProcessReturnTransactionData::Reconciliation,
    ];
    if source.data().original_nonce_pending {
        purposes.insert(1, ProcessReturnTransactionData::OriginalNonceCustody);
    }
    let mut prices = Vec::new();
    let mut total_frames = 0_u64;
    for purpose in purposes {
        let rows = rows::describe_finishing_transaction(purpose)?;
        let mut trees = Vec::new();
        for row in rows {
            let tree = if row.table() == ProcessReturnTableData::Meta {
                // The compiled future singleton has one INTEGER PRIMARY KEY
                // and no secondary indexes. Its actual presence must be part
                // of the new cohort before this can become spendable funding.
                if row.before_record_bytes().is_none()
                    || !row.mutable_index_record_bytes().is_empty()
                {
                    return Err(unavailable());
                }
                SqliteTreeWriteShapeData::singleton_root(
                    row.maximum_after_record_bytes(),
                    row.mutations(),
                )
            } else {
                SqliteTreeWriteShapeData::record(
                    row.before_record_bytes(),
                    row.maximum_after_record_bytes(),
                    row.mutations(),
                )
            }
            .map_err(|_| unavailable())?;
            trees.push(tree);
            for maximum_index in row.mutable_index_record_bytes() {
                // Every mutable index is an independent tree. A possible old
                // image retains the same complete index bound, without credit.
                trees.push(
                    SqliteTreeWriteShapeData::record(
                        row.before_record_bytes().map(|_| *maximum_index),
                        *maximum_index,
                        row.mutations(),
                    )
                    .map_err(|_| unavailable())?,
                );
            }
        }
        let transaction =
            SqliteTransactionWriteShapeData::checked(trees).map_err(|_| unavailable())?;
        let price =
            price_transaction_write_shape(&profile, &transaction).map_err(|_| unavailable())?;
        total_frames = total_frames
            .checked_add(price.wal_frames())
            .ok_or_else(unavailable)?;
        prices.push(ProcessFinishingTransactionPriceData {
            purpose,
            wal_bytes: price.wal_bytes(),
            disk_bytes: price.disk_bytes(),
            wal_frames: price.wal_frames(),
        });
    }
    let (log, _) = catalog::observe_wal_frontier(tx)?;
    log.checked_add(total_frames)
        .filter(|frames| *frames <= i32::MAX as u64)
        .ok_or_else(unavailable)?;
    // WAL caps, free-space floors and shared-filesystem summation are owning
    // preservation checks, never inferred from a successful pure price.
    Ok(prices)
}

fn require_complete_process_return_bank(_tx: &Connection) -> Result<(), ProcessError> {
    // The new bank has no authenticated full cold inverse yet. In particular
    // an absent meta table cannot be priced as an existing singleton root or
    // treated as zero retained liability. This gate remains an owning RED seam.
    Err(ProcessError::Configuration(
        "Process complete original return bank has not been installed",
    ))
}

fn unavailable() -> ProcessError {
    ProcessError::Configuration("Process original finishing price is unavailable")
}
