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
    source::verify_prepared_pricing_cut(tx, source)?;
    // Authenticate the actual pre-enrollment state. A first account must
    // fund the family activation as part of Enrollment; requiring that bank
    // to exist before pricing would prevent its only owning installer from
    // ever receiving funding. An existing family still requires its complete
    // catalog, rows and retained history, with no repair or absence fallback.
    cohort::verify_before_open(tx)?;
    let activation_required = !cohort::family_present(tx)?;
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
        let mut rows = rows::describe_finishing_transaction(tx, purpose)?;
        if activation_required && purpose == ProcessReturnTransactionData::Enrollment {
            rows.extend(rows::describe_return_bank_activation(tx)?);
        }
        let mut trees = Vec::new();
        for row in rows {
            let tree = if row.table() == ProcessReturnTableData::Meta
                && row.before_record_bytes().is_some()
            {
                // The compiled future singleton has one INTEGER PRIMARY KEY
                // and no secondary indexes. First enrollment separately
                // prices its root creation and initial insert before this
                // same transaction updates the frontier for its new account.
                if !row.mutable_index_record_bytes().is_empty() {
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

/// Price one actual current write from its described rows and this file's
/// active profile. The result is a debt amount for the capacity equation,
/// never an allowance or a zero estimate.
pub(super) fn price_current_write(
    tx: &Connection,
    store_path: &Path,
    namespace: &str,
    authority: &str,
    kernel_key: &str,
    rows: &[ProcessReturnRowEnvelopeData],
) -> Result<SqlitePhysicalDebtAmountData, ProcessError> {
    let profile =
        catalog::prepare_active_profile(tx, store_path, namespace, authority, kernel_key)?;
    price_rows(&profile, rows)
}

/// Price one startup write of a provably empty or pre-layout journal as the
/// smaller of the generic shape bound and the enforced page ceiling of this
/// file. The ceiling is the file's actual page count plus the shape's
/// maximum_page_growth from the shared calculator, so it stays valid under
/// the locked authenticated layout delta and never caps owned history for
/// later progress. The caller installs the ceiling on the writing connection
/// inside the startup transaction, reads it back, and restores the original
/// connection settings on every exit path; this grants no funding.
pub(super) fn price_startup_rows(
    tx: &Connection,
    profile: &catalog::ProcessWriteProfileData,
    rows: &[ProcessReturnRowEnvelopeData],
) -> Result<(SqlitePhysicalDebtAmountData, u64), ProcessError> {
    let frame_profile =
        SqliteFramePriceProfileData::checked(profile.page_size(), profile.reserved_bytes())
            .map_err(|_| unavailable())?;
    let mut trees = Vec::new();
    for row in rows {
        trees.push(
            SqliteTreeWriteShapeData::record(
                row.before_record_bytes(),
                row.maximum_after_record_bytes(),
                row.mutations(),
            )
            .map_err(|_| unavailable())?,
        );
        for maximum_index in row.mutable_index_record_bytes() {
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
    let transaction = SqliteTransactionWriteShapeData::checked(trees).map_err(|_| unavailable())?;
    let pages =
        u64::try_from(tx.query_row("PRAGMA main.page_count", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| unavailable())?;
    let growth = transaction
        .maximum_page_growth(&frame_profile)
        .map_err(|_| unavailable())?;
    let ceiling = pages
        .checked_add(growth)
        .filter(|ceiling| *ceiling <= i32::MAX as u64)
        .ok_or_else(unavailable)?;
    let price = transaction
        .price_within_pages(&frame_profile, ceiling)
        .map_err(|_| unavailable())?;
    let priced = SqlitePhysicalDebtAmountData::checked(price.wal_bytes(), price.disk_bytes())
        .map_err(|_| unavailable())?;
    Ok((priced, ceiling))
}

/// Price described rows under an already authenticated write profile.
pub(super) fn price_rows(
    profile: &catalog::ProcessWriteProfileData,
    rows: &[ProcessReturnRowEnvelopeData],
) -> Result<SqlitePhysicalDebtAmountData, ProcessError> {
    let frame_profile =
        SqliteFramePriceProfileData::checked(profile.page_size(), profile.reserved_bytes())
            .map_err(|_| unavailable())?;
    let mut trees = Vec::new();
    for row in rows {
        trees.push(
            SqliteTreeWriteShapeData::record(
                row.before_record_bytes(),
                row.maximum_after_record_bytes(),
                row.mutations(),
            )
            .map_err(|_| unavailable())?,
        );
        for maximum_index in row.mutable_index_record_bytes() {
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
    let transaction = SqliteTransactionWriteShapeData::checked(trees).map_err(|_| unavailable())?;
    let price =
        price_transaction_write_shape(&frame_profile, &transaction).map_err(|_| unavailable())?;
    SqlitePhysicalDebtAmountData::checked(price.wal_bytes(), price.disk_bytes())
        .map_err(|_| unavailable())
}

fn unavailable() -> ProcessError {
    ProcessError::Configuration("Process original finishing price is unavailable")
}
