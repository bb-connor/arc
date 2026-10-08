//! Checked frame-cost DATA shared by independently authenticated writers.
//! These descriptors neither authenticate a source nor reserve disk or WAL.

const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAMES: u64 = 2;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;

/// Mathematical inputs for the pinned bundled SQLite frame calculation.
/// The owning adapter separately verifies its actual file, UTF-8 row codec,
/// FULL WAL, auto-vacuum policy, source cut, and complete writer catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteFramePriceProfileData {
    page_size: u64,
}

impl SqliteFramePriceProfileData {
    pub fn checked(page_size: u64, reserved_bytes: u64) -> Result<Self, String> {
        if !(512..=65_536).contains(&page_size)
            || !page_size.is_power_of_two()
            || reserved_bytes != 0
        {
            return Err("SQLite frame price geometry is unsupported".to_owned());
        }
        Ok(Self { page_size })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeKindData {
    Record,
    FreshInsertions,
    SingletonRoot,
}

/// One table or index tree, including every repeated actual producer mutation.
/// Each mutable index is a distinct descriptor. WITHOUT ROWID primary keys
/// belong to the table tree and must not be counted as an invented extra index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteTreeWriteShapeData {
    kind: TreeKindData,
    possible_before_bytes: Option<u64>,
    maximum_after_bytes: u64,
    mutations: u64,
}

impl SqliteTreeWriteShapeData {
    pub fn record(
        possible_before_bytes: Option<u64>,
        maximum_after_bytes: u64,
        mutations: u64,
    ) -> Result<Self, String> {
        if maximum_after_bytes == 0 || possible_before_bytes == Some(0) || mutations == 0 {
            return Err("SQLite tree shape lost its complete record bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::Record,
            possible_before_bytes,
            maximum_after_bytes,
            mutations,
        })
    }

    /// Only a source-proved append of distinct fresh records can use this
    /// insert-only pattern. Multiple mutations in `record` remain ambiguous
    /// and conservatively retain intermediate existing-row costs.
    pub fn fresh_insertions(maximum_record_bytes: u64, insertions: u64) -> Result<Self, String> {
        if maximum_record_bytes == 0 || insertions == 0 {
            return Err("SQLite insert-only shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::FreshInsertions,
            possible_before_bytes: None,
            maximum_after_bytes: maximum_record_bytes,
            mutations: insertions,
        })
    }

    /// Only an authenticated, existing INTEGER PRIMARY KEY singleton table
    /// without secondary indexes can use this fixed-root descriptor.
    pub fn singleton_root(maximum_record_bytes: u64, mutations: u64) -> Result<Self, String> {
        if maximum_record_bytes == 0 || mutations == 0 {
            return Err("SQLite singleton shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::SingletonRoot,
            possible_before_bytes: Some(maximum_record_bytes),
            maximum_after_bytes: maximum_record_bytes,
            mutations,
        })
    }
}

/// A whole independently committed transaction. The source adapter includes
/// its tables, mutable indexes, history, metadata and bank writes together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteTransactionWriteShapeData {
    trees: Vec<SqliteTreeWriteShapeData>,
}

impl SqliteTransactionWriteShapeData {
    pub fn checked(trees: Vec<SqliteTreeWriteShapeData>) -> Result<Self, String> {
        if trees.is_empty() {
            return Err("SQLite transaction price has no producing trees".to_owned());
        }
        Ok(Self { trees })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteTransactionWritePriceData {
    wal_bytes: u64,
    disk_bytes: u64,
    wal_frames: u64,
}

impl SqliteTransactionWritePriceData {
    pub fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }

    /// Appended WAL and possible later main-file allocation coexist. An owning
    /// adapter adds its independently authenticated anchor or side-file cost.
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub fn wal_frames(&self) -> u64 {
        self.wal_frames
    }
}

/// Stable calculator identity DATA to bind into the actual source profile.
/// It identifies the bound, not a supported producer or a funded loan.
pub fn write_price_algorithm_descriptor() -> &'static str {
    "chio.sqlite.transaction-frame-price.v2; bundled3.51.3; depth20; balance6; newwalk1; existingwalk3; allocation_or_free2; frame24; header32; FULL_sector65536; reserved0; before_or_intermediate_overflow; ambiguous_new_rewrites_existing_cost; explicit_fresh_insertions; independent_transactions"
}

pub fn price_transaction_write_shape(
    profile: &SqliteFramePriceProfileData,
    transaction: &SqliteTransactionWriteShapeData,
) -> Result<SqliteTransactionWritePriceData, String> {
    let payload = profile
        .page_size
        .checked_sub(4)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| "SQLite overflow divisor is invalid".to_owned())?;
    // Page1 can be dirtied by allocation, even when the source tables are small.
    let mut frames = 1;
    for tree in &transaction.trees {
        match tree.kind {
            TreeKindData::SingletonRoot => {
                if tree.maximum_after_bytes > profile.page_size - 100 {
                    return Err("SQLite singleton record exceeds its fixed root".to_owned());
                }
                frames = add(frames, tree.mutations)?;
            }
            TreeKindData::Record | TreeKindData::FreshInsertions => {
                let intermediate_existing = tree.kind == TreeKindData::Record
                    && tree.possible_before_bytes.is_none()
                    && tree.mutations > 1;
                let walks = if tree.possible_before_bytes.is_some() || intermediate_existing {
                    EXISTING_BALANCE_WALKS
                } else {
                    NEW_BALANCE_WALKS
                };
                let balance = mul(
                    mul(mul(tree.mutations, walks)?, CURSOR_LEVELS)?,
                    BALANCE_PAGES_PER_LEVEL,
                )?;
                let after = ceil(tree.maximum_after_bytes, payload)?;
                let previous = match tree.possible_before_bytes {
                    Some(bytes) => ceil(bytes.max(tree.maximum_after_bytes), payload)?,
                    None if intermediate_existing => ceil(tree.maximum_after_bytes, payload)?,
                    None => 0,
                };
                let overflow = mul(add(after, previous)?, tree.mutations)?;
                frames = add(
                    frames,
                    mul(add(balance, overflow)?, ALLOCATION_OR_FREE_FRAMES)?,
                )?;
            }
        }
    }
    let frame_bytes = add(profile.page_size, FRAME_HEADER_BYTES)?;
    let padding = ceil(MAX_WAL_SECTOR_BYTES, frame_bytes)?;
    let wal_frames = add(frames, padding)?;
    let wal_bytes = add(mul(wal_frames, frame_bytes)?, WAL_HEADER_BYTES)?;
    Ok(SqliteTransactionWritePriceData {
        wal_bytes,
        disk_bytes: mul(wal_bytes, 2)?,
        wal_frames,
    })
}

fn add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "SQLite physical price sum exhausted".to_owned())
}

fn mul(left: u64, right: u64) -> Result<u64, String> {
    left.checked_mul(right)
        .ok_or_else(|| "SQLite physical price product exhausted".to_owned())
}

fn ceil(value: u64, divisor: u64) -> Result<u64, String> {
    if divisor == 0 {
        return Err("SQLite physical price divisor is zero".to_owned());
    }
    value
        .checked_div(divisor)
        .and_then(|quotient| quotient.checked_add(u64::from(value % divisor != 0)))
        .ok_or_else(|| "SQLite physical price ceiling exhausted".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_transactions_retain_separate_commit_costs() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let first = SqliteTreeWriteShapeData::record(None, 16_384, 1)?;
        let second = SqliteTreeWriteShapeData::record(Some(16_384), 16_384, 1)?;
        let first_price = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![first.clone()])?,
        )?;
        let second_price = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![second.clone()])?,
        )?;
        let merged = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![first, second])?,
        )?;
        assert!(first_price.wal_bytes() + second_price.wal_bytes() > merged.wal_bytes());
        assert!(first_price.disk_bytes() + second_price.disk_bytes() > merged.disk_bytes());
        Ok(())
    }

    #[test]
    fn same_size_rewrites_retain_old_images_and_every_history_write() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(512, 0)?;
        let price = |mutations| -> Result<SqliteTransactionWritePriceData, String> {
            price_transaction_write_shape(
                &profile,
                &SqliteTransactionWriteShapeData::checked(vec![
                    SqliteTreeWriteShapeData::record(Some(32_768), 32_768, mutations)?,
                    SqliteTreeWriteShapeData::record(None, 1024, mutations)?,
                    SqliteTreeWriteShapeData::singleton_root(256, mutations)?,
                ])?,
            )
        };
        assert!(price(3)?.wal_bytes() > 2 * price(1)?.wal_bytes());
        assert!(price(3)?.wal_frames() > price(1)?.wal_frames());
        Ok(())
    }

    #[test]
    fn an_initially_absent_repeated_row_keeps_its_intermediate_existing_image() -> Result<(), String>
    {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let price = |tree| {
            price_transaction_write_shape(
                &profile,
                &SqliteTransactionWriteShapeData::checked(vec![tree])?,
            )
        };
        let inserted_then_rewritten = price(SqliteTreeWriteShapeData::record(None, 1_048_576, 2)?)?;
        let already_existing = price(SqliteTreeWriteShapeData::record(
            Some(1_048_576),
            1_048_576,
            2,
        )?)?;
        let distinct_fresh_records =
            price(SqliteTreeWriteShapeData::fresh_insertions(1_048_576, 2)?)?;
        assert_eq!(inserted_then_rewritten, already_existing);
        assert!(inserted_then_rewritten.wal_bytes() > distinct_fresh_records.wal_bytes());
        assert!(inserted_then_rewritten.disk_bytes() > distinct_fresh_records.disk_bytes());
        Ok(())
    }

    #[test]
    fn malformed_geometry_and_exhausted_record_counts_refuse() -> Result<(), String> {
        assert!(SqliteFramePriceProfileData::checked(512, 32).is_err());
        assert!(SqliteFramePriceProfileData::checked(1000, 0).is_err());
        assert!(SqliteTreeWriteShapeData::record(Some(0), 1024, 1).is_err());
        assert!(SqliteTreeWriteShapeData::record(None, 1024, 0).is_err());
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let exhausted =
            SqliteTransactionWriteShapeData::checked(vec![SqliteTreeWriteShapeData::record(
                Some(u64::MAX),
                u64::MAX,
                u64::MAX,
            )?])?;
        assert!(price_transaction_write_shape(&profile, &exhausted).is_err());
        Ok(())
    }
}
