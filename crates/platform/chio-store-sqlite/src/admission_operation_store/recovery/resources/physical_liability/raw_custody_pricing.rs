//! Price the entire atomic Raw producer rather than its auxiliary metadata.
use super::*;
use crate::admission_operation_store::raw_custody_liability::{
    RawWriteTableData, VerifiedRawCustodyWriteLiability,
};
use crate::serving_owner::{NativeSourceTransactionOrigin, SqliteServingOwner};

const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAME_MULTIPLIER: u64 = 2;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
// sqlite3SectorSize clamps the actual WAL sector size to this compiled bound.
// Always price padding, including when a previously opened WAL cached a device
// property different from the current main file's powersafe-overwrite flag.
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;
const ANCHOR_FILE_BYTES: u64 = 2 * 1_024;

pub(in crate::admission_operation_store) fn raw_custody_price_algorithm_fingerprint(
) -> Result<String, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.raw-custody-frame-price.v1",
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
            ANCHOR_FILE_BYTES,
        ),
        "old and maximum intermediate overflow plus one freelist frame per allocation or free",
        "one whole Raw transaction including at most two admission and two global appends",
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Actual source DATA remains required. No public row-size constructor or
/// caller-supplied amount is a priced Raw purpose or usable bank allowance.
pub(in crate::admission_operation_store) fn price_raw_custody_liability(
    tx: &Transaction<'_>,
    writer: (&SqliteServingOwner, &NativeSourceTransactionOrigin<'_>),
    source: &VerifiedRawCustodyWriteLiability<'_, '_>,
) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
    source.verify_before(tx, writer)?;
    let page_size = source.profile().page_size();
    let usable_payload = page_size
        .checked_sub(4)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| invariant("Raw overflow payload divisor is invalid"))?;
    let mut frames = 1_u64; // page1 remains pinned by the actual Btree transaction.
    for shape in source.rows() {
        let mutations = shape.mutations();
        if mutations == 0 {
            continue;
        }
        let after_bytes = shape.maximum_after_record_bytes();
        if after_bytes == 0 || mutations > 2 {
            return Err(invariant(
                "Raw row descriptor is outside its producer bound",
            ));
        }
        if matches!(
            shape.table(),
            RawWriteTableData::AdmissionMeta | RawWriteTableData::GlobalMeta
        ) {
            // Both compiled tables have one INTEGER PRIMARY KEY singleton=1,
            // no secondary index and a fixed small record fitting their root.
            if !shape.index_record_bytes().is_empty()
                || shape.before_record_bytes().is_none()
                || after_bytes > page_size.saturating_sub(100)
            {
                return Err(invariant("Raw metadata singleton footprint is invalid"));
            }
            frames = add(frames, mutations)?;
            continue;
        }
        let before = shape.before_record_bytes();
        let existing = before.is_some();
        let walks = if existing {
            EXISTING_BALANCE_WALKS
        } else {
            NEW_BALANCE_WALKS
        };
        let tree_frames = mul(
            mul(mul(mutations, walks)?, CURSOR_LEVELS)?,
            BALANCE_PAGES_PER_LEVEL,
        )?;
        let after_overflow = ceil(after_bytes, usable_payload)?;
        let old_overflow = if let Some(before_bytes) = before {
            // The first update can allocate its maximum new image, and the
            // second can free that image. A small original is not same-size
            // credit against the intermediate owning producer's body.
            ceil(before_bytes.max(after_bytes), usable_payload)?
        } else {
            0
        };
        let overflow = mul(add(after_overflow, old_overflow)?, mutations)?;
        let table_frames = add(tree_frames, overflow)?;
        frames = add(
            frames,
            mul(table_frames, ALLOCATION_OR_FREE_FRAME_MULTIPLIER)?,
        )?;
        for index_bytes in shape.index_record_bytes() {
            if *index_bytes == 0 {
                return Err(invariant("Raw index descriptor lost its key bound"));
            }
            let index_overflow = mul(
                ceil(*index_bytes, usable_payload)?,
                if existing { 2 } else { 1 },
            )?;
            let index_frames = add(tree_frames, mul(index_overflow, mutations)?)?;
            frames = add(
                frames,
                mul(index_frames, ALLOCATION_OR_FREE_FRAME_MULTIPLIER)?,
            )?;
        }
    }
    // Auto-vacuum is off. Each allocation/free affects at most one freelist
    // trunk beyond the changed data page under BTALLOC_ANY. Pricing both frames
    // per allocation or free permits repeated spills of that trunk. The blob's
    // payload/next-pointer pages stay referenced until each page is complete.
    // Tree balance pages are similarly charged per actual mutation, including
    // repeated old/new image work and secure deletion. No dirty-page union is
    // substituted for the enabled-spill writer's complete frame envelope.
    let frame_bytes = add(page_size, FRAME_HEADER_BYTES)?;
    let padding_frames = ceil(MAX_WAL_SECTOR_BYTES, frame_bytes)?;
    let maximum_frames = add(frames, padding_frames)?;
    require_wal_frame_space(tx, maximum_frames)?;
    let wal_bytes = add(mul(maximum_frames, frame_bytes)?, WAL_HEADER_BYTES)?;
    let price = PhysicalLiabilityData {
        wal_bytes,
        // Appended WAL and later main-file allocation coexist. The serving
        // anchor overwrites its existing fixed slots without extending them;
        // retaining its whole fixed file adds a separate conservative margin.
        disk_bytes: add(mul(wal_bytes, 2)?, ANCHOR_FILE_BYTES)?,
        recovery_appends: 0,
        global_appends: 2,
    };
    price.validate()?;
    Ok(price)
}

fn require_wal_frame_space(
    tx: &Connection,
    maximum_frames: u64,
) -> Result<(), AdmissionOperationStoreError> {
    // NOOP checkpoints cannot run on the writer transaction. The read-only
    // observer must borrow the exact same main file, never an inferred path.
    let path = tx
        .path()
        .ok_or_else(|| invariant("Raw WAL pricing requires a persistent authority"))?;
    let observer = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_error)?;
    observer
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(sqlite_error)?;
    if chio_sqlite_file_identity::main_database_file_identity(tx).map_err(invariant)?
        != chio_sqlite_file_identity::main_database_file_identity(&observer).map_err(invariant)?
    {
        return Err(invariant(
            "Raw WAL observer changed its actual authority file",
        ));
    }
    let (busy, log, checkpointed): (i64, i64, i64) = observer
        .query_row("PRAGMA main.wal_checkpoint(NOOP)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(sqlite_error)?;
    // SQLite returns these u32 counters through signed int outputs. Negative
    // outputs can also be wrapped exhausted frontiers, not just an unused WAL.
    // This initialized authority must supply unambiguous nonnegative counters.
    let log = if matches!(busy, 0 | 1) && log >= 0 && (0..=log).contains(&checkpointed) {
        stored_u64(log, "Raw WAL frame frontier")?
    } else {
        return Err(invariant("Raw WAL frame frontier is unavailable"));
    };
    log.checked_add(maximum_frames)
        .filter(|frames| *frames <= i32::MAX as u64)
        .ok_or_else(|| invariant("Raw WAL frame frontier is exhausted"))?;
    Ok(())
}

fn add(left: u64, right: u64) -> Result<u64, AdmissionOperationStoreError> {
    left.checked_add(right)
        .ok_or_else(|| invariant("Raw physical byte or frame sum exhausted"))
}

fn mul(left: u64, right: u64) -> Result<u64, AdmissionOperationStoreError> {
    left.checked_mul(right)
        .ok_or_else(|| invariant("Raw physical byte or frame product exhausted"))
}

fn ceil(value: u64, divisor: u64) -> Result<u64, AdmissionOperationStoreError> {
    if divisor == 0 {
        return Err(invariant("Raw physical divisor is zero"));
    }
    value
        .checked_div(divisor)
        .and_then(|quotient| quotient.checked_add(u64::from(value % divisor != 0)))
        .ok_or_else(|| invariant("Raw physical ceiling division exhausted"))
}
