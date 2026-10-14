//! Page writes are priced independently from logical retained payload bytes.
use super::*;
use chio_sqlite_file_identity::{
    main_database_write_geometry, write_price_algorithm_descriptor, SqliteFramePriceProfileData,
    SqliteWriteGeometryData,
};

const SQLITE_SOURCE: &str = crate::admission_operation_store::BUNDLED_SQLITE_SOURCE_ID;
const PROTECTED_RECORD_HEADER_BYTES: u64 = 3072;
const GLOBAL_INDEX_HEADER_BYTES: u64 = 4096;
const SCOPE_INDEX_HEADER_BYTES: u64 = 256;
const FIXED_COMMAND_PAGES: u64 = 3;
const NEW_COMMAND_TREES: u64 = 7;
const EXISTING_COMMAND_TREES: u64 = 5;
const NEW_PARTIAL_INDEX_WALKS: u64 = 1;
const EXISTING_PARTIAL_INDEX_WALKS: u64 = 3;

/// A verified physical layout description. This DATA is neither a reservation
/// nor a complete native producer profile.
pub(in crate::admission_operation_store) struct PhysicalCommandWriteProfileData {
    page_size: u64,
    fingerprint: String,
}

impl PhysicalCommandWriteProfileData {
    pub(in crate::admission_operation_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(in crate::admission_operation_store) fn page_size(&self) -> u64 {
        self.page_size
    }
}

pub(in crate::admission_operation_store) fn physical_command_write_profile(
    tx: &Connection,
) -> Result<PhysicalCommandWriteProfileData, AdmissionOperationStoreError> {
    let (page_size, geometry) = verify_profile(tx)?;
    let catalog = super::super::super::super::schema::verify_physical_command_catalog(tx)?;
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.protected-command-write-profile.v3",
        SQLITE_SOURCE,
        page_size,
        (0_u8, 0_u8, "wal"),
        catalog.fingerprint(),
        write_price_algorithm_descriptor(),
        (
            "UTF-8",
            2_u8,
            geometry.reserved_bytes(),
            geometry.sector_bytes(),
            geometry.device_characteristics(),
            geometry.vfs_name(),
        ),
        (
            "main",
            "no-attached-database",
            "no-protected-temporary-source-or-trigger",
            connection_namespace::COMMAND_TABLES,
        ),
        (
            CURSOR_LEVELS,
            BALANCE_PAGES_PER_LEVEL,
            PROTECTED_RECORD_HEADER_BYTES,
            GLOBAL_INDEX_HEADER_BYTES,
            SCOPE_INDEX_HEADER_BYTES,
            FIXED_COMMAND_PAGES,
            (NEW_COMMAND_TREES, EXISTING_COMMAND_TREES),
            (NEW_PARTIAL_INDEX_WALKS, EXISTING_PARTIAL_INDEX_WALKS),
        ),
        (
            MAX_RECOVERY_BATCH,
            MAX_RECOVERY_RECORD_BYTES,
            MAX_TRUSTED_UNIX_MS,
        ),
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(PhysicalCommandWriteProfileData {
        page_size,
        fingerprint: sha256_hex(&bytes),
    })
}

/// Describe a bounded command write. This DATA grants no authority to append
/// native source, publish a migration, or consume an owed purpose.
pub(in crate::admission_operation_store) fn price_protected_command_liability(
    tx: &Connection,
    plan: &ProtectedCommandLiabilityPlan,
) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
    price_command_plan(tx, plan, None)
}

pub(in crate::admission_operation_store) fn price_protected_command_with_row_limits(
    tx: &Connection,
    plan: &ProtectedCommandLiabilityPlan,
    limits: &std::collections::BTreeMap<String, u64>,
) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
    price_command_plan(tx, plan, Some(limits))
}

fn price_command_plan(
    tx: &Connection,
    plan: &ProtectedCommandLiabilityPlan,
    limits: Option<&std::collections::BTreeMap<String, u64>>,
) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
    let profile = physical_command_write_profile(tx)?;
    let page_size = profile.page_size;
    let mut dirty_pages = 0_u64;
    for (position, command) in plan.commands.iter().enumerate() {
        command.verify(tx)?;
        let preceding = plan.commands[..position]
            .iter()
            .filter(|prior| prior.key == command.key)
            .count();
        if preceding != 0 && command.source.is_none() && !command.rewrite {
            return Err(invariant("physical plan repeats a pristine command"));
        }
        if let Some(source) = &command.source {
            source
                .version
                .checked_add(
                    u64::try_from(preceding + 1)
                        .map_err(|_| invariant("physical source version liability exhausted"))?,
                )
                .filter(|version| *version <= MAX_TRUSTED_UNIX_MS)
                .ok_or_else(|| invariant("physical source version liability exhausted"))?;
        }
        // Each command mutates its table and appends a table/index pair for
        // recovery events and global commits. A new command also inserts its
        // immutable primary-key and scope indexes. Existing header columns are
        // unchanged; the native partial index is empty for this command kind.
        let existing = command.source.is_some() || command.rewrite;
        let trees = if existing {
            EXISTING_COMMAND_TREES
        } else {
            NEW_COMMAND_TREES
        };
        let partial = matching_partial_indexes(tx, command)?;
        // An updated expression index can delete at an internal node (up to2
        // balance walks) and then insert (one). New entries only insert once.
        let walks = if existing {
            EXISTING_PARTIAL_INDEX_WALKS
        } else {
            NEW_PARTIAL_INDEX_WALKS
        };
        let levels = |table: &str| -> Result<u64, AdmissionOperationStoreError> {
            match limits {
                None => Ok(CURSOR_LEVELS),
                Some(limits) => {
                    chio_sqlite_file_identity::SqliteTreeWriteShapeData::retained_row_cursor_levels(
                        *limits.get(table).ok_or_else(|| {
                            invariant("native command lacks its retained row ceiling")
                        })?,
                    )
                    .map_err(invariant)
                }
            }
        };
        let balance_levels = if limits.is_some() {
            // Existing headers and their indexes are immutable. Fresh records
            // add the PK and scope trees. Each history has one mutable tree
            // and one insert-only index; each index has at most its table's rows.
            levels("admission_operation_recovery_records")?
                .checked_mul(if existing { 1 } else { 3 })
                .and_then(|sum| {
                    sum.checked_add(2 * levels("admission_operation_recovery_events").ok()?)
                })
                .and_then(|sum| sum.checked_add(2 * levels("authority_global_commits").ok()?))
                .and_then(|sum| sum.checked_add(partial * walks * CURSOR_LEVELS))
                .ok_or_else(|| invariant("native command balance bound exhausted"))?
        } else {
            (trees + partial * walks) * CURSOR_LEVELS
        };
        // SQL bounds keys by characters. A512-character UTF-8 key can occupy
        // 2048 bytes. Include serial headers and other fixed columns, and price
        // history/index overflow even on the supported512-byte page profile.
        let overflow = ceiling_divide(
            command.max_payload_bytes + PROTECTED_RECORD_HEADER_BYTES,
            page_size - 4,
        )?;
        let histories = ceiling_divide(PROTECTED_RECORD_HEADER_BYTES, page_size - 4)? * 3
            + ceiling_divide(GLOBAL_INDEX_HEADER_BYTES, page_size - 4)?;
        let new_header_indexes = if !existing {
            ceiling_divide(PROTECTED_RECORD_HEADER_BYTES, page_size - 4)?
                + ceiling_divide(SCOPE_INDEX_HEADER_BYTES, page_size - 4)?
        } else {
            0
        };
        let partial_overflow = partial
            * ceiling_divide(
                command.max_payload_bytes + PROTECTED_RECORD_HEADER_BYTES,
                page_size - 4,
            )?
            * if existing { 2 } else { 1 };
        // With auto-vacuum off, only page1 and the final unconsumed original
        // freelist trunk fall outside changed/allocated/freed data pages. Old
        // overflow pages are included even when secure deletion is enabled.
        let old_and_new_overflow = overflow * if existing { 2 } else { 1 };
        let pages = balance_levels
            .checked_mul(BALANCE_PAGES_PER_LEVEL)
            .and_then(|value| value.checked_add(old_and_new_overflow))
            .and_then(|value| value.checked_add(histories))
            .and_then(|value| value.checked_add(new_header_indexes))
            .and_then(|value| value.checked_add(partial_overflow))
            .and_then(|value| value.checked_add(FIXED_COMMAND_PAGES))
            .ok_or_else(|| invariant("physical command page price exhausted"))?;
        dirty_pages = dirty_pages
            .checked_add(pages)
            .ok_or_else(|| invariant("physical command page price exhausted"))?;
    }
    if plan.commands.is_empty() {
        return Ok(PhysicalLiabilityData::zero());
    }
    // Frame the complete dirty-page bound once for the committed transaction.
    let frame_profile = SqliteFramePriceProfileData::checked(page_size, 0).map_err(invariant)?;
    let framed = frame_profile.price_frames(dirty_pages).map_err(invariant)?;
    let wal_bytes = framed.wal_bytes();
    let appends = u64::try_from(plan.commands.len())
        .map_err(|_| invariant("physical append price exhausted"))?;
    let price = PhysicalLiabilityData {
        wal_bytes,
        // WAL and later checkpoint/database growth can coexist on disk; the
        // shared calculator already retains the overlap multiplier.
        disk_bytes: framed.disk_bytes(),
        recovery_appends: appends,
        global_appends: appends,
    };
    price.validate()?;
    Ok(price)
}

pub(super) fn verify_profile(
    tx: &Connection,
) -> Result<(u64, SqliteWriteGeometryData), AdmissionOperationStoreError> {
    connection_namespace::require_command_namespace(tx)?;
    let source: String = tx
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size: u64 = tx
        .query_row("PRAGMA main.page_size", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_error)
        .and_then(|value| stored_u64(value, "physical page size"))?;
    let auto_vacuum: i64 = tx
        .query_row("PRAGMA main.auto_vacuum", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let spill: i64 = tx
        .query_row("PRAGMA main.cache_spill", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let encoding: String = tx
        .query_row("PRAGMA main.encoding", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let synchronous: i64 = tx
        .query_row("PRAGMA main.synchronous", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    // The helper validates the actual main-database geometry itself; the
    // closed command row codec additionally requires its zero pending
    // reserved bytes, which reading only the old database header would miss.
    let geometry = main_database_write_geometry(tx).map_err(invariant)?;
    if source != SQLITE_SOURCE
        || !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || auto_vacuum != 0
        // The generic dirty-page bound depends on no mid-transaction spill:
        // a spilled cache would dirty additional pages after this bound.
        || spill != 0
        || encoding != "UTF-8"
        // Every priced FULL commit retains the bundled sector padding.
        || synchronous != 2
        || geometry.reserved_bytes() != 0
    {
        return Err(invariant("physical SQLite write profile is unsupported"));
    }
    let journal: String = tx
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if journal != "wal" {
        return Err(invariant("physical SQLite WAL profile is unsupported"));
    }
    Ok((page_size, geometry))
}

fn ceiling_divide(value: u64, divisor: u64) -> Result<u64, AdmissionOperationStoreError> {
    value
        .checked_add(divisor - 1)
        .map(|value| value / divisor)
        .ok_or_else(|| invariant("physical overflow page price exhausted"))
}

pub(super) fn verify_command_catalog(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    connection_namespace::require_command_namespace(tx)?;
    super::super::super::super::schema::verify_physical_command_catalog(tx).map(|_| ())
}

fn matching_partial_indexes(
    tx: &Connection,
    command: &PlannedCommand,
) -> Result<u64, AdmissionOperationStoreError> {
    // These current indexes require a separate complete writer bound. Their
    // inclusion in the authenticated catalog is not a physical price.
    for (name, prefix) in [
        (
            "admission_operation_recovery_command_alias",
            "command-alias:",
        ),
        ("admission_operation_recovery_first_report", "command:"),
        (
            "admission_operation_recovery_reference_capacity",
            "knowledge-reference-capacity:",
        ),
        (
            "idx_recovery_knowledge_journal_chunk_authority",
            "knowledge-encoding-chunk:",
        ),
        ("idx_recovery_knowledge_join_release", "knowledge-join:"),
    ] {
        if command.key.starts_with(prefix) {
            let present: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name=?1)",
                    [name],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if present {
                return Err(invariant(
                    "current command partial index writer is not priced",
                ));
            }
        }
    }
    // The never-released successor-ownership prototype indexes refuse
    // pricing through the verified catalog, so no partial index is priced.
    Ok(0)
}
