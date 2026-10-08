//! Page writes are priced independently from logical retained payload bytes.
use super::*;

const SQLITE_SOURCE: &str =
    "2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618";
// The bundled SQLite cursor has at most20 levels. balance_nonroot retains at
// most3 old siblings, allocates at most5 resulting siblings, and dirties their
// parent. Their union plus parent is at most6 pages at each traversed level.
const BTREE_LEVELS: u64 = 20;
const PAGES_PER_BALANCE_LEVEL: u64 = 6;
const PROTECTED_RECORD_HEADER_BYTES: u64 = 3072;
const GLOBAL_INDEX_HEADER_BYTES: u64 = 4096;
const SCOPE_INDEX_HEADER_BYTES: u64 = 256;
const FIXED_COMMAND_PAGES: u64 = 3;
const NEW_COMMAND_TREES: u64 = 7;
const EXISTING_COMMAND_TREES: u64 = 5;
const NEW_PARTIAL_INDEX_WALKS: u64 = 1;
const EXISTING_PARTIAL_INDEX_WALKS: u64 = 3;
const WAL_FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
const DISK_OVERLAP_MULTIPLIER: u64 = 2;

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
}

pub(in crate::admission_operation_store) fn physical_command_write_profile(
    tx: &Connection,
) -> Result<PhysicalCommandWriteProfileData, AdmissionOperationStoreError> {
    let page_size = verify_profile(tx)?;
    let catalog = super::super::super::super::schema::verify_physical_command_catalog(tx)?;
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.protected-command-write-profile.v2",
        SQLITE_SOURCE,
        page_size,
        (0_u8, 0_u8, "wal"),
        catalog.fingerprint(),
        (
            "main",
            "no-attached-database",
            "no-protected-temporary-source-or-trigger",
            connection_namespace::COMMAND_TABLES,
        ),
        (
            BTREE_LEVELS,
            PAGES_PER_BALANCE_LEVEL,
            PROTECTED_RECORD_HEADER_BYTES,
            GLOBAL_INDEX_HEADER_BYTES,
            SCOPE_INDEX_HEADER_BYTES,
            FIXED_COMMAND_PAGES,
            (NEW_COMMAND_TREES, EXISTING_COMMAND_TREES),
            (NEW_PARTIAL_INDEX_WALKS, EXISTING_PARTIAL_INDEX_WALKS),
            (
                WAL_FRAME_HEADER_BYTES,
                WAL_HEADER_BYTES,
                DISK_OVERLAP_MULTIPLIER,
            ),
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
    let profile = physical_command_write_profile(tx)?;
    let page_size = profile.page_size;
    let mut dirty_pages = 0_u64;
    for (position, command) in plan.commands.iter().enumerate() {
        command.verify(tx)?;
        let preceding = plan.commands[..position]
            .iter()
            .filter(|prior| prior.key == command.key)
            .count();
        if preceding != 0 && command.source.is_none() {
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
        let trees = if command.source.is_some() {
            EXISTING_COMMAND_TREES
        } else {
            NEW_COMMAND_TREES
        };
        let partial = matching_partial_indexes(tx, command)?;
        // An updated expression index can delete at an internal node (up to2
        // balance walks) and then insert (one). New entries only insert once.
        let walks = if command.source.is_some() {
            EXISTING_PARTIAL_INDEX_WALKS
        } else {
            NEW_PARTIAL_INDEX_WALKS
        };
        let balances = trees + partial * walks;
        // SQL bounds keys by characters. A512-character UTF-8 key can occupy
        // 2048 bytes. Include serial headers and other fixed columns, and price
        // history/index overflow even on the supported512-byte page profile.
        let overflow = ceiling_divide(
            command.max_payload_bytes + PROTECTED_RECORD_HEADER_BYTES,
            page_size - 4,
        )?;
        let histories = ceiling_divide(PROTECTED_RECORD_HEADER_BYTES, page_size - 4)? * 3
            + ceiling_divide(GLOBAL_INDEX_HEADER_BYTES, page_size - 4)?;
        let new_header_indexes = if command.source.is_none() {
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
            * if command.source.is_some() { 2 } else { 1 };
        // With auto-vacuum off, only page1 and the final unconsumed original
        // freelist trunk fall outside changed/allocated/freed data pages. Old
        // overflow pages are included even when secure deletion is enabled.
        let old_and_new_overflow = overflow * if command.source.is_some() { 2 } else { 1 };
        let pages = balances
            .checked_mul(BTREE_LEVELS)
            .and_then(|value| value.checked_mul(PAGES_PER_BALANCE_LEVEL))
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
    let wal_bytes = dirty_pages
        .checked_mul(page_size + WAL_FRAME_HEADER_BYTES)
        .and_then(|value| value.checked_add(WAL_HEADER_BYTES))
        .ok_or_else(|| invariant("physical WAL price exhausted"))?;
    let appends = u64::try_from(plan.commands.len())
        .map_err(|_| invariant("physical append price exhausted"))?;
    let price = PhysicalLiabilityData {
        wal_bytes,
        // WAL and later checkpoint/database growth can coexist on disk.
        disk_bytes: wal_bytes
            .checked_mul(DISK_OVERLAP_MULTIPLIER)
            .ok_or_else(|| invariant("physical disk price exhausted"))?,
        recovery_appends: appends,
        global_appends: appends,
    };
    price.validate()?;
    Ok(price)
}

pub(super) fn verify_profile(tx: &Connection) -> Result<u64, AdmissionOperationStoreError> {
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
    if source != SQLITE_SOURCE
        || !(512..=65536).contains(&page_size)
        || !page_size.is_power_of_two()
        || auto_vacuum != 0
        || spill != 0
    {
        return Err(invariant("physical SQLite write profile is unsupported"));
    }
    let journal: String = tx
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if journal != "wal" {
        return Err(invariant("physical SQLite WAL profile is unsupported"));
    }
    Ok(page_size)
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
    let original: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema
         WHERE name='admission_operation_recovery_original_owner')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !original {
        return Ok(0);
    }
    if command.source.is_none() {
        return Ok(u64::from(
            [
                "recovery-original-owner:",
                "recovery-original-transfer:",
                "recovery-original-tombstone:",
                "unused-setup-generation:",
            ]
            .iter()
            .any(|prefix| command.key.starts_with(prefix)),
        ));
    }
    // Only transfer's payload expression is mutable in an existing fixed
    // header. The other known partial indexes depend exclusively on that header.
    Ok(u64::from(
        command.key.starts_with("recovery-original-transfer:"),
    ))
}
