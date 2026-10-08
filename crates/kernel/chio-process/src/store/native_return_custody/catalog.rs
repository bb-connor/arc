//! Actual Process recipe and complete maintained catalog are source DATA.
use super::*;
use chio_sqlite_file_identity::write_price_algorithm_descriptor;
use chio_sqlite_file_identity::{main_database_file_identity, main_database_write_geometry};

const SQLITE_SOURCE: &str =
    "2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618";
type CatalogRow = (String, String, String, Option<String>);

pub(super) struct ProcessWriteProfileData {
    page_size: u64,
    file_device: u64,
    file_inode: u64,
    sector_bytes: u64,
    device_characteristics: u32,
    cache_spill: u64,
    catalog_digest: String,
    recipe_digest: String,
}
impl ProcessWriteProfileData {
    pub(super) fn page_size(&self) -> u64 {
        self.page_size
    }
    pub(super) fn reserved_bytes(&self) -> u64 {
        0
    }
    pub(super) fn file_device(&self) -> u64 {
        self.file_device
    }
    pub(super) fn file_inode(&self) -> u64 {
        self.file_inode
    }
    pub(super) fn sector_bytes(&self) -> u64 {
        self.sector_bytes
    }
    pub(super) fn device_characteristics(&self) -> u32 {
        self.device_characteristics
    }
    pub(super) fn cache_spill(&self) -> u64 {
        self.cache_spill
    }
    pub(super) fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }
    pub(super) fn recipe_digest(&self) -> &str {
        &self.recipe_digest
    }
}

/// Borrow the actual same-file writer; there is no caller geometry selector.
pub(super) fn prepare_profile(
    tx: &Transaction<'_>,
    store_path: &Path,
    expected_namespace: &str,
    expected_authority: &str,
    expected_key: &str,
) -> Result<ProcessWriteProfileData, ProcessError> {
    require_namespace(tx)?;
    let (version, namespace, authority, key): (i64, String, String, String) = tx.query_row(
        "SELECT version,namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(version, 1..=7)
        || namespace != expected_namespace
        || authority != expected_authority
        || key != expected_key
        || uuid::Uuid::parse_str(&namespace).map_or(true, |value| value.to_string() != namespace)
        || uuid::Uuid::parse_str(&authority).map_or(true, |value| value.to_string() != authority)
    {
        return Err(unsupported());
    }
    // Existing real cohorts are verified independently. Draft 8 cannot enter
    // this predecessor path or acquire current funding by changing one number.
    super::super::unused_recovery_reservation::verify_before_open(tx)?;
    super::super::confined_delivery::verify_before_open(tx)?;
    let source: String = tx.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    let encoding: String = tx.query_row("PRAGMA main.encoding", [], |row| row.get(0))?;
    let journal: String = tx.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    let page_size =
        u64::try_from(tx.query_row("PRAGMA main.page_size", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| unsupported())?;
    let vacuum =
        u64::try_from(tx.query_row("PRAGMA main.auto_vacuum", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| unsupported())?;
    let sync =
        u64::try_from(tx.query_row("PRAGMA main.synchronous", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| unsupported())?;
    let cache_spill =
        u64::try_from(tx.query_row("PRAGMA main.cache_spill", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| unsupported())?;
    let geometry = main_database_write_geometry(tx).map_err(|_| unsupported())?;
    let file = main_database_file_identity(tx).map_err(|_| unsupported())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_file = std::fs::symlink_metadata(store_path)?;
        if !path_file.is_file()
            || file.link_count != 1
            || (path_file.dev(), path_file.ino()) != (file.device, file.inode)
        {
            return Err(unsupported());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = store_path;
        return Err(unsupported());
    }
    if source != SQLITE_SOURCE
        || encoding != "UTF-8"
        || journal != "wal"
        || !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || vacuum != 0
        || sync != 2
        || geometry.reserved_bytes() != 0
    {
        return Err(unsupported());
    }
    let actual = catalog(tx)?;
    if actual != expected_predecessor_catalog()? {
        return Err(unsupported());
    }
    let catalog_digest = digest(&actual)?;
    let recipe_digest = digest(&(
        "chio.process-native-return-write-profile.v1",
        SQLITE_SOURCE,
        &catalog_digest,
        page_size,
        "UTF-8",
        "wal",
        0_u8,
        2_u8,
        geometry.reserved_bytes(),
        geometry.sector_bytes(),
        geometry.device_characteristics(),
        geometry.vfs_name(),
        cache_spill,
        "whole old/new rows and mutable indexes, per mutation, FULL sector padding",
        write_price_algorithm_descriptor(),
    ))?;
    Ok(ProcessWriteProfileData {
        page_size,
        file_device: file.device,
        file_inode: file.inode,
        sector_bytes: geometry.sector_bytes(),
        device_characteristics: geometry.device_characteristics(),
        cache_spill,
        catalog_digest,
        recipe_digest,
    })
}

fn require_namespace(tx: &Connection) -> Result<(), ProcessError> {
    let mut statement = tx.prepare("PRAGMA database_list")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if names.iter().any(|name| name != "main" && name != "temp")
        || !names.iter().any(|name| name == "main")
    {
        return Err(unsupported());
    }
    let shadowed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema t WHERE t.type='trigger' OR (t.type IN('table','view') AND (lower(t.name) IN('sqlite_schema','sqlite_master','dbstat') OR lower(t.name) GLOB 'pragma_*' OR EXISTS(SELECT 1 FROM main.sqlite_schema m WHERE m.type IN('table','view') AND t.name=m.name COLLATE NOCASE))))",
        [], |row| row.get(0),
    )?;
    if shadowed {
        return Err(unsupported());
    }
    Ok(())
}

fn catalog(tx: &Connection) -> Result<Vec<CatalogRow>, ProcessError> {
    // The exact known predecessor guard is checked by its owner, before it is
    // excluded from this comparison. No generic predicate normalization occurs.
    super::super::unused_recovery_reservation::verify_retained_version_guard(tx)?;
    let mut statement = tx.prepare(
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name!='process_recovery_version_monotone' ORDER BY type,name,tbl_name",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn expected_predecessor_catalog() -> Result<Vec<CatalogRow>, ProcessError> {
    let model = Connection::open_in_memory()?;
    model.execute_batch(include_str!("../../store.sql"))?;
    model.execute_batch(include_str!("../unused_recovery_reservation/schema.sql"))?;
    model.execute_batch(include_str!("../confined_delivery/schema.sql"))?;
    model.execute_batch(
        "CREATE TRIGGER process_knowledge_no_downgrade BEFORE UPDATE OF version ON process_runtime
            WHEN OLD.version>=3 AND NEW.version<OLD.version
            BEGIN SELECT RAISE(ABORT,'knowledge enforcement is permanent'); END;",
    )?;
    catalog(&model)
}

/// An observer checks the same actual file and its own Process WAL. It cannot
/// borrow the native file's WAL or turn an unavailable counter into zero.
pub(super) fn observe_wal_frontier(tx: &Connection) -> Result<(u64, u64), ProcessError> {
    let path = tx.path().ok_or_else(unsupported)?;
    let observer = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    observer.busy_timeout(Duration::ZERO)?;
    if main_database_file_identity(tx).map_err(|_| unsupported())?
        != main_database_file_identity(&observer).map_err(|_| unsupported())?
    {
        return Err(unsupported());
    }
    let (busy, log, checkpointed): (i64, i64, i64) =
        observer.query_row("PRAGMA main.wal_checkpoint(NOOP)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if !matches!(busy, 0 | 1) || log < 0 || !(0..=log).contains(&checkpointed) {
        return Err(unsupported());
    }
    Ok((
        u64::try_from(log).map_err(|_| unsupported())?,
        u64::try_from(checkpointed).map_err(|_| unsupported())?,
    ))
}

fn unsupported() -> ProcessError {
    ProcessError::Configuration("Process original finishing source recipe is unsupported")
}
