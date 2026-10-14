//! Actual Process recipe and complete maintained catalog are source DATA.
use super::*;
use chio_sqlite_file_identity::write_price_algorithm_descriptor;
use chio_sqlite_file_identity::{main_database_file_identity, main_database_write_geometry};
use std::ops::RangeInclusive;

const SQLITE_SOURCE: &str =
    "2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618";
pub(super) type CatalogRow = (String, String, String, Option<String>);

pub(super) struct ProcessWriteProfileData {
    page_size: u64,
    file_device: u64,
    file_inode: u64,
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
    pub(super) fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }
    pub(super) fn recipe_digest(&self) -> &str {
        &self.recipe_digest
    }
}

/// The five retained feature-level objects of the borrowed base schema.
const FEATURE_TABLE: &str = "process_feature_level";
const FEATURE_TRIGGERS: [&str; 4] = [
    "process_feature_level_retained_at_cohort",
    "process_feature_level_retained_once",
    "process_feature_level_monotone",
    "process_feature_level_no_delete",
];

/// Borrow the actual same-file writer; there is no caller geometry selector.
/// A version-one-to-seven journal is either the exact new base layout with
/// the retained feature-level family or the exact legacy layout without it;
/// both are authenticated, byte-exact, with their own feature-level rules.
pub(super) fn prepare_profile(
    tx: &Connection,
    store_path: &Path,
    expected_namespace: &str,
    expected_authority: &str,
    expected_key: &str,
) -> Result<ProcessWriteProfileData, ProcessError> {
    profile_against(
        tx,
        store_path,
        expected_namespace,
        expected_authority,
        expected_key,
        (1..=7, expected_predecessor_catalogs()?),
    )
}

/// Whether the journal is exactly the compiled layout of its activation
/// state: every catalog row matches the predecessor or cohort model and the
/// version guard is the compiled text, so opening it writes nothing.
pub(super) fn layout_is_current(tx: &Connection) -> Result<bool, ProcessError> {
    let model = predecessor_model()?;
    let expected = if cohort::family_present(tx)? {
        expected_cohort_catalog()?
    } else {
        catalog(&model)?
    };
    if catalog(tx)? != expected {
        return Ok(false);
    }
    let guard = |connection: &Connection| -> Result<Option<String>, ProcessError> {
        Ok(connection
            .query_row(
                "SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name='process_recovery_version_monotone'",
                [],
                |row| row.get(0),
            )
            .optional()?)
    };
    Ok(guard(tx)? == guard(&model)?)
}

/// The retained cohort recipe: the complete funded bank family belongs to the
/// maintained catalog of an activated journal. A draft or partial family is
/// never priced as the predecessor recipe.
pub(super) fn prepare_cohort_profile(
    tx: &Connection,
    store_path: &Path,
    expected_namespace: &str,
    expected_authority: &str,
    expected_key: &str,
) -> Result<ProcessWriteProfileData, ProcessError> {
    profile_against(
        tx,
        store_path,
        expected_namespace,
        expected_authority,
        expected_key,
        ((8..=8), vec![expected_cohort_catalog()?]),
    )
}

/// The active write profile of this file: the exact predecessor recipe before
/// activation, the retained cohort recipe once the funded family is present.
pub(super) fn prepare_active_profile(
    tx: &Connection,
    store_path: &Path,
    expected_namespace: &str,
    expected_authority: &str,
    expected_key: &str,
) -> Result<ProcessWriteProfileData, ProcessError> {
    if cohort::family_present(tx)? {
        prepare_cohort_profile(
            tx,
            store_path,
            expected_namespace,
            expected_authority,
            expected_key,
        )
    } else {
        prepare_profile(
            tx,
            store_path,
            expected_namespace,
            expected_authority,
            expected_key,
        )
    }
}

fn profile_against(
    tx: &Connection,
    store_path: &Path,
    expected_namespace: &str,
    expected_authority: &str,
    expected_key: &str,
    expected: (RangeInclusive<u32>, Vec<Vec<CatalogRow>>),
) -> Result<ProcessWriteProfileData, ProcessError> {
    let (expected_versions, expected_catalogs) = expected;
    require_namespace(tx)?;
    let (version, namespace, authority, key): (u32, String, String, String) = tx.query_row(
        "SELECT version,namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !expected_versions.contains(&version)
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
    let actual = catalog(tx)?;
    if !expected_catalogs.iter().any(|expected| &actual == expected) {
        return Err(unsupported());
    }
    // The retained feature-level layout of this exact version is part of the
    // authenticated base: the historical layout predating the family, two
    // predecessor variants or the complete cohort.
    verify_feature_level_layout(tx, version)?;
    physical_profile(tx, store_path, &["wal"], &actual)
}

/// The physical write profile of the held file: the pinned SQLite build and
/// encoding, the page geometry, the synchronous level, the actual file
/// identity and the stated journal modes. `catalog` is the layout the recipe
/// is bound to.
fn physical_profile(
    tx: &Connection,
    store_path: &Path,
    journal_modes: &[&str],
    catalog: &[CatalogRow],
) -> Result<ProcessWriteProfileData, ProcessError> {
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
        || !journal_modes.contains(&journal.as_str())
        || !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || vacuum != 0
        || sync != 2
        || geometry.reserved_bytes() != 0
    {
        return Err(unsupported());
    }
    let catalog_digest = digest(&catalog)?;
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
        catalog_digest,
        recipe_digest,
    })
}

/// The held file before its first write: no catalog objects and no pages
/// beyond the header, authenticated from the actual file. Its recipe is the
/// one the journal has once the compiled layout is in WAL mode.
pub(super) fn prepare_empty_profile(
    tx: &Connection,
    store_path: &Path,
) -> Result<ProcessWriteProfileData, ProcessError> {
    require_namespace(tx)?;
    require_empty_file(tx)?;
    physical_profile(tx, store_path, &["delete", "wal"], &[])
}

/// A file with an empty catalog, no user data pages and no application
/// identity. Positive observations only; an error is never read as empty.
pub(super) fn require_empty_file(tx: &Connection) -> Result<(), ProcessError> {
    let objects: i64 = tx.query_row("SELECT count(*) FROM main.sqlite_schema", [], |row| {
        row.get(0)
    })?;
    let pages: i64 = tx.query_row("PRAGMA main.page_count", [], |row| row.get(0))?;
    let user: i64 = tx.query_row("PRAGMA main.user_version", [], |row| row.get(0))?;
    let application: i64 = tx.query_row("PRAGMA main.application_id", [], |row| row.get(0))?;
    if objects != 0 || !(0..=1).contains(&pages) || user != 0 || application != 0 {
        return Err(unsupported());
    }
    Ok(())
}

/// The exact historical layout that predates the retained feature-level
/// family: only the version guard may stand on the runtime table, and no
/// feature-level object exists.
fn verify_historical_layout(tx: &Connection) -> Result<(), ProcessError> {
    let family: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_feature_level*'",
        [],
        |row| row.get(0),
    )?;
    let triggers: Vec<String> = {
        let mut statement = tx.prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name='process_runtime' ORDER BY name",
        )?;
        let names = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        names
    };
    // The authentic first shipped schema carries no trigger on its runtime
    // table. A later binary that already served the same version one
    // catalog may have installed exactly the version guard, whose text its
    // owner verifies separately before this layout comparison. Any other
    // trigger set is an unsupported layout.
    let authentic = triggers.is_empty();
    let guarded = triggers.len() == 1 && triggers[0] == "process_recovery_version_monotone";
    if family != 0 || !(authentic || guarded) {
        return Err(unsupported());
    }
    Ok(())
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
        [],
        |row| row.get(0),
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

fn predecessor_model() -> Result<Connection, ProcessError> {
    let model = Connection::open_in_memory()?;
    model.execute_batch(include_str!("../../store.sql"))?;
    model.execute_batch(include_str!("../unused_recovery_reservation/schema.sql"))?;
    model.execute_batch(include_str!("../confined_delivery/schema.sql"))?;
    model.execute_batch(&format!(
        "{};",
        crate::store::KNOWLEDGE_NO_DOWNGRADE_TRIGGER
    ))?;
    Ok(model)
}

/// The exact legacy base layout: an old binary's journal carries none of the
/// five retained feature-level objects. Old files may also retain the exact
/// old version-guard text; that trigger is excluded from this comparison by
/// name and preserved by its own explicit predecessor guard.
fn legacy_predecessor_model() -> Result<Connection, ProcessError> {
    let model = predecessor_model()?;
    model.execute_batch(
        "DROP TRIGGER IF EXISTS process_feature_level_retained_at_cohort;
         DROP TRIGGER IF EXISTS process_feature_level_retained_once;
         DROP TRIGGER IF EXISTS process_feature_level_monotone;
         DROP TRIGGER IF EXISTS process_feature_level_no_delete;
         DROP TABLE IF EXISTS process_feature_level;",
    )?;
    Ok(model)
}

/// The exact historical base layout, retained as the original schema text of
/// the first shipped journal. It lacks the recovery, knowledge, delivery and
/// feature-level families and the knowledge columns of the state blobs.
fn historical_model() -> Result<Connection, ProcessError> {
    let model = Connection::open_in_memory()?;
    model.execute_batch(include_str!(
        "../../../tests/fixtures/legacy-process-v1.sql"
    ))?;
    Ok(model)
}

pub(super) fn historical_catalog() -> Result<Vec<CatalogRow>, ProcessError> {
    catalog(&historical_model()?)
}

/// The compiled layout every supported source is brought to.
pub(super) fn compiled_catalog() -> Result<Vec<CatalogRow>, ProcessError> {
    catalog(&predecessor_model()?)
}

/// The compiled version guard text, excluded from catalog comparison by name.
pub(super) fn compiled_guard_sql() -> Result<String, ProcessError> {
    Ok(predecessor_model()?.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='process_recovery_version_monotone'",
        [],
        |row| row.get(0),
    )?)
}

/// The actual catalog of the held file, excluding the version guard.
pub(super) fn actual_catalog(tx: &Connection) -> Result<Vec<CatalogRow>, ProcessError> {
    catalog(tx)
}

/// The actual version guard text of the held file, if any.
pub(super) fn actual_guard_sql(tx: &Connection) -> Result<Option<String>, ProcessError> {
    Ok(tx
        .query_row(
            "SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name='process_recovery_version_monotone'",
            [],
            |row| row.get(0),
        )
        .optional()?)
}

/// Every exact supported base layout of a version-one-to-seven journal.
fn expected_predecessor_catalogs() -> Result<Vec<Vec<CatalogRow>>, ProcessError> {
    Ok(vec![
        catalog(&predecessor_model()?)?,
        catalog(&legacy_predecessor_model()?)?,
        historical_catalog()?,
    ])
}

/// Digests of the exact supported predecessor catalogs. A source cut before
/// its journal completed cohort activation retains one of these until it is
/// consumed.
pub(super) fn predecessor_catalog_digests() -> Result<Vec<String>, ProcessError> {
    Ok(expected_predecessor_catalogs()?
        .into_iter()
        .map(|expected| digest(&expected))
        .collect::<Result<Vec<_>, _>>()?)
}

/// Authenticate the retained feature-level layout of one journal version.
/// A version-one-to-seven journal is either the exact legacy layout without
/// the five feature objects or the exact new base layout with all five
/// byte-exact and an empty level table. Version eight requires all five
/// byte-exact plus exactly one retained level row between one and seven. No
/// unknown trigger on process_runtime or the feature table is accepted, and
/// no arbitrary empty old cohort is.
pub(super) fn verify_feature_level_layout(
    connection: &Connection,
    version: u32,
) -> Result<(), ProcessError> {
    // The historical layout predates the whole family: it is recognized by
    // its exact catalog and has its own trigger set.
    if version != 8 && catalog(connection)? == historical_catalog()? {
        return verify_historical_layout(connection);
    }
    let model = predecessor_model()?;
    let mut present = 0_usize;
    for name in std::iter::once(FEATURE_TABLE).chain(FEATURE_TRIGGERS) {
        let expected: (String, String, Option<String>) = model.query_row(
            "SELECT type,sql,tbl_name FROM sqlite_schema WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let actual: Option<(String, String, Option<String>)> = connection
            .query_row(
                "SELECT type,sql,tbl_name FROM sqlite_schema WHERE name=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if actual.as_ref() == Some(&expected) {
            present += 1;
        }
    }
    let family: usize = usize::try_from(connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_feature_level*'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .map_err(|_| unsupported())?;
    let feature_triggers: usize = usize::try_from(connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND tbl_name='process_feature_level'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
    .map_err(|_| unsupported())?;
    if family != present || (present != 0 && present != FEATURE_TRIGGERS.len() + 1) {
        return Err(unsupported());
    }
    if present == 0 && (family != 0 || feature_triggers != 0 || version == 8) {
        // The legacy layout exists only below the retained cohort version.
        return Err(unsupported());
    }
    if present != 0 {
        // The activation trigger belongs to process_runtime; the other
        // three guards belong to the retained feature-level table.
        if feature_triggers != FEATURE_TRIGGERS.len() - 1 {
            return Err(unsupported());
        }
        let rows: i64 =
            connection.query_row("SELECT count(*) FROM process_feature_level", [], |row| {
                row.get(0)
            })?;
        match version {
            1..=7 => {
                if rows != 0 {
                    return Err(unsupported());
                }
            }
            8 => {
                let (singleton, level): (i64, i64) = connection.query_row(
                    "SELECT singleton,level FROM process_feature_level",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if rows != 1 || singleton != 1 || !(1..=7).contains(&level) {
                    return Err(unsupported());
                }
            }
            _ => return Err(unsupported()),
        }
    } else if !matches!(version, 1..=7) {
        return Err(unsupported());
    }
    // No unknown trigger on process_runtime: the exact trigger set of this
    // version's layout, plus the native return cohort's two version triggers
    // once the retained cohort is committed.
    let mut expected_names: Vec<String> = {
        let mut statement = model.prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name='process_runtime' ORDER BY name",
        )?;
        let collected: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };
    if present == 0 {
        expected_names.retain(|name| name != "process_feature_level_retained_at_cohort");
    }
    if version == 8 {
        expected_names.push("process_native_return_version_requires_account".to_owned());
        expected_names.push("process_native_return_version_no_downgrade".to_owned());
    }
    let actual_names: Vec<String> = {
        let mut statement = connection.prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name='process_runtime' ORDER BY name",
        )?;
        let collected: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };
    expected_names.sort();
    if actual_names != expected_names {
        return Err(unsupported());
    }
    Ok(())
}

pub(super) fn expected_cohort_catalog() -> Result<Vec<CatalogRow>, ProcessError> {
    let model = predecessor_model()?;
    model.execute_batch(include_str!("schema.sql"))?;
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
