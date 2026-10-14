//! Startup of the held journal file. The real file is held open, its layout is
//! authenticated from its actual catalog, and the namespace of a new journal is
//! chosen before the first mutation. A genesis or an upgrade is described as the
//! actual catalog delta from its authenticated source and runs only under the
//! native current-write scope, which revalidates this same plan inside the
//! Process transaction before anything is written.
use super::*;
use chio_kernel::process_return_custody::{
    ProcessReturnInventoryDataV1, PROCESS_RETURN_INVENTORY_SCHEMA,
};
use rusqlite::Transaction;
use std::path::Path;

/// The authenticated layout an installation starts from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LayoutSource {
    /// A file with an empty catalog and no pages beyond its header.
    Empty,
    /// An exact supported base layout lacking only compiled objects or
    /// carrying an earlier version guard.
    Predecessor,
    /// The exact historical layout of the first shipped journal.
    Historical,
}

/// What the held journal needs before it can serve any write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StartupPlan {
    /// The compiled layout: opening writes nothing.
    Ready,
    /// A new journal whose namespace was chosen before any mutation.
    Genesis { namespace: String },
    /// A supported source layout to bring to the compiled layout.
    Upgrade(LayoutSource),
}

fn unsupported() -> ProcessError {
    ProcessError::Configuration("unsupported process journal layout")
}

/// Classify the held file from positive observations only. An empty file is
/// genesis, the compiled layout is ready, an exact supported source layout is
/// an upgrade, and anything else refuses without a write. No error is read as
/// absence.
pub(crate) fn classify(
    tx: &Connection,
    path: &Path,
    authority: &str,
    kernel_key: &str,
) -> Result<StartupPlan, ProcessError> {
    let objects: i64 = tx.query_row("SELECT count(*) FROM main.sqlite_schema", [], |row| {
        row.get(0)
    })?;
    if objects == 0 {
        catalog::require_empty_file(tx)?;
        return Ok(StartupPlan::Genesis {
            namespace: uuid::Uuid::new_v4().to_string(),
        });
    }
    let runtime: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='process_runtime')",
        [],
        |row| row.get(0),
    )?;
    if !runtime {
        return Err(unsupported());
    }
    let row: Option<(u32, String)> = tx
        .query_row(
            "SELECT version,namespace FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((version, namespace)) = row else {
        return Err(unsupported());
    };
    let family = cohort::family_present(tx)?;
    if (version == 8) != family {
        return Err(unsupported());
    }
    if catalog::layout_is_current(tx)? {
        return Ok(StartupPlan::Ready);
    }
    if family {
        return Err(unsupported());
    }
    match catalog::prepare_profile(tx, path, &namespace, authority, kernel_key) {
        Ok(_) if catalog::actual_catalog(tx)? == catalog::historical_catalog()? => {
            Ok(StartupPlan::Upgrade(LayoutSource::Historical))
        }
        Ok(_) => Ok(StartupPlan::Upgrade(LayoutSource::Predecessor)),
        Err(ProcessError::Configuration(_)) => Err(unsupported()),
        Err(error) => Err(error),
    }
}

/// Revalidate under the writing transaction that the file is still exactly
/// the planned source.
pub(crate) fn verify_plan(
    tx: &Connection,
    path: &Path,
    authority: &str,
    kernel_key: &str,
    plan: &StartupPlan,
) -> Result<(), ProcessError> {
    let found = classify(tx, path, authority, kernel_key)?;
    let same = match (plan, &found) {
        (StartupPlan::Ready, StartupPlan::Ready) => true,
        (StartupPlan::Genesis { .. }, StartupPlan::Genesis { .. }) => true,
        (StartupPlan::Upgrade(planned), StartupPlan::Upgrade(actual)) => planned == actual,
        _ => false,
    };
    if same {
        Ok(())
    } else {
        Err(ProcessError::Conflict)
    }
}

/// The exact complete observation of a file that is still empty, bound to the
/// held file's identity, the chosen namespace, the explicit authority and key,
/// the actual empty catalog and the recipe the journal has once written. Its
/// counts are measured zeros of an empty catalog, never inferred from an
/// error; the native owner proves them against its whole inverse.
pub(crate) fn empty_inventory(
    tx: &Connection,
    path: &Path,
    namespace: &str,
    authority: &str,
    kernel_key: &str,
) -> Result<ProcessReturnInventoryDataV1, ProcessError> {
    let profile = catalog::prepare_empty_profile(tx, path)?;
    let none = Vec::<()>::new();
    let inventory = ProcessReturnInventoryDataV1 {
        schema: PROCESS_RETURN_INVENTORY_SCHEMA.to_owned(),
        journal_namespace: namespace.to_owned(),
        journal_authority: authority.to_owned(),
        kernel_key_digest: digest(&kernel_key)?,
        file_device: profile.file_device(),
        file_inode: profile.file_inode(),
        catalog_digest: profile.catalog_digest().to_owned(),
        physical_profile_digest: profile.recipe_digest().to_owned(),
        whole_source_cut_digest: digest(&(
            "chio.process-native-whole-source-cut.v1",
            &none,
            &none,
            &none,
        ))?,
        roots_digest: digest(&(("chio.process-native-roots.v1", &none)))?,
        root_count: 0,
        process_count: 0,
        account_count: 0,
        phase_count: 0,
        current_write_count: 1,
        history_sequence: 0,
        history_digest: digest(&(
            "chio.process-native-return-history.v1",
            "genesis",
            namespace,
            authority,
            profile.catalog_digest(),
        ))?,
    };
    inventory
        .validate_data()
        .map_err(|_| ProcessError::Conflict)?;
    Ok(inventory)
}

/// Every row the installation from `source` writes, from the actual catalog
/// and data of the held file.
pub(crate) fn describe(
    tx: &Connection,
    source: LayoutSource,
    authority: &str,
    kernel_key: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let target = catalog::compiled_catalog()?;
    let guard = catalog::compiled_guard_sql()?;
    if source == LayoutSource::Empty {
        return rows::describe_layout_delta(
            &rows::LayoutDelta {
                source: &[],
                target: &target,
                source_guard: None,
                target_guard: &guard,
            },
            None,
            Some(&rows::RuntimeInsert {
                authority_bytes: u64::try_from(authority.len())
                    .map_err(|_| ProcessError::Conflict)?,
                key_bytes: u64::try_from(kernel_key.len()).map_err(|_| ProcessError::Conflict)?,
            }),
        );
    }
    let actual = catalog::actual_catalog(tx)?;
    let actual_guard = catalog::actual_guard_sql(tx)?;
    let blobs = if source == LayoutSource::Historical {
        let (rows_count, largest): (i64, i64) = tx.query_row(
            "SELECT count(*),COALESCE(max(length(data)),0) FROM main.process_state_blobs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Some(rows::BlobRebuild {
            rows: u64::try_from(rows_count).map_err(|_| ProcessError::Conflict)?,
            largest_data_bytes: u64::try_from(largest).map_err(|_| ProcessError::Conflict)?,
        })
    } else {
        None
    };
    rows::describe_layout_delta(
        &rows::LayoutDelta {
            source: &actual,
            target: &target,
            source_guard: actual_guard.as_deref(),
            target_guard: &guard,
        },
        blobs.as_ref(),
        None,
    )
}

/// Bring the held file from `source` to the compiled layout inside the
/// caller's transaction and authenticate the result. The historical state
/// blobs are rebuilt as the exact compiled table with their data carried over;
/// unchanged objects are never rewritten.
pub(crate) fn install(
    tx: &Transaction<'_>,
    source: LayoutSource,
    authority: &str,
    kernel_key: &str,
    namespace: &str,
) -> Result<(), ProcessError> {
    let guard = catalog::compiled_guard_sql()?;
    if catalog::actual_guard_sql(tx)?.is_some_and(|sql| sql != guard) {
        tx.execute_batch("DROP TRIGGER process_recovery_version_monotone")?;
    }
    if source == LayoutSource::Historical {
        tx.execute_batch(
            "CREATE TABLE process_state_blobs_stage AS
                 SELECT process_id,sha256,data FROM main.process_state_blobs;
             DROP TABLE main.process_state_blobs;",
        )?;
    }
    tx.execute_batch(include_str!("../../store.sql"))?;
    if trigger_sql(tx, "process_knowledge_no_downgrade")?.is_none() {
        tx.execute_batch(&format!("{KNOWLEDGE_NO_DOWNGRADE_TRIGGER};"))?;
    }
    if source == LayoutSource::Historical {
        tx.execute_batch(
            "INSERT INTO main.process_state_blobs
                 (process_id,sha256,data,legacy_quarantined,knowledge_generation)
                 SELECT process_id,sha256,data,1,'legacy' FROM main.process_state_blobs_stage;
             DROP TABLE main.process_state_blobs_stage;",
        )?;
    }
    if source == LayoutSource::Empty {
        tx.execute(
            "INSERT INTO process_runtime(singleton, version, namespace, authority, kernel_key)
             VALUES (1, 1, ?1, ?2, ?3)",
            params![namespace, authority, kernel_key],
        )?;
    }
    let (version, found) = read_identity(tx, authority, kernel_key)?;
    if found != namespace {
        return Err(ProcessError::Conflict);
    }
    verify_cohorts(tx, version)?;
    if !catalog::layout_is_current(tx)? {
        return Err(ProcessError::Configuration(
            "installed process journal is not the compiled layout",
        ));
    }
    Ok(())
}
