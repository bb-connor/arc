//! Bounded genuine operator history in the accepted pre-budget record format.
//! Available only with admission-test-support; no arbitrary records or SQL API.
use super::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct LegacyPlanningConstruction {
    path: PathBuf,
    owner: Option<String>,
    saves: u32,
}

thread_local! {
    static LEGACY_PLANNING_CONSTRUCTION: RefCell<Option<LegacyPlanningConstruction>> = const { RefCell::new(None) };
}

/// Suppress only the new planning metadata from one fresh store's beginning.
/// This constructs old-format evidence and does not emulate a schema35 binary.
pub struct RecoveryLegacyPlanningFixtureScope {
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for RecoveryLegacyPlanningFixtureScope {
    fn drop(&mut self) {
        LEGACY_PLANNING_CONSTRUCTION.with(|state| *state.borrow_mut() = None);
    }
}

pub fn construct_recovery_planning_fixture_legacy_format(
    database_path: &Path,
) -> Result<RecoveryLegacyPlanningFixtureScope, AdmissionOperationStoreError> {
    if database_path.exists()
        || database_path.file_name() != Some(std::ffi::OsStr::new("admission.db"))
    {
        return Err(invariant(
            "legacy planning construction requires a fresh store",
        ));
    }
    let parent = database_path
        .parent()
        .ok_or_else(|| invariant("legacy planning fixture path refused"))?;
    let path = std::fs::canonicalize(parent)
        .map_err(|_| invariant("legacy planning fixture parent unavailable"))?
        .join("admission.db");
    if path.exists() {
        return Err(invariant(
            "legacy planning construction requires a fresh store",
        ));
    }
    LEGACY_PLANNING_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        if state.is_some() {
            return Err(invariant("legacy planning construction is already active"));
        }
        *state = Some(LegacyPlanningConstruction {
            path,
            owner: None,
            saves: 0,
        });
        Ok(RecoveryLegacyPlanningFixtureScope {
            _thread_bound: PhantomData,
        })
    })
}

pub(super) fn constructing_legacy_planning(
    tx: &Connection,
    owner: &SqliteServingOwner,
    save: bool,
) -> Result<bool, AdmissionOperationStoreError> {
    LEGACY_PLANNING_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else { return Ok(false) };
        let path: String = tx.query_row("SELECT file FROM pragma_database_list WHERE name='main'", [], |row| row.get(0)).map_err(sqlite_error)?;
        let path = std::fs::canonicalize(path).map_err(|_| invariant("legacy planning fixture database unavailable"))?;
        if path != state.path { return Ok(false); }
        if state.owner.as_ref().is_some_and(|id| id != &owner.fence.store_uuid) {
            return Err(invariant("legacy planning construction owner changed"));
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-planning-quota:*')
                OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-planning-quota:*')
                OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'recovery-planning-quota:*')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if exists { return Err(invariant("legacy planning construction cannot reset allocation history")); }
        state.owner = Some(owner.fence.store_uuid.clone());
        if save {
            if state.saves >= 30008 { return Err(invariant("legacy planning construction save bound exhausted")); }
            state.saves += 1;
        }
        Ok(true)
    })
}

/// Append up to thirty thousand real, valid deployment revisions on one key.
/// Both profiles are validated and alternate; historical roots are not inflated.
pub fn retain_recovery_planning_fixture_legacy_revisions(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    count: u32,
) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
    if count == 0
        || count > 30000
        || count % 2 != 0
        || scope.authority_domain.as_str() != fence.store_uuid
    {
        return Err(invariant("legacy planning revision fixture bound refused"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    if !constructing_legacy_planning(&tx, &store.serving_owner, false)? {
        return Err(invariant("legacy planning construction is not active"));
    }
    let original = deployment_tx(&tx, scope)?;
    validate_deployment(&original, fence)?;
    let mut alternate = original.clone();
    let mut actors = alternate.actors.as_slice().to_vec();
    let actor = actors
        .first_mut()
        .ok_or_else(|| invariant("legacy planning fixture actor is absent"))?;
    let permissions = actor
        .permissions
        .as_slice()
        .iter()
        .copied()
        .filter(|permission| *permission != RecoveryPermission::Cancel)
        .collect::<Vec<_>>();
    if permissions.len() == actor.permissions.as_slice().len() {
        return Err(invariant(
            "legacy planning fixture requires a cancel assignment",
        ));
    }
    actor.permissions = BoundedList::new(permissions)
        .map_err(|_| invariant("legacy planning fixture permissions refused"))?;
    alternate.actors = NonEmptyBoundedList::new(actors)
        .map_err(|_| invariant("legacy planning fixture actors refused"))?;
    alternate.authority_scope = recovery_authority_scope_digest(&alternate)
        .map_err(|_| invariant("legacy planning fixture scope refused"))?;
    validate_deployment(&alternate, fence)?;
    let (bytes, events): (i64, i64) = tx.query_row(
        "SELECT (SELECT coalesce(sum(length(payload)),0) FROM admission_operation_recovery_records),
            (SELECT count(*) FROM admission_operation_recovery_events)", [], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    let maximum = encode(&original)?.len().max(encode(&alternate)?.len()) as i64;
    if events
        .checked_add(i64::from(count))
        .is_none_or(|total| total > 57344)
        || bytes
            .checked_add(maximum)
            .is_none_or(|total| total > 48 * 1024 * 1024)
    {
        return Err(invariant(
            "legacy planning fixture exceeds original shared limits",
        ));
    }
    command_quota_test_support::install_fixture_observed_time_index(&tx)?;
    for revision in 0..count {
        let profile = if revision % 2 == 0 {
            &alternate
        } else {
            &original
        };
        storage::save_legacy_planning_fixture_profile(&tx, &store.serving_owner, profile)?;
    }
    command_quota_test_support::restore_fixture_canonical_schema(&tx)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(alternate)
}
