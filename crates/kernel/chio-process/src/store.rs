use std::path::Path;
use std::time::Duration;

use chio_core_types::capability::token::CapabilityToken;
use chio_kernel::ToolCallRequest;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;

use crate::{digest, Checkpoint, ProcessError, ProcessLimits, ProcessSnapshot, ProcessState};

mod blobs;
mod children;
mod confined_delivery;
mod confined_slots;
#[cfg(feature = "worker-server")]
mod credentials;
mod knowledge;
pub(crate) mod native_return_custody;
mod nonces;
mod objects;
mod original_snapshot;
mod recovery;
pub(crate) mod unused_recovery_reservation;
pub(crate) use blobs::put_blob_call;
pub(crate) use children::{
    provision_signers_call, record_wait_call, submit_child_call, ChildPlan, WaitInsert,
};
pub(crate) use confined_delivery::begin_confined_delivery_call;
pub(crate) use confined_slots::{
    fill_confined_return_slot_call, reserve_confined_return_slot_call,
};
#[cfg(feature = "worker-server")]
pub(crate) use credentials::{issue_worker_credential_call, revoke_worker_credentials_call};
pub(crate) use knowledge::enable_knowledge_call;
pub(crate) use nonces::retain_nonce_call;
pub(crate) use objects::{collect_knowledge_object_call, stage_knowledge_object_call, Collection};
pub(crate) use original_snapshot::OriginalProcessSnapshot;
pub(crate) use recovery::{finalize_recovery_call, reserve_recovery_call};
pub(crate) use unused_recovery_reservation::close_unused_recovery_reservation_call;

pub(crate) struct Store {
    connection: Connection,
    pub namespace: String,
    path: std::path::PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
    authority: String,
    kernel_key: String,
    startup: native_return_custody::StartupPlan,
}

/// The compiled replacement of the knowledge downgrade guard. The catalog
/// stores this text verbatim from `CREATE` through `END`.
pub(crate) const KNOWLEDGE_NO_DOWNGRADE_TRIGGER: &str =
    "CREATE TRIGGER process_knowledge_no_downgrade BEFORE UPDATE OF version ON process_runtime
            WHEN OLD.version>=3 AND NEW.version<OLD.version
            BEGIN SELECT RAISE(ABORT,'knowledge enforcement is permanent'); END";

impl Store {
    /// Hold the journal file open and authenticate its layout from positive
    /// observations without writing anything: not even a journal mode or
    /// header is set here. A journal in the compiled layout is ready. A new
    /// file, or an exact supported source layout, records the startup plan
    /// (with the namespace of a new journal chosen now) that the registry
    /// runs under the native current-write scope before any schema write.
    /// Any other layout, including a foreign authority or key, refuses.
    pub fn open(path: &Path, authority: &str, kernel_key: &str) -> Result<Self, ProcessError> {
        let path = private_file(path)?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            let file = std::fs::symlink_metadata(&path)?;
            (file.dev(), file.ino())
        };
        let mut connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        confined_delivery::verify_before_open(&tx)?;
        unused_recovery_reservation::verify_before_open(&tx)?;
        native_return_custody::verify_before_open(&tx)?;
        let startup = native_return_custody::classify(&tx, &path, authority, kernel_key)?;
        let namespace = match &startup {
            native_return_custody::StartupPlan::Genesis { namespace } => namespace.clone(),
            native_return_custody::StartupPlan::Ready => {
                let (version, namespace) = read_identity(&tx, authority, kernel_key)?;
                verify_cohorts(&tx, version)?;
                namespace
            }
            native_return_custody::StartupPlan::Upgrade(_) => {
                read_identity(&tx, authority, kernel_key)?.1
            }
        };
        tx.commit()?;
        Ok(Self {
            connection,
            namespace,
            path,
            #[cfg(unix)]
            identity,
            authority: authority.to_owned(),
            kernel_key: kernel_key.to_owned(),
            startup,
        })
    }

    /// Whether the journal still needs its routed startup write.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub(crate) fn startup_pending(&self) -> bool {
        self.startup != native_return_custody::StartupPlan::Ready
    }

    pub(crate) fn startup_complete(&mut self) {
        self.startup = native_return_custody::StartupPlan::Ready;
    }

    /// Read-only handle for the admission-test-support inspection surface.
    /// A production build never compiles this accessor.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub(crate) fn inspection_connection(&self) -> &Connection {
        &self.connection
    }

    /// Mutable handle for the admission-test-support corruption controls.
    /// A production build never compiles this accessor.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub(crate) fn inspection_connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub fn process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        read_process(&self.connection, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))
    }

    pub fn require_running(&self, id: &str) -> Result<(), ProcessError> {
        require_running(&self.process(id)?)
    }

    pub fn lineage(&self, id: &str) -> Result<Vec<CapabilityToken>, ProcessError> {
        let mut result = Vec::new();
        let mut process = self.process(id)?;
        loop {
            require_running(&process)?;
            result.push(process.capability);
            if result.len() > 65 {
                return Err(ProcessError::Invalid(
                    "process lineage exceeds maximum depth",
                ));
            }
            let Some(parent) = process.parent_id else {
                break;
            };
            process = self.process(&parent)?;
        }
        result.reverse();
        Ok(result)
    }

    /// Host storage custody preserves exact ancestry after execution ends.
    /// This grants neither original token liveness nor a new journal attachment.
    pub(crate) fn retained_lineage(
        &self,
        id: &str,
    ) -> Result<(ProcessSnapshot, Vec<CapabilityToken>), ProcessError> {
        let snapshot = self.process(id)?;
        let mut process = snapshot.clone();
        let mut result = Vec::new();
        loop {
            let parent = process.parent_id;
            result.push(process.capability);
            if result.len() > 65 {
                return Err(ProcessError::Invalid(
                    "process lineage exceeds maximum depth",
                ));
            }
            let Some(parent) = parent else {
                if process.id != snapshot.root_id {
                    return Err(ProcessError::Conflict);
                }
                break;
            };
            process = self.process(&parent)?;
            if process.root_id != snapshot.root_id {
                return Err(ProcessError::Conflict);
            }
        }
        result.reverse();
        Ok((snapshot, result))
    }

    /// Test fixtures drive the actual admission body directly; production
    /// admission always runs through the routed current writer.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub fn admit(
        &mut self,
        id: &str,
        key: &str,
        request: &ToolCallRequest,
        request_hash: &str,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        admit_call(&tx, id, key, request, request_hash)?;
        tx.commit()?;
        Ok(())
    }

    /// The dispatch attempt recorded for a logical operation. Operations that
    /// have not been admitted, and every operation of an older journal, are at one.
    pub fn call_attempt(&self, id: &str, key: &str) -> Result<u32, ProcessError> {
        Ok(self
            .connection
            .query_row(
                "SELECT attempts FROM process_calls WHERE process_id = ?1 AND operation_key = ?2",
                params![id, key],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(1))
    }
}

fn read_identity(
    connection: &Connection,
    authority: &str,
    kernel_key: &str,
) -> Result<(u32, String), ProcessError> {
    let (version, namespace, stored_authority, stored_key): (u32, String, String, String) = connection.query_row(
        "SELECT version, namespace, authority, kernel_key FROM process_runtime WHERE singleton = 1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(version, 1..=8) || stored_authority != authority || stored_key != kernel_key {
        return Err(ProcessError::Configuration(
            "process journal belongs to a different durable authority, kernel key or version",
        ));
    }
    Ok((version, namespace))
}

/// The retained recovery and delivery cohorts of a journal at its feature
/// level. They are verified; a family that is genuinely absent is installed.
fn verify_cohorts(connection: &Connection, version: u32) -> Result<(), ProcessError> {
    let level = level_for_version(connection, version)?;
    if level < 5
        && connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_confined_return_slots)",
            [],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(ProcessError::Configuration(
            "confined return data requires its journal version",
        ));
    }
    unused_recovery_reservation::install_or_verify(connection, level)?;
    confined_delivery::install_or_verify(connection, level)
}

fn trigger_sql(connection: &Connection, name: &str) -> Result<Option<String>, ProcessError> {
    Ok(connection
        .query_row(
            "SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?)
}

/// The complete cancellation body inside one writer transaction: the bounded
/// recursive state rewrite and the ordered-return observation. The original
/// semantics commit the rewrite and then report an ordered confined return,
/// so the body returns `(count, ordered)` and the caller decides after the
/// commit. Shared by the direct writer and the bank-proven routed writer.
pub(crate) fn cancel_call(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> Result<(usize, bool), ProcessError> {
    read_process(tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
    let count = tx.execute(
        "WITH RECURSIVE descendants(id) AS (
            SELECT id FROM processes WHERE id = ?1
            UNION ALL SELECT p.id FROM processes p JOIN descendants d ON p.parent_id = d.id
         ) UPDATE processes SET state = 'cancelled' WHERE id IN (SELECT id FROM descendants) AND state = 'running'",
        [id],
    )?;
    let ordered = confined_delivery::cancellation_has_ordered_return(tx, id)?;
    Ok((count, ordered))
}

/// The complete advance-attempt body inside one writer transaction, shared by
/// the direct writer and the bank-proven routed writer.
pub(crate) fn advance_attempt_call(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    key: &str,
    request_hash: &str,
    current: u32,
    maximum: u32,
) -> Result<u32, ProcessError> {
    if current >= maximum {
        return Err(ProcessError::Limit("dispatch attempts"));
    }
    let process = read_process(tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
    require_running(&process)?;
    let changed = tx.execute(
        "UPDATE process_calls SET attempts = attempts + 1 WHERE process_id = ?1 AND operation_key = ?2 AND request_hash = ?3 AND attempts = ?4",
        params![id, key, request_hash, current],
    )?;
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    Ok(current + 1)
}

/// The complete create-root body inside one writer transaction, shared by the
/// direct writer and the bank-proven routed writer.
pub(crate) fn create_root_call(
    tx: &Connection,
    id: &str,
    capability: &CapabilityToken,
    limits: ProcessLimits,
) -> Result<(), ProcessError> {
    if let Some(existing) = read_process(tx, id)? {
        if existing.parent_id.is_some()
            || digest(&existing.capability)? != digest(capability)?
            || existing.limits != limits
        {
            return Err(ProcessError::Conflict);
        }
    } else {
        tx.execute(
            "INSERT INTO processes(id, parent_id, root_id, depth, capability, limits) VALUES (?1, NULL, ?1, 0, ?2, ?3)",
            params![id, serde_json::to_string(capability)?, serde_json::to_string(&limits)?],
        )?;
    }
    Ok(())
}

/// The complete admission body of one logical call, executed inside the owning
/// writer transaction: the open-reservation guard, the persisted identity and
/// capability binding, the frozen request and reservation expectations, the
/// tree-wide call debit and the immutable call row. Shared by the direct
/// writer and the bank-proven routed writer.
pub(crate) fn admit_call(
    tx: &Connection,
    id: &str,
    key: &str,
    request: &ToolCallRequest,
    request_hash: &str,
) -> Result<(), ProcessError> {
    unused_recovery_reservation::require_open_recovery_reservation(tx, id, key)?;
    let process = read_process(tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
    require_running(&process)?;
    if digest(&process.capability)? != digest(&request.capability)?
        || request.agent_id != process.capability.subject.to_hex()
    {
        return Err(ProcessError::Conflict);
    }
    let existing: Option<String> = tx
        .query_row(
            "SELECT request_hash FROM process_calls WHERE process_id = ?1 AND operation_key = ?2",
            params![id, key],
            |row| row.get(0),
        )
        .optional()?;
    let reserved: Option<Option<String>> = tx
        .query_row(
            "SELECT final_binding FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2",
            params![id, key],
            |row| row.get(0),
        )
        .optional()?;
    if reserved
        .as_ref()
        .is_some_and(|binding| binding.as_deref() != Some(request_hash))
        || (reserved.is_some() && existing.is_none())
    {
        return Err(ProcessError::Conflict);
    }
    match existing {
        Some(hash) if hash != request_hash => return Err(ProcessError::Conflict),
        Some(_) => {}
        None => {
            let changed = tx.execute(
                "UPDATE processes SET tree_calls = tree_calls + 1 WHERE id = ?1 AND tree_calls < ?2",
                params![process.root_id, process.limits.max_calls],
            )?;
            if changed != 1 {
                return Err(ProcessError::Limit("logical tool calls"));
            }
            tx.execute(
                "INSERT INTO process_calls(process_id, operation_key, request_hash) VALUES (?1, ?2, ?3)",
                params![id, key, request_hash],
            )?;
        }
    }
    Ok(())
}

/// The complete checkpoint body of one process, executed inside the owning
/// writer transaction: revision arithmetic, running identity and the
/// compare-and-swap row rewrite. Shared by the direct writer and the
/// bank-proven routed writer.
pub(crate) fn checkpoint_call(
    tx: &Connection,
    id: &str,
    expected_revision: u64,
    value: Value,
) -> Result<Checkpoint, ProcessError> {
    let next = expected_revision
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(ProcessError::CheckpointConflict)?;
    let process = read_process(tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
    require_running(&process)?;
    let changed = tx.execute(
        "UPDATE processes SET checkpoint = ?1, revision = ?2 WHERE id = ?3 AND revision = ?4",
        params![
            serde_json::to_string(&value)?,
            next as i64,
            id,
            expected_revision as i64
        ],
    )?;
    if changed != 1 {
        return Err(ProcessError::CheckpointConflict);
    }
    Ok(Checkpoint {
        revision: next,
        value,
    })
}

/// The complete attach-child body inside one writer transaction, shared by
/// the direct writer and the bank-proven routed writer.
pub(crate) fn attach_child(
    tx: &Connection,
    parent_id: &str,
    child_id: &str,
    capability: &CapabilityToken,
    validate: impl FnOnce(&CapabilityToken, &CapabilityToken) -> Result<(), ProcessError>,
) -> Result<(), ProcessError> {
    let parent =
        read_process(tx, parent_id)?.ok_or_else(|| ProcessError::NotFound(parent_id.to_owned()))?;
    require_running(&parent)?;
    validate(&parent.capability, capability)?;
    if let Some(existing) = read_process(tx, child_id)? {
        if existing.parent_id.as_deref() != Some(parent_id)
            || digest(&existing.capability)? != digest(capability)?
        {
            return Err(ProcessError::Conflict);
        }
        require_running(&existing)?;
    } else {
        if parent.depth >= parent.limits.max_depth {
            return Err(ProcessError::Limit("depth"));
        }
        let count: u32 = tx.query_row(
            "SELECT COUNT(*) FROM processes WHERE root_id = ?1",
            [&parent.root_id],
            |row| row.get(0),
        )?;
        if count >= parent.limits.max_processes {
            return Err(ProcessError::Limit("process count"));
        }
        // Allocate sibling shares when processes are attached, including
        // parents that only spawn grandchildren and never invoke a tool.
        // Retain cancelled allocations while their effect history exists.
        let mut shares = u32::from(capability.budget_share_bps.unwrap_or(10_000));
        let mut statement = tx.prepare("SELECT capability FROM processes WHERE parent_id = ?1")?;
        for row in statement.query_map([parent_id], |row| row.get::<_, String>(0))? {
            let sibling: CapabilityToken = serde_json::from_str(&row?)?;
            shares = shares
                .checked_add(u32::from(sibling.budget_share_bps.unwrap_or(10_000)))
                .ok_or(ProcessError::Limit("sibling budget shares"))?;
        }
        if shares > u32::from(parent.capability.budget_share_bps.unwrap_or(10_000)) {
            return Err(ProcessError::Limit("sibling budget shares"));
        }
        tx.execute("INSERT INTO processes(id, parent_id, root_id, depth, capability, limits) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![child_id, parent_id, parent.root_id, parent.depth + 1,
                    serde_json::to_string(capability)?, serde_json::to_string(&parent.limits)?])?;
    }
    Ok(())
}

fn read_process(
    connection: &Connection,
    id: &str,
) -> Result<Option<ProcessSnapshot>, ProcessError> {
    let row = connection.query_row(
        "SELECT p.id, p.parent_id, p.root_id, p.depth, p.capability, p.state, p.limits, p.revision, p.checkpoint, root.tree_calls
         FROM processes p JOIN processes root ON p.root_id = root.id WHERE p.id = ?1", [id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, String>(2)?, row.get::<_, u32>(3)?,
            row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?, row.get::<_, i64>(7)?, row.get::<_, String>(8)?, row.get::<_, u32>(9)?)),
    ).optional()?;
    let Some((
        id,
        parent_id,
        root_id,
        depth,
        capability,
        state,
        limits,
        revision,
        checkpoint,
        tree_calls,
    )) = row
    else {
        return Ok(None);
    };
    let state = match state.as_str() {
        "running" => ProcessState::Running,
        "cancelled" => ProcessState::Cancelled,
        _ => return Err(ProcessError::Invalid("corrupt process state")),
    };
    Ok(Some(ProcessSnapshot {
        id,
        parent_id,
        root_id,
        depth,
        capability: serde_json::from_str(&capability)?,
        state,
        limits: serde_json::from_str(&limits)?,
        checkpoint: Checkpoint {
            revision: u64::try_from(revision)
                .map_err(|_| ProcessError::Invalid("negative checkpoint revision"))?,
            value: serde_json::from_str(&checkpoint)?,
        },
        tree_calls,
    }))
}

/// The journal's feature cohort level. Before the native return cohort it is
/// the runtime version itself. Activating that cohort moves the journal to
/// version eight and retains the predecessor level, which later feature
/// activations raise; version eight never stands in for a feature level.
pub(crate) fn feature_level(connection: &Connection) -> Result<u32, ProcessError> {
    let version: u32 = connection.query_row(
        "SELECT version FROM process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    level_for_version(connection, version)
}

pub(crate) fn level_for_version(
    connection: &Connection,
    version: u32,
) -> Result<u32, ProcessError> {
    let retained: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='process_feature_level')",
        [],
        |row| row.get(0),
    )?;
    let level: Option<u32> = if retained {
        connection
            .query_row(
                "SELECT level FROM process_feature_level WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
    } else {
        None
    };
    match (version, level) {
        (1..=7, None) => Ok(version),
        (8, Some(level)) if (1..=7).contains(&level) => Ok(level),
        _ => Err(ProcessError::Configuration(
            "process journal feature level differs from its version",
        )),
    }
}

/// Raise one feature cohort from `from` to `to` inside the activating write.
/// Before the native return cohort the runtime version carries the level.
pub(crate) fn raise_feature_level(
    tx: &rusqlite::Transaction<'_>,
    from: u32,
    to: u32,
) -> Result<(), ProcessError> {
    let version: u32 = tx.query_row(
        "SELECT version FROM process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let changed = if version == 8 {
        tx.execute(
            "UPDATE process_feature_level SET level=?2 WHERE singleton=1 AND level=?1",
            params![from, to],
        )?
    } else {
        tx.execute(
            "UPDATE process_runtime SET version=?2 WHERE singleton=1 AND version=?1",
            params![from, to],
        )?
    };
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

fn require_running(process: &ProcessSnapshot) -> Result<(), ProcessError> {
    if process.state != ProcessState::Running {
        return Err(ProcessError::Cancelled(process.id.clone()));
    }
    Ok(())
}

pub(crate) fn private_file(path: &Path) -> Result<std::path::PathBuf, ProcessError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = std::fs::metadata(parent)?;
    if !metadata.is_dir() {
        return Err(ProcessError::Invalid(
            "process journal parent is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProcessError::Configuration(
                "process journal directory must be private (mode 0700)",
            ));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let file = std::fs::symlink_metadata(path)?;
    if !file.is_file() {
        return Err(ProcessError::Configuration(
            "process journal must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if file.nlink() != 1 {
            return Err(ProcessError::Configuration(
                "process journal cannot have hard-link aliases",
            ));
        }
        if file.permissions().mode() & 0o077 != 0 {
            return Err(ProcessError::Configuration(
                "process journal must be private (mode 0600)",
            ));
        }
    }
    // An absolute filesystem path cannot be interpreted as SQLite's special
    // :memory: name or a file: URI that silently disables persistence.
    Ok(std::fs::canonicalize(path)?)
}
