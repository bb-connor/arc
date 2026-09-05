use std::path::Path;
use std::time::Duration;

use chio_core_types::capability::token::CapabilityToken;
use chio_kernel::ToolCallRequest;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;

use crate::{digest, Checkpoint, ProcessError, ProcessLimits, ProcessSnapshot, ProcessState};

#[cfg(feature = "worker-server")]
mod credentials;

pub(crate) struct Store {
    connection: Connection,
    pub namespace: String,
}

impl Store {
    pub fn open(path: &Path, authority: &str, kernel_key: &str) -> Result<Self, ProcessError> {
        let path = private_file(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("store.sql"))?;
        tx.execute(
            "INSERT OR IGNORE INTO process_runtime(singleton, version, namespace, authority, kernel_key)
             VALUES (1, 1, ?1, ?2, ?3)",
            params![uuid::Uuid::new_v4().to_string(), authority, kernel_key],
        )?;
        let (version, namespace, stored_authority, stored_key): (u32, String, String, String) = tx.query_row(
            "SELECT version, namespace, authority, kernel_key FROM process_runtime WHERE singleton = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if version != 1 || stored_authority != authority || stored_key != kernel_key {
            return Err(ProcessError::Configuration(
                "process journal belongs to a different durable authority, kernel key or version",
            ));
        }
        tx.commit()?;
        Ok(Self {
            connection,
            namespace,
        })
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

    pub fn create_root(
        &mut self,
        id: &str,
        capability: &CapabilityToken,
        limits: ProcessLimits,
    ) -> Result<ProcessSnapshot, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_process(&tx, id)? {
            if existing.parent_id.is_some()
                || digest(&existing.capability)? != digest(capability)?
                || existing.limits != limits
            {
                return Err(ProcessError::Conflict);
            }
        } else {
            tx.execute("INSERT INTO processes(id, parent_id, root_id, depth, capability, limits) VALUES (?1, NULL, ?1, 0, ?2, ?3)",
                params![id, serde_json::to_string(capability)?, serde_json::to_string(&limits)?])?;
        }
        tx.commit()?;
        self.process(id)
    }

    pub fn spawn(
        &mut self,
        parent_id: &str,
        child_id: &str,
        capability: &CapabilityToken,
        validate: impl FnOnce(&CapabilityToken, &CapabilityToken) -> Result<(), ProcessError>,
    ) -> Result<ProcessSnapshot, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = read_process(&tx, parent_id)?
            .ok_or_else(|| ProcessError::NotFound(parent_id.to_owned()))?;
        require_running(&parent)?;
        validate(&parent.capability, capability)?;
        if let Some(existing) = read_process(&tx, child_id)? {
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
            let mut statement =
                tx.prepare("SELECT capability FROM processes WHERE parent_id = ?1")?;
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
        tx.commit()?;
        self.process(child_id)
    }

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
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        require_running(&process)?;
        if digest(&process.capability)? != digest(&request.capability)?
            || request.agent_id != process.capability.subject.to_hex()
        {
            return Err(ProcessError::Conflict);
        }
        let existing: Option<String> = tx.query_row(
            "SELECT request_hash FROM process_calls WHERE process_id = ?1 AND operation_key = ?2",
            params![id, key], |row| row.get(0),
        ).optional()?;
        match existing {
            Some(hash) if hash != request_hash => return Err(ProcessError::Conflict),
            Some(_) => {}
            None => {
                let changed = tx.execute("UPDATE processes SET tree_calls = tree_calls + 1 WHERE id = ?1 AND tree_calls < ?2",
                    params![process.root_id, process.limits.max_calls])?;
                if changed != 1 {
                    return Err(ProcessError::Limit("logical tool calls"));
                }
                tx.execute("INSERT INTO process_calls(process_id, operation_key, request_hash) VALUES (?1, ?2, ?3)",
                    params![id, key, request_hash])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn checkpoint(
        &mut self,
        id: &str,
        expected_revision: u64,
        value: Value,
    ) -> Result<Checkpoint, ProcessError> {
        let next = expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(ProcessError::CheckpointConflict)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
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
        tx.commit()?;
        Ok(Checkpoint {
            revision: next,
            value,
        })
    }

    pub fn cancel(&mut self, id: &str) -> Result<usize, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        let count = tx.execute(
            "WITH RECURSIVE descendants(id) AS (
                SELECT id FROM processes WHERE id = ?1
                UNION ALL SELECT p.id FROM processes p JOIN descendants d ON p.parent_id = d.id
             ) UPDATE processes SET state = 'cancelled' WHERE id IN (SELECT id FROM descendants) AND state = 'running'", [id],
        )?;
        tx.commit()?;
        Ok(count)
    }
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

fn require_running(process: &ProcessSnapshot) -> Result<(), ProcessError> {
    if process.state != ProcessState::Running {
        return Err(ProcessError::Cancelled(process.id.clone()));
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<std::path::PathBuf, ProcessError> {
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
        use std::os::unix::fs::PermissionsExt;
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
