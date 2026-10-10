//! Same-value command identities retain their original reply as cold custody.
use super::*;
use crate::admission_operation_store::recovery::commands::VerifiedSettledCommandAlias;

const MAX_ALIAS_BYTES: usize = 4096;

fn require_current_alias_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    // Co-located stores have independent revisions. The database-wide pragma
    // cannot prove this component's serving format.
    let format: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION < 38
        || format != Some(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    {
        return Err(invariant(
            "durable command aliases require the current serving format",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
enum AliasSchema {
    #[serde(rename = "chio.recovery.command-alias.v1")]
    V1,
}

#[derive(Serialize, Deserialize)]
enum AliasMode {
    #[serde(rename = "control_only")]
    ControlOnly,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedGeneration {
    record_key: String,
    record_version: SafeInteger,
    record_digest: ProjectionDigest,
    event_sequence: SafeInteger,
    global_commit_sequence: SafeInteger,
    initial_record_digest: ProjectionDigest,
    initial_global_commit_sequence: SafeInteger,
    generation: SafeInteger,
    step_id: StepId,
    continuation_id: ContinuationId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettledCommandAlias {
    schema: AliasSchema,
    scope: RecoveryScopeV1,
    principal: chio_security_types::PrincipalId,
    permission: RecoveryPermission,
    digest: CommandDigest,
    response: RecoveryCommandResponseV1,
    selection: AcceptedGeneration,
    mode: AliasMode,
}

fn identity(value: &SettledCommandAlias) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "command-alias:{}",
        sha256_hex(&encode(&(
            &value.scope,
            &value.principal,
            value.permission.wire_name(),
            &value.response.command_id,
        ))?)
    ))
}

fn alias_key(command_key: &str) -> Result<String, AdmissionOperationStoreError> {
    let digest = command_key
        .strip_prefix("command:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| invariant("command alias identity refused"))?;
    Ok(format!("command-alias:{digest}"))
}

fn verify_alias(
    tx: &Connection,
    key: &str,
    row: &RawRecord,
    value: &SettledCommandAlias,
) -> Result<(), AdmissionOperationStoreError> {
    if row.version != 1
        || row.kind != "command"
        || row.payload.len() > MAX_ALIAS_BYTES
        || row.scope != scope_key(&value.scope)?
        || key != identity(value)?
        || !matches!(
            value.permission,
            RecoveryPermission::Create
                | RecoveryPermission::Select
                | RecoveryPermission::Approve
                | RecoveryPermission::Resume
                | RecoveryPermission::Cancel
                | RecoveryPermission::Report
        )
        || value.selection.generation.get() != 1
        || value.selection.record_version != value.response.revision
        || value.selection.record_key != workflow_key(&value.scope, &value.response.workflow_id)?
    {
        return Err(invariant("settled command alias custody changed"));
    }
    source_reference(tx, key)?;
    let current = source_reference(tx, &value.selection.record_key)?;
    let owner = raw_checked(tx, &value.selection.record_key)?
        .ok_or_else(|| invariant("command alias physical generation disappeared"))?;
    let owner: RecoveryWorkflowRecordV1 = decode(&owner.payload)?;
    if current.kind() != "workflow"
        || current.scope_key() != row.scope
        || current.version() < value.selection.record_version.get()
        || owner.scope != value.scope
        || owner.workflow_id != value.response.workflow_id
        || owner.step_id != value.selection.step_id
        || owner.continuation_id != value.selection.continuation_id
    {
        return Err(invariant("command alias physical generation changed"));
    }
    let (digest, global) = historical_record_reference(
        tx,
        &value.selection.record_key,
        value.selection.record_version.get(),
    )?;
    let (first_digest, first_global) =
        historical_record_reference(tx, &value.selection.record_key, 1)?;
    let event: i64 = tx.query_row(
        "SELECT sequence FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
        params![value.selection.record_key, i64::try_from(value.selection.record_version.get())
            .map_err(|_| invariant("command alias source version exhausted"))?], |r| r.get(0),
    ).map_err(sqlite_error)?;
    if digest != hex::encode(value.selection.record_digest.as_bytes())
        || global != value.selection.global_commit_sequence.get()
        || first_digest != hex::encode(value.selection.initial_record_digest.as_bytes())
        || first_global != value.selection.initial_global_commit_sequence.get()
        || stored_u64(event, "command alias source event")? != value.selection.event_sequence.get()
    {
        return Err(invariant(
            "command alias accepted generation lost authenticated history",
        ));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn retained_command_alias(
    tx: &Connection,
    command_key: &str,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
) -> Result<Option<(CommandDigest, RecoveryCommandResponseV1)>, AdmissionOperationStoreError> {
    let key = alias_key(command_key)?;
    let Some(row) = raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let value: SettledCommandAlias = decode(&row.payload)?;
    verify_alias(tx, &key, &row, &value)?;
    if value.scope != *actor.scope()
        || value.principal != *actor.principal()
        || value.permission.wire_name() != command.command.permission()
        || value.response.command_id != command.command_id
    {
        return Err(invariant("command alias actor namespace changed"));
    }
    Ok(Some((value.digest, value.response)))
}

/// Preserve the exact immutable accepted descriptor and permanent control mode.
/// This backend data is wrapped as authority only by the owning Kernel port.
pub(super) fn retained_command_alias_outcome(
    tx: &Connection,
    command_key: &str,
    actor: &AuthenticatedRecoveryActor,
    command_id: &CommandId,
) -> Result<Option<RecoveryCommandPortOutcome>, AdmissionOperationStoreError> {
    let key = alias_key(command_key)?;
    let Some(row) = raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let value: SettledCommandAlias = decode(&row.payload)?;
    verify_alias(tx, &key, &row, &value)?;
    if value.scope != *actor.scope()
        || value.principal != *actor.principal()
        || value.permission != actor.permission()
        || value.response.command_id != *command_id
    {
        return Err(invariant("command alias selected actor namespace changed"));
    }
    let selection = RecoveryCommandPortSelection {
        scope: value.scope,
        workflow_id: value.response.workflow_id.clone(),
        command_id: value.response.command_id.clone(),
        command_digest: value.digest,
        accepted_root_revision: value.response.revision,
        generation: RecoveryCommandAcceptedGeneration {
            record_key: RecoveryProtectedRecordKey::new(value.selection.record_key)?,
            record_version: value.selection.record_version,
            record_digest: value.selection.record_digest,
            event_sequence: value.selection.event_sequence,
            global_commit_sequence: value.selection.global_commit_sequence,
            initial_record_digest: value.selection.initial_record_digest,
            initial_global_commit_sequence: value.selection.initial_global_commit_sequence,
            generation: RecoveryGenerationOrdinal::new(value.selection.generation.get())?,
            step_id: value.selection.step_id,
            continuation_id: value.selection.continuation_id,
        },
        mode: RecoveryCommandContinuationMode::ControlOnly,
    };
    Ok(Some(RecoveryCommandPortOutcome {
        response: value.response,
        selection,
    }))
}

/// The command owner minted this affine proof after current preview and exact
/// same-value validation. It cannot select a mutation or finishing allowance.
pub(in crate::admission_operation_store) fn save_settled_command_alias(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    witness: VerifiedSettledCommandAlias<'_, '_>,
) -> Result<RecoveryCommandResponseV1, RecoveryCommandPortError> {
    witness.verify(tx)?;
    require_current_alias_format(tx)?;
    let source = witness.source();
    let (initial, initial_global) = historical_record_reference(tx, source.record_key(), 1)?;
    let initial: [u8; 32] = hex::decode(initial)
        .map_err(|_| invariant("command alias initial digest refused"))?
        .try_into()
        .map_err(|_| invariant("command alias initial digest refused"))?;
    let record = witness.record();
    let response = witness.response()?;
    let value = SettledCommandAlias {
        schema: AliasSchema::V1,
        scope: witness.actor().scope().clone(),
        principal: witness.actor().principal().clone(),
        permission: witness.actor().permission(),
        digest: witness.digest(),
        response: response.clone(),
        selection: AcceptedGeneration {
            record_key: source.record_key().to_owned(),
            record_version: SafeInteger::new(source.version())
                .map_err(|_| invariant("command alias source version refused"))?,
            record_digest: *source.digest(),
            event_sequence: SafeInteger::new(source.event_sequence())
                .map_err(|_| invariant("command alias source event refused"))?,
            global_commit_sequence: SafeInteger::new(source.global_commit_sequence())
                .map_err(|_| invariant("command alias source commit refused"))?,
            initial_record_digest: ProjectionDigest::from_bytes(initial),
            initial_global_commit_sequence: SafeInteger::new(initial_global)
                .map_err(|_| invariant("command alias initial commit refused"))?,
            generation: SafeInteger::new(1)
                .map_err(|_| invariant("command alias generation refused"))?,
            step_id: record.step_id.clone(),
            continuation_id: record.continuation_id.clone(),
        },
        mode: AliasMode::ControlOnly,
    };
    let key = identity(&value)?;
    if raw_checked(tx, &key)?.is_some() {
        return Err(invariant("command alias identity already allocated").into());
    }
    let payload = encode(&value)?;
    if payload.len() > MAX_ALIAS_BYTES {
        return Err(invariant("command alias metadata envelope exhausted").into());
    }
    // This immediately settled identity is ordinary fresh intake. It never
    // calls save_command, mutates workflow quota or creates a finishing loan.
    super::super::resources::check_intake_committing(tx)?;
    persist_record(
        tx,
        owner,
        &key,
        &scope_key(witness.actor().scope())?,
        "command",
        &payload,
        None,
    )?;
    let row = raw_checked(tx, &key)?.ok_or_else(|| invariant("command alias did not persist"))?;
    verify_alias(tx, &key, &row, &value)?;
    Ok(response)
}

pub(super) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE kind='command' AND record_key GLOB 'command-alias:*'
         ORDER BY scope_key,record_key",
        )
        .map_err(sqlite_error)?;
    for key in statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row = raw_checked(tx, &key)?.ok_or_else(|| invariant("command alias disappeared"))?;
        let value = decode(&row.payload)?;
        verify_alias(tx, &key, &row, &value)?;
    }
    Ok(())
}

#[cfg(test)]
mod format_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn connection() -> Result<Connection, rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE chio_store_schema_versions (
                store_key TEXT PRIMARY KEY, version INTEGER NOT NULL
             );",
        )?;
        Ok(connection)
    }

    #[test]
    fn current_component_stamp_with_zero_global_pragma_is_read_only() -> TestResult {
        let connection = connection()?;
        connection.execute(
            "INSERT INTO chio_store_schema_versions VALUES(?1,?2)",
            params![
                ADMISSION_OPERATION_SCHEMA_KEY,
                ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION
            ],
        )?;
        let before = connection.total_changes();
        let global: i32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(global, 0);
        require_current_alias_format(&connection)?;
        assert_eq!(connection.total_changes(), before);
        let stamp: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )?;
        assert_eq!(stamp, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn global_pragma_cannot_upgrade_a_prior_component_stamp() -> TestResult {
        let connection = connection()?;
        connection.execute(
            "INSERT INTO chio_store_schema_versions VALUES(?1,37)",
            [ADMISSION_OPERATION_SCHEMA_KEY],
        )?;
        connection.pragma_update(
            None,
            "user_version",
            ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        )?;
        let before = connection.total_changes();
        assert!(matches!(
            require_current_alias_format(&connection),
            Err(AdmissionOperationStoreError::Invariant(_))
        ));
        assert_eq!(connection.total_changes(), before);
        let stamp: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )?;
        assert_eq!(stamp, 37);
        Ok(())
    }

    #[test]
    fn sibling_component_stamp_does_not_initialize_missing_alias_format() -> TestResult {
        let connection = connection()?;
        connection.execute(
            "INSERT INTO chio_store_schema_versions VALUES('receipt',?1)",
            [ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION],
        )?;
        connection.pragma_update(
            None,
            "user_version",
            ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        )?;
        let before = connection.total_changes();
        assert!(matches!(
            require_current_alias_format(&connection),
            Err(AdmissionOperationStoreError::Invariant(_))
        ));
        assert_eq!(connection.total_changes(), before);
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_store_schema_versions WHERE store_key=?1)",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )?;
        assert!(!exists);
        Ok(())
    }
}
