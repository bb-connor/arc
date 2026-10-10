//! Immutable first-artifact preparation pins, serialized with action commit/fence.
// tenant-read-contract: security_response_automatic_preparations; class=tenant-predicate; principal=security-runtime
use super::*;
use chio_security_types::ports::{
    AutomaticResponsePreparationClaimOutcome, AutomaticResponsePreparationClaimRequest,
};

const TABLE: &str = "security_response_automatic_preparations";
const TABLE_DDL: &str = r#"
CREATE TABLE security_response_automatic_preparations (
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    prepared_binding_body BLOB NOT NULL CHECK (length(prepared_binding_body) <= 1048576),
    prepared_binding_hash BLOB NOT NULL CHECK (length(prepared_binding_hash) = 32),
    claimed_at INTEGER NOT NULL CHECK (claimed_at > 0),
    PRIMARY KEY (tenant_id, action_id),
    UNIQUE (tenant_id, dispatch_id)
)
"#;
const UPDATE_DDL: &str = r#"
CREATE TRIGGER security_response_automatic_preparations_immutable
BEFORE UPDATE ON security_response_automatic_preparations
BEGIN
    SELECT RAISE(ABORT, 'automatic preparation mutation is rejected');
END
"#;
const DELETE_DDL: &str = r#"
CREATE TRIGGER security_response_automatic_preparations_delete_rejected
BEFORE DELETE ON security_response_automatic_preparations
BEGIN
    SELECT RAISE(ABORT, 'automatic preparation deletion is rejected');
END
"#;

pub(in crate::security_state) fn preflight_automatic_preparation_schema(
    connection: &Connection,
) -> PortResult<()> {
    let kind: Option<String> = connection
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = ?1 COLLATE NOCASE",
            params![TABLE],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if kind.is_none() {
        let reserved_objects: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name COLLATE NOCASE IN ('security_response_automatic_preparations_immutable', 'security_response_automatic_preparations_delete_rejected')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        return if reserved_objects == 0 {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        };
    }
    validate_automatic_preparation_schema(connection)
}

pub(in crate::security_state) fn ensure_automatic_preparation_schema(
    connection: &Connection,
) -> PortResult<()> {
    preflight_automatic_preparation_schema(connection)?;
    connection
        .execute_batch(&format!(
            "{};{};{};",
            TABLE_DDL.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1),
            UPDATE_DDL.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1),
            DELETE_DDL.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1),
        ))
        .map_err(sqlite_error)?;
    validate_automatic_preparation_schema(connection)
}

pub(super) fn validate_automatic_preparation_schema(connection: &Connection) -> PortResult<()> {
    if !super::super::table_definition_is_exact(connection, TABLE, TABLE_DDL)?
        || !super::super::schema_object_definition_is_exact(
            connection,
            "trigger",
            "security_response_automatic_preparations_immutable",
            UPDATE_DDL,
        )?
        || !super::super::schema_object_definition_is_exact(
            connection,
            "trigger",
            "security_response_automatic_preparations_delete_rejected",
            DELETE_DDL,
        )?
    {
        return Err(PortError::integrity_failure());
    }
    let mut statement = connection
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map(params![TABLE], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let expected = [
        ("tenant_id", "TEXT", 1, 1),
        ("action_id", "TEXT", 1, 2),
        ("dispatch_id", "TEXT", 1, 0),
        ("prepared_binding_body", "BLOB", 1, 0),
        ("prepared_binding_hash", "BLOB", 1, 0),
        ("claimed_at", "INTEGER", 1, 0),
    ];
    if columns.len() != expected.len()
        || columns.iter().zip(expected).any(|(actual, wanted)| {
            actual.0 != wanted.0
                || actual.1 != wanted.1
                || actual.2 != wanted.2
                || actual.3 != wanted.3
        })
    {
        return Err(PortError::integrity_failure());
    }
    let foreign_keys: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
            params![TABLE],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let triggers: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?1",
            params![TABLE],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if foreign_keys != 0 || triggers != 2 {
        return Err(PortError::integrity_failure());
    }
    let mut statement = connection
        .prepare("SELECT name, \"unique\", origin, partial FROM pragma_index_list(?1)")
        .map_err(sqlite_error)?;
    let indexes = statement
        .query_map(params![TABLE], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if indexes.len() != 2 {
        return Err(PortError::integrity_failure());
    }
    let mut primary = false;
    let mut unique_dispatch = false;
    for (name, unique, origin, partial) in indexes {
        if unique != 1 || partial != 0 {
            return Err(PortError::integrity_failure());
        }
        let mut statement = connection
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .map_err(sqlite_error)?;
        let fields = statement
            .query_map(params![name], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        match origin.as_str() {
            "pk" if fields == ["tenant_id", "action_id"] => primary = true,
            "u" if fields == ["tenant_id", "dispatch_id"] => unique_dispatch = true,
            _ => return Err(PortError::integrity_failure()),
        }
    }
    if !primary || !unique_dispatch {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn load_preparation(
    connection: &Connection,
    binding: &PreparedActiveResponseDispatchBinding,
) -> PortResult<Option<PreparedActiveResponseDispatchBinding>> {
    let stored: Option<(String, Vec<u8>, Vec<u8>, i64)> = connection.query_row(
        "SELECT dispatch_id, prepared_binding_body, prepared_binding_hash, claimed_at FROM security_response_automatic_preparations WHERE tenant_id = ?1 AND action_id = ?2",
        params![binding.tenant_id.as_str(), binding.action_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((id, bytes, hash, claimed_at)) = stored else {
        return Ok(None);
    };
    if bytes.len() > 1_048_576 || claimed_at <= 0 {
        return Err(PortError::integrity_failure());
    }
    let decoded: PreparedActiveResponseDispatchBinding =
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 1_048_576)
            .and_then(|input| input.decode_signed())
            .map_err(|_| PortError::integrity_failure())?;
    let (canonical, canonical_hash) = canonical_prepared_dispatch_binding(&decoded)?;
    if canonical != bytes
        || canonical_hash != decode_digest(hash)?
        || decoded.dispatch_id.as_str() != id
        || decoded.tenant_id != binding.tenant_id
        || decoded.action_id != binding.action_id
        || decoded.schema_version != PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION
        || decoded.admission_artifact_fingerprint.is_none()
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(decoded))
}

fn same_original_tuple(
    a: &PreparedActiveResponseDispatchBinding,
    b: &PreparedActiveResponseDispatchBinding,
) -> bool {
    a.schema_version == b.schema_version
        && a.tenant_id == b.tenant_id
        && a.action_id == b.action_id
        && a.plan_hash == b.plan_hash
        && a.executor_authority_id == b.executor_authority_id
        && a.executor_authority_generation == b.executor_authority_generation
        && a.authorization_capability_hash == b.authorization_capability_hash
        && a.governed_intent_hash == b.governed_intent_hash
        && a.policy_decision_hash == b.policy_decision_hash
        && a.approval == b.approval
        && a.admission_artifact_fingerprint == b.admission_artifact_fingerprint
}

pub(super) fn claim_automatic_preparation(
    store: &SqliteSecurityStateStore,
    request: &AutomaticResponsePreparationClaimRequest,
) -> PortResult<AutomaticResponsePreparationClaimOutcome> {
    let binding = &request.prepared_dispatch_binding;
    binding
        .validate_for_plan(&request.response_plan)
        .map_err(|_| PortError::invalid_data())?;
    if binding.schema_version != PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION
        || binding.admission_artifact_fingerprint.is_none()
        || !matches!(binding.approval, ResponseDispatchApproval::Automatic)
    {
        return Err(PortError::invalid_data());
    }
    let mut connection = store.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    validate_automatic_preparation_schema(&transaction)?;
    if load_automatic_response_dispatch_fence(
        &transaction,
        &binding.tenant_id,
        &binding.action_id,
        &binding.dispatch_id,
    )?
    .is_some()
        || load_response_dispatch_for_identity(
            &transaction,
            &binding.tenant_id,
            &binding.action_id,
            &binding.dispatch_id,
        )?
        .is_some()
    {
        return Err(PortError::conflict());
    }
    let now = store.trusted_now_in_transaction(&transaction)?;
    if now == 0
        || now < binding.authorized_at_unix_ms
        || now < request.response_plan.created_at_unix_ms
        || now >= request.response_plan.expires_at_unix_ms
    {
        return Err(PortError::conflict());
    }
    if let Some(existing) = load_preparation(&transaction, binding)? {
        existing
            .validate_for_plan(&request.response_plan)
            .map_err(|_| PortError::integrity_failure())?;
        if !same_original_tuple(&existing, binding)
            || existing.authorized_at_unix_ms > binding.authorized_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        transaction.commit().map_err(sqlite_error)?;
        return Ok(AutomaticResponsePreparationClaimOutcome::Existing(
            Box::new(existing),
        ));
    }
    let (bytes, hash) = canonical_prepared_dispatch_binding(binding)?;
    transaction.execute(
        "INSERT INTO security_response_automatic_preparations (tenant_id, action_id, dispatch_id, prepared_binding_body, prepared_binding_hash, claimed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![binding.tenant_id.as_str(), binding.action_id.as_str(), binding.dispatch_id.as_str(), bytes, hash.as_bytes().as_slice(), to_i64(now)?],
    ).map_err(sqlite_error)?;
    let stored =
        load_preparation(&transaction, binding)?.ok_or_else(PortError::integrity_failure)?;
    if &stored != binding {
        return Err(PortError::integrity_failure());
    }
    transaction.commit().map_err(sqlite_error)?;
    Ok(AutomaticResponsePreparationClaimOutcome::Created(Box::new(
        stored,
    )))
}

pub(super) fn require_exact_automatic_preparation(
    connection: &Connection,
    binding: &PreparedActiveResponseDispatchBinding,
) -> PortResult<()> {
    validate_automatic_preparation_schema(connection)?;
    if binding.schema_version != PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION
        || binding.admission_artifact_fingerprint.is_none()
    {
        return Err(PortError::invalid_data());
    }
    if load_preparation(connection, binding)?.as_ref() != Some(binding) {
        return Err(PortError::conflict());
    }
    Ok(())
}

pub(super) fn validate_all_automatic_preparations(connection: &Connection) -> PortResult<()> {
    validate_automatic_preparation_schema(connection)?;
    let mut statement = connection.prepare("SELECT tenant_id, action_id, prepared_binding_body FROM security_response_automatic_preparations").map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (tenant, action, bytes) = row.map_err(sqlite_error)?;
        if bytes.len() > 1_048_576 {
            return Err(PortError::integrity_failure());
        }
        let binding: PreparedActiveResponseDispatchBinding =
            chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 1_048_576)
                .and_then(|input| input.decode_signed())
                .map_err(|_| PortError::integrity_failure())?;
        if binding.tenant_id.as_str() != tenant || binding.action_id.as_str() != action {
            return Err(PortError::integrity_failure());
        }
        require_exact_automatic_preparation(connection, &binding)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "automatic_preparation/tests.rs"]
mod tests;
