use super::*;

pub(super) const TABLE: &str = "security_response_effect_finality";
const TABLE_DDL: &str = r#"
CREATE TABLE security_response_effect_finality (
    tenant_id TEXT NOT NULL CHECK (length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 256),
    effect_kind TEXT NOT NULL CHECK (effect_kind IN ('suspend_session', 'restrict_egress', 'throttle_session', 'suspend_capability_set', 'freeze_issuance')),
    effect_id TEXT NOT NULL CHECK (length(CAST(effect_id AS BLOB)) BETWEEN 1 AND 256),
    action_id TEXT NOT NULL CHECK (length(CAST(action_id AS BLOB)) BETWEEN 1 AND 256),
    remove_idempotency_key TEXT NOT NULL CHECK (length(CAST(remove_idempotency_key AS BLOB)) BETWEEN 1 AND 256),
    marker_body BLOB NOT NULL CHECK (typeof(marker_body) = 'blob' AND length(marker_body) BETWEEN 1 AND 16384),
    marker_body_hash BLOB NOT NULL CHECK (typeof(marker_body_hash) = 'blob' AND length(marker_body_hash) = 32),
    PRIMARY KEY (tenant_id, effect_kind, effect_id),
    UNIQUE (tenant_id, effect_kind, remove_idempotency_key)
)
"#;
const UPDATE_DDL: &str = r#"
CREATE TRIGGER security_response_effect_finality_immutable
BEFORE UPDATE ON security_response_effect_finality
BEGIN
    SELECT RAISE(ABORT, 'completed effect removal mutation is rejected');
END
"#;
const DELETE_DDL: &str = r#"
CREATE TRIGGER security_response_effect_finality_delete_rejected
BEFORE DELETE ON security_response_effect_finality
BEGIN
    SELECT RAISE(ABORT, 'completed effect removal deletion is rejected');
END
"#;

pub(in crate::security_state) fn revision(connection: &Connection) -> PortResult<i32> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE lower(name) = 'chio_store_schema_versions')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !present {
        return Ok(0);
    }
    let mut statement = connection.prepare(
        "SELECT store_key, typeof(version), version FROM chio_store_schema_versions WHERE lower(store_key) = 'security_state'",
    ).map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    match rows.as_slice() {
        [] => Ok(0),
        [(key, kind, value)]
            if key == "security_state" && kind == "integer" && (*value == 0 || *value == 1) =>
        {
            Ok(*value)
        }
        _ => Err(PortError::integrity_failure()),
    }
}

pub(in crate::security_state) fn objects_absent(connection: &Connection) -> PortResult<bool> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE lower(name) GLOB 'security_response_effect_finality*' OR lower(tbl_name) = 'security_response_effect_finality'",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    Ok(count == 0)
}

pub(in crate::security_state) fn preflight(connection: &Connection) -> PortResult<()> {
    match revision(connection)? {
        0 if objects_absent(connection)? => Ok(()),
        0 => Err(PortError::integrity_failure()),
        1 => {
            validate_schema(connection)?;
            super::migration::verify_coverage(connection)
        }
        _ => Err(PortError::integrity_failure()),
    }
}

pub(in crate::security_state) fn ensure_schema(connection: &Connection) -> PortResult<()> {
    connection
        .execute_batch(&format!(
            "{};{};{};",
            TABLE_DDL.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1),
            UPDATE_DDL.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1),
            DELETE_DDL.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1),
        ))
        .map_err(sqlite_error)?;
    validate_schema(connection)
}

pub(in crate::security_state) fn validate_schema(connection: &Connection) -> PortResult<()> {
    let namespace_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE lower(name) GLOB 'security_response_effect_finality*' OR lower(tbl_name) = 'security_response_effect_finality'",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if namespace_count != 5 {
        return Err(PortError::integrity_failure());
    }
    if !crate::security_state::table_definition_is_exact(connection, TABLE, TABLE_DDL)?
        || !crate::security_state::schema_object_definition_is_exact(
            connection,
            "trigger",
            "security_response_effect_finality_immutable",
            UPDATE_DDL,
        )?
        || !crate::security_state::schema_object_definition_is_exact(
            connection,
            "trigger",
            "security_response_effect_finality_delete_rejected",
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
        ("effect_kind", "TEXT", 1, 2),
        ("effect_id", "TEXT", 1, 3),
        ("action_id", "TEXT", 1, 0),
        ("remove_idempotency_key", "TEXT", 1, 0),
        ("marker_body", "BLOB", 1, 0),
        ("marker_body_hash", "BLOB", 1, 0),
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
    let mut unique_remove = false;
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
            "pk" if fields == ["tenant_id", "effect_kind", "effect_id"] => primary = true,
            "u" if fields == ["tenant_id", "effect_kind", "remove_idempotency_key"] => {
                unique_remove = true
            }
            _ => return Err(PortError::integrity_failure()),
        }
    }
    if !primary || !unique_remove {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}
