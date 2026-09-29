use super::*;

pub(super) const ATTESTED_FINDING_BATCH_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_batches (
    batch_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, batch_id)
)
"#;

pub(super) const CORRELATION_INGRESS_CANONICAL_DDL: &str = r#"
CREATE TABLE security_correlation_ingress (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    producer_id TEXT NOT NULL,
    event_time INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    source_evidence BLOB NOT NULL CHECK (length(source_evidence) <= 1048576),
    evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES security_verified_events (tenant_id, event_id)
)
"#;
pub(super) const CORRELATION_INGRESS_PENDING_INDEX_DDL: &str = r#"
CREATE INDEX security_correlation_ingress_pending
ON security_correlation_ingress (acknowledged, event_time, sequence)
"#;
pub(super) const CORRELATION_INGRESS_LEGACY_PENDING_INDEX_DDL: &str = r#"
CREATE INDEX security_correlation_ingress_pending
ON security_correlation_ingress (acknowledged, sequence)
"#;
pub(super) const CORRELATION_INGRESS_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_ingress_immutable
BEFORE UPDATE ON security_correlation_ingress
WHEN OLD.sequence != NEW.sequence
    OR OLD.tenant_id != NEW.tenant_id
    OR OLD.event_id != NEW.event_id
    OR OLD.producer_id != NEW.producer_id
    OR OLD.event_time != NEW.event_time
    OR OLD.received_at != NEW.received_at
    OR OLD.body != NEW.body
    OR OLD.body_hash != NEW.body_hash
    OR OLD.source_evidence != NEW.source_evidence
    OR OLD.evidence_hash != NEW.evidence_hash
    OR OLD.acknowledged = 1
    OR NEW.acknowledged != 1
BEGIN
    SELECT RAISE(ABORT, 'correlation ingress mutation is rejected');
END
"#;
pub(super) const CORRELATION_INGRESS_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_ingress_delete_rejected
BEFORE DELETE ON security_correlation_ingress
BEGIN
    SELECT RAISE(ABORT, 'correlation ingress deletion is rejected');
END
"#;
pub(super) const CORRELATION_OUTCOMES_CANONICAL_DDL: &str = r#"
CREATE TABLE security_correlation_outcomes (
    tenant_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'accepted', 'advisory_only', 'duplicate', 'irrelevant', 'matched',
        'suppressed', 'too_late'
    )),
    watermark INTEGER NOT NULL CHECK (watermark >= 0),
    rule_version_hash BLOB NOT NULL CHECK (length(rule_version_hash) = 32),
    event_body_hash BLOB NOT NULL CHECK (length(event_body_hash) = 32),
    event_evidence_hash BLOB NOT NULL CHECK (length(event_evidence_hash) = 32),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, rule_id, event_id),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES security_verified_events (tenant_id, event_id)
)
"#;
pub(super) const CORRELATION_OUTCOMES_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_outcomes_immutable
BEFORE UPDATE ON security_correlation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'correlation outcome mutation is rejected');
END
"#;
pub(super) const CORRELATION_OUTCOMES_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_outcomes_delete_rejected
BEFORE DELETE ON security_correlation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'correlation outcome deletion is rejected');
END
"#;
pub(super) const ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_batch_items (
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (
        length(finding_hash) = 32 AND finding_hash != zeroblob(32)
    ),
    action_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, batch_id, ordinal),
    UNIQUE (tenant_id, evidence_id),
    UNIQUE (tenant_id, finding_id),
    UNIQUE (tenant_id, action_id),
    UNIQUE (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, batch_id)
        REFERENCES security_attested_finding_batches (tenant_id, batch_id)
)
"#;
pub(super) const ATTESTED_FINDING_BATCH_LEGACY_DDL: &str = r#"
CREATE TABLE security_attested_finding_batches (
    batch_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (batch_id)
)
"#;
pub(super) const ATTESTED_FINDING_BATCH_ITEM_LEGACY_DDL: &str = r#"
CREATE TABLE security_attested_finding_batch_items (
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (length(finding_hash) = 32),
    action_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    PRIMARY KEY (batch_id, ordinal),
    UNIQUE (tenant_id, evidence_id),
    UNIQUE (tenant_id, finding_id),
    UNIQUE (tenant_id, action_id),
    UNIQUE (tenant_id, reservation_id),
    FOREIGN KEY (batch_id)
        REFERENCES security_attested_finding_batches (batch_id)
)
"#;

pub(super) fn validate_no_attested_finding_batch_schema_extensions(connection: &Connection) -> PortResult<()> {
    let extension_count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type IN ('index', 'trigger')
              AND (
                  tbl_name IN (
                      'security_attested_finding_batches',
                      'security_attested_finding_batch_items'
                  )
                  OR (
                      type = 'trigger'
                      AND (
                          instr(lower(sql), 'security_attested_finding_batches') > 0
                          OR instr(lower(sql), 'security_attested_finding_batch_items') > 0
                      )
                  )
              )
              AND sql IS NOT NULL
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if extension_count != 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn validate_attested_finding_batch_records(connection: &Connection) -> PortResult<()> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check(\"security_attested_finding_batch_items\")")
        .map_err(sqlite_error)?;
    if foreign_key_check
        .query([])
        .map_err(sqlite_error)?
        .next()
        .map_err(sqlite_error)?
        .is_some()
    {
        return Err(PortError::integrity_failure());
    }
    drop(foreign_key_check);

    let mut cursor: Option<(String, String)> = None;
    loop {
        let (cursor_tenant, cursor_batch) =
            cursor.as_ref().map_or((None, None), |(tenant, batch)| {
                (Some(tenant.as_str()), Some(batch.as_str()))
            });
        let mut statement = connection
            .prepare(
                r#"
                SELECT tenant_id, batch_id
                FROM security_attested_finding_batches
                WHERE ?1 IS NULL
                   OR tenant_id > ?1
                   OR (tenant_id = ?1 AND batch_id > ?2)
                ORDER BY tenant_id, batch_id
                LIMIT 256
                "#,
            )
            .map_err(sqlite_error)?;
        let page = statement
            .query_map(params![cursor_tenant, cursor_batch], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        if page.is_empty() {
            break;
        }
        for (tenant, batch) in &page {
            let key = AttestedFindingBatchKey {
                tenant_id: TenantId::new(tenant.clone())
                    .map_err(|_| PortError::integrity_failure())?,
                batch_id: RecordId::new(batch.clone())
                    .map_err(|_| PortError::integrity_failure())?,
            };
            if load_attested_finding_batch_record(connection, &key)?.is_none() {
                return Err(PortError::integrity_failure());
            }
        }
        cursor = page.last().cloned();
    }
    Ok(())
}

pub(super) fn validate_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
    if !table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_CANONICAL_DDL,
    )? || !table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL,
    )? {
        return Err(PortError::integrity_failure());
    }
    validate_no_attested_finding_batch_schema_extensions(connection)?;
    validate_attested_finding_batch_records(connection)
}

pub(super) fn attested_finding_batch_legacy_schema_is_exact(connection: &Connection) -> PortResult<bool> {
    Ok(table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_LEGACY_DDL,
    )? && table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_LEGACY_DDL,
    )?)
}

pub(super) fn count_rows(connection: &Connection, table: &str) -> PortResult<i64> {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)
}

pub(super) fn table_has_foreign_key_violation(connection: &Connection, table: &str) -> PortResult<bool> {
    let mut statement = connection
        .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    rows.next().map(|row| row.is_some()).map_err(sqlite_error)
}

pub(super) fn ensure_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
    if table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_CANONICAL_DDL,
    )? && table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL,
    )? {
        return validate_attested_finding_batch_tenant_keys(connection);
    }
    if !attested_finding_batch_legacy_schema_is_exact(connection)? {
        return Err(PortError::integrity_failure());
    }
    validate_no_attested_finding_batch_schema_extensions(connection)?;
    validate_attested_finding_batch_records(connection)?;

    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS security_attested_finding_response_outbox_delete_rejected;
            DROP TRIGGER IF EXISTS security_attested_finding_response_outbox_immutable;
            DROP INDEX IF EXISTS security_attested_finding_response_outbox_due;
            DROP TABLE IF EXISTS security_attested_finding_response_outbox;
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;

    const BATCH_STAGING: &str = "security_attested_finding_batches_tenant_migration";
    const ITEM_STAGING: &str = "security_attested_finding_batch_items_tenant_migration";
    let batch_staging_ddl = ATTESTED_FINDING_BATCH_CANONICAL_DDL
        .replace("security_attested_finding_batches", BATCH_STAGING);
    let item_staging_ddl = ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL
        .replace("security_attested_finding_batch_items", ITEM_STAGING)
        .replace("security_attested_finding_batches", BATCH_STAGING);
    connection
        .execute_batch(&format!("{batch_staging_ddl};{item_staging_ddl};"))
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            r#"
            INSERT INTO {BATCH_STAGING} (
                batch_id, tenant_id, item_count, body, body_hash
            )
            SELECT batch_id, tenant_id, item_count, body, body_hash
            FROM security_attested_finding_batches;
            INSERT INTO {ITEM_STAGING} (
                batch_id, ordinal, tenant_id, evidence_id, finding_id,
                finding_hash, action_id, reservation_id
            )
            SELECT batch_id, ordinal, tenant_id, evidence_id, finding_id,
                   finding_hash, action_id, reservation_id
            FROM security_attested_finding_batch_items;
            "#,
        ))
        .map_err(|_| PortError::integrity_failure())?;
    let original_batch_count = count_rows(connection, "security_attested_finding_batches")?;
    let original_item_count = count_rows(connection, "security_attested_finding_batch_items")?;
    if count_rows(connection, BATCH_STAGING)? != original_batch_count
        || count_rows(connection, ITEM_STAGING)? != original_item_count
        || table_has_foreign_key_violation(connection, ITEM_STAGING)?
    {
        return Err(PortError::integrity_failure());
    }

    connection
        .execute_batch(
            r#"
            DROP TABLE security_attested_finding_batch_items;
            DROP TABLE security_attested_finding_batches;
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            "{ATTESTED_FINDING_BATCH_CANONICAL_DDL};{ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL};"
        ))
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            r#"
            INSERT INTO security_attested_finding_batches (
                batch_id, tenant_id, item_count, body, body_hash
            )
            SELECT batch_id, tenant_id, item_count, body, body_hash
            FROM {BATCH_STAGING};
            INSERT INTO security_attested_finding_batch_items (
                batch_id, ordinal, tenant_id, evidence_id, finding_id,
                finding_hash, action_id, reservation_id
            )
            SELECT batch_id, ordinal, tenant_id, evidence_id, finding_id,
                   finding_hash, action_id, reservation_id
            FROM {ITEM_STAGING};
            "#,
        ))
        .map_err(|_| PortError::integrity_failure())?;
    if count_rows(connection, "security_attested_finding_batches")? != original_batch_count
        || count_rows(connection, "security_attested_finding_batch_items")? != original_item_count
        || table_has_foreign_key_violation(connection, "security_attested_finding_batch_items")?
    {
        return Err(PortError::integrity_failure());
    }
    connection
        .execute_batch(&format!(
            "DROP TABLE {ITEM_STAGING};DROP TABLE {BATCH_STAGING};"
        ))
        .map_err(|_| PortError::integrity_failure())?;
    validate_attested_finding_batch_tenant_keys(connection)
}

pub(super) fn validate_correlation_durable_schema(connection: &Connection) -> PortResult<()> {
    if !table_definition_is_exact(
        connection,
        "security_correlation_ingress",
        CORRELATION_INGRESS_CANONICAL_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "index",
        "security_correlation_ingress_pending",
        CORRELATION_INGRESS_PENDING_INDEX_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_correlation_ingress_immutable",
        CORRELATION_INGRESS_IMMUTABLE_TRIGGER_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_correlation_ingress_delete_rejected",
        CORRELATION_INGRESS_DELETE_TRIGGER_DDL,
    )? || !table_definition_is_exact(
        connection,
        "security_correlation_outcomes",
        CORRELATION_OUTCOMES_CANONICAL_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_correlation_outcomes_immutable",
        CORRELATION_OUTCOMES_IMMUTABLE_TRIGGER_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_correlation_outcomes_delete_rejected",
        CORRELATION_OUTCOMES_DELETE_TRIGGER_DDL,
    )? || table_has_foreign_key_violation(connection, "security_correlation_ingress")?
        || table_has_foreign_key_violation(connection, "security_correlation_outcomes")?
        || correlation_schema_has_extensions(connection)?
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn upgrade_correlation_ingress_pending_index(connection: &Connection) -> PortResult<()> {
    if schema_object_definition_is_exact(
        connection,
        "index",
        "security_correlation_ingress_pending",
        CORRELATION_INGRESS_PENDING_INDEX_DDL,
    )? {
        return Ok(());
    }
    if !schema_object_definition_is_exact(
        connection,
        "index",
        "security_correlation_ingress_pending",
        CORRELATION_INGRESS_LEGACY_PENDING_INDEX_DDL,
    )? {
        return Err(PortError::integrity_failure());
    }
    connection
        .execute_batch(
            r#"
            DROP INDEX security_correlation_ingress_pending;
            CREATE INDEX security_correlation_ingress_pending
                ON security_correlation_ingress (acknowledged, event_time, sequence);
            "#,
        )
        .map_err(sqlite_error)
}

pub(super) fn correlation_schema_has_extensions(connection: &Connection) -> PortResult<bool> {
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type IN ('index', 'trigger')
              AND (
                  tbl_name IN (
                      'security_correlation_ingress',
                      'security_correlation_outcomes'
                  )
                  OR (
                      type = 'trigger'
                      AND (
                          instr(lower(sql), 'security_correlation_ingress') > 0
                          OR instr(lower(sql), 'security_correlation_outcomes') > 0
                      )
                  )
              )
              AND sql IS NOT NULL
              AND name NOT IN (
                  'security_correlation_ingress_pending',
                  'security_correlation_ingress_immutable',
                  'security_correlation_ingress_delete_rejected',
                  'security_correlation_outcomes_immutable',
                  'security_correlation_outcomes_delete_rejected'
              )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    Ok(count != 0)
}
