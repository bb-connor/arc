fn table_definition_is_exact(
    connection: &Connection,
    table: &str,
    expected_sql: &str,
) -> PortResult<bool> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected_sql)))
}

fn schema_object_definition_is_exact(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected_sql: &str,
) -> PortResult<bool> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected_sql)))
}

fn validate_correlation_durable_schema(connection: &Connection) -> PortResult<()> {
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

fn upgrade_correlation_ingress_pending_index(connection: &Connection) -> PortResult<()> {
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

fn correlation_schema_has_extensions(connection: &Connection) -> PortResult<bool> {
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

fn ensure_response_dispatch_commit_mode_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_response_dispatches)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.iter().any(|column| column == "commit_mode") {
        connection
            .execute(
                "ALTER TABLE security_response_dispatches ADD COLUMN commit_mode TEXT NOT NULL DEFAULT 'fresh' CHECK (commit_mode IN ('fresh', 'governed_committed_resume', 'governed_committed_expired_resume'))",
                [],
            )
            .map_err(sqlite_error)?;
    }
    let invalid: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_response_dispatches WHERE commit_mode NOT IN ('fresh', 'governed_committed_resume', 'governed_committed_expired_resume')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid != 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn ensure_attested_finding_response_outbox_schema(connection: &Connection) -> PortResult<()> {
    let table_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL.replacen(
        "CREATE TABLE ",
        "CREATE TABLE IF NOT EXISTS ",
        1,
    );
    let index_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL.replacen(
        "CREATE INDEX ",
        "CREATE INDEX IF NOT EXISTS ",
        1,
    );
    let immutable_trigger_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL.replacen(
        "CREATE TRIGGER ",
        "CREATE TRIGGER IF NOT EXISTS ",
        1,
    );
    let delete_trigger_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL.replacen(
        "CREATE TRIGGER ",
        "CREATE TRIGGER IF NOT EXISTS ",
        1,
    );
    connection
        .execute_batch(&format!(
            "{};{};{};{};",
            table_ddl, index_ddl, immutable_trigger_ddl, delete_trigger_ddl,
        ))
        .map_err(sqlite_error)?;
    if connection
        .execute(
            r#"
            INSERT INTO security_attested_finding_response_outbox (
                tenant_id, batch_id, ordinal, evidence_id, finding_id,
                finding_hash, action_id, reservation_id, planning_state,
                admission_state, completion_state
            )
            SELECT item.tenant_id, item.batch_id, item.ordinal, item.evidence_id,
                   item.finding_id, item.finding_hash, item.action_id,
                   item.reservation_id, 'pending', 'pending', 'not_started'
            FROM security_attested_finding_batch_items AS item
            WHERE NOT EXISTS (
                SELECT 1
                FROM security_attested_finding_response_outbox AS outbox
                WHERE outbox.tenant_id = item.tenant_id
                  AND outbox.action_id = item.action_id
            )
            "#,
            [],
        )
        .is_err()
    {
        return Err(PortError::integrity_failure());
    }
    if !table_definition_is_exact(
        connection,
        "security_attested_finding_response_outbox",
        ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "index",
        "security_attested_finding_response_outbox_due",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_immutable",
        ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_delete_rejected",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL,
    )? || table_has_foreign_key_violation(
        connection,
        "security_attested_finding_response_outbox",
    )? || !attested_finding_response_outbox_is_one_to_one(connection)? {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn attested_finding_response_outbox_is_one_to_one(
    connection: &Connection,
) -> PortResult<bool> {
    let (batch_items, outbox_rows, exact_matches): (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_attested_finding_batch_items),
                (SELECT COUNT(*) FROM security_attested_finding_response_outbox),
                (
                    SELECT COUNT(*)
                    FROM security_attested_finding_batch_items AS item
                    JOIN security_attested_finding_response_outbox AS outbox
                      ON outbox.tenant_id = item.tenant_id
                     AND outbox.batch_id = item.batch_id
                     AND outbox.ordinal = item.ordinal
                     AND outbox.evidence_id = item.evidence_id
                     AND outbox.finding_id = item.finding_id
                     AND outbox.finding_hash = item.finding_hash
                     AND outbox.action_id = item.action_id
                     AND outbox.reservation_id = item.reservation_id
                )
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    Ok(batch_items == outbox_rows && batch_items == exact_matches)
}
