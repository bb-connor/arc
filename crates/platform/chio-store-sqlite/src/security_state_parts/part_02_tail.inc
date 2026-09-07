fn validate_no_attested_finding_batch_schema_extensions(connection: &Connection) -> PortResult<()> {
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

fn validate_attested_finding_batch_records(connection: &Connection) -> PortResult<()> {
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

fn validate_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
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

fn attested_finding_batch_legacy_schema_is_exact(connection: &Connection) -> PortResult<bool> {
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

fn count_rows(connection: &Connection, table: &str) -> PortResult<i64> {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)
}

fn table_has_foreign_key_violation(connection: &Connection, table: &str) -> PortResult<bool> {
    let mut statement = connection
        .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    rows.next().map(|row| row.is_some()).map_err(sqlite_error)
}

fn ensure_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
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

fn ensure_lineage_fence_binding_columns(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_lineage_fences)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.contains("scheduler_lease_owner_id") {
        connection
            .execute(
                "ALTER TABLE security_lineage_fences ADD COLUMN scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !columns.contains("scheduler_fencing_token") {
        connection
            .execute(
                "ALTER TABLE security_lineage_fences ADD COLUMN scheduler_fencing_token INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    let mut statement = connection
        .prepare("PRAGMA table_info(security_issuance_freeze_effects)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.contains("external_scheduler_lease_owner_id") {
        connection
            .execute(
                "ALTER TABLE security_issuance_freeze_effects ADD COLUMN external_scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !columns.contains("external_scheduler_fencing_token") {
        connection
            .execute(
                "ALTER TABLE security_issuance_freeze_effects ADD COLUMN external_scheduler_fencing_token INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn ensure_response_effect_generation_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_response_effects)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut generation_exists = false;
    let mut scheduler_lease_owner_id_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        if name == "generation" {
            generation_exists = true;
        } else if name == "scheduler_lease_owner_id" {
            scheduler_lease_owner_id_exists = true;
        }
    }
    drop(rows);
    drop(statement);
    if !generation_exists {
        connection
            .execute(
                "ALTER TABLE security_response_effects ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !scheduler_lease_owner_id_exists {
        connection
            .execute(
                "ALTER TABLE security_response_effects ADD COLUMN scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
        connection
            .execute(
                r#"
                UPDATE security_response_effects AS effects
                SET scheduler_lease_owner_id = (
                    SELECT leases.lease_owner_id
                    FROM security_scheduler_leases AS leases
                    WHERE leases.tenant_id = effects.tenant_id
                      AND leases.action_id = effects.action_id
                      AND leases.fencing_token = effects.scheduler_fencing_token
                )
                WHERE scheduler_lease_owner_id = ''
                  AND EXISTS (
                    SELECT 1
                    FROM security_scheduler_leases AS leases
                    WHERE leases.tenant_id = effects.tenant_id
                      AND leases.action_id = effects.action_id
                      AND leases.fencing_token = effects.scheduler_fencing_token
                  )
                "#,
                [],
            )
            .map_err(sqlite_error)?;
    }
    let unresolved_owner: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_response_effects WHERE scheduler_lease_owner_id IS NULL OR scheduler_lease_owner_id = '')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if unresolved_owner {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn ensure_scheduler_lease_body_hash_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_scheduler_leases)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    let body_hash_exists = columns.contains("lease_body_hash");
    if !body_hash_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_leases ADD COLUMN lease_body_hash BLOB",
                [],
            )
            .map_err(sqlite_error)?;
    }

    type StoredLeaseBody = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        Option<Vec<u8>>,
    );
    let mut statement = connection
        .prepare(
            r#"
            SELECT tenant_id, action_id, claim_id, claim_ordinal,
                   lease_owner_id, lease_expires_at, fencing_token,
                   lease_body_hash
            FROM security_scheduler_leases
            ORDER BY tenant_id, action_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .map_err(sqlite_error)?;
    let mut leases = Vec::<StoredLeaseBody>::new();
    for row in rows {
        leases.push(row.map_err(sqlite_error)?);
    }
    drop(statement);

    for (
        tenant_id,
        action_id,
        claim_id,
        claim_ordinal,
        lease_owner_id,
        lease_expires_at,
        fencing_token,
        stored_hash,
    ) in leases
    {
        TenantId::new(tenant_id.clone()).map_err(|_| PortError::integrity_failure())?;
        ActionId::new(action_id.clone()).map_err(|_| PortError::integrity_failure())?;
        RecordId::new(claim_id.clone()).map_err(|_| PortError::integrity_failure())?;
        LeaseOwnerId::new(lease_owner_id.clone()).map_err(|_| PortError::integrity_failure())?;
        let claim_ordinal = from_i64(claim_ordinal)?;
        let lease_expires_at = from_i64(lease_expires_at)?;
        let fencing_token = from_i64(fencing_token)?;
        if lease_expires_at == 0 || fencing_token == 0 {
            return Err(PortError::integrity_failure());
        }
        let expected_hash = scheduler_lease_body_hash(
            &tenant_id,
            &action_id,
            &claim_id,
            claim_ordinal,
            &lease_owner_id,
            lease_expires_at,
            fencing_token,
        )?;
        if body_hash_exists {
            let stored_hash = stored_hash.ok_or_else(PortError::integrity_failure)?;
            if stored_hash.as_slice() != expected_hash.as_slice() {
                return Err(PortError::integrity_failure());
            }
        } else {
            let updated = connection
                .execute(
                    r#"
                    UPDATE security_scheduler_leases
                    SET lease_body_hash = ?3
                    WHERE tenant_id = ?1 AND action_id = ?2
                      AND lease_body_hash IS NULL
                    "#,
                    params![tenant_id, action_id, expected_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(PortError::integrity_failure());
            }
        }
    }
    let invalid_hash_exists = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM security_scheduler_leases
                WHERE lease_body_hash IS NULL OR length(lease_body_hash) != 32
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_hash_exists {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn ensure_scheduler_retry_health_columns(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_scheduler_retries)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut first_failure_exists = false;
    let mut health_event_id_exists = false;
    let mut health_event_delivered_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        match name.as_str() {
            "first_failure_at" => first_failure_exists = true,
            "health_event_id" => health_event_id_exists = true,
            "health_event_delivered" => health_event_delivered_exists = true,
            _ => {}
        }
    }
    drop(rows);
    drop(statement);
    if !first_failure_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN first_failure_at INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_id_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_id TEXT",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_delivered_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_delivered INTEGER NOT NULL DEFAULT 0 CHECK (health_event_delivered IN (0, 1))",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn sqlite_error(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            PortError::conflict()
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..) => PortError::integrity_failure(),
        rusqlite::Error::ToSqlConversionFailure(_) => PortError::invalid_data(),
        _ => PortError::unavailable(),
    }
}

fn schema_version_error(error: crate::SchemaVersionError) -> PortError {
    match error {
        crate::SchemaVersionError::Sqlite(error) => sqlite_error(error),
        crate::SchemaVersionError::ForeignDatabase { .. }
        | crate::SchemaVersionError::MismatchedStore { .. }
        | crate::SchemaVersionError::FutureSchema { .. } => PortError::integrity_failure(),
    }
}

fn to_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn from_i64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

fn body_hash(body: &[u8]) -> [u8; 32] {
    let hash = sha256(body);
    let mut result = [0_u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn validate_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    if body_hash(body.as_bytes()).as_slice() != expected.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_canonical_json_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    validate_body(body, expected)?;
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn decode_digest(bytes: Vec<u8>) -> PortResult<Digest32> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Digest32::new(value))
}

fn canonical_request_hash<T: serde::Serialize>(value: &T) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    Ok(body_hash(canonical.as_ref()))
}

#[derive(Serialize)]
struct SchedulerLeaseBody<'a> {
    schema_version: u32,
    tenant_id: &'a str,
    action_id: &'a str,
    claim_id: &'a str,
    claim_ordinal: u64,
    lease_owner_id: &'a str,
    lease_expires_at_unix_ms: u64,
    fencing_token: u64,
}

fn scheduler_lease_body_hash(
    tenant_id: &str,
    action_id: &str,
    claim_id: &str,
    claim_ordinal: u64,
    lease_owner_id: &str,
    lease_expires_at_unix_ms: u64,
    fencing_token: u64,
) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(&SchedulerLeaseBody {
        schema_version: 1,
        tenant_id,
        action_id,
        claim_id,
        claim_ordinal,
        lease_owner_id,
        lease_expires_at_unix_ms,
        fencing_token,
    })
    .map_err(|_| PortError::integrity_failure())?;
    Ok(body_hash(canonical.as_ref()))
}

fn validate_encrypted_blob_reference(
    connection: &Connection,
    tenant_id: &str,
    reference: &RecordId,
) -> PortResult<()> {
    let lengths: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT length(nonce), length(ciphertext) FROM chio_encrypted_blobs
            WHERE blob_id = ?1 AND tenant_id = ?2
            "#,
            params![reference.as_str(), tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((nonce_length, ciphertext_length)) = lengths else {
        return Err(PortError::invalid_data());
    };
    if nonce_length != 12 || ciphertext_length < 16 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn encode_label(label: &InformationLabel) -> PortResult<(Vec<u8>, [u8; 32])> {
    let body = canonical_json_bytes(label).map_err(|_| PortError::invalid_data())?;
    let hash = body_hash(body.as_ref());
    Ok((body, hash))
}

fn decode_label(body: Vec<u8>, stored_hash: Vec<u8>) -> PortResult<InformationLabel> {
    let hash = decode_digest(stored_hash)?;
    if body_hash(&body).as_slice() != hash.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    let label: InformationLabel =
        serde_json::from_slice(&body).map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&label).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_slice() {
        return Err(PortError::integrity_failure());
    }
    Ok(label)
}

fn transition_status(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    let existing: Option<(String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT tenant_id, transition_kind, request_hash FROM security_transitions WHERE tenant_id = ?1 AND transition_id = ?2",
            params![tenant_id, transition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((existing_tenant, existing_kind, existing_hash)) = existing {
        if existing_tenant == tenant_id
            && existing_kind == kind
            && existing_hash.as_slice() == request_hash
        {
            return Ok(true);
        }
        return Err(PortError::conflict());
    }
    Ok(false)
}

fn record_transition(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    connection
        .execute(
            "INSERT INTO security_transitions (transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4)",
            params![transition_id, tenant_id, kind, request_hash.as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredLabel = (Vec<u8>, Vec<u8>, i64);

fn load_principal_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_principal_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_lineage_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_lineage_flow_state
            WHERE tenant_id = ?1 AND lineage_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_session_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_session_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2
              AND session_id = ?3 AND isolation_epoch_id = ?4
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_context_generation(connection: &Connection, key: &FlowStateKey) -> PortResult<Option<u64>> {
    let generation: Option<i64> = connection
        .query_row(
            r#"
            SELECT generation FROM security_flow_contexts
            WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    generation.map(from_i64).transpose()
}

fn session_membership_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_session_memberships
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn isolation_epoch_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}
