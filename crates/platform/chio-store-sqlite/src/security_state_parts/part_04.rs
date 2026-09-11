fn validate_declassification_evidence_schema(connection: &Connection) -> PortResult<()> {
    const EXPECTED_SCHEMA_DIGEST_HEX: &str =
        "83c3175ea1984bf501f554ac29bf7d279b858b06a8cc343cedc8571a681c867f";
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
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

    for (table, expected_sql) in [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(PortError::integrity_failure());
        }
    }

    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, sql
            FROM sqlite_master
            WHERE sql IS NOT NULL AND (
                name LIKE 'security_declassification_%'
                OR tbl_name IN (
                    'security_declassification_lifecycle',
                    'security_declassification_uses',
                    'security_declassification_evidence_identity',
                    'security_declassification_receipt_outbox',
                    'security_declassification_tombstones'
                )
                OR (
                    type = 'trigger'
                    AND instr(lower(sql), 'security_declassification_') > 0
                )
            )
            ORDER BY type, name
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let canonical = rows
        .into_iter()
        .map(|(object_type, name, sql)| format!("{object_type}|{name}|{}", normalize_sql(&sql)))
        .collect::<Vec<_>>()
        .join("\n");
    if hex::encode(sha256(canonical.as_bytes()).as_bytes()) != EXPECTED_SCHEMA_DIGEST_HEX {
        return Err(PortError::integrity_failure());
    }

    declassification::verify_legacy_lifecycle(connection)
}

fn validate_declassification_evidence_integrity(connection: &Connection) -> PortResult<()> {
    declassification::verify_legacy_integrity(connection)
}

fn load_lineage_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<(LineageFence, bool)>> {
    type StoredFence = (String, i64, Vec<u8>, i64, String, i64, i64, String);
    let stored: Option<StoredFence> = connection
        .query_row(
            r#"
            SELECT tenant_id, commit_index, affected_set_hash, fencing_token,
                   scheduler_lease_owner_id, scheduler_fencing_token, expires_at, state
            FROM security_lineage_fences WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
            |row| {
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
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                tenant_id,
                commit_index,
                affected_set_hash,
                fencing_token,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                expires_at,
                state,
            )| {
                let active = match state.as_str() {
                    "active" => true,
                    "released" => false,
                    _ => return Err(PortError::integrity_failure()),
                };
                Ok((
                    LineageFence {
                        tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        action_id: ActionId::new(action_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        commit_index: from_i64(commit_index)?,
                        affected_set_hash: decode_digest(affected_set_hash)?,
                        fencing_token: from_i64(fencing_token)?,
                        scheduler_lease_owner_id: LeaseOwnerId::new(scheduler_lease_owner_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        scheduler_fencing_token: from_i64(scheduler_fencing_token)?,
                        expires_at_unix_ms: from_i64(expires_at)?,
                    },
                    active,
                ))
            },
        )
        .transpose()
}

impl LineageFenceStore for SqliteSecurityStateStore {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        if request.scheduler_fencing_token == 0 || request.expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }
        let existing = load_lineage_fence(
            &transaction,
            request.tenant_id.as_str(),
            request.action_id.as_str(),
        )?;
        let fencing_token = if let Some((existing, active)) = existing.as_ref() {
            if !active {
                return Err(PortError::conflict());
            }
            if existing.commit_index != request.expected_commit_index
                || existing.affected_set_hash != request.expected_affected_set_hash
                || existing.scheduler_lease_owner_id != request.scheduler_lease_owner_id
                || existing.scheduler_fencing_token != request.scheduler_fencing_token
            {
                return Err(PortError::conflict());
            }
            if existing.expires_at_unix_ms > trusted_now {
                if existing.expires_at_unix_ms != request.expires_at_unix_ms {
                    return Err(PortError::conflict());
                }
                transaction.commit().map_err(sqlite_error)?;
                return Ok(existing.clone());
            }
            existing
                .fencing_token
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        } else {
            1
        };
        transaction
            .execute(
                r#"
                INSERT INTO security_lineage_fences (
                    action_id, tenant_id, commit_index, affected_set_hash,
                    fencing_token, scheduler_lease_owner_id, scheduler_fencing_token,
                    expires_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')
                ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                    fencing_token = excluded.fencing_token,
                    scheduler_lease_owner_id = excluded.scheduler_lease_owner_id,
                    scheduler_fencing_token = excluded.scheduler_fencing_token,
                    expires_at = excluded.expires_at,
                    state = 'active'
                "#,
                params![
                    request.action_id.as_str(),
                    request.tenant_id.as_str(),
                    to_i64(request.expected_commit_index)?,
                    request.expected_affected_set_hash.as_bytes().as_slice(),
                    to_i64(fencing_token)?,
                    request.scheduler_lease_owner_id.as_str(),
                    to_i64(request.scheduler_fencing_token)?,
                    to_i64(request.expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        let fence = LineageFence {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            commit_index: request.expected_commit_index,
            affected_set_hash: request.expected_affected_set_hash,
            fencing_token,
            scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: request.scheduler_fencing_token,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let stored =
            load_lineage_fence(&transaction, action.tenant_id.as_str(), action.id.as_str())?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        transaction.commit().map_err(sqlite_error)?;
        let Some((fence, active)) = stored else {
            return Ok(None);
        };
        if !active || fence.expires_at_unix_ms <= trusted_now {
            return Ok(None);
        }
        Ok(Some(fence))
    }

    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        if renewal.fencing_token == 0
            || renewal.scheduler_fencing_token == 0
            || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        let (existing, active) = load_lineage_fence(
            &transaction,
            renewal.tenant_id.as_str(),
            renewal.action_id.as_str(),
        )?
        .ok_or_else(PortError::conflict)?;
        if !active
            || existing.expires_at_unix_ms <= trusted_now
            || existing.fencing_token != renewal.fencing_token
            || existing.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
            || existing.scheduler_fencing_token != renewal.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if existing.expires_at_unix_ms == renewal.renewed_expires_at_unix_ms {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        if existing.expires_at_unix_ms != renewal.expected_expires_at_unix_ms {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_lineage_fences SET expires_at = ?6
                WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
                  AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
                  AND expires_at = ?7 AND state = 'active'
                "#,
                params![
                    renewal.tenant_id.as_str(),
                    renewal.action_id.as_str(),
                    to_i64(renewal.fencing_token)?,
                    renewal.scheduler_lease_owner_id.as_str(),
                    to_i64(renewal.scheduler_fencing_token)?,
                    to_i64(renewal.renewed_expires_at_unix_ms)?,
                    to_i64(renewal.expected_expires_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let renewed = LineageFence {
            expires_at_unix_ms: renewal.renewed_expires_at_unix_ms,
            ..existing
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(renewed)
    }

    fn takeover(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        if takeover.expected_fencing_token == 0
            || takeover.expected_scheduler_fencing_token == 0
            || takeover.successor_scheduler_fencing_token
                <= takeover.expected_scheduler_fencing_token
            || takeover.successor_expires_at_unix_ms < takeover.expected_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        let (existing, active) = load_lineage_fence(
            &transaction,
            takeover.tenant_id.as_str(),
            takeover.action_id.as_str(),
        )?
        .ok_or_else(PortError::conflict)?;
        if !active
            || existing.expires_at_unix_ms <= trusted_now
            || existing.fencing_token != takeover.expected_fencing_token
            || existing.scheduler_lease_owner_id != takeover.expected_scheduler_lease_owner_id
            || existing.scheduler_fencing_token != takeover.expected_scheduler_fencing_token
            || existing.expires_at_unix_ms != takeover.expected_expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        let successor_fencing_token = existing
            .fencing_token
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_lineage_fences
                SET fencing_token = ?9, scheduler_lease_owner_id = ?7,
                    scheduler_fencing_token = ?8, expires_at = ?6
                WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
                  AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
                  AND expires_at = ?10 AND state = 'active'
                "#,
                params![
                    takeover.tenant_id.as_str(),
                    takeover.action_id.as_str(),
                    to_i64(takeover.expected_fencing_token)?,
                    takeover.expected_scheduler_lease_owner_id.as_str(),
                    to_i64(takeover.expected_scheduler_fencing_token)?,
                    to_i64(takeover.successor_expires_at_unix_ms)?,
                    takeover.successor_scheduler_lease_owner_id.as_str(),
                    to_i64(takeover.successor_scheduler_fencing_token)?,
                    to_i64(successor_fencing_token)?,
                    to_i64(takeover.expected_expires_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let successor = LineageFence {
            fencing_token: successor_fencing_token,
            scheduler_lease_owner_id: takeover.successor_scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: takeover.successor_scheduler_fencing_token,
            expires_at_unix_ms: takeover.successor_expires_at_unix_ms,
            ..existing
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(successor)
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        let existing = load_lineage_fence(
            &transaction,
            release.tenant_id.as_str(),
            release.action_id.as_str(),
        )?;
        let Some((existing, active)) = existing else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        };
        if existing.fencing_token != release.fencing_token
            || existing.scheduler_lease_owner_id != release.scheduler_lease_owner_id
            || existing.scheduler_fencing_token != release.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if !active {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        if existing.expires_at_unix_ms <= trusted_now {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                "UPDATE security_lineage_fences SET state = 'released', expires_at = 0 WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3 AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5 AND state = 'active'",
                params![
                    release.tenant_id.as_str(),
                    release.action_id.as_str(),
                    to_i64(release.fencing_token)?,
                    release.scheduler_lease_owner_id.as_str(),
                    to_i64(release.scheduler_fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}
