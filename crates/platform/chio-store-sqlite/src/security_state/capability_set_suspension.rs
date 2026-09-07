use super::{
    body_hash, decode_digest, effect_request_matches_query, from_i64, sqlite_error, to_i64,
    validate_canonical_json_body, validate_scheduler_fence, SqliteSecurityStateStore,
};
use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    predict_capability_set_suspension_apply, predict_capability_set_suspension_remove,
    response_affected_set_hash, validate_capability_set_suspension_snapshot,
    validate_capability_suspension_decision, ActionId, CapabilitySetSuspensionApplyRequest,
    CapabilitySetSuspensionCommand, CapabilitySetSuspensionContribution,
    CapabilitySetSuspensionContributions, CapabilitySetSuspensionKey, CapabilitySetSuspensionMatch,
    CapabilitySetSuspensionMatches, CapabilitySetSuspensionRemoveRequest,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore,
    CapabilitySuspensionDecision, CapabilitySuspensionQuery, Digest32, EffectExecutionStatus,
    EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery, PortError,
    PortResult, RecordId, RecordIdSet, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

fn suspension_key(request: &EffectRequest) -> PortResult<CapabilitySetSuspensionKey> {
    let ResponseTarget::CapabilitySet { affected_set_hash } = &request.target else {
        return Err(PortError::invalid_data());
    };
    Ok(CapabilitySetSuspensionKey {
        tenant_id: request.tenant_id.clone(),
        affected_set_hash: *affected_set_hash,
    })
}

fn decode_suspension_spec(request: &EffectRequest) -> PortResult<CapabilitySetSuspensionSpec> {
    validate_canonical_json_body(&request.canonical_contribution, &request.contribution_hash)?;
    let spec: CapabilitySetSuspensionSpec =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&spec).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes()
        || spec.affected_ids.as_slice().is_empty()
        || response_affected_set_hash(&request.tenant_id, &spec.affected_ids)?
            != suspension_key(request)?.affected_set_hash
    {
        return Err(PortError::invalid_data());
    }
    Ok(spec)
}

fn command_contribution(
    request: &EffectRequest,
) -> PortResult<CapabilitySetSuspensionContribution> {
    let spec = decode_suspension_spec(request)?;
    Ok(CapabilitySetSuspensionContribution {
        action_id: request.action_id.clone(),
        effect_id: request.effect_id.clone(),
        affected_ids: spec.affected_ids,
        contribution_hash: request.contribution_hash,
        expires_at_unix_ms: request.plan_expires_at_unix_ms,
    })
}

fn validate_command_common(command: &CapabilitySetSuspensionCommand) -> PortResult<()> {
    let request = &command.request;
    if request.effect_kind != ResponseEffectKind::SuspendCapabilitySet
        || !matches!(&request.target, ResponseTarget::CapabilitySet { .. })
        || request.plan_expires_at_unix_ms == 0
        || request.scheduler_fencing_token == 0
        || !request
            .idempotency_key
            .as_str()
            .starts_with("response_effect_command:")
        || command.result.effect_id != request.effect_id
        || command.result.applied != matches!(request.operation, EffectOperation::Apply)
        || command.result.resulting_version_hash == Digest32::new([0_u8; 32])
    {
        return Err(PortError::invalid_data());
    }
    let key = suspension_key(request)?;
    let contribution = command_contribution(request)?;
    validate_capability_set_suspension_snapshot(&command.resulting_snapshot, &key)?;
    match request.operation {
        EffectOperation::Apply => {
            if capability_set_suspension_installed_version_hash(&key, &contribution)?
                != command.result.resulting_version_hash
                || !command
                    .resulting_snapshot
                    .contributions
                    .as_slice()
                    .iter()
                    .any(|stored| stored == &contribution)
            {
                return Err(PortError::invalid_data());
            }
        }
        EffectOperation::Remove => {
            if capability_set_suspension_installed_version_hash(&key, &contribution)?
                != request.expected_version_hash
                || capability_set_suspension_version_hash(&command.resulting_snapshot)?
                    != command.result.resulting_version_hash
                || command
                    .resulting_snapshot
                    .contributions
                    .as_slice()
                    .iter()
                    .any(|stored| {
                        stored.action_id == request.action_id
                            && stored.effect_id == request.effect_id
                    })
            {
                return Err(PortError::invalid_data());
            }
        }
    }
    Ok(())
}

fn validate_apply_request(request: &CapabilitySetSuspensionApplyRequest) -> PortResult<()> {
    validate_command_common(&request.command)?;
    let command = &request.command.request;
    if command.operation != EffectOperation::Apply
        || suspension_key(command)? != request.key
        || command.action_id != request.contribution.action_id
        || command.effect_id != request.contribution.effect_id
        || command.contribution_hash != request.contribution.contribution_hash
        || command.plan_expires_at_unix_ms != request.contribution.expires_at_unix_ms
        || command.scheduler_fencing_token != request.scheduler_fencing_token
        || command_contribution(command)? != request.contribution
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_remove_request(request: &CapabilitySetSuspensionRemoveRequest) -> PortResult<()> {
    validate_command_common(&request.command)?;
    let command = &request.command.request;
    if command.operation != EffectOperation::Remove
        || suspension_key(command)? != request.key
        || command.action_id != request.action_id
        || command.effect_id != request.effect_id
        || command.scheduler_fencing_token != request.scheduler_fencing_token
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_stored_command(command: &CapabilitySetSuspensionCommand) -> PortResult<()> {
    validate_command_common(command).map_err(|_| PortError::integrity_failure())
}

fn load_command(
    connection: &Connection,
    tenant_id: &str,
    idempotency_key: &str,
) -> PortResult<Option<CapabilitySetSuspensionCommand>> {
    type StoredCommand = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let stored: Option<StoredCommand> = connection
        .query_row(
            r#"
            SELECT request_body, request_body_hash, result_body, result_body_hash,
                   resulting_snapshot_body, resulting_snapshot_body_hash
            FROM security_capability_set_suspension_commands
            WHERE tenant_id = ?1 AND idempotency_key = ?2
            "#,
            params![tenant_id, idempotency_key],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                request_body,
                request_hash,
                result_body,
                result_hash,
                snapshot_body,
                snapshot_hash,
            )| {
                let request_hash = decode_digest(request_hash)?;
                let result_hash = decode_digest(result_hash)?;
                let snapshot_hash = decode_digest(snapshot_hash)?;
                if body_hash(&request_body).as_slice() != request_hash.as_bytes()
                    || body_hash(&result_body).as_slice() != result_hash.as_bytes()
                    || body_hash(&snapshot_body).as_slice() != snapshot_hash.as_bytes()
                {
                    return Err(PortError::integrity_failure());
                }
                let request: EffectRequest = serde_json::from_slice(&request_body)
                    .map_err(|_| PortError::integrity_failure())?;
                let result: EffectResult = serde_json::from_slice(&result_body)
                    .map_err(|_| PortError::integrity_failure())?;
                let resulting_snapshot: CapabilitySetSuspensionSnapshot =
                    serde_json::from_slice(&snapshot_body)
                        .map_err(|_| PortError::integrity_failure())?;
                if canonical_json_bytes(&request).map_err(|_| PortError::integrity_failure())?
                    != request_body
                    || canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?
                        != result_body
                    || canonical_json_bytes(&resulting_snapshot)
                        .map_err(|_| PortError::integrity_failure())?
                        != snapshot_body
                    || request.tenant_id.as_str() != tenant_id
                    || request.idempotency_key.as_str() != idempotency_key
                {
                    return Err(PortError::integrity_failure());
                }
                Ok(CapabilitySetSuspensionCommand {
                    request,
                    result,
                    resulting_snapshot,
                })
            },
        )
        .transpose()
}

fn persist_command(
    transaction: &Transaction<'_>,
    command: &CapabilitySetSuspensionCommand,
) -> PortResult<()> {
    if let Some(existing) = load_command(
        transaction,
        command.request.tenant_id.as_str(),
        command.request.idempotency_key.as_str(),
    )? {
        return if &existing == command {
            Ok(())
        } else {
            Err(PortError::conflict())
        };
    }
    let request_body =
        canonical_json_bytes(&command.request).map_err(|_| PortError::invalid_data())?;
    let result_body =
        canonical_json_bytes(&command.result).map_err(|_| PortError::invalid_data())?;
    let snapshot_body =
        canonical_json_bytes(&command.resulting_snapshot).map_err(|_| PortError::invalid_data())?;
    let request_hash = body_hash(&request_body);
    let result_hash = body_hash(&result_body);
    let snapshot_hash = body_hash(&snapshot_body);
    transaction
        .execute(
            r#"
            INSERT INTO security_capability_set_suspension_commands (
                tenant_id, idempotency_key, request_body, request_body_hash,
                result_body, result_body_hash, resulting_snapshot_body,
                resulting_snapshot_body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                command.request.tenant_id.as_str(),
                command.request.idempotency_key.as_str(),
                request_body,
                request_hash.as_slice(),
                result_body,
                result_hash.as_slice(),
                snapshot_body,
                snapshot_hash.as_slice()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn load_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(Vec<u8>, String)>> {
    connection
        .query_row(
            r#"
            SELECT affected_set_hash, action_id
            FROM security_capability_set_suspension_effects
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn load_members(
    connection: &Connection,
    key: &CapabilitySetSuspensionKey,
    action_id: &ActionId,
    effect_id: &EffectId,
) -> PortResult<RecordIdSet> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT capability_id
            FROM security_capability_set_suspension_members
            WHERE tenant_id = ?1 AND affected_set_hash = ?2
              AND action_id = ?3 AND effect_id = ?4
            ORDER BY capability_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                key.tenant_id.as_str(),
                key.affected_set_hash.as_bytes().as_slice(),
                action_id.as_str(),
                effect_id.as_str()
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?;
    let mut members = Vec::new();
    for row in rows {
        members.push(
            RecordId::new(row.map_err(sqlite_error)?)
                .map_err(|_| PortError::integrity_failure())?,
        );
    }
    RecordIdSet::new(members).map_err(|_| PortError::integrity_failure())
}

fn load_snapshot(
    connection: &Connection,
    key: &CapabilitySetSuspensionKey,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    let state: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT generation, highest_fencing_token
            FROM security_capability_set_suspension_state
            WHERE tenant_id = ?1 AND affected_set_hash = ?2
            "#,
            params![
                key.tenant_id.as_str(),
                key.affected_set_hash.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let state_exists = state.is_some();
    let (generation, highest_fencing_token) = state.unwrap_or((0, 0));
    let mut statement = connection
        .prepare(
            r#"
            SELECT action_id, effect_id, affected_ids_body, contribution_hash,
                   expires_at, installed_fencing_token
            FROM security_capability_set_suspension_effects
            WHERE tenant_id = ?1 AND affected_set_hash = ?2
            ORDER BY action_id, effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                key.tenant_id.as_str(),
                key.affected_set_hash.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut contributions = Vec::new();
    let mut highest_installed_fencing_token = 0_u64;
    for row in rows {
        let (
            action_id,
            effect_id,
            affected_ids_body,
            contribution_hash,
            expires_at,
            installed_fencing_token,
        ) = row.map_err(sqlite_error)?;
        let action_id = ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
        let effect_id = EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?;
        let affected_ids: RecordIdSet = serde_json::from_slice(&affected_ids_body)
            .map_err(|_| PortError::integrity_failure())?;
        if affected_ids.as_slice().is_empty()
            || canonical_json_bytes(&affected_ids).map_err(|_| PortError::integrity_failure())?
                != affected_ids_body
            || response_affected_set_hash(&key.tenant_id, &affected_ids)? != key.affected_set_hash
            || load_members(connection, key, &action_id, &effect_id)? != affected_ids
        {
            return Err(PortError::integrity_failure());
        }
        highest_installed_fencing_token =
            highest_installed_fencing_token.max(from_i64(installed_fencing_token)?);
        contributions.push(CapabilitySetSuspensionContribution {
            action_id,
            effect_id,
            affected_ids,
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms: from_i64(expires_at)?,
        });
    }
    if !state_exists && !contributions.is_empty() {
        return Err(PortError::integrity_failure());
    }
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: key.clone(),
        generation: from_i64(generation)?,
        contributions: CapabilitySetSuspensionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: from_i64(highest_fencing_token)?,
    };
    validate_capability_set_suspension_snapshot(&snapshot, key)?;
    if snapshot.highest_fencing_token < highest_installed_fencing_token {
        return Err(PortError::integrity_failure());
    }
    Ok(snapshot)
}

fn persist_state(
    transaction: &Transaction<'_>,
    snapshot: &CapabilitySetSuspensionSnapshot,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_capability_set_suspension_state (
                tenant_id, affected_set_hash, generation, highest_fencing_token
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, affected_set_hash) DO UPDATE SET
                generation = excluded.generation,
                highest_fencing_token = excluded.highest_fencing_token
            "#,
            params![
                snapshot.key.tenant_id.as_str(),
                snapshot.key.affected_set_hash.as_bytes().as_slice(),
                to_i64(snapshot.generation)?,
                to_i64(snapshot.highest_fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn persist_effect(
    transaction: &Transaction<'_>,
    key: &CapabilitySetSuspensionKey,
    contribution: &CapabilitySetSuspensionContribution,
    scheduler_fencing_token: u64,
) -> PortResult<()> {
    let affected_ids_body =
        canonical_json_bytes(&contribution.affected_ids).map_err(|_| PortError::invalid_data())?;
    transaction
        .execute(
            r#"
            INSERT INTO security_capability_set_suspension_effects (
                tenant_id, affected_set_hash, action_id, effect_id, affected_ids_body,
                contribution_hash, expires_at, installed_fencing_token
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                key.tenant_id.as_str(),
                key.affected_set_hash.as_bytes().as_slice(),
                contribution.action_id.as_str(),
                contribution.effect_id.as_str(),
                affected_ids_body,
                contribution.contribution_hash.as_bytes().as_slice(),
                to_i64(contribution.expires_at_unix_ms)?,
                to_i64(scheduler_fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    for capability_id in contribution.affected_ids.as_slice() {
        transaction
            .execute(
                r#"
                INSERT INTO security_capability_set_suspension_members (
                    tenant_id, affected_set_hash, action_id, effect_id, capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.affected_set_hash.as_bytes().as_slice(),
                    contribution.action_id.as_str(),
                    contribution.effect_id.as_str(),
                    capability_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

impl CapabilitySetSuspensionStore for SqliteSecurityStateStore {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()> {
        let mut connection = self.connection()?;
        let orphan_effect: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_capability_set_suspension_effects AS effects
                    LEFT JOIN security_capability_set_suspension_state AS state
                      ON state.tenant_id = effects.tenant_id
                     AND state.affected_set_hash = effects.affected_set_hash
                    WHERE state.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let orphan_member: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_capability_set_suspension_members AS members
                    LEFT JOIN security_capability_set_suspension_effects AS effects
                      ON effects.tenant_id = members.tenant_id
                     AND effects.affected_set_hash = members.affected_set_hash
                     AND effects.action_id = members.action_id
                     AND effects.effect_id = members.effect_id
                    WHERE effects.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphan_effect || orphan_member {
            return Err(PortError::integrity_failure());
        }

        let mut state_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, affected_set_hash
                FROM security_capability_set_suspension_state
                ORDER BY tenant_id, affected_set_hash
                "#,
            )
            .map_err(sqlite_error)?;
        let state_rows = state_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut keys = Vec::new();
        for row in state_rows {
            let (tenant_id, affected_set_hash) = row.map_err(sqlite_error)?;
            keys.push(CapabilitySetSuspensionKey {
                tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
                affected_set_hash: decode_digest(affected_set_hash)?,
            });
        }
        drop(state_statement);
        for key in keys {
            load_snapshot(&connection, &key)?;
        }

        let mut command_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, idempotency_key
                FROM security_capability_set_suspension_commands
                ORDER BY tenant_id, idempotency_key
                "#,
            )
            .map_err(sqlite_error)?;
        let command_rows = command_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut command_keys = Vec::new();
        for row in command_rows {
            command_keys.push(row.map_err(sqlite_error)?);
        }
        drop(command_statement);
        for (tenant_id, idempotency_key) in command_keys {
            let command = load_command(&connection, &tenant_id, &idempotency_key)?
                .ok_or_else(PortError::integrity_failure)?;
            validate_stored_command(&command)?;
        }
        let writable_probe = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        writable_probe.rollback().map_err(sqlite_error)?;
        Ok(())
    }

    fn apply_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        validate_apply_request(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.contribution.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.resulting_snapshot);
        }
        let binding = load_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )?;
        if let Some((affected_set_hash, action_id)) = binding.as_ref() {
            if decode_digest(affected_set_hash.clone())? != request.key.affected_set_hash
                || action_id != request.contribution.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        let current = load_snapshot(&transaction, &request.key)?;
        let predicted = predict_capability_set_suspension_apply(
            &current,
            &request.contribution,
            request.scheduler_fencing_token,
        )?;
        if predicted != request.command.resulting_snapshot {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.contribution.action_id
                && entry.effect_id == request.contribution.effect_id
        }) {
            if existing != &request.contribution || binding.is_none() {
                return Err(PortError::conflict());
            }
            persist_state(&transaction, &predicted)?;
            let stored = load_snapshot(&transaction, &request.key)?;
            if stored != predicted {
                return Err(PortError::integrity_failure());
            }
            persist_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        if binding.is_some()
            || current.generation != request.expected_generation
            || capability_set_suspension_version_hash(&current)?
                != request.command.request.expected_version_hash
            || request.contribution.expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::conflict());
        }
        persist_state(&transaction, &current)?;
        persist_effect(
            &transaction,
            &request.key,
            &request.contribution,
            request.scheduler_fencing_token,
        )?;
        persist_state(&transaction, &predicted)?;
        let stored = load_snapshot(&transaction, &request.key)?;
        if stored != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn remove_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        validate_remove_request(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.resulting_snapshot);
        }
        let binding = load_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        if let Some((affected_set_hash, action_id)) = binding.as_ref() {
            if decode_digest(affected_set_hash.clone())? != request.key.affected_set_hash
                || action_id != request.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        let current = load_snapshot(&transaction, &request.key)?;
        let predicted = predict_capability_set_suspension_remove(
            &current,
            &request.action_id,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        if predicted != request.command.resulting_snapshot {
            return Err(PortError::conflict());
        }
        let Some(stored_contribution) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.action_id && entry.effect_id == request.effect_id
        }) else {
            if binding.is_some() {
                return Err(PortError::integrity_failure());
            }
            persist_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        };
        if stored_contribution != &command_contribution(&request.command.request)?
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let deleted = transaction
            .execute(
                r#"
                DELETE FROM security_capability_set_suspension_effects
                WHERE tenant_id = ?1 AND affected_set_hash = ?2
                  AND action_id = ?3 AND effect_id = ?4
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.affected_set_hash.as_bytes().as_slice(),
                    request.action_id.as_str(),
                    request.effect_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        persist_state(&transaction, &predicted)?;
        let stored = load_snapshot(&transaction, &request.key)?;
        if stored != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn load_capability_set_suspensions(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>> {
        let connection = self.connection()?;
        let exists: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM security_capability_set_suspension_state
                    WHERE tenant_id = ?1 AND affected_set_hash = ?2
                )
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.affected_set_hash.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exists {
            return Ok(None);
        }
        Ok(Some(load_snapshot(&connection, key)?))
    }

    fn evaluate_capability_suspension(
        &self,
        query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT affected_set_hash
                FROM security_capability_set_suspension_state
                WHERE tenant_id = ?1
                ORDER BY affected_set_hash
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![query.tenant_id.as_str()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(sqlite_error)?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(CapabilitySetSuspensionKey {
                tenant_id: query.tenant_id.clone(),
                affected_set_hash: decode_digest(row.map_err(sqlite_error)?)?,
            });
        }
        drop(statement);
        let mut matches = Vec::new();
        for key in keys {
            let snapshot = load_snapshot(&transaction, &key)?;
            for contribution in snapshot.contributions.as_slice() {
                if contribution
                    .affected_ids
                    .as_slice()
                    .binary_search(&query.capability_id)
                    .is_ok()
                {
                    matches.push(CapabilitySetSuspensionMatch {
                        affected_set_hash: key.affected_set_hash,
                        action_id: contribution.action_id.clone(),
                        effect_id: contribution.effect_id.clone(),
                        contribution_hash: contribution.contribution_hash,
                        expires_at_unix_ms: contribution.expires_at_unix_ms,
                    });
                }
            }
        }
        matches.sort_by(|left, right| {
            (&left.action_id, &left.effect_id, left.affected_set_hash).cmp(&(
                &right.action_id,
                &right.effect_id,
                right.affected_set_hash,
            ))
        });
        let active_matches = CapabilitySetSuspensionMatches::new(matches)
            .map_err(|_| PortError::integrity_failure())?;
        let decision = CapabilitySuspensionDecision {
            tenant_id: query.tenant_id.clone(),
            capability_id: query.capability_id.clone(),
            denied: !active_matches.is_empty(),
            active_matches,
        };
        validate_capability_suspension_decision(query, &decision)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(decision)
    }

    fn load_capability_set_suspension_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let connection = self.connection()?;
        let Some(command) = load_command(
            &connection,
            query.tenant_id.as_str(),
            query.idempotency_key.as_str(),
        )?
        else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        validate_stored_command(&command)?;
        if !effect_request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result,
        })
    }
}
