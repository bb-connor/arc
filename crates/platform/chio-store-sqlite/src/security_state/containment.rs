#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    body_hash, canonical_json_bytes, containment_installed_version_hash,
    containment_overlay_version_hash, containment_session_target, decode_digest,
    effect_request_matches_query, from_i64, params, predict_containment_overlay_apply,
    predict_containment_overlay_remove, sqlite_error, to_i64, validate_canonical_json_body,
    validate_containment_overlay_snapshot, validate_scheduler_fence, Connection,
    ContainmentOverlayCommand, ContainmentOverlayStore, Deserialize, Digest32,
    EffectExecutionStatus, EffectId, EffectOperation, EffectRequest, EffectResult,
    EffectResultQuery, OptionalExtension, OverlayApplyRequest, OverlayContribution,
    OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, PortError, PortResult, RecordId,
    ResponseEffectKind, ResponseTarget, Serialize, SqliteSecurityStateStore, TenantScopedId,
    Transaction, TransactionBehavior,
};

impl ContainmentOverlayStore for SqliteSecurityStateStore {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        let mut connection = self.connection()?;
        let orphan_contribution: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_effect_contributions AS contributions
                    LEFT JOIN security_overlay_state AS state
                      ON state.tenant_id = contributions.tenant_id
                     AND state.target_id = contributions.target_id
                    WHERE state.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphan_contribution {
            return Err(PortError::integrity_failure());
        }

        let mut state_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, target_id
                FROM security_overlay_state
                ORDER BY tenant_id, target_id
                "#,
            )
            .map_err(sqlite_error)?;
        let state_rows = state_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?;
        let mut targets = Vec::new();
        for row in state_rows {
            let (tenant_id, target_id) = row.map_err(sqlite_error)?;
            targets.push(TenantScopedId {
                tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                id: RecordId::new(target_id).map_err(|_| PortError::integrity_failure())?,
            });
        }
        drop(state_statement);
        for target in targets {
            load_overlay_snapshot(&connection, &target)?;
        }

        let mut command_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, idempotency_key
                FROM security_containment_overlay_commands
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
            let command = load_containment_overlay_command(
                &connection,
                tenant_id.as_str(),
                idempotency_key.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            validate_stored_containment_overlay_command(&command)?;
        }
        let writable_probe = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        writable_probe.rollback().map_err(sqlite_error)?;
        Ok(())
    }

    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        validate_containment_apply_command(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        validate_scheduler_fence(
            &transaction,
            request.target.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_containment_overlay_command(
            &transaction,
            request.target.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            let result = existing.resulting_snapshot;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }
        if let Some((target_id, action_id)) = load_contribution_binding(
            &transaction,
            request.target.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )? {
            if target_id != request.target.id.as_str() || action_id != request.action_id.as_str() {
                return Err(PortError::conflict());
            }
        }
        let current = load_overlay_snapshot(&transaction, &request.target)?;
        if containment_overlay_version_hash(&current)?
            != request.command.request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        let predicted = predict_containment_overlay_apply(
            &current,
            &request.contribution,
            request.scheduler_fencing_token,
        )?;
        if request.command.resulting_snapshot != predicted {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            let stored_action_id: String = transaction
                .query_row(
                    r#"
                    SELECT action_id FROM security_effect_contributions
                    WHERE tenant_id = ?1 AND target_id = ?2 AND effect_id = ?3
                    "#,
                    params![
                        request.target.tenant_id.as_str(),
                        request.target.id.as_str(),
                        request.contribution.effect_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if stored_action_id != request.action_id.as_str() || existing != &request.contribution {
                return Err(PortError::conflict());
            }
            persist_overlay_state(
                &transaction,
                &request.target,
                current.generation,
                current
                    .highest_fencing_token
                    .max(request.scheduler_fencing_token),
            )?;
            let snapshot = load_overlay_snapshot(&transaction, &request.target)?;
            if snapshot != predicted {
                return Err(PortError::integrity_failure());
            }
            persist_containment_overlay_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let Some(expires_at_unix_ms) = request.contribution.expires_at_unix_ms else {
            return Err(PortError::invalid_data());
        };
        if expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_effect_contributions (
                    tenant_id, target_id, effect_id, action_id,
                    posture_rank, contribution_hash, expires_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.target.tenant_id.as_str(),
                    request.target.id.as_str(),
                    request.contribution.effect_id.as_str(),
                    request.action_id.as_str(),
                    i64::from(request.contribution.posture_rank),
                    request.contribution.contribution_hash.as_bytes().as_slice(),
                    request
                        .contribution
                        .expires_at_unix_ms
                        .map(to_i64)
                        .transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_overlay_state(
            &transaction,
            &request.target,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_overlay_snapshot(&transaction, &request.target)?;
        if snapshot != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_containment_overlay_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        validate_containment_remove_command(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        validate_scheduler_fence(
            &transaction,
            request.target.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_containment_overlay_command(
            &transaction,
            request.target.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )? {
            if existing != request.command {
                return Err(PortError::conflict());
            }
            let result = existing.resulting_snapshot;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }
        let binding = load_contribution_binding(
            &transaction,
            request.target.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        if let Some((target_id, action_id)) = binding.as_ref() {
            if target_id != request.target.id.as_str() || action_id != request.action_id.as_str() {
                return Err(PortError::conflict());
            }
        }
        let current = load_overlay_snapshot(&transaction, &request.target)?;
        let predicted = predict_containment_overlay_remove(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        if request.command.resulting_snapshot != predicted {
            return Err(PortError::conflict());
        }
        if !current
            .active_contributions
            .as_slice()
            .iter()
            .any(|entry| entry.effect_id == request.effect_id)
        {
            if binding.is_some() {
                return Err(PortError::integrity_failure());
            }
            persist_containment_overlay_command(&transaction, &request.command)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        let command_contribution =
            decode_containment_command_contribution(&request.command.request)?;
        let stored_contribution = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        if stored_contribution.posture_rank != command_contribution.posture_rank
            || stored_contribution.contribution_hash != request.command.request.contribution_hash
            || stored_contribution.expires_at_unix_ms
                != Some(request.command.request.plan_expires_at_unix_ms)
        {
            return Err(PortError::conflict());
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let deleted = transaction
            .execute(
                "DELETE FROM security_effect_contributions WHERE tenant_id = ?1 AND target_id = ?2 AND effect_id = ?3 AND action_id = ?4",
                params![
                    request.target.tenant_id.as_str(),
                    request.target.id.as_str(),
                    request.effect_id.as_str(),
                    request.action_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_overlay_state(
            &transaction,
            &request.target,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_overlay_snapshot(&transaction, &request.target)?;
        if snapshot != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_containment_overlay_command(&transaction, &request.command)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM security_overlay_state WHERE tenant_id = ?1 AND target_id = ?2)",
                params![target.tenant_id.as_str(), target.id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exists {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(None);
        }
        let snapshot = load_overlay_snapshot(&transaction, target)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(Some(snapshot))
    }

    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let connection = self.connection()?;
        let Some(command) = load_containment_overlay_command(
            &connection,
            query.tenant_id.as_str(),
            query.idempotency_key.as_str(),
        )?
        else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        validate_stored_containment_overlay_command(&command)?;
        if !effect_request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContainmentCommandContributionBody {
    posture_rank: u32,
}

fn validate_stored_containment_overlay_command(
    command: &ContainmentOverlayCommand,
) -> PortResult<()> {
    validate_containment_command_common(command).map_err(|_| PortError::integrity_failure())
}

fn validate_containment_apply_command(request: &OverlayApplyRequest) -> PortResult<()> {
    validate_containment_command_common(&request.command)?;
    let command = &request.command.request;
    let canonical_target = containment_command_target(command)?;
    let contribution = decode_containment_command_contribution(command)?;
    if canonical_target != request.target
        || command.action_id != request.action_id
        || command.effect_id != request.contribution.effect_id
        || command.operation != EffectOperation::Apply
        || command.plan_expires_at_unix_ms != request.contribution.expires_at_unix_ms.unwrap_or(0)
        || command.contribution_hash != request.contribution.contribution_hash
        || command.scheduler_fencing_token != request.scheduler_fencing_token
        || contribution.posture_rank != request.contribution.posture_rank
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_containment_remove_command(request: &OverlayRemoveRequest) -> PortResult<()> {
    validate_containment_command_common(&request.command)?;
    let command = &request.command.request;
    let canonical_target = containment_command_target(command)?;
    if canonical_target != request.target
        || command.action_id != request.action_id
        || command.effect_id != request.effect_id
        || command.operation != EffectOperation::Remove
        || command.scheduler_fencing_token != request.scheduler_fencing_token
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_containment_command_common(command: &ContainmentOverlayCommand) -> PortResult<()> {
    let request = &command.request;
    if request.effect_kind != ResponseEffectKind::SuspendSession
        || !matches!(&request.target, ResponseTarget::Session { .. })
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
    let contribution = decode_containment_command_contribution(request)?;
    if contribution.posture_rank == 0 {
        return Err(PortError::invalid_data());
    }
    let target = containment_command_target(request)?;
    validate_containment_overlay_snapshot(&command.resulting_snapshot, &target)?;
    let overlay_contribution = OverlayContribution {
        effect_id: request.effect_id.clone(),
        posture_rank: contribution.posture_rank,
        contribution_hash: request.contribution_hash,
        expires_at_unix_ms: Some(request.plan_expires_at_unix_ms),
    };
    match request.operation {
        EffectOperation::Apply => {
            if containment_installed_version_hash(&target, &overlay_contribution)?
                != command.result.resulting_version_hash
                || !command
                    .resulting_snapshot
                    .active_contributions
                    .as_slice()
                    .iter()
                    .any(|stored| stored == &overlay_contribution)
            {
                return Err(PortError::invalid_data());
            }
        }
        EffectOperation::Remove => {
            if containment_installed_version_hash(&target, &overlay_contribution)?
                != request.expected_version_hash
                || containment_overlay_version_hash(&command.resulting_snapshot)?
                    != command.result.resulting_version_hash
                || command
                    .resulting_snapshot
                    .active_contributions
                    .as_slice()
                    .iter()
                    .any(|stored| stored.effect_id == request.effect_id)
            {
                return Err(PortError::invalid_data());
            }
        }
    }
    Ok(())
}

fn containment_command_target(request: &EffectRequest) -> PortResult<TenantScopedId> {
    let ResponseTarget::Session { session_id } = &request.target else {
        return Err(PortError::invalid_data());
    };
    containment_session_target(&request.tenant_id, session_id)
}

fn decode_containment_command_contribution(
    request: &EffectRequest,
) -> PortResult<ContainmentCommandContributionBody> {
    validate_canonical_json_body(&request.canonical_contribution, &request.contribution_hash)?;
    let contribution: ContainmentCommandContributionBody =
        chio_core::canonical::UntrustedJsonText::from_wire(
            request.canonical_contribution.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|_| PortError::invalid_data())?;
    let canonical =
        canonical_json_bytes(&contribution).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

pub(super) type StoredEffectCommandProjection =
    (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_containment_overlay_command(
    connection: &Connection,
    tenant_id: &str,
    idempotency_key: &str,
) -> PortResult<Option<ContainmentOverlayCommand>> {
    let stored: Option<StoredEffectCommandProjection> = connection
        .query_row(
            r#"
            SELECT request_body, request_body_hash, result_body, result_body_hash,
                   resulting_snapshot_body, resulting_snapshot_body_hash
            FROM security_containment_overlay_commands
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
                if body_hash(&request_body).as_slice() != request_hash.as_bytes() {
                    return Err(PortError::integrity_failure());
                }
                let request: EffectRequest = chio_core::canonical::UntrustedJsonText::from_wire(
                    &request_body,
                    64 * 1024 * 1024,
                )
                .and_then(|input| input.decode_signed())
                .map_err(|_| PortError::integrity_failure())?;
                let canonical_request =
                    canonical_json_bytes(&request).map_err(|_| PortError::integrity_failure())?;
                if canonical_request.as_slice() != request_body.as_slice() {
                    return Err(PortError::integrity_failure());
                }
                let result_hash = decode_digest(result_hash)?;
                if body_hash(&result_body).as_slice() != result_hash.as_bytes() {
                    return Err(PortError::integrity_failure());
                }
                let result: EffectResult = chio_core::canonical::UntrustedJsonText::from_wire(
                    &result_body,
                    64 * 1024 * 1024,
                )
                .and_then(|input| input.decode_signed())
                .map_err(|_| PortError::integrity_failure())?;
                let canonical_result =
                    canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?;
                let snapshot_hash = decode_digest(snapshot_hash)?;
                if body_hash(&snapshot_body).as_slice() != snapshot_hash.as_bytes() {
                    return Err(PortError::integrity_failure());
                }
                let resulting_snapshot: OverlaySnapshot =
                    chio_core::canonical::UntrustedJsonText::from_wire(
                        &snapshot_body,
                        64 * 1024 * 1024,
                    )
                    .and_then(|input| input.decode_signed())
                    .map_err(|_| PortError::integrity_failure())?;
                let canonical_snapshot = canonical_json_bytes(&resulting_snapshot)
                    .map_err(|_| PortError::integrity_failure())?;
                if canonical_result.as_slice() != result_body.as_slice()
                    || canonical_snapshot.as_slice() != snapshot_body.as_slice()
                    || request.tenant_id.as_str() != tenant_id
                    || request.idempotency_key.as_str() != idempotency_key
                {
                    return Err(PortError::integrity_failure());
                }
                Ok(ContainmentOverlayCommand {
                    request,
                    result,
                    resulting_snapshot,
                })
            },
        )
        .transpose()
}

fn persist_containment_overlay_command(
    transaction: &Transaction<'_>,
    command: &ContainmentOverlayCommand,
) -> PortResult<()> {
    if let Some(existing) = load_containment_overlay_command(
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
    let request_hash = body_hash(&request_body);
    let result_body =
        canonical_json_bytes(&command.result).map_err(|_| PortError::invalid_data())?;
    let result_hash = body_hash(&result_body);
    let snapshot_body =
        canonical_json_bytes(&command.resulting_snapshot).map_err(|_| PortError::invalid_data())?;
    let snapshot_hash = body_hash(&snapshot_body);
    transaction
        .execute(
            r#"
            INSERT INTO security_containment_overlay_commands (
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

fn load_contribution_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(String, String)>> {
    connection
        .query_row(
            r#"
            SELECT target_id, action_id FROM security_effect_contributions
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

pub(super) fn load_overlay_snapshot(
    connection: &Connection,
    target: &TenantScopedId,
) -> PortResult<OverlaySnapshot> {
    let state: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT generation, effective_posture_rank, highest_fencing_token FROM security_overlay_state WHERE tenant_id = ?1 AND target_id = ?2",
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let state_exists = state.is_some();
    let (generation, effective_posture_rank, highest_fencing_token) = state.unwrap_or((0, 0, 0));
    let mut statement = connection
        .prepare(
            r#"
            SELECT effect_id, posture_rank, contribution_hash, expires_at
            FROM security_effect_contributions
            WHERE tenant_id = ?1 AND target_id = ?2
            ORDER BY effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut contributions = Vec::new();
    for row in rows {
        let (effect_id, posture_rank, contribution_hash, expires_at) = row.map_err(sqlite_error)?;
        contributions.push(OverlayContribution {
            effect_id: EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?,
            posture_rank: u32::try_from(posture_rank)
                .map_err(|_| PortError::integrity_failure())?,
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms: expires_at.map(from_i64).transpose()?,
        });
    }
    if !state_exists && !contributions.is_empty() {
        return Err(PortError::integrity_failure());
    }
    let stored_posture =
        u32::try_from(effective_posture_rank).map_err(|_| PortError::integrity_failure())?;
    let recomputed_posture = contributions
        .iter()
        .map(|contribution| contribution.posture_rank)
        .max()
        .unwrap_or(0);
    if stored_posture != recomputed_posture {
        return Err(PortError::integrity_failure());
    }
    let generation = from_i64(generation)?;
    let highest_fencing_token = from_i64(highest_fencing_token)?;
    if generation
        < u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?
        || (!contributions.is_empty() && highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    let snapshot = OverlaySnapshot {
        target: target.clone(),
        generation,
        effective_posture_rank: stored_posture,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token,
    };
    validate_containment_overlay_snapshot(&snapshot, target)?;
    Ok(snapshot)
}

fn persist_overlay_state(
    transaction: &Transaction<'_>,
    target: &TenantScopedId,
    generation: u64,
    fencing_token: u64,
) -> PortResult<()> {
    let posture: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(posture_rank), 0) FROM security_effect_contributions WHERE tenant_id = ?1 AND target_id = ?2",
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_overlay_state (
                tenant_id, target_id, generation, effective_posture_rank, highest_fencing_token
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (tenant_id, target_id) DO UPDATE SET
                generation = excluded.generation,
                effective_posture_rank = excluded.effective_posture_rank,
                highest_fencing_token = excluded.highest_fencing_token
            "#,
            params![
                target.tenant_id.as_str(),
                target.id.as_str(),
                to_i64(generation)?,
                posture,
                to_i64(fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
