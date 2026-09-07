use super::{
    body_hash, decode_digest, effect_request_matches_query, from_i64, sqlite_error, to_i64,
    validate_canonical_json_body, validate_scheduler_fence, validate_scheduler_lease_binding,
    SqliteSecurityStateStore,
};
use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    issuance_freeze_installed_version_hash, issuance_freeze_version_hash,
    predict_issuance_freeze_apply, predict_issuance_freeze_remove, response_affected_set_hash,
    validate_issuance_freeze_admission_decision, validate_issuance_freeze_contribution,
    validate_issuance_freeze_snapshot, ActionId, BlastRadiusResult, CapabilityIssuanceOperation,
    Digest32, EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery,
    IssuanceFreezeAdmissionDecision, IssuanceFreezeAdmissionQuery, IssuanceFreezeApplyRequest,
    IssuanceFreezeCommand, IssuanceFreezeContribution, IssuanceFreezeContributions,
    IssuanceFreezeFenceMaintenanceRequest, IssuanceFreezeKey, IssuanceFreezeMatch,
    IssuanceFreezeMatches, IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease,
    IssuanceFreezeRemoveRequest, IssuanceFreezeSnapshot, IssuanceFreezeSpec, IssuanceFreezeStore,
    LeaseOwnerId, LineageFence, PortError, PortResult, RecordId, RecordIdSet,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const COMMAND_RELEASE_PENDING: &str = "release_pending";
const COMMAND_COMPLETED: &str = "completed";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredCommandState {
    ReleasePending,
    Completed,
}

impl StoredCommandState {
    fn parse(value: &str) -> PortResult<Self> {
        match value {
            COMMAND_RELEASE_PENDING => Ok(Self::ReleasePending),
            COMMAND_COMPLETED => Ok(Self::Completed),
            _ => Err(PortError::integrity_failure()),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ReleasePending => COMMAND_RELEASE_PENDING,
            Self::Completed => COMMAND_COMPLETED,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredCommand {
    state: StoredCommandState,
    command: IssuanceFreezeCommand,
    pending_contribution: Option<IssuanceFreezeContribution>,
}

fn freeze_key(request: &EffectRequest) -> PortResult<IssuanceFreezeKey> {
    let ResponseTarget::Lineage { lineage_id } = &request.target else {
        return Err(PortError::invalid_data());
    };
    Ok(IssuanceFreezeKey {
        tenant_id: request.tenant_id.clone(),
        lineage_id: lineage_id.clone(),
    })
}

fn decode_freeze_spec(request: &EffectRequest) -> PortResult<IssuanceFreezeSpec> {
    validate_canonical_json_body(&request.canonical_contribution, &request.contribution_hash)?;
    let spec: IssuanceFreezeSpec =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&spec).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes() {
        return Err(PortError::invalid_data());
    }
    let key = freeze_key(request)?;
    let root = RecordId::new(key.lineage_id.as_str()).map_err(|_| PortError::invalid_data())?;
    let acquisition = &spec.acquisition;
    let blast_request = &acquisition.request;
    let BlastRadiusResult::Exact {
        metadata,
        sorted_affected_ids,
        affected_set_hash,
        graph_slice_hash,
    } = &acquisition.approved_result
    else {
        return Err(PortError::invalid_data());
    };
    let bounds = &blast_request.query_bounds;
    let exact_binding = spec.lineage_id == key.lineage_id
        && blast_request.tenant_id == request.tenant_id
        && blast_request.action_id == request.action_id
        && blast_request.seed_ids.len() == 1
        && blast_request.seed_ids.as_slice().first() == Some(&root)
        && bounds.max_depth > 0
        && bounds.max_nodes > 0
        && bounds.max_edges > 0
        && metadata.query_bounds == *bounds
        && metadata.source_lineage_version > 0
        && metadata.commit_index > 0
        && metadata.commit_index == metadata.authoritative_commit_index
        && metadata
            .completeness_watermark
            .is_some_and(|watermark| watermark >= metadata.commit_index)
        && !sorted_affected_ids.as_slice().is_empty()
        && sorted_affected_ids.as_slice().binary_search(&root).is_ok()
        && response_affected_set_hash(&request.tenant_id, sorted_affected_ids)?
            == *affected_set_hash
        && *graph_slice_hash != Digest32::new([0_u8; 32])
        && acquisition.expires_at_unix_ms <= request.plan_expires_at_unix_ms
        && acquisition.expires_at_unix_ms > 0;
    if !exact_binding {
        return Err(PortError::invalid_data());
    }
    Ok(spec)
}

fn contribution_matches_spec(
    request: &EffectRequest,
    contribution: &IssuanceFreezeContribution,
) -> PortResult<bool> {
    let spec = decode_freeze_spec(request)?;
    let BlastRadiusResult::Exact {
        metadata,
        sorted_affected_ids,
        affected_set_hash,
        graph_slice_hash,
    } = &spec.acquisition.approved_result
    else {
        return Err(PortError::invalid_data());
    };
    Ok(contribution.action_id == request.action_id
        && contribution.effect_id == request.effect_id
        && contribution.commit_index == metadata.commit_index
        && contribution.affected_set_hash == *affected_set_hash
        && contribution.frozen_affected_ids == *sorted_affected_ids
        && contribution.graph_slice_hash == *graph_slice_hash
        && contribution.external_fence.tenant_id == request.tenant_id
        && contribution.external_fence.action_id == request.action_id
        && contribution.external_fence.commit_index == metadata.commit_index
        && contribution.external_fence.affected_set_hash == *affected_set_hash
        && contribution.external_fence.scheduler_lease_owner_id == request.scheduler_lease_owner_id
        && contribution.external_fence.scheduler_fencing_token == request.scheduler_fencing_token
        && contribution.external_fence.expires_at_unix_ms > 0
        && contribution.contribution_hash == request.contribution_hash
        && contribution.expires_at_unix_ms == request.plan_expires_at_unix_ms)
}

fn validate_command_common(command: &IssuanceFreezeCommand) -> PortResult<()> {
    let request = &command.request;
    if request.effect_kind != ResponseEffectKind::FreezeIssuance
        || !matches!(&request.target, ResponseTarget::Lineage { .. })
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
    let spec = decode_freeze_spec(request)?;
    let key = freeze_key(request)?;
    validate_issuance_freeze_snapshot(&command.resulting_snapshot, &key)?;
    match request.operation {
        EffectOperation::Apply => {
            let contribution = command
                .resulting_snapshot
                .contributions
                .as_slice()
                .iter()
                .find(|entry| {
                    entry.action_id == request.action_id && entry.effect_id == request.effect_id
                })
                .ok_or_else(PortError::invalid_data)?;
            if !contribution_matches_spec(request, contribution)?
                || contribution.external_fence.expires_at_unix_ms
                    != spec.acquisition.expires_at_unix_ms
                || issuance_freeze_installed_version_hash(&key, contribution)?
                    != command.result.resulting_version_hash
            {
                return Err(PortError::invalid_data());
            }
        }
        EffectOperation::Remove => {
            if command
                .resulting_snapshot
                .contributions
                .as_slice()
                .iter()
                .any(|entry| {
                    entry.action_id == request.action_id && entry.effect_id == request.effect_id
                })
                || issuance_freeze_version_hash(&command.resulting_snapshot)?
                    != command.result.resulting_version_hash
            {
                return Err(PortError::invalid_data());
            }
        }
    }
    Ok(())
}

fn validate_apply_request(request: &IssuanceFreezeApplyRequest) -> PortResult<()> {
    validate_command_common(&request.command)?;
    let command = &request.command.request;
    let spec = decode_freeze_spec(command)?;
    if command.operation != EffectOperation::Apply
        || freeze_key(command)? != request.key
        || command.action_id != request.contribution.action_id
        || command.effect_id != request.contribution.effect_id
        || command.scheduler_fencing_token != request.scheduler_fencing_token
        || !contribution_matches_spec(command, &request.contribution)?
        || request.contribution.external_fence.expires_at_unix_ms
            != spec.acquisition.expires_at_unix_ms
        || issuance_freeze_installed_version_hash(&request.key, &request.contribution)?
            != request.command.result.resulting_version_hash
    {
        return Err(PortError::invalid_data());
    }
    validate_issuance_freeze_contribution(&request.key, &request.contribution)
        .map_err(|_| PortError::invalid_data())
}

fn validate_remove_request(request: &IssuanceFreezeRemoveRequest) -> PortResult<()> {
    validate_command_common(&request.command)?;
    let command = &request.command.request;
    if command.operation != EffectOperation::Remove
        || freeze_key(command)? != request.key
        || command.action_id != request.action_id
        || command.effect_id != request.effect_id
        || command.scheduler_fencing_token != request.scheduler_fencing_token
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_stored_command(stored: &StoredCommand) -> PortResult<()> {
    validate_command_common(&stored.command).map_err(|_| PortError::integrity_failure())?;
    match (stored.state, stored.pending_contribution.as_ref()) {
        (StoredCommandState::ReleasePending, Some(contribution))
            if stored.command.request.operation == EffectOperation::Remove
                && contribution_matches_spec(&stored.command.request, contribution)
                    .map_err(|_| PortError::integrity_failure())?
                && issuance_freeze_installed_version_hash(
                    &freeze_key(&stored.command.request)
                        .map_err(|_| PortError::integrity_failure())?,
                    contribution,
                )
                .map_err(|_| PortError::integrity_failure())?
                    == stored.command.request.expected_version_hash =>
        {
            Ok(())
        }
        (StoredCommandState::Completed, None) => Ok(()),
        _ => Err(PortError::integrity_failure()),
    }
}

fn decode_canonical<T>(body: Vec<u8>, hash: Vec<u8>) -> PortResult<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let digest = decode_digest(hash)?;
    if body_hash(&body).as_slice() != digest.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    let value: T = serde_json::from_slice(&body).map_err(|_| PortError::integrity_failure())?;
    if canonical_json_bytes(&value).map_err(|_| PortError::integrity_failure())? != body {
        return Err(PortError::integrity_failure());
    }
    Ok(value)
}

fn load_command(
    connection: &Connection,
    tenant_id: &str,
    idempotency_key: &str,
) -> PortResult<Option<StoredCommand>> {
    type StoredRow = (
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let row: Option<StoredRow> = connection
        .query_row(
            r#"
            SELECT lineage_id, action_id, effect_id, command_state,
                   request_body, request_body_hash, result_body, result_body_hash,
                   resulting_snapshot_body, resulting_snapshot_body_hash,
                   pending_contribution_body, pending_contribution_body_hash
            FROM security_issuance_freeze_commands
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
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(
        |(
            lineage_id,
            action_id,
            effect_id,
            state,
            request_body,
            request_hash,
            result_body,
            result_hash,
            snapshot_body,
            snapshot_hash,
            pending_body,
            pending_hash,
        )| {
            let request: EffectRequest = decode_canonical(request_body, request_hash)?;
            let result: EffectResult = decode_canonical(result_body, result_hash)?;
            let resulting_snapshot: IssuanceFreezeSnapshot =
                decode_canonical(snapshot_body, snapshot_hash)?;
            let pending_contribution = match (pending_body, pending_hash) {
                (Some(body), Some(hash)) => Some(decode_canonical(body, hash)?),
                (None, None) => None,
                _ => return Err(PortError::integrity_failure()),
            };
            if request.tenant_id.as_str() != tenant_id
                || request.idempotency_key.as_str() != idempotency_key
                || freeze_key(&request)
                    .map_err(|_| PortError::integrity_failure())?
                    .lineage_id
                    .as_str()
                    != lineage_id
                || request.action_id.as_str() != action_id
                || request.effect_id.as_str() != effect_id
            {
                return Err(PortError::integrity_failure());
            }
            let stored = StoredCommand {
                state: StoredCommandState::parse(&state)?,
                command: IssuanceFreezeCommand {
                    request,
                    result,
                    resulting_snapshot,
                },
                pending_contribution,
            };
            validate_stored_command(&stored)?;
            Ok(stored)
        },
    )
    .transpose()
}

fn encode_canonical<T: serde::Serialize>(value: &T) -> PortResult<(Vec<u8>, [u8; 32])> {
    let body = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    let hash = body_hash(&body);
    Ok((body, hash))
}

fn persist_command(transaction: &Transaction<'_>, stored: &StoredCommand) -> PortResult<()> {
    validate_stored_command(stored).map_err(|_| PortError::invalid_data())?;
    let request = &stored.command.request;
    if let Some(existing) = load_command(
        transaction,
        request.tenant_id.as_str(),
        request.idempotency_key.as_str(),
    )? {
        if existing == *stored {
            return Ok(());
        }
        if existing.state == StoredCommandState::ReleasePending
            && stored.state == StoredCommandState::Completed
            && existing.command == stored.command
            && stored.pending_contribution.is_none()
        {
            transaction
                .execute(
                    r#"
                    UPDATE security_issuance_freeze_commands
                    SET command_state = ?3,
                        pending_contribution_body = NULL,
                        pending_contribution_body_hash = NULL
                    WHERE tenant_id = ?1 AND idempotency_key = ?2
                      AND command_state = ?4
                    "#,
                    params![
                        request.tenant_id.as_str(),
                        request.idempotency_key.as_str(),
                        COMMAND_COMPLETED,
                        COMMAND_RELEASE_PENDING
                    ],
                )
                .map_err(sqlite_error)?;
            return Ok(());
        }
        return Err(PortError::conflict());
    }
    let (request_body, request_hash) = encode_canonical(request)?;
    let (result_body, result_hash) = encode_canonical(&stored.command.result)?;
    let (snapshot_body, snapshot_hash) = encode_canonical(&stored.command.resulting_snapshot)?;
    let (pending_body, pending_hash) = stored
        .pending_contribution
        .as_ref()
        .map(encode_canonical)
        .transpose()?
        .map_or((None, None), |(body, hash)| (Some(body), Some(hash)));
    let key = freeze_key(request)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_issuance_freeze_commands (
                tenant_id, idempotency_key, lineage_id, action_id, effect_id,
                command_state, request_body, request_body_hash, result_body,
                result_body_hash, resulting_snapshot_body,
                resulting_snapshot_body_hash, pending_contribution_body,
                pending_contribution_body_hash
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
            )
            "#,
            params![
                request.tenant_id.as_str(),
                request.idempotency_key.as_str(),
                key.lineage_id.as_str(),
                request.action_id.as_str(),
                request.effect_id.as_str(),
                stored.state.as_str(),
                request_body,
                request_hash.as_slice(),
                result_body,
                result_hash.as_slice(),
                snapshot_body,
                snapshot_hash.as_slice(),
                pending_body,
                pending_hash.map(|hash| hash.to_vec())
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn load_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(String, String)>> {
    connection
        .query_row(
            r#"
            SELECT lineage_id, action_id
            FROM security_issuance_freeze_effects
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn pending_command_exists(
    connection: &Connection,
    key: &IssuanceFreezeKey,
    except_idempotency_key: Option<&str>,
) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM security_issuance_freeze_commands
                WHERE tenant_id = ?1 AND lineage_id = ?2
                  AND command_state = ?3
                  AND (?4 IS NULL OR idempotency_key <> ?4)
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                COMMAND_RELEASE_PENDING,
                except_idempotency_key
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn load_pending_release(
    connection: &Connection,
    key: &IssuanceFreezeKey,
    action_id: &ActionId,
    effect_id: &EffectId,
) -> PortResult<Option<IssuanceFreezePendingRelease>> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT idempotency_key
            FROM security_issuance_freeze_commands
            WHERE tenant_id = ?1 AND lineage_id = ?2
              AND command_state = ?3 AND action_id = ?4 AND effect_id = ?5
            ORDER BY idempotency_key
            LIMIT 2
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                COMMAND_RELEASE_PENDING,
                action_id.as_str(),
                effect_id.as_str()
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?;
    let mut idempotency_keys = Vec::new();
    for row in rows {
        idempotency_keys.push(row.map_err(sqlite_error)?);
    }
    drop(statement);
    let [idempotency_key] = idempotency_keys.as_slice() else {
        return if idempotency_keys.is_empty() {
            Ok(None)
        } else {
            Err(PortError::integrity_failure())
        };
    };
    let stored = load_command(connection, key.tenant_id.as_str(), idempotency_key)?
        .ok_or_else(PortError::integrity_failure)?;
    if stored.state != StoredCommandState::ReleasePending {
        return Err(PortError::integrity_failure());
    }
    let contribution = stored
        .pending_contribution
        .ok_or_else(PortError::integrity_failure)?;
    let current = load_snapshot(connection, key)?;
    if !current
        .contributions
        .as_slice()
        .iter()
        .any(|entry| entry == &contribution)
        || current.generation.checked_add(1) != Some(stored.command.resulting_snapshot.generation)
    {
        return Err(PortError::integrity_failure());
    }
    let request = IssuanceFreezeRemoveRequest {
        key: key.clone(),
        action_id: action_id.clone(),
        effect_id: effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token: stored.command.request.scheduler_fencing_token,
        command: stored.command,
    };
    validate_remove_request(&request).map_err(|_| PortError::integrity_failure())?;
    Ok(Some(IssuanceFreezePendingRelease {
        request,
        contribution,
    }))
}

fn load_completed_release(
    connection: &Connection,
    key: &IssuanceFreezeKey,
    action_id: &ActionId,
    effect_id: &EffectId,
    plan_hash: Digest32,
) -> PortResult<Option<IssuanceFreezeCommand>> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT idempotency_key
            FROM security_issuance_freeze_commands
            WHERE tenant_id = ?1 AND lineage_id = ?2
              AND command_state = ?3 AND action_id = ?4 AND effect_id = ?5
            ORDER BY idempotency_key
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                COMMAND_COMPLETED,
                action_id.as_str(),
                effect_id.as_str()
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?;
    let mut completed = None;
    for row in rows {
        let idempotency_key = row.map_err(sqlite_error)?;
        let stored = load_command(connection, key.tenant_id.as_str(), &idempotency_key)?
            .ok_or_else(PortError::integrity_failure)?;
        if stored.command.request.operation == EffectOperation::Remove
            && stored.command.request.plan_hash == plan_hash
            && completed.replace(stored.command).is_some()
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(completed)
}

fn load_snapshot(
    connection: &Connection,
    key: &IssuanceFreezeKey,
) -> PortResult<IssuanceFreezeSnapshot> {
    let state: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT generation, highest_scheduler_fencing_token
            FROM security_issuance_freeze_state
            WHERE tenant_id = ?1 AND lineage_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let state_exists = state.is_some();
    let (generation, highest_scheduler_fencing_token) = state.unwrap_or((0, 0));
    type EffectRow = (
        String,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
        i64,
        i64,
        Vec<u8>,
        i64,
        i64,
    );
    let mut statement = connection
        .prepare(
            r#"
            SELECT action_id, effect_id, commit_index, affected_set_hash,
                   frozen_affected_ids_body, graph_slice_hash,
                   external_fencing_token, external_scheduler_lease_owner_id,
                   external_scheduler_fencing_token, external_fence_expires_at,
                   contribution_hash, expires_at,
                   installed_scheduler_fencing_token
            FROM security_issuance_freeze_effects
            WHERE tenant_id = ?1 AND lineage_id = ?2
            ORDER BY action_id, effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut contributions = Vec::new();
    let mut highest_installed_token = 0_u64;
    for row in rows {
        let row: EffectRow = row.map_err(sqlite_error)?;
        let (
            action_id,
            effect_id,
            commit_index,
            affected_set_hash,
            frozen_affected_ids_body,
            graph_slice_hash,
            external_fencing_token,
            external_scheduler_lease_owner_id,
            external_scheduler_fencing_token,
            external_fence_expires_at,
            contribution_hash,
            expires_at,
            installed_scheduler_fencing_token,
        ) = row;
        let action_id = ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
        let effect_id = EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?;
        let frozen_affected_ids: RecordIdSet = serde_json::from_slice(&frozen_affected_ids_body)
            .map_err(|_| PortError::integrity_failure())?;
        if canonical_json_bytes(&frozen_affected_ids).map_err(|_| PortError::integrity_failure())?
            != frozen_affected_ids_body
        {
            return Err(PortError::integrity_failure());
        }
        let commit_index = from_i64(commit_index)?;
        let affected_set_hash = decode_digest(affected_set_hash)?;
        let external_fencing_token = from_i64(external_fencing_token)?;
        let external_scheduler_lease_owner_id =
            LeaseOwnerId::new(external_scheduler_lease_owner_id)
                .map_err(|_| PortError::integrity_failure())?;
        let external_scheduler_fencing_token = from_i64(external_scheduler_fencing_token)?;
        let external_fence_expires_at = from_i64(external_fence_expires_at)?;
        let expires_at_unix_ms = from_i64(expires_at)?;
        let installed_scheduler_fencing_token = from_i64(installed_scheduler_fencing_token)?;
        highest_installed_token = highest_installed_token.max(installed_scheduler_fencing_token);
        contributions.push(IssuanceFreezeContribution {
            action_id: action_id.clone(),
            effect_id,
            commit_index,
            affected_set_hash,
            frozen_affected_ids,
            graph_slice_hash: decode_digest(graph_slice_hash)?,
            external_fence: LineageFence {
                tenant_id: key.tenant_id.clone(),
                action_id,
                commit_index,
                affected_set_hash,
                fencing_token: external_fencing_token,
                scheduler_lease_owner_id: external_scheduler_lease_owner_id,
                scheduler_fencing_token: external_scheduler_fencing_token,
                expires_at_unix_ms: external_fence_expires_at,
            },
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms,
        });
    }
    if !state_exists && !contributions.is_empty() {
        return Err(PortError::integrity_failure());
    }
    let snapshot = IssuanceFreezeSnapshot {
        key: key.clone(),
        generation: from_i64(generation)?,
        contributions: IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: from_i64(highest_scheduler_fencing_token)?,
    };
    validate_issuance_freeze_snapshot(&snapshot, key)?;
    if snapshot.highest_scheduler_fencing_token < highest_installed_token {
        return Err(PortError::integrity_failure());
    }
    Ok(snapshot)
}

fn persist_state(
    transaction: &Transaction<'_>,
    snapshot: &IssuanceFreezeSnapshot,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_issuance_freeze_state (
                tenant_id, lineage_id, generation,
                highest_scheduler_fencing_token
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, lineage_id) DO UPDATE SET
                generation = excluded.generation,
                highest_scheduler_fencing_token =
                    excluded.highest_scheduler_fencing_token
            "#,
            params![
                snapshot.key.tenant_id.as_str(),
                snapshot.key.lineage_id.as_str(),
                to_i64(snapshot.generation)?,
                to_i64(snapshot.highest_scheduler_fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn persist_effect(
    transaction: &Transaction<'_>,
    key: &IssuanceFreezeKey,
    contribution: &IssuanceFreezeContribution,
    scheduler_fencing_token: u64,
) -> PortResult<()> {
    let frozen_affected_ids_body = canonical_json_bytes(&contribution.frozen_affected_ids)
        .map_err(|_| PortError::invalid_data())?;
    transaction
        .execute(
            r#"
            INSERT INTO security_issuance_freeze_effects (
                tenant_id, lineage_id, action_id, effect_id, commit_index,
                affected_set_hash, frozen_affected_ids_body, graph_slice_hash,
                external_fencing_token, external_scheduler_lease_owner_id,
                external_scheduler_fencing_token, external_fence_expires_at,
                contribution_hash, expires_at,
                installed_scheduler_fencing_token
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                contribution.action_id.as_str(),
                contribution.effect_id.as_str(),
                to_i64(contribution.commit_index)?,
                contribution.affected_set_hash.as_bytes().as_slice(),
                frozen_affected_ids_body,
                contribution.graph_slice_hash.as_bytes().as_slice(),
                to_i64(contribution.external_fence.fencing_token)?,
                contribution
                    .external_fence
                    .scheduler_lease_owner_id
                    .as_str(),
                to_i64(contribution.external_fence.scheduler_fencing_token)?,
                to_i64(contribution.external_fence.expires_at_unix_ms)?,
                contribution.contribution_hash.as_bytes().as_slice(),
                to_i64(contribution.expires_at_unix_ms)?,
                to_i64(scheduler_fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn effect_exists(
    connection: &Connection,
    key: &IssuanceFreezeKey,
    action_id: &ActionId,
    effect_id: &EffectId,
) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_issuance_freeze_effects
                WHERE tenant_id = ?1 AND lineage_id = ?2
                  AND action_id = ?3 AND effect_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                action_id.as_str(),
                effect_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

impl IssuanceFreezeStore for SqliteSecurityStateStore {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()> {
        let mut connection = self.connection()?;
        let orphan_effect: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_issuance_freeze_effects AS effects
                    LEFT JOIN security_issuance_freeze_state AS state
                      ON state.tenant_id = effects.tenant_id
                     AND state.lineage_id = effects.lineage_id
                    WHERE state.tenant_id IS NULL
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphan_effect {
            return Err(PortError::integrity_failure());
        }

        let mut command_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, idempotency_key
                FROM security_issuance_freeze_commands
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
            let stored = load_command(&connection, &tenant_id, &idempotency_key)?
                .ok_or_else(PortError::integrity_failure)?;
            if stored.state == StoredCommandState::ReleasePending {
                let contribution = stored
                    .pending_contribution
                    .as_ref()
                    .ok_or_else(PortError::integrity_failure)?;
                let key = freeze_key(&stored.command.request)
                    .map_err(|_| PortError::integrity_failure())?;
                let snapshot = load_snapshot(&connection, &key)?;
                if !snapshot
                    .contributions
                    .as_slice()
                    .iter()
                    .any(|entry| entry == contribution)
                {
                    return Err(PortError::integrity_failure());
                }
            }
        }
        let writable_probe = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        writable_probe.rollback().map_err(sqlite_error)?;
        Ok(())
    }

    fn apply_issuance_freeze(
        &self,
        request: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
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
            let expected = StoredCommand {
                state: StoredCommandState::Completed,
                command: request.command.clone(),
                pending_contribution: None,
            };
            if existing != expected {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.command.resulting_snapshot);
        }
        if pending_command_exists(&transaction, &request.key, None)? {
            return Err(PortError::conflict());
        }
        let binding = load_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )?;
        if let Some((lineage_id, action_id)) = binding.as_ref() {
            if lineage_id != request.key.lineage_id.as_str()
                || action_id != request.contribution.action_id.as_str()
            {
                return Err(PortError::conflict());
            }
        }
        let current = load_snapshot(&transaction, &request.key)?;
        let predicted = predict_issuance_freeze_apply(
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
            let stored_snapshot = load_snapshot(&transaction, &request.key)?;
            if stored_snapshot != predicted {
                return Err(PortError::integrity_failure());
            }
            persist_command(
                &transaction,
                &StoredCommand {
                    state: StoredCommandState::Completed,
                    command: request.command.clone(),
                    pending_contribution: None,
                },
            )?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored_snapshot);
        }
        if binding.is_some()
            || current.generation != request.expected_generation
            || issuance_freeze_version_hash(&current)?
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
        let stored_snapshot = load_snapshot(&transaction, &request.key)?;
        if stored_snapshot != predicted {
            return Err(PortError::integrity_failure());
        }
        persist_command(
            &transaction,
            &StoredCommand {
                state: StoredCommandState::Completed,
                command: request.command.clone(),
                pending_contribution: None,
            },
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored_snapshot)
    }

    fn prepare_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution> {
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
            if existing.state != StoredCommandState::ReleasePending
                || existing.command != request.command
            {
                return Err(PortError::conflict());
            }
            let contribution = existing
                .pending_contribution
                .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(contribution);
        }
        if pending_command_exists(&transaction, &request.key, None)? {
            return Err(PortError::conflict());
        }
        let binding = load_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        let Some((lineage_id, action_id)) = binding else {
            return Err(PortError::conflict());
        };
        if lineage_id != request.key.lineage_id.as_str() || action_id != request.action_id.as_str()
        {
            return Err(PortError::conflict());
        }
        let current = load_snapshot(&transaction, &request.key)?;
        let contribution = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
        if !contribution_matches_spec(&request.command.request, &contribution)?
            || issuance_freeze_installed_version_hash(&request.key, &contribution)?
                != request.command.request.expected_version_hash
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let predicted = predict_issuance_freeze_remove(
            &current,
            &request.action_id,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        if predicted != request.command.resulting_snapshot {
            return Err(PortError::conflict());
        }
        persist_command(
            &transaction,
            &StoredCommand {
                state: StoredCommandState::ReleasePending,
                command: request.command.clone(),
                pending_contribution: Some(contribution.clone()),
            },
        )?;
        if !effect_exists(
            &transaction,
            &request.key,
            &request.action_id,
            &request.effect_id,
        )? {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(contribution)
    }

    fn complete_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        validate_remove_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing = load_command(
            &transaction,
            request.key.tenant_id.as_str(),
            request.command.request.idempotency_key.as_str(),
        )?
        .ok_or_else(PortError::conflict)?;
        if existing.command != request.command {
            return Err(PortError::conflict());
        }
        if existing.state == StoredCommandState::Completed {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing.command.resulting_snapshot);
        }
        let pending_contribution = existing
            .pending_contribution
            .ok_or_else(PortError::integrity_failure)?;
        let current = load_snapshot(&transaction, &request.key)?;
        let active = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .ok_or_else(PortError::integrity_failure)?;
        if active != &pending_contribution
            || current.generation != request.expected_generation
            || predict_issuance_freeze_remove(
                &current,
                &request.action_id,
                &request.effect_id,
                request.scheduler_fencing_token,
            )? != request.command.resulting_snapshot
        {
            return Err(PortError::integrity_failure());
        }
        let deleted = transaction
            .execute(
                r#"
                DELETE FROM security_issuance_freeze_effects
                WHERE tenant_id = ?1 AND lineage_id = ?2
                  AND action_id = ?3 AND effect_id = ?4
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.lineage_id.as_str(),
                    request.action_id.as_str(),
                    request.effect_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::integrity_failure());
        }
        persist_state(&transaction, &request.command.resulting_snapshot)?;
        let stored_snapshot = load_snapshot(&transaction, &request.key)?;
        if stored_snapshot != request.command.resulting_snapshot {
            return Err(PortError::integrity_failure());
        }
        persist_command(
            &transaction,
            &StoredCommand {
                state: StoredCommandState::Completed,
                command: request.command.clone(),
                pending_contribution: None,
            },
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored_snapshot)
    }

    fn load_issuance_freezes(
        &self,
        key: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>> {
        let connection = self.connection()?;
        let exists: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM security_issuance_freeze_state
                    WHERE tenant_id = ?1 AND lineage_id = ?2
                )
                "#,
                params![key.tenant_id.as_str(), key.lineage_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exists {
            return Ok(None);
        }
        Ok(Some(load_snapshot(&connection, key)?))
    }

    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision> {
        query
            .operation
            .validate_parent(query.parent_capability_id.as_ref())?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let key = IssuanceFreezeKey {
            tenant_id: query.tenant_id.clone(),
            lineage_id: query.lineage_id.clone(),
        };
        let snapshot = load_snapshot(&transaction, &key)?;
        let mut matches = Vec::new();
        for contribution in snapshot.contributions.as_slice() {
            if contribution.external_fence.expires_at_unix_ms <= trusted_now {
                return Err(PortError::unavailable());
            }
            if matches!(query.operation, CapabilityIssuanceOperation::Delegate) {
                let parent = query
                    .parent_capability_id
                    .as_ref()
                    .ok_or_else(PortError::invalid_data)?;
                if contribution
                    .frozen_affected_ids
                    .as_slice()
                    .binary_search(parent)
                    .is_err()
                    && parent.as_str() != query.lineage_id.as_str()
                {
                    return Err(PortError::integrity_failure());
                }
            }
            matches.push(IssuanceFreezeMatch {
                action_id: contribution.action_id.clone(),
                effect_id: contribution.effect_id.clone(),
                commit_index: contribution.commit_index,
                affected_set_hash: contribution.affected_set_hash,
                contribution_hash: contribution.contribution_hash,
                expires_at_unix_ms: contribution.expires_at_unix_ms,
            });
        }
        let active_matches =
            IssuanceFreezeMatches::new(matches).map_err(|_| PortError::integrity_failure())?;
        let decision = IssuanceFreezeAdmissionDecision {
            query: query.clone(),
            frozen: !active_matches.is_empty(),
            active_matches,
        };
        validate_issuance_freeze_admission_decision(query, &decision)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(decision)
    }

    fn load_issuance_freeze_operation(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus> {
        let connection = self.connection()?;
        let Some(stored) = load_command(
            &connection,
            query.tenant_id.as_str(),
            query.idempotency_key.as_str(),
        )?
        else {
            return Ok(IssuanceFreezeOperationStatus::NotExecuted);
        };
        if !effect_request_matches_query(&stored.command.request, query) {
            return Err(PortError::conflict());
        }
        match stored.state {
            StoredCommandState::ReleasePending => {
                Ok(IssuanceFreezeOperationStatus::ReleasePending {
                    contribution: Box::new(
                        stored
                            .pending_contribution
                            .ok_or_else(PortError::integrity_failure)?,
                    ),
                })
            }
            StoredCommandState::Completed => Ok(IssuanceFreezeOperationStatus::Completed {
                result: stored.command.result,
            }),
        }
    }

    fn load_pending_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
    ) -> PortResult<Option<IssuanceFreezePendingRelease>> {
        let connection = self.connection()?;
        load_pending_release(&connection, key, action_id, effect_id)
    }

    fn load_completed_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
        plan_hash: Digest32,
    ) -> PortResult<Option<IssuanceFreezeCommand>> {
        let connection = self.connection()?;
        load_completed_release(&connection, key, action_id, effect_id, plan_hash)
    }

    fn maintain_issuance_freeze_fence(
        &self,
        request: &IssuanceFreezeFenceMaintenanceRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        let work = &request.scheduler_work;
        let expected = &request.expected_external_fence;
        let maintained = &request.maintained_external_fence;
        if work.tenant_id != request.key.tenant_id
            || work.action_id != request.action_id
            || work.fencing_token == 0
            || maintained.tenant_id != request.key.tenant_id
            || maintained.action_id != request.action_id
            || maintained.commit_index != expected.commit_index
            || maintained.affected_set_hash != expected.affected_set_hash
            || maintained.scheduler_lease_owner_id != work.lease_owner_id
            || maintained.scheduler_fencing_token != work.fencing_token
            || maintained.expires_at_unix_ms == 0
        {
            return Err(PortError::invalid_data());
        }
        let same_scheduler_epoch = maintained.scheduler_lease_owner_id
            == expected.scheduler_lease_owner_id
            && maintained.scheduler_fencing_token == expected.scheduler_fencing_token
            && maintained.fencing_token == expected.fencing_token
            && maintained.expires_at_unix_ms >= expected.expires_at_unix_ms;
        let scheduler_takeover = maintained.scheduler_fencing_token
            > expected.scheduler_fencing_token
            && maintained.fencing_token > expected.fencing_token
            && maintained.expires_at_unix_ms >= expected.expires_at_unix_ms;
        if !same_scheduler_epoch && !scheduler_takeover {
            return Err(PortError::invalid_data());
        }

        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_lease_binding(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
            &work.lease_owner_id,
            work.fencing_token,
            trusted_now,
        )?;
        let current = load_snapshot(&transaction, &request.key)?;
        let position = current
            .contributions
            .as_slice()
            .iter()
            .position(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .ok_or_else(PortError::conflict)?;
        let current_contribution = &current.contributions.as_slice()[position];
        if current_contribution.external_fence == *maintained {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        if current_contribution.external_fence != *expected {
            return Err(PortError::conflict());
        }
        let mut contributions = current.contributions.clone().into_vec();
        contributions[position].external_fence = maintained.clone();
        validate_issuance_freeze_contribution(&request.key, &contributions[position])?;
        let next = IssuanceFreezeSnapshot {
            key: current.key.clone(),
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?,
            contributions: IssuanceFreezeContributions::new(contributions)
                .map_err(|_| PortError::integrity_failure())?,
            highest_scheduler_fencing_token: current
                .highest_scheduler_fencing_token
                .max(work.fencing_token),
        };
        validate_issuance_freeze_snapshot(&next, &request.key)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_issuance_freeze_effects
                SET external_fencing_token = ?9,
                    external_scheduler_lease_owner_id = ?10,
                    external_scheduler_fencing_token = ?11,
                    external_fence_expires_at = ?12,
                    installed_scheduler_fencing_token = ?13
                WHERE tenant_id = ?1 AND lineage_id = ?2
                  AND action_id = ?3 AND effect_id = ?4
                  AND external_fencing_token = ?5
                  AND external_scheduler_lease_owner_id = ?6
                  AND external_scheduler_fencing_token = ?7
                  AND external_fence_expires_at = ?8
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.lineage_id.as_str(),
                    request.action_id.as_str(),
                    request.effect_id.as_str(),
                    to_i64(expected.fencing_token)?,
                    expected.scheduler_lease_owner_id.as_str(),
                    to_i64(expected.scheduler_fencing_token)?,
                    to_i64(expected.expires_at_unix_ms)?,
                    to_i64(maintained.fencing_token)?,
                    maintained.scheduler_lease_owner_id.as_str(),
                    to_i64(maintained.scheduler_fencing_token)?,
                    to_i64(maintained.expires_at_unix_ms)?,
                    to_i64(work.fencing_token)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        persist_state(&transaction, &next)?;
        let stored = load_snapshot(&transaction, &request.key)?;
        if stored != next {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }
}
