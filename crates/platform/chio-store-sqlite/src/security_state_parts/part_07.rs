fn load_response_dispatch(
    connection: &Connection,
    key: &ResponseDispatchKey,
) -> PortResult<Option<ResponseDispatchRecord>> {
    type StoredDispatch = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
        i64,
        i64,
    );
    let stored: Option<StoredDispatch> = connection
        .query_row(
            r#"
            SELECT action_id, commit_mode, authorization_body, authorization_body_hash,
                   response_generation, response_state, response_body,
                   response_body_hash, response_due_at, initial_lease_owner_id,
                   initial_lease_expires_at, initial_fencing_token
            FROM security_response_dispatches
            WHERE tenant_id = ?1 AND dispatch_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.dispatch_id.as_str()],
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
    let Some((
        action_id,
        commit_mode,
        authorization_body,
        authorization_body_hash,
        response_generation,
        response_state,
        response_body,
        response_body_hash,
        response_due_at,
        initial_lease_owner_id,
        initial_lease_expires_at,
        initial_fencing_token,
    )) = stored
    else {
        return Ok(None);
    };
    let action_id = ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
    let authorization_body_hash = decode_digest(authorization_body_hash)?;
    let canonical_authorization =
        CanonicalBody::new(authorization_body).map_err(|_| PortError::integrity_failure())?;
    validate_canonical_json_body(&canonical_authorization, &authorization_body_hash)
        .map_err(|_| PortError::integrity_failure())?;
    let authorization_body: ResponseDispatchAuthorizationBody =
        serde_json::from_slice(canonical_authorization.as_bytes())
            .map_err(|_| PortError::integrity_failure())?;
    let response_body_hash = decode_digest(response_body_hash)?;
    let canonical_response =
        CanonicalBody::new(response_body).map_err(|_| PortError::integrity_failure())?;
    let response_plan = ResponsePlanRecord {
        tenant_id: key.tenant_id.clone(),
        action_id: action_id.clone(),
        generation: from_i64(response_generation)?,
        state: RecordId::new(response_state).map_err(|_| PortError::integrity_failure())?,
        canonical_body: canonical_response,
        body_hash: response_body_hash,
        due_at_unix_ms: Some(from_i64(response_due_at)?),
    };
    let initial_work = ScheduledWork {
        tenant_id: key.tenant_id.clone(),
        action_id,
        lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(initial_lease_owner_id)
            .map_err(|_| PortError::integrity_failure())?,
        lease_expires_at_unix_ms: from_i64(initial_lease_expires_at)?,
        fencing_token: from_i64(initial_fencing_token)?,
    };
    if initial_work.fencing_token == 0 {
        return Err(PortError::integrity_failure());
    }
    let record = ResponseDispatchRecord {
        authorization: ResponseDispatchAuthorization {
            body: authorization_body,
            canonical_body: canonical_authorization,
            body_hash: authorization_body_hash,
        },
        response_plan,
        initial_work,
    };
    let validation = ResponseDispatchCommitRequest {
        mode: parse_response_dispatch_commit_mode(&commit_mode)?,
        authorization: record.authorization.clone(),
        response_plan: record.response_plan.clone(),
        initial_lease: ResponseDispatchLease {
            lease_owner_id: record.initial_work.lease_owner_id.clone(),
            lease_expires_at_unix_ms: record.initial_work.lease_expires_at_unix_ms,
        },
    };
    validate_response_dispatch_request(&validation).map_err(|_| PortError::integrity_failure())?;
    if record.authorization.body.key != *key
        || record.authorization.body.action_id != record.initial_work.action_id
    {
        return Err(PortError::integrity_failure());
    }
    let current = load_response_plan(
        connection,
        key.tenant_id.as_str(),
        record.initial_work.action_id.as_str(),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    let current_snapshot =
        decode_response_snapshot(&current).map_err(|_| PortError::integrity_failure())?;
    if current.generation < record.response_plan.generation
        || current_snapshot.plan.plan_hash != record.authorization.body.plan_hash
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(record))
}

fn prepared_binding_from_response_dispatch(
    record: &ResponseDispatchRecord,
) -> PreparedActiveResponseDispatchBinding {
    prepared_binding_from_response_authorization(&record.authorization.body)
}

fn prepared_binding_from_response_authorization(
    authorization: &ResponseDispatchAuthorizationBody,
) -> PreparedActiveResponseDispatchBinding {
    PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: authorization.key.tenant_id.clone(),
        action_id: authorization.action_id.clone(),
        plan_hash: authorization.plan_hash,
        dispatch_id: authorization.key.dispatch_id.clone(),
        executor_authority_id: authorization.executor_authority_id.clone(),
        executor_authority_generation: authorization.executor_authority_generation,
        authorized_at_unix_ms: authorization.authorized_at_unix_ms,
        authorization_capability_hash: authorization.authorization_capability_hash,
        governed_intent_hash: authorization.governed_intent_hash,
        policy_decision_hash: authorization.policy_decision_hash,
        approval: authorization.approval.clone(),
    }
}

fn canonical_prepared_dispatch_binding(
    binding: &PreparedActiveResponseDispatchBinding,
) -> PortResult<(Vec<u8>, Digest32)> {
    let body = canonical_json_bytes(binding).map_err(|_| PortError::invalid_data())?;
    if body.len() > 1_048_576 {
        return Err(PortError::invalid_data());
    }
    let hash = Digest32::new(body_hash(&body));
    Ok((body, hash))
}

fn load_response_dispatch_for_identity(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &ActionId,
    dispatch_id: &RecordId,
) -> PortResult<Option<ResponseDispatchRecord>> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT dispatch_id
            FROM security_response_dispatches
            WHERE tenant_id = ?1 AND (action_id = ?2 OR dispatch_id = ?3)
            ORDER BY dispatch_id ASC
            "#,
        )
        .map_err(sqlite_error)?;
    let dispatch_ids = statement
        .query_map(
            params![tenant_id.as_str(), action_id.as_str(), dispatch_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if dispatch_ids.len() > 1 {
        return Err(PortError::integrity_failure());
    }
    let Some(stored_dispatch_id) = dispatch_ids.into_iter().next() else {
        return Ok(None);
    };
    let stored_dispatch_id =
        RecordId::new(stored_dispatch_id).map_err(|_| PortError::integrity_failure())?;
    load_response_dispatch(
        connection,
        &ResponseDispatchKey {
            tenant_id: tenant_id.clone(),
            dispatch_id: stored_dispatch_id,
        },
    )
}

fn load_automatic_response_dispatch_fence(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &ActionId,
    dispatch_id: &RecordId,
) -> PortResult<Option<AutomaticResponseDispatchFenceRecord>> {
    type StoredFence = (String, String, Vec<u8>, Vec<u8>, i64);
    let mut statement = connection
        .prepare(
            r#"
            SELECT dispatch_id, action_id, prepared_binding_body,
                   prepared_binding_hash, fenced_at
            FROM security_response_dispatch_fences
            WHERE tenant_id = ?1 AND (action_id = ?2 OR dispatch_id = ?3)
            ORDER BY dispatch_id ASC
            "#,
        )
        .map_err(sqlite_error)?;
    let stored = statement
        .query_map(
            params![tenant_id.as_str(), action_id.as_str(), dispatch_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<StoredFence>, _>>()
        .map_err(sqlite_error)?;
    if stored.len() > 1 {
        return Err(PortError::integrity_failure());
    }
    let Some((stored_dispatch_id, stored_action_id, body, stored_hash, fenced_at)) =
        stored.into_iter().next()
    else {
        return Ok(None);
    };
    let binding = serde_json::from_slice::<PreparedActiveResponseDispatchBinding>(&body)
        .map_err(|_| PortError::integrity_failure())?;
    validate_automatic_response_dispatch_fence_binding_shape(&binding)?;
    let (canonical_body, canonical_hash) = canonical_prepared_dispatch_binding(&binding)
        .map_err(|_| PortError::integrity_failure())?;
    if canonical_body != body
        || canonical_hash != decode_digest(stored_hash)?
        || &binding.tenant_id != tenant_id
        || binding.action_id.as_str() != stored_action_id.as_str()
        || binding.dispatch_id.as_str() != stored_dispatch_id.as_str()
    {
        return Err(PortError::integrity_failure());
    }
    let fenced_at_unix_ms = from_i64(fenced_at)?;
    if fenced_at_unix_ms == 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(AutomaticResponseDispatchFenceRecord {
        prepared_dispatch_binding: binding,
        binding_hash: canonical_hash,
        fenced_at_unix_ms,
    }))
}

fn validate_automatic_response_dispatch_fence_binding_shape(
    binding: &PreparedActiveResponseDispatchBinding,
) -> PortResult<()> {
    if binding.schema_version != PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION
        || binding.executor_authority_generation == 0
        || binding.authorized_at_unix_ms == 0
        || binding.plan_hash.is_zero()
        || binding.authorization_capability_hash.is_zero()
        || binding.governed_intent_hash.is_zero()
        || binding.policy_decision_hash.is_zero()
        || !matches!(&binding.approval, ResponseDispatchApproval::Automatic)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_all_automatic_response_dispatch_fences(connection: &Connection) -> PortResult<()> {
    type StoredFenceIdentity = (String, String, String);
    let mut statement = connection
        .prepare(
            r#"
            SELECT tenant_id, action_id, dispatch_id
            FROM security_response_dispatch_fences
            ORDER BY tenant_id ASC, action_id ASC, dispatch_id ASC
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;
    let identities = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|_| PortError::integrity_failure())?
        .collect::<Result<Vec<StoredFenceIdentity>, _>>()
        .map_err(|_| PortError::integrity_failure())?;
    drop(statement);
    for (tenant_id, action_id, dispatch_id) in identities {
        let tenant_id = TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?;
        let action_id = ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
        let dispatch_id = RecordId::new(dispatch_id).map_err(|_| PortError::integrity_failure())?;
        if load_automatic_response_dispatch_fence(connection, &tenant_id, &action_id, &dispatch_id)?
            .is_none()
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(())
}

fn load_response_dispatch_commit_mode(
    connection: &Connection,
    key: &ResponseDispatchKey,
) -> PortResult<Option<ResponseDispatchCommitMode>> {
    connection
        .query_row(
            "SELECT commit_mode FROM security_response_dispatches WHERE tenant_id = ?1 AND dispatch_id = ?2",
            params![key.tenant_id.as_str(), key.dispatch_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|value| parse_response_dispatch_commit_mode(&value))
        .transpose()
}

const fn response_dispatch_commit_mode(mode: ResponseDispatchCommitMode) -> &'static str {
    match mode {
        ResponseDispatchCommitMode::Fresh => "fresh",
        ResponseDispatchCommitMode::GovernedCommittedResume => "governed_committed_resume",
        ResponseDispatchCommitMode::GovernedCommittedExpiredResume => {
            "governed_committed_expired_resume"
        }
    }
}

fn parse_response_dispatch_commit_mode(value: &str) -> PortResult<ResponseDispatchCommitMode> {
    match value {
        "fresh" => Ok(ResponseDispatchCommitMode::Fresh),
        "governed_committed_resume" => Ok(ResponseDispatchCommitMode::GovernedCommittedResume),
        "governed_committed_expired_resume" => {
            Ok(ResponseDispatchCommitMode::GovernedCommittedExpiredResume)
        }
        _ => Err(PortError::integrity_failure()),
    }
}

fn load_response_dispatch_recovery(
    connection: &Connection,
    request: &ResponseDispatchRecoveryRequest,
    request_hash: &[u8; 32],
) -> PortResult<Option<ResponseDispatchRecoveryOutcome>> {
    type StoredRecovery = (String, String, String, Vec<u8>, String, String, i64, i64);
    let stored: Option<StoredRecovery> = connection
        .query_row(
            r#"
            SELECT dispatch_id, action_id, recovery_id, request_hash, outcome,
                   lease_owner_id, lease_expires_at, fencing_token
            FROM security_response_dispatch_recoveries
            WHERE tenant_id = ?1 AND recovery_id = ?2
            "#,
            params![request.key.tenant_id.as_str(), request.recovery_id.as_str()],
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
    let Some((
        dispatch_id,
        action_id,
        recovery_id,
        stored_hash,
        outcome,
        lease_owner_id,
        lease_expires_at,
        fencing_token,
    )) = stored
    else {
        return Ok(None);
    };
    if dispatch_id != request.key.dispatch_id.as_str()
        || action_id != request.action_id.as_str()
        || recovery_id != request.recovery_id.as_str()
        || stored_hash.as_slice() != request_hash
    {
        return Err(PortError::conflict());
    }
    let work = ScheduledWork {
        tenant_id: request.key.tenant_id.clone(),
        action_id: request.action_id.clone(),
        lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(lease_owner_id)
            .map_err(|_| PortError::integrity_failure())?,
        lease_expires_at_unix_ms: from_i64(lease_expires_at)?,
        fencing_token: from_i64(fencing_token)?,
    };
    if work.lease_owner_id != request.lease_owner_id {
        return Err(PortError::integrity_failure());
    }
    let outcome = match outcome.as_str() {
        "live_lease"
            if request
                .expected_fencing_token
                .is_none_or(|expected| expected == work.fencing_token) =>
        {
            ResponseDispatchRecoveryOutcome::LiveLease(work)
        }
        "takeover"
            if request
                .expected_fencing_token
                .is_none_or(|expected| work.fencing_token > expected) =>
        {
            ResponseDispatchRecoveryOutcome::Takeover(work)
        }
        "live_lease" | "takeover" => return Err(PortError::integrity_failure()),
        _ => return Err(PortError::integrity_failure()),
    };
    Ok(Some(outcome))
}

fn record_response_dispatch_recovery(
    transaction: &Transaction<'_>,
    request: &ResponseDispatchRecoveryRequest,
    request_hash: &[u8; 32],
    outcome: &ResponseDispatchRecoveryOutcome,
) -> PortResult<()> {
    let (outcome_name, work, fencing_is_bound) = match outcome {
        ResponseDispatchRecoveryOutcome::LiveLease(work) => (
            "live_lease",
            work,
            request
                .expected_fencing_token
                .is_none_or(|expected| expected == work.fencing_token),
        ),
        ResponseDispatchRecoveryOutcome::Takeover(work) => (
            "takeover",
            work,
            request
                .expected_fencing_token
                .is_none_or(|expected| work.fencing_token > expected),
        ),
    };
    if work.tenant_id != request.key.tenant_id
        || work.action_id != request.action_id
        || work.lease_owner_id != request.lease_owner_id
        || !fencing_is_bound
    {
        return Err(PortError::integrity_failure());
    }
    transaction
        .execute(
            r#"
            INSERT INTO security_response_dispatch_recoveries (
                recovery_id, tenant_id, dispatch_id, action_id, request_hash,
                outcome, lease_owner_id, lease_expires_at, fencing_token
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                request.recovery_id.as_str(),
                request.key.tenant_id.as_str(),
                request.key.dispatch_id.as_str(),
                request.action_id.as_str(),
                request_hash.as_slice(),
                outcome_name,
                work.lease_owner_id.as_str(),
                to_i64(work.lease_expires_at_unix_ms)?,
                to_i64(work.fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn load_response_plan(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<ResponsePlanRecord>> {
    type StoredPlan = (String, i64, String, Vec<u8>, Vec<u8>, Option<i64>);
    let stored: Option<StoredPlan> = connection
        .query_row(
            r#"
            SELECT tenant_id, generation, state, body, body_hash, due_at
            FROM security_response_plans WHERE tenant_id = ?1 AND action_id = ?2
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
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(tenant_id, generation, state, body, stored_hash, due_at)| {
                let body_hash = decode_digest(stored_hash)?;
                let canonical_body =
                    CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
                validate_canonical_json_body(&canonical_body, &body_hash)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(ResponsePlanRecord {
                    tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    generation: from_i64(generation)?,
                    state: RecordId::new(state).map_err(|_| PortError::integrity_failure())?,
                    canonical_body,
                    body_hash,
                    due_at_unix_ms: due_at.map(from_i64).transpose()?,
                })
            },
        )
        .transpose()
}

fn load_response_receipt_cursor(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<ResponseReceiptCursor>> {
    type StoredCursor = (String, String, Vec<u8>, i64, String);
    let stored: Option<StoredCursor> = connection
        .query_row(
            r#"
            SELECT tenant_id, action_id, plan_hash, generation, current_evidence_id
            FROM security_response_receipt_cursors
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(tenant_id, action_id, plan_hash, generation, current_evidence_id)| {
                Ok(ResponseReceiptCursor {
                    tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    plan_hash: decode_digest(plan_hash)?,
                    generation: from_i64(generation)?,
                    current_evidence_id: OpaqueReceiptRef::new(current_evidence_id)
                        .map_err(|_| PortError::integrity_failure())?,
                })
            },
        )
        .transpose()
}

fn load_response_effect(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<ResponseEffectRecord>> {
    type StoredEffect = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
    );
    let stored: Option<StoredEffect> = connection
        .query_row(
            r#"
            SELECT tenant_id, action_id, effect_id, generation, scheduler_lease_owner_id,
                   scheduler_fencing_token, state, body, body_hash, encrypted_rollback_ref
            FROM security_response_effects WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
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
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                tenant_id,
                action_id,
                effect_id,
                generation,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                state,
                body,
                stored_hash,
                encrypted_rollback_ref,
            )| {
                let body_hash = decode_digest(stored_hash)?;
                let canonical_body =
                    CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
                validate_canonical_json_body(&canonical_body, &body_hash)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(ResponseEffectRecord {
                    tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    effect_id: EffectId::new(effect_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    generation: from_i64(generation)?,
                    scheduler_lease_owner_id: LeaseOwnerId::new(scheduler_lease_owner_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    scheduler_fencing_token: from_i64(scheduler_fencing_token)?,
                    state: RecordId::new(state).map_err(|_| PortError::integrity_failure())?,
                    canonical_body,
                    body_hash,
                    encrypted_rollback_ref: encrypted_rollback_ref
                        .map(RecordId::new)
                        .transpose()
                        .map_err(|_| PortError::integrity_failure())?,
                })
            },
        )
        .transpose()
}

fn validate_scheduler_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
    fencing_token: u64,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    let tenant_id = TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?;
    let stored =
        load_valid_scheduler_lease(connection, &tenant_id, action_id, trusted_now_unix_ms, true)?;
    let Some(stored) = stored else {
        return Err(PortError::invalid_data());
    };
    if stored.fencing_token != fencing_token {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn validate_scheduler_lease_binding(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
    lease_owner_id: &LeaseOwnerId,
    fencing_token: u64,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    let tenant_id = TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?;
    let stored =
        load_valid_scheduler_lease(connection, &tenant_id, action_id, trusted_now_unix_ms, true)?;
    let Some(stored) = stored else {
        return Err(PortError::invalid_data());
    };
    if stored.lease_owner_id != *lease_owner_id || stored.fencing_token != fencing_token {
        return Err(PortError::conflict());
    }
    Ok(())
}

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
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
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
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
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
struct ContainmentCommandContributionBody {
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
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    let canonical =
        canonical_json_bytes(&contribution).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

type StoredEffectCommandProjection = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

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
                let request: EffectRequest = serde_json::from_slice(&request_body)
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
                let result: EffectResult = serde_json::from_slice(&result_body)
                    .map_err(|_| PortError::integrity_failure())?;
                let canonical_result =
                    canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?;
                let snapshot_hash = decode_digest(snapshot_hash)?;
                if body_hash(&snapshot_body).as_slice() != snapshot_hash.as_bytes() {
                    return Err(PortError::integrity_failure());
                }
                let resulting_snapshot: OverlaySnapshot = serde_json::from_slice(&snapshot_body)
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

fn load_overlay_snapshot(
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

fn validate_stored_session_throttle_command(command: &SessionThrottleCommand) -> PortResult<()> {
    validate_session_throttle_command_common(command).map_err(|_| PortError::integrity_failure())
}

fn validate_session_throttle_apply_command(
    request: &SessionThrottleApplyRequest,
) -> PortResult<()> {
    validate_session_throttle_command_common(&request.command)?;
    let command = &request.command.request;
    let key = session_throttle_command_key(command)?;
    let limits = decode_session_throttle_limits(command)?;
    if key != request.key
        || command.action_id != request.action_id
        || command.effect_id != request.contribution.effect_id
        || command.operation != EffectOperation::Apply
        || command.plan_expires_at_unix_ms != request.contribution.expires_at_unix_ms
        || command.contribution_hash != request.contribution.contribution_hash
        || command.scheduler_fencing_token != request.scheduler_fencing_token
        || limits != request.contribution.limits
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_session_throttle_remove_command(
    request: &SessionThrottleRemoveRequest,
) -> PortResult<()> {
    validate_session_throttle_command_common(&request.command)?;
    let command = &request.command.request;
    let key = session_throttle_command_key(command)?;
    if key != request.key
        || command.action_id != request.action_id
        || command.effect_id != request.effect_id
        || command.operation != EffectOperation::Remove
        || command.scheduler_fencing_token != request.scheduler_fencing_token
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_session_throttle_command_common(command: &SessionThrottleCommand) -> PortResult<()> {
    let request = &command.request;
    if request.effect_kind != ResponseEffectKind::ThrottleSession
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
    let limits = decode_session_throttle_limits(request)?;
    limits.validate()?;
    let key = session_throttle_command_key(request)?;
    validate_session_throttle_snapshot(&command.resulting_snapshot, &key)?;
    let contribution = SessionThrottleContribution {
        effect_id: request.effect_id.clone(),
        limits,
        contribution_hash: request.contribution_hash,
        expires_at_unix_ms: request.plan_expires_at_unix_ms,
    };
    match request.operation {
        EffectOperation::Apply => {
            if session_throttle_installed_version_hash(&key, &contribution)?
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
            if session_throttle_installed_version_hash(&key, &contribution)?
                != request.expected_version_hash
                || session_throttle_version_hash(&command.resulting_snapshot)?
                    != command.result.resulting_version_hash
                || command
                    .resulting_snapshot
                    .contributions
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

fn session_throttle_command_key(request: &EffectRequest) -> PortResult<SessionThrottleKey> {
    let ResponseTarget::Session { session_id } = &request.target else {
        return Err(PortError::invalid_data());
    };
    Ok(SessionThrottleKey {
        tenant_id: request.tenant_id.clone(),
        session_id: session_id.clone(),
    })
}

fn decode_session_throttle_limits(request: &EffectRequest) -> PortResult<SessionThrottleLimits> {
    validate_canonical_json_body(&request.canonical_contribution, &request.contribution_hash)?;
    let limits: SessionThrottleLimits =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    limits.validate()?;
    let canonical = canonical_json_bytes(&limits).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(limits)
}

fn load_session_throttle_command(
    connection: &Connection,
    tenant_id: &str,
    idempotency_key: &str,
) -> PortResult<Option<SessionThrottleCommand>> {
    let stored: Option<StoredEffectCommandProjection> = connection
        .query_row(
            r#"
            SELECT request_body, request_body_hash, result_body, result_body_hash,
                   resulting_snapshot_body, resulting_snapshot_body_hash
            FROM security_session_throttle_commands
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
                let resulting_snapshot: SessionThrottleSnapshot =
                    serde_json::from_slice(&snapshot_body)
                        .map_err(|_| PortError::integrity_failure())?;
                let canonical_request =
                    canonical_json_bytes(&request).map_err(|_| PortError::integrity_failure())?;
                let canonical_result =
                    canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?;
                let canonical_snapshot = canonical_json_bytes(&resulting_snapshot)
                    .map_err(|_| PortError::integrity_failure())?;
                if canonical_request.as_slice() != request_body.as_slice()
                    || canonical_result.as_slice() != result_body.as_slice()
                    || canonical_snapshot.as_slice() != snapshot_body.as_slice()
                    || request.tenant_id.as_str() != tenant_id
                    || request.idempotency_key.as_str() != idempotency_key
                {
                    return Err(PortError::integrity_failure());
                }
                Ok(SessionThrottleCommand {
                    request,
                    result,
                    resulting_snapshot,
                })
            },
        )
        .transpose()
}

fn persist_session_throttle_command(
    transaction: &Transaction<'_>,
    command: &SessionThrottleCommand,
) -> PortResult<()> {
    if let Some(existing) = load_session_throttle_command(
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
            INSERT INTO security_session_throttle_commands (
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

fn load_session_throttle_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(String, String)>> {
    connection
        .query_row(
            r#"
            SELECT session_id, action_id FROM security_session_throttle_effects
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn load_session_throttle_snapshot(
    connection: &Connection,
    key: &SessionThrottleKey,
) -> PortResult<SessionThrottleSnapshot> {
    let state: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT generation, highest_fencing_token
            FROM security_session_throttle_state
            WHERE tenant_id = ?1 AND session_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.session_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let state_exists = state.is_some();
    let (generation, highest_fencing_token) = state.unwrap_or((0, 0));
    let mut statement = connection
        .prepare(
            r#"
            SELECT effect_id, action_id, window_ms, max_invocations,
                   contribution_hash, expires_at, installed_fencing_token
            FROM security_session_throttle_effects
            WHERE tenant_id = ?1 AND session_id = ?2
            ORDER BY effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![key.tenant_id.as_str(), key.session_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut contributions = Vec::new();
    let mut highest_installed_fencing_token = 0_u64;
    for row in rows {
        let (
            effect_id,
            action_id,
            window_ms,
            max_invocations,
            contribution_hash,
            expires_at,
            installed_fencing_token,
        ) = row.map_err(sqlite_error)?;
        ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?;
        highest_installed_fencing_token =
            highest_installed_fencing_token.max(from_i64(installed_fencing_token)?);
        let limits = SessionThrottleLimits {
            window_ms: from_i64(window_ms)?,
            max_invocations: u32::try_from(max_invocations)
                .map_err(|_| PortError::integrity_failure())?,
        };
        limits
            .validate()
            .map_err(|_| PortError::integrity_failure())?;
        contributions.push(SessionThrottleContribution {
            effect_id: EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?,
            limits,
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms: from_i64(expires_at)?,
        });
    }
    if !state_exists && !contributions.is_empty() {
        return Err(PortError::integrity_failure());
    }
    let snapshot = SessionThrottleSnapshot {
        key: key.clone(),
        generation: from_i64(generation)?,
        contributions: SessionThrottleContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: from_i64(highest_fencing_token)?,
    };
    validate_session_throttle_snapshot(&snapshot, key)?;
    if snapshot.highest_fencing_token < highest_installed_fencing_token {
        return Err(PortError::integrity_failure());
    }
    Ok(snapshot)
}

fn persist_session_throttle_state(
    transaction: &Transaction<'_>,
    key: &SessionThrottleKey,
    generation: u64,
    fencing_token: u64,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_session_throttle_state (
                tenant_id, session_id, generation, highest_fencing_token
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, session_id) DO UPDATE SET
                generation = excluded.generation,
                highest_fencing_token = excluded.highest_fencing_token
            "#,
            params![
                key.tenant_id.as_str(),
                key.session_id.as_str(),
                to_i64(generation)?,
                to_i64(fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
