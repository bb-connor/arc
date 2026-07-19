fn load_scheduler_retry(
    connection: &Connection,
    key: &SchedulerWorkKey,
) -> PortResult<Option<SchedulerRetryState>> {
    type StoredRetry = (i64, String, i64, i64, Option<String>, i64);
    let stored: Option<StoredRetry> = connection
        .query_row(
            r#"
            SELECT attempts, last_error, first_failure_at, not_before,
                   health_event_id, health_event_delivered
            FROM security_scheduler_retries
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.action_id.as_str()],
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
                attempts,
                last_error,
                first_failure_at,
                not_before,
                health_event_id,
                health_event_delivered,
            )| {
                let health_event_delivered = match health_event_delivered {
                    0 => false,
                    1 => true,
                    _ => return Err(PortError::integrity_failure()),
                };
                let health_event_id = health_event_id
                    .map(RecordId::new)
                    .transpose()
                    .map_err(|_| PortError::integrity_failure())?;
                if health_event_delivered && health_event_id.is_none() {
                    return Err(PortError::integrity_failure());
                }
                Ok(SchedulerRetryState {
                    key: key.clone(),
                    attempts: u32::try_from(from_i64(attempts)?)
                        .map_err(|_| PortError::integrity_failure())?,
                    last_error: ErrorCode::new(last_error)
                        .map_err(|_| PortError::integrity_failure())?,
                    first_failure_at_unix_ms: from_i64(first_failure_at)?,
                    not_before_unix_ms: from_i64(not_before)?,
                    health_event_id,
                    health_event_delivered,
                })
            },
        )
        .transpose()
}

fn load_scheduler_lease(
    connection: &Connection,
    key: &SchedulerWorkKey,
) -> PortResult<Option<ScheduledWork>> {
    type StoredLease = (String, String, i64, i64);
    let stored: Option<StoredLease> = connection
        .query_row(
            r#"
            SELECT action_id, lease_owner_id, lease_expires_at, fencing_token
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.action_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(action_id, lease_owner_id, lease_expires_at, fencing_token)| {
                Ok(ScheduledWork {
                    tenant_id: key.tenant_id.clone(),
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(lease_owner_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    lease_expires_at_unix_ms: from_i64(lease_expires_at)?,
                    fencing_token: from_i64(fencing_token)?,
                })
            },
        )
        .transpose()
}

fn validate_scheduler_work(
    connection: &Connection,
    work: &ScheduledWork,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    let stored = load_scheduler_lease(
        connection,
        &SchedulerWorkKey {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
        },
    )?
    .ok_or_else(PortError::conflict)?;
    if stored != *work || stored.lease_expires_at_unix_ms <= trusted_now_unix_ms {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn delete_scheduler_lease(connection: &Connection, work: &ScheduledWork) -> PortResult<()> {
    let deleted = connection
        .execute(
            r#"
            DELETE FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2 AND lease_owner_id = ?3
              AND lease_expires_at = ?4 AND fencing_token = ?5
            "#,
            params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                work.lease_owner_id.as_str(),
                to_i64(work.lease_expires_at_unix_ms)?,
                to_i64(work.fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    if deleted != 1 {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn load_scheduler_claim(
    connection: &Connection,
    request: &SchedulerClaimRequest,
    request_hash: &[u8; 32],
    trusted_now: u64,
) -> PortResult<Option<Vec<ScheduledWork>>> {
    type StoredClaim = (Vec<u8>, String, i64, i64);
    let stored: Option<StoredClaim> = connection
        .query_row(
            r#"
            SELECT request_hash, lease_owner_id, lease_expires_at, result_count
            FROM security_scheduler_claims
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            params![request.tenant_id.as_str(), request.claim_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((stored_hash, stored_owner, stored_expiry, stored_count)) = stored else {
        return Ok(None);
    };
    let stored_expiry = from_i64(stored_expiry)?;
    if stored_hash.as_slice() != request_hash
        || stored_owner != request.lease_owner_id.as_str()
        || stored_expiry != request.lease_expires_at_unix_ms
    {
        return Err(PortError::conflict());
    }
    if stored_expiry <= trusted_now {
        return Err(PortError::conflict());
    }
    let expected_count =
        usize::try_from(from_i64(stored_count)?).map_err(|_| PortError::integrity_failure())?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT action_id, lease_owner_id, lease_expires_at, fencing_token
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND claim_id = ?2
            ORDER BY claim_ordinal
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![request.tenant_id.as_str(), request.claim_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut claimed = Vec::with_capacity(expected_count);
    for row in rows {
        let (action_id, lease_owner_id, lease_expires_at, fencing_token) =
            row.map_err(sqlite_error)?;
        if lease_owner_id != request.lease_owner_id.as_str()
            || from_i64(lease_expires_at)? != request.lease_expires_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        claimed.push(ScheduledWork {
            tenant_id: request.tenant_id.clone(),
            action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
            lease_owner_id: request.lease_owner_id.clone(),
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            fencing_token: from_i64(fencing_token)?,
        });
    }
    if claimed.len() != expected_count {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(claimed))
}

fn next_scheduler_fencing_token(transaction: &Transaction<'_>, tenant_id: &str) -> PortResult<u64> {
    let sequence_token: Option<i64> = transaction
        .query_row(
            "SELECT last_fencing_token FROM security_scheduler_fence_sequences WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let lease_token: Option<i64> = transaction
        .query_row(
            "SELECT MAX(fencing_token) FROM security_scheduler_leases WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = sequence_token
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(lease_token.map(from_i64).transpose()?.unwrap_or(0));
    let next = current
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_scheduler_fence_sequences (tenant_id, last_fencing_token)
            VALUES (?1, ?2)
            ON CONFLICT (tenant_id) DO UPDATE SET
                last_fencing_token = excluded.last_fencing_token
            "#,
            params![tenant_id, to_i64(next)?],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn decode_response_snapshot(record: &ResponsePlanRecord) -> PortResult<ResponseSnapshot> {
    validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
    let snapshot: ResponseSnapshot = serde_json::from_slice(record.canonical_body.as_bytes())
        .map_err(|_| PortError::invalid_data())?;
    if snapshot.schema_version != RESPONSE_STATE_SCHEMA_VERSION
        || snapshot.plan.tenant_id != record.tenant_id
        || snapshot.plan.action_id != record.action_id
        || snapshot.generation != record.generation
        || snapshot.state.as_str() != record.state.as_str()
        || snapshot.due_at_unix_ms != record.due_at_unix_ms
        || snapshot.plan.validate_shape().is_err()
        || snapshot
            .execution_dispatch
            .as_ref()
            .is_some_and(|binding| binding.validate_for_plan(&snapshot.plan).is_err())
        || match (
            &snapshot.execution_dispatch,
            &snapshot.dispatch_authorization_hash,
        ) {
            (None, None) => false,
            (Some(_), Some(hash)) => hash.as_bytes().iter().all(|byte| *byte == 0),
            _ => true,
        }
    {
        return Err(PortError::invalid_data());
    }
    validate_response_snapshot_lifecycle(&snapshot, false)
        .map_err(|_| PortError::invalid_data())?;
    Ok(snapshot)
}

fn response_mutation_scheduler_fence(
    mutation: &ResponseMutationRecord,
) -> PortResult<(Option<&LeaseOwnerId>, Option<u64>)> {
    match mutation {
        ResponseMutationRecord::Requested(_) => Err(PortError::invalid_data()),
        ResponseMutationRecord::Transition(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::EffectRequested(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            Some(record.scheduler_fencing_token),
        )),
        ResponseMutationRecord::EffectApplied(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            Some(record.scheduler_fencing_token),
        )),
        ResponseMutationRecord::EffectFailed(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            Some(record.scheduler_fencing_token),
        )),
        ResponseMutationRecord::Rollback(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            Some(record.scheduler_fencing_token),
        )),
        ResponseMutationRecord::Failed(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::Final(record) => Ok((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
    }
}

fn validate_initial_dispatch_history(
    snapshot: &ResponseSnapshot,
    authorization: &ResponseDispatchAuthorizationBody,
) -> PortResult<()> {
    let lease_expires_at_unix_ms = snapshot
        .applying_lease_expires_at_unix_ms
        .ok_or_else(PortError::invalid_data)?;
    let valid = match (&authorization.approval, snapshot.mutations.as_slice()) {
        (
            ResponseDispatchApproval::Automatic,
            [ResponseMutationRecord::Requested(requested), ResponseMutationRecord::Transition(applying)],
        ) => {
            snapshot.generation == 1
                && requested.generation == 0
                && requested.occurred_at_unix_ms == snapshot.plan.created_at_unix_ms
                && applying.generation == 1
                && applying.from_state == ResponseState::Planned
                && applying.to_state == ResponseState::Applying
                && applying.cause == ResponseTransitionCause::ApplyStarted
                && applying.applying_lease_expires_at_unix_ms == Some(lease_expires_at_unix_ms)
                && applying.scheduler_lease_owner_id.is_none()
                && applying.scheduler_fencing_token.is_none()
                && applying.occurred_at_unix_ms == authorization.authorized_at_unix_ms
                && requested.transition_id != applying.transition_id
        }
        (
            ResponseDispatchApproval::Governed {
                admission_operation_version,
                ..
            },
            [ResponseMutationRecord::Requested(requested), ResponseMutationRecord::Transition(awaiting), ResponseMutationRecord::Transition(applying)],
        ) => {
            *admission_operation_version > 0
                && snapshot.generation == 2
                && requested.generation == 0
                && requested.occurred_at_unix_ms == snapshot.plan.created_at_unix_ms
                && awaiting.generation == 1
                && awaiting.from_state == ResponseState::Planned
                && awaiting.to_state == ResponseState::AwaitingApproval
                && awaiting.cause == ResponseTransitionCause::ApprovalRequested
                && awaiting.applying_lease_expires_at_unix_ms.is_none()
                && awaiting.scheduler_lease_owner_id.is_none()
                && awaiting.scheduler_fencing_token.is_none()
                && awaiting.occurred_at_unix_ms == snapshot.plan.created_at_unix_ms
                && applying.generation == 2
                && applying.from_state == ResponseState::AwaitingApproval
                && applying.to_state == ResponseState::Applying
                && applying.cause == ResponseTransitionCause::ApprovalSatisfied
                && applying.applying_lease_expires_at_unix_ms == Some(lease_expires_at_unix_ms)
                && applying.scheduler_lease_owner_id.is_none()
                && applying.scheduler_fencing_token.is_none()
                && applying.occurred_at_unix_ms == authorization.authorized_at_unix_ms
                && requested.transition_id != awaiting.transition_id
                && requested.transition_id != applying.transition_id
                && awaiting.transition_id != applying.transition_id
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(PortError::invalid_data())
    }
}

fn validate_response_dispatch_request(
    request: &ResponseDispatchCommitRequest,
) -> PortResult<ResponseSnapshot> {
    validate_canonical_json_body(
        &request.authorization.canonical_body,
        &request.authorization.body_hash,
    )?;
    let decoded_authorization: ResponseDispatchAuthorizationBody =
        serde_json::from_slice(request.authorization.canonical_body.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    if decoded_authorization != request.authorization.body
        || decoded_authorization.schema_version != RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION
        || decoded_authorization.key.tenant_id != request.response_plan.tenant_id
        || decoded_authorization.action_id != request.response_plan.action_id
        || decoded_authorization.executor_authority_generation == 0
    {
        return Err(PortError::invalid_data());
    }
    let snapshot = decode_response_snapshot(&request.response_plan)?;
    let mut normalized_snapshot = snapshot.clone();
    normalized_snapshot.dispatch_authorization_hash = None;
    let normalized_bytes = canonical_json_bytes(&normalized_snapshot)
        .map_err(|_| PortError::invalid_data())?;
    let normalized_body_hash = Digest32::new(*sha256(&normalized_bytes).as_bytes());
    let execution_dispatch = snapshot
        .execution_dispatch
        .as_ref()
        .ok_or_else(PortError::invalid_data)?;
    execution_dispatch
        .validate_for_plan(&snapshot.plan)
        .map_err(|_| PortError::invalid_data())?;
    if snapshot.state != ResponseState::Applying
        || snapshot.operator_page_required
        || snapshot.applying_lease_expires_at_unix_ms
            != Some(request.initial_lease.lease_expires_at_unix_ms)
        || snapshot.due_at_unix_ms != Some(request.initial_lease.lease_expires_at_unix_ms)
        || snapshot.plan.plan_hash != decoded_authorization.plan_hash
        || snapshot.dispatch_authorization_hash != Some(request.authorization.body_hash)
        || decoded_authorization.response_body_hash != normalized_body_hash
        || snapshot.plan.operator_capability.capability_digest
            != decoded_authorization.authorization_capability_hash
        || decoded_authorization.authorized_at_unix_ms < snapshot.plan.created_at_unix_ms
        || decoded_authorization.authorized_at_unix_ms >= snapshot.plan.expires_at_unix_ms
        || request.initial_lease.lease_expires_at_unix_ms
            <= decoded_authorization.authorized_at_unix_ms
        || request.initial_lease.lease_expires_at_unix_ms > snapshot.plan.expires_at_unix_ms
        || execution_dispatch.dispatch_id != decoded_authorization.key.dispatch_id
        || execution_dispatch.executor_authority_id
            != decoded_authorization.executor_authority_id
        || execution_dispatch.executor_authority_generation
            != decoded_authorization.executor_authority_generation
        || execution_dispatch.authorization_capability_hash
            != decoded_authorization.authorization_capability_hash
        || execution_dispatch.governed_intent_hash
            != decoded_authorization.governed_intent_hash
        || execution_dispatch.policy_decision_hash
            != decoded_authorization.policy_decision_hash
        || execution_dispatch.approval != decoded_authorization.approval
        || execution_dispatch.authorized_at_unix_ms
            != decoded_authorization.authorized_at_unix_ms
    {
        return Err(PortError::invalid_data());
    }
    match (
        &snapshot.plan.approval_requirement,
        &decoded_authorization.approval,
    ) {
        (ResponseApprovalRequirement::Automatic, ResponseDispatchApproval::Automatic)
        | (
            ResponseApprovalRequirement::Governed { .. },
            ResponseDispatchApproval::Governed { .. },
        ) => {}
        _ => return Err(PortError::invalid_data()),
    }
    if matches!(
        request.mode,
        ResponseDispatchCommitMode::GovernedCommittedResume
            | ResponseDispatchCommitMode::GovernedCommittedExpiredResume
    )
        && !matches!(
            (
                &snapshot.plan.approval_requirement,
                &decoded_authorization.approval,
            ),
            (
                ResponseApprovalRequirement::Governed { .. },
                ResponseDispatchApproval::Governed { .. }
            )
        )
    {
        return Err(PortError::invalid_data());
    }
    validate_initial_dispatch_history(&snapshot, &decoded_authorization)?;
    Ok(snapshot)
}
