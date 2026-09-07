fn load_valid_scheduler_lease(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &str,
    trusted_now: u64,
    expected_live: bool,
) -> PortResult<Option<ScheduledWork>> {
    type StoredLease = (String, i64, String, i64, i64, Vec<u8>);
    let stored: Option<StoredLease> = connection
        .query_row(
            r#"
            SELECT claim_id, claim_ordinal, lease_owner_id,
                   lease_expires_at, fencing_token, lease_body_hash
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id.as_str(), action_id],
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
    let Some((
        claim_id,
        claim_ordinal_sql,
        lease_owner_id,
        lease_expires_at,
        fencing_token,
        stored_body_hash,
    )) = stored
    else {
        return Ok(None);
    };
    let claim_id = RecordId::new(claim_id).map_err(|_| PortError::integrity_failure())?;
    let claim_ordinal = from_i64(claim_ordinal_sql)?;
    let work = ScheduledWork {
        tenant_id: tenant_id.clone(),
        action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
        lease_owner_id: LeaseOwnerId::new(lease_owner_id)
            .map_err(|_| PortError::integrity_failure())?,
        lease_expires_at_unix_ms: from_i64(lease_expires_at)?,
        fencing_token: from_i64(fencing_token)?,
    };
    if work.lease_expires_at_unix_ms == 0 || work.fencing_token == 0 {
        return Err(PortError::integrity_failure());
    }
    let expected_body_hash = scheduler_lease_body_hash(
        work.tenant_id.as_str(),
        work.action_id.as_str(),
        claim_id.as_str(),
        claim_ordinal,
        work.lease_owner_id.as_str(),
        work.lease_expires_at_unix_ms,
        work.fencing_token,
    )?;
    if stored_body_hash.as_slice() != expected_body_hash.as_slice() {
        return Err(PortError::integrity_failure());
    }

    let scheduler_claim: Option<(String, i64, i64, i64)> = connection
        .query_row(
            r#"
            SELECT lease_owner_id, lease_expires_at, result_count, committed_at
            FROM security_scheduler_claims
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            params![tenant_id.as_str(), claim_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let mut valid_origins = 0_u8;
    if let Some((claim_owner_id, claim_expires_at, result_count, committed_at)) = scheduler_claim {
        let matching_claim_ordinal_rows = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM security_scheduler_leases
                WHERE tenant_id = ?1 AND claim_id = ?2 AND claim_ordinal = ?3
                "#,
                params![tenant_id.as_str(), claim_id.as_str(), claim_ordinal_sql],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?;
        let valid = claim_owner_id == work.lease_owner_id.as_str()
            && claim_expires_at > 0
            && claim_expires_at <= lease_expires_at
            && result_count > 0
            && result_count <= i64::from(MAX_SCHEDULER_CLAIMS)
            && committed_at >= 0
            && from_i64(committed_at)? <= trusted_now
            && claim_expires_at > committed_at
            && claim_ordinal_sql < result_count
            && matching_claim_ordinal_rows == 1;
        if valid {
            valid_origins = valid_origins
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
    }

    let initial_dispatch: Option<(String, String, String, i64, i64)> = connection
        .query_row(
            r#"
            SELECT action_id, commit_mode, initial_lease_owner_id,
                   initial_lease_expires_at, initial_fencing_token
            FROM security_response_dispatches
            WHERE tenant_id = ?1 AND dispatch_id = ?2
            "#,
            params![tenant_id.as_str(), claim_id.as_str()],
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
    if let Some((dispatch_action_id, commit_mode, owner_id, expires_at, token)) = initial_dispatch {
        let valid = dispatch_action_id == work.action_id.as_str()
            && matches!(commit_mode.as_str(), "fresh" | "governed_committed_resume")
            && owner_id == work.lease_owner_id.as_str()
            && claim_ordinal == 0
            && expires_at > 0
            && expires_at <= lease_expires_at
            && token == fencing_token;
        if valid {
            valid_origins = valid_origins
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
    }

    let dispatch_recovery: Option<(String, String, String, i64, i64, Option<String>)> = connection
        .query_row(
            r#"
            SELECT recoveries.action_id, recoveries.outcome,
                   recoveries.lease_owner_id, recoveries.lease_expires_at,
                   recoveries.fencing_token, dispatches.action_id
            FROM security_response_dispatch_recoveries AS recoveries
            LEFT JOIN security_response_dispatches AS dispatches
              ON dispatches.tenant_id = recoveries.tenant_id
             AND dispatches.dispatch_id = recoveries.dispatch_id
            WHERE recoveries.tenant_id = ?1 AND recoveries.recovery_id = ?2
            "#,
            params![tenant_id.as_str(), claim_id.as_str()],
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
    if let Some((recovery_action_id, outcome, owner_id, expires_at, token, dispatch_action_id)) =
        dispatch_recovery
    {
        let valid = recovery_action_id == work.action_id.as_str()
            && dispatch_action_id.as_deref() == Some(work.action_id.as_str())
            && outcome == "takeover"
            && owner_id == work.lease_owner_id.as_str()
            && claim_ordinal == 0
            && expires_at > 0
            && expires_at <= lease_expires_at
            && token == fencing_token;
        if valid {
            valid_origins = valid_origins
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
    }
    if valid_origins != 1 {
        return Err(PortError::integrity_failure());
    }

    let durable_fencing_token: Option<i64> = connection
        .query_row(
            r#"
            SELECT last_fencing_token
            FROM security_scheduler_fence_sequences
            WHERE tenant_id = ?1
            "#,
            params![tenant_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if durable_fencing_token
        .map(from_i64)
        .transpose()?
        .is_none_or(|token| token < work.fencing_token)
    {
        return Err(PortError::integrity_failure());
    }
    if (work.lease_expires_at_unix_ms > trusted_now) != expected_live {
        return Err(PortError::conflict());
    }
    Ok(Some(work))
}

impl SqliteSecurityStateStore {
    pub fn cleanup_expired_terminal_scheduler_leases(
        &self,
        tenant_id: &TenantId,
        max_leases: u32,
    ) -> PortResult<(u32, bool)> {
        if max_leases == 0 || max_leases > MAX_SCHEDULER_CLAIMS {
            return Err(PortError::invalid_data());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let orphaned_expired_lease = transaction
            .query_row(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM security_scheduler_leases AS leases
                    LEFT JOIN security_response_plans AS plans
                      ON plans.tenant_id = leases.tenant_id
                     AND plans.action_id = leases.action_id
                    WHERE leases.tenant_id = ?1
                      AND leases.lease_expires_at <= ?2
                      AND plans.action_id IS NULL
                )
                "#,
                params![tenant_id.as_str(), to_i64(trusted_now)?],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        if orphaned_expired_lease {
            return Err(PortError::integrity_failure());
        }
        let mut statement = transaction
            .prepare(
                r#"
                SELECT leases.action_id
                FROM security_scheduler_leases AS leases
                JOIN security_response_plans AS plans
                  ON plans.tenant_id = leases.tenant_id
                 AND plans.action_id = leases.action_id
                WHERE leases.tenant_id = ?1
                  AND leases.lease_expires_at <= ?2
                  AND (
                       plans.state IN ('cancelled', 'expired', 'failed', 'lifted')
                    OR CASE
                         WHEN json_valid(CAST(plans.body AS TEXT))
                         THEN json_extract(CAST(plans.body AS TEXT), '$.state')
                              IN ('cancelled', 'expired', 'failed', 'lifted')
                         ELSE 1
                       END
                  )
                ORDER BY leases.lease_expires_at, leases.claim_id,
                         leases.claim_ordinal, leases.action_id
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    tenant_id.as_str(),
                    to_i64(trusted_now)?,
                    i64::from(max_leases).saturating_add(1),
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut durable_leases = Vec::new();
        for row in rows {
            durable_leases.push(row.map_err(sqlite_error)?);
        }
        drop(statement);
        let terminal_remaining = durable_leases.len() > max_leases as usize;
        durable_leases.truncate(max_leases as usize);
        let mut cleaned = 0_u32;
        for action_id in durable_leases {
            let work = load_valid_scheduler_lease(
                &transaction,
                tenant_id,
                &action_id,
                trusted_now,
                false,
            )?
            .ok_or_else(PortError::integrity_failure)?;
            let current_plan = load_response_plan(
                &transaction,
                work.tenant_id.as_str(),
                work.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            let snapshot = decode_response_snapshot(&current_plan)
                .map_err(|_| PortError::integrity_failure())?;
            let durable_dispatch_id: Option<String> = transaction
                .query_row(
                    r#"
                    SELECT dispatch_id
                    FROM security_response_dispatches
                    WHERE tenant_id = ?1 AND action_id = ?2
                    "#,
                    params![work.tenant_id.as_str(), work.action_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let durable_dispatch_id = durable_dispatch_id
                .map(RecordId::new)
                .transpose()
                .map_err(|_| PortError::integrity_failure())?;
            match (&snapshot.execution_dispatch, durable_dispatch_id) {
                (None, None) => {}
                (Some(dispatch), Some(durable_dispatch_id))
                    if dispatch.dispatch_id == durable_dispatch_id =>
                {
                    let key = ResponseDispatchKey {
                        tenant_id: dispatch.tenant_id.clone(),
                        dispatch_id: dispatch.dispatch_id.clone(),
                    };
                    let durable_dispatch = load_response_dispatch(&transaction, &key)?
                        .ok_or_else(PortError::integrity_failure)?;
                    let authorization = &durable_dispatch.authorization.body;
                    if snapshot.dispatch_authorization_hash
                        != Some(durable_dispatch.authorization.body_hash)
                        || dispatch.schema_version != authorization.schema_version
                        || dispatch.tenant_id != authorization.key.tenant_id
                        || dispatch.dispatch_id != authorization.key.dispatch_id
                        || dispatch.action_id != authorization.action_id
                        || dispatch.plan_hash != authorization.plan_hash
                        || dispatch.executor_authority_id != authorization.executor_authority_id
                        || dispatch.executor_authority_generation
                            != authorization.executor_authority_generation
                        || dispatch.authorization_capability_hash
                            != authorization.authorization_capability_hash
                        || dispatch.governed_intent_hash != authorization.governed_intent_hash
                        || dispatch.policy_decision_hash != authorization.policy_decision_hash
                        || dispatch.approval != authorization.approval
                        || dispatch.authorized_at_unix_ms != authorization.authorized_at_unix_ms
                    {
                        return Err(PortError::integrity_failure());
                    }
                }
                _ => return Err(PortError::integrity_failure()),
            }
            if !snapshot.state.is_terminal() {
                return Err(PortError::integrity_failure());
            }
            let retry_key = SchedulerWorkKey {
                tenant_id: work.tenant_id.clone(),
                action_id: work.action_id.clone(),
            };
            if let Some(retry) = load_scheduler_retry(&transaction, &retry_key)? {
                if retry.attempts == 0
                    || retry.first_failure_at_unix_ms >= retry.not_before_unix_ms
                    || retry.not_before_unix_ms > trusted_now
                {
                    return Err(PortError::integrity_failure());
                }
            }
            delete_scheduler_lease(&transaction, &work)?;
            let deleted_retries = transaction
                .execute(
                    "DELETE FROM security_scheduler_retries WHERE tenant_id = ?1 AND action_id = ?2",
                    params![work.tenant_id.as_str(), work.action_id.as_str()],
                )
                .map_err(sqlite_error)?;
            if deleted_retries > 1 {
                return Err(PortError::integrity_failure());
            }
            let cleanup_hash = canonical_request_hash(&(&work, true))?;
            let transition_id = RecordId::new(format!(
                "scheduler-expired-terminal-cleanup-{}",
                hex::encode(cleanup_hash)
            ))
            .map_err(|_| PortError::integrity_failure())?;
            record_transition(
                &transaction,
                work.tenant_id.as_str(),
                transition_id.as_str(),
                "scheduler_expired_terminal_cleanup",
                &cleanup_hash,
            )?;
            cleaned = cleaned
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok((cleaned, terminal_remaining))
    }
}

impl ResponseStore for SqliteSecurityStateStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let connection = self.connection()?;
        load_response_plan(&connection, key.tenant_id.as_str(), key.action_id.as_str())
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_response_plan(
            &transaction,
            record.tenant_id.as_str(),
            record.action_id.as_str(),
        )? {
            if existing == *record {
                transaction.commit().map_err(sqlite_error)?;
                return Ok(CreateOutcome::Existing);
            }
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_plans (
                    action_id, tenant_id, generation, state, body, body_hash, due_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    record.action_id.as_str(),
                    record.tenant_id.as_str(),
                    to_i64(record.generation)?,
                    record.state.as_str(),
                    record.canonical_body.as_bytes(),
                    record.body_hash.as_bytes().as_slice(),
                    record.due_at_unix_ms.map(to_i64).transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        validate_canonical_json_body(&request.record.canonical_body, &request.record.body_hash)?;
        let candidate_snapshot = decode_response_snapshot(&request.record)?;
        let candidate_mutations = candidate_snapshot.mutations.as_slice();
        let appended = candidate_mutations
            .last()
            .ok_or_else(PortError::invalid_data)?;
        if candidate_snapshot.execution_dispatch.is_some()
            || appended.transition_id() != &request.transition_id
            || appended.generation() != request.record.generation
        {
            return Err(PortError::invalid_data());
        }
        if request.record.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_cas",
            &request_hash,
        )? {
            let existing = load_response_plan(
                &transaction,
                request.record.tenant_id.as_str(),
                request.record.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let current = load_response_plan(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.action_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let current_snapshot =
            decode_response_snapshot(&current).map_err(|_| PortError::integrity_failure())?;
        let current_mutations = current_snapshot.mutations.as_slice();
        let exact_prefix = current_mutations
            .len()
            .checked_add(1)
            .is_some_and(|expected| candidate_mutations.len() == expected)
            && &candidate_mutations[..current_mutations.len()] == current_mutations;
        if !exact_prefix
            || candidate_snapshot.schema_version != current_snapshot.schema_version
            || candidate_snapshot.plan != current_snapshot.plan
            || candidate_snapshot.execution_dispatch != current_snapshot.execution_dispatch
            || candidate_snapshot.dispatch_authorization_hash
                != current_snapshot.dispatch_authorization_hash
        {
            return Err(PortError::invalid_data());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_plans
                SET generation = ?4, state = ?5, body = ?6, body_hash = ?7, due_at = ?8
                WHERE action_id = ?1 AND tenant_id = ?2 AND generation = ?3
                "#,
                params![
                    request.record.action_id.as_str(),
                    request.record.tenant_id.as_str(),
                    to_i64(request.expected_generation)?,
                    to_i64(request.record.generation)?,
                    request.record.state.as_str(),
                    request.record.canonical_body.as_bytes(),
                    request.record.body_hash.as_bytes().as_slice(),
                    request.record.due_at_unix_ms.map(to_i64).transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.record.clone())
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        let connection = self.connection()?;
        load_response_effect(&connection, key.tenant_id.as_str(), key.effect_id.as_str())
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(reference) = record.encrypted_rollback_ref.as_ref() {
            validate_encrypted_blob_reference(&transaction, record.tenant_id.as_str(), reference)?;
        }
        validate_scheduler_fence(
            &transaction,
            record.tenant_id.as_str(),
            record.action_id.as_str(),
            record.scheduler_fencing_token,
            trusted_now,
        )?;
        validate_scheduler_lease_binding(
            &transaction,
            record.tenant_id.as_str(),
            record.action_id.as_str(),
            &record.scheduler_lease_owner_id,
            record.scheduler_fencing_token,
            trusted_now,
        )?;
        if let Some(existing) = load_response_effect(
            &transaction,
            record.tenant_id.as_str(),
            record.effect_id.as_str(),
        )? {
            if existing != *record {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_effects (
                    effect_id, tenant_id, action_id, generation, scheduler_lease_owner_id,
                    scheduler_fencing_token, state, body, body_hash, encrypted_rollback_ref
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    record.effect_id.as_str(),
                    record.tenant_id.as_str(),
                    record.action_id.as_str(),
                    to_i64(record.generation)?,
                    record.scheduler_lease_owner_id.as_str(),
                    to_i64(record.scheduler_fencing_token)?,
                    record.state.as_str(),
                    record.canonical_body.as_bytes(),
                    record.body_hash.as_bytes().as_slice(),
                    record.encrypted_rollback_ref.as_ref().map(RecordId::as_str)
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        validate_canonical_json_body(&request.record.canonical_body, &request.record.body_hash)?;
        if request.record.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(reference) = request.record.encrypted_rollback_ref.as_ref() {
            validate_encrypted_blob_reference(
                &transaction,
                request.record.tenant_id.as_str(),
                reference,
            )?;
        }
        validate_scheduler_fence(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.action_id.as_str(),
            request.record.scheduler_fencing_token,
            trusted_now,
        )?;
        validate_scheduler_lease_binding(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.action_id.as_str(),
            &request.record.scheduler_lease_owner_id,
            request.record.scheduler_fencing_token,
            trusted_now,
        )?;
        if transition_status(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_effect_cas",
            &request_hash,
        )? {
            let existing = load_response_effect(
                &transaction,
                request.record.tenant_id.as_str(),
                request.record.effect_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let current = load_response_effect(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.effect_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.action_id != request.record.action_id
            || current.effect_id != request.record.effect_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_effects
                SET generation = ?4, scheduler_lease_owner_id = ?5,
                    scheduler_fencing_token = ?6, state = ?7,
                    body = ?8, body_hash = ?9, encrypted_rollback_ref = ?10
                WHERE effect_id = ?1 AND tenant_id = ?2 AND generation = ?3
                "#,
                params![
                    request.record.effect_id.as_str(),
                    request.record.tenant_id.as_str(),
                    to_i64(request.expected_generation)?,
                    to_i64(request.record.generation)?,
                    request.record.scheduler_lease_owner_id.as_str(),
                    to_i64(request.record.scheduler_fencing_token)?,
                    request.record.state.as_str(),
                    request.record.canonical_body.as_bytes(),
                    request.record.body_hash.as_bytes().as_slice(),
                    request
                        .record
                        .encrypted_rollback_ref
                        .as_ref()
                        .map(RecordId::as_str)
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_effect_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.record.clone())
    }

    fn load_receipt_cursor(
        &self,
        key: &ResponsePlanKey,
    ) -> PortResult<Option<ResponseReceiptCursor>> {
        let connection = self.connection()?;
        load_response_receipt_cursor(&connection, key.tenant_id.as_str(), key.action_id.as_str())
    }

    fn initialize_receipt_cursor(
        &self,
        cursor: &ResponseReceiptCursor,
    ) -> PortResult<CreateOutcome> {
        if cursor.generation != 0 {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let plan = load_response_plan(
            &transaction,
            cursor.tenant_id.as_str(),
            cursor.action_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        let snapshot = decode_response_snapshot(&plan)?;
        if snapshot.plan.plan_hash != cursor.plan_hash
            || snapshot.plan.trigger_finding_receipt_id != cursor.current_evidence_id
        {
            return Err(PortError::invalid_data());
        }
        if let Some(existing) = load_response_receipt_cursor(
            &transaction,
            cursor.tenant_id.as_str(),
            cursor.action_id.as_str(),
        )? {
            if existing != *cursor {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_receipt_cursors (
                    tenant_id, action_id, plan_hash, generation, current_evidence_id
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    cursor.tenant_id.as_str(),
                    cursor.action_id.as_str(),
                    cursor.plan_hash.as_bytes().as_slice(),
                    to_i64(cursor.generation)?,
                    cursor.current_evidence_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap_receipt_cursor(
        &self,
        request: &ResponseReceiptCursorCasRequest,
    ) -> PortResult<ResponseReceiptCursor> {
        if request.cursor.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.cursor.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_receipt_cursor_cas",
            &request_hash,
        )? {
            let existing = load_response_receipt_cursor(
                &transaction,
                request.cursor.tenant_id.as_str(),
                request.cursor.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let current = load_response_receipt_cursor(
            &transaction,
            request.cursor.tenant_id.as_str(),
            request.cursor.action_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.cursor.tenant_id
            || current.action_id != request.cursor.action_id
            || current.plan_hash != request.cursor.plan_hash
            || current.generation != request.expected_generation
            || current.current_evidence_id != request.expected_evidence_id
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_receipt_cursors
                SET generation = ?4, current_evidence_id = ?5
                WHERE tenant_id = ?1 AND action_id = ?2 AND generation = ?3
                  AND current_evidence_id = ?6
                "#,
                params![
                    request.cursor.tenant_id.as_str(),
                    request.cursor.action_id.as_str(),
                    to_i64(request.expected_generation)?,
                    to_i64(request.cursor.generation)?,
                    request.cursor.current_evidence_id.as_str(),
                    request.expected_evidence_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.cursor.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_receipt_cursor_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.cursor.clone())
    }

    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        let trusted_now = self.trusted_now_unix_ms()?;
        if request.max_claims == 0 || request.max_claims > MAX_SCHEDULER_CLAIMS {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(claimed) =
            load_scheduler_claim(&transaction, request, &request_hash, trusted_now)?
        {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(claimed);
        }
        if request.lease_expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }
        let orphaned_claim_lease = transaction
            .query_row(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM security_scheduler_leases
                    WHERE tenant_id = ?1 AND claim_id = ?2
                )
                "#,
                params![request.tenant_id.as_str(), request.claim_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        if orphaned_claim_lease {
            return Err(PortError::integrity_failure());
        }
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS {
            return Err(PortError::invalid_data());
        }
        let trusted_now_sql = to_i64(trusted_now)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT plans.action_id
                FROM security_response_plans AS plans
                LEFT JOIN security_scheduler_leases AS leases
                  ON leases.action_id = plans.action_id
                 AND leases.tenant_id = plans.tenant_id
                LEFT JOIN security_scheduler_retries AS retries
                  ON retries.action_id = plans.action_id
                 AND retries.tenant_id = plans.tenant_id
                WHERE plans.tenant_id = ?1
                  AND plans.due_at IS NOT NULL
                  AND (
                        plans.due_at <= ?2
                     OR EXISTS (
                            SELECT 1
                            FROM security_issuance_freeze_effects AS freezes
                            WHERE freezes.tenant_id = plans.tenant_id
                              AND freezes.action_id = plans.action_id
                              AND freezes.external_fence_expires_at <= ?4
                              AND freezes.expires_at > ?2
                        )
                  )
                  AND (retries.action_id IS NULL OR retries.not_before <= ?2)
                  AND (leases.action_id IS NULL OR leases.lease_expires_at <= ?2)
                  AND NOT EXISTS (
                        SELECT 1
                        FROM security_response_dispatches AS committed_dispatch
                        WHERE committed_dispatch.tenant_id = plans.tenant_id
                          AND committed_dispatch.action_id = plans.action_id
                          AND plans.state = 'applying'
                          AND plans.generation = committed_dispatch.response_generation
                          AND plans.body = committed_dispatch.response_body
                          AND plans.body_hash = committed_dispatch.response_body_hash
                          AND plans.due_at = committed_dispatch.response_due_at
                  )
                ORDER BY
                  MIN(
                    CASE
                      WHEN retries.not_before IS NOT NULL
                       AND retries.not_before > plans.due_at
                      THEN retries.not_before
                      ELSE plans.due_at
                    END,
                    COALESCE(
                      (
                        SELECT MIN(freezes.external_fence_expires_at) - ?5
                        FROM security_issuance_freeze_effects AS freezes
                        WHERE freezes.tenant_id = plans.tenant_id
                          AND freezes.action_id = plans.action_id
                          AND freezes.expires_at > ?2
                      ),
                      9223372036854775807
                    )
                  ),
                  plans.action_id
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let action_rows = statement
            .query_map(
                params![
                    request.tenant_id.as_str(),
                    trusted_now_sql,
                    i64::from(request.max_claims),
                    to_i64(trusted_now.saturating_add(LINEAGE_FENCE_RENEWAL_MARGIN_MS))?,
                    to_i64(LINEAGE_FENCE_RENEWAL_MARGIN_MS)?
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut action_ids = Vec::new();
        for row in action_rows {
            action_ids.push(row.map_err(sqlite_error)?);
        }
        drop(statement);
        let mut claimed = Vec::new();
        for (claim_ordinal, action_id) in action_ids.into_iter().enumerate() {
            let plan = load_response_plan(&transaction, request.tenant_id.as_str(), &action_id)?
                .ok_or_else(PortError::integrity_failure)?;
            let due_for_fence_maintenance = transaction
                .query_row(
                    r#"
                    SELECT EXISTS(
                        SELECT 1
                        FROM security_issuance_freeze_effects
                        WHERE tenant_id = ?1 AND action_id = ?2
                          AND external_fence_expires_at <= ?3
                          AND expires_at > ?4
                    )
                    "#,
                    params![
                        request.tenant_id.as_str(),
                        action_id.as_str(),
                        to_i64(trusted_now.saturating_add(LINEAGE_FENCE_RENEWAL_MARGIN_MS))?,
                        trusted_now_sql,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(sqlite_error)?;
            if plan.due_at_unix_ms.is_none()
                || (plan
                    .due_at_unix_ms
                    .is_some_and(|due_at| due_at > trusted_now)
                    && !due_for_fence_maintenance)
            {
                return Err(PortError::integrity_failure());
            }
            let _ = load_valid_scheduler_lease(
                &transaction,
                &request.tenant_id,
                &action_id,
                trusted_now,
                false,
            )?;
            let fencing_token =
                next_scheduler_fencing_token(&transaction, request.tenant_id.as_str())?;
            let claim_ordinal =
                u64::try_from(claim_ordinal).map_err(|_| PortError::integrity_failure())?;
            let lease_body_hash = scheduler_lease_body_hash(
                request.tenant_id.as_str(),
                &action_id,
                request.claim_id.as_str(),
                claim_ordinal,
                request.lease_owner_id.as_str(),
                request.lease_expires_at_unix_ms,
                fencing_token,
            )?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token,
                        lease_body_hash
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                        claim_id = excluded.claim_id,
                        claim_ordinal = excluded.claim_ordinal,
                        lease_owner_id = excluded.lease_owner_id,
                        lease_expires_at = excluded.lease_expires_at,
                        fencing_token = excluded.fencing_token,
                        lease_body_hash = excluded.lease_body_hash
                    "#,
                    params![
                        action_id,
                        request.tenant_id.as_str(),
                        request.claim_id.as_str(),
                        to_i64(claim_ordinal)?,
                        request.lease_owner_id.as_str(),
                        to_i64(request.lease_expires_at_unix_ms)?,
                        to_i64(fencing_token)?,
                        lease_body_hash.as_slice()
                    ],
                )
                .map_err(sqlite_error)?;
            claimed.push(ScheduledWork {
                tenant_id: request.tenant_id.clone(),
                action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
                lease_owner_id: request.lease_owner_id.clone(),
                lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
                fencing_token,
            });
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_scheduler_claims (
                    tenant_id, claim_id, request_hash, lease_owner_id,
                    lease_expires_at, result_count, committed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.tenant_id.as_str(),
                    request.claim_id.as_str(),
                    request_hash.as_slice(),
                    request.lease_owner_id.as_str(),
                    to_i64(request.lease_expires_at_unix_ms)?,
                    to_i64(claimed.len() as u64)?,
                    trusted_now_sql
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(claimed)
    }
}

include!("part_06_scheduler_and_dispatch.inc");
