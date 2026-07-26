impl ResponseSchedulerStore for SqliteSecurityStateStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        let connection = self.connection()?;
        load_scheduler_retry(&connection, key)
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let connection = self.connection()?;
        validate_scheduler_work(&connection, work, trusted_now)
    }

    fn compare_and_swap_scheduled_mutation(
        &self,
        request: &ResponseScheduledMutationCasRequest,
    ) -> PortResult<ResponsePlanRecord> {
        validate_canonical_json_body(&request.current.canonical_body, &request.current.body_hash)?;
        validate_canonical_json_body(
            &request.candidate.canonical_body,
            &request.candidate.body_hash,
        )?;
        let current_snapshot = decode_response_snapshot(&request.current)?;
        let candidate_snapshot = decode_response_snapshot(&request.candidate)?;
        let current_mutations = current_snapshot.mutations.as_slice();
        let candidate_mutations = candidate_snapshot.mutations.as_slice();
        let appended = candidate_mutations
            .last()
            .ok_or_else(PortError::invalid_data)?;
        let expected_candidate_generation = request
            .current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let exact_prefix = current_mutations
            .len()
            .checked_add(1)
            .is_some_and(|expected| candidate_mutations.len() == expected)
            && &candidate_mutations[..current_mutations.len()] == current_mutations;
        let (scheduler_owner, scheduler_token) = response_mutation_scheduler_fence(appended)?;
        if request.current.tenant_id != request.work.tenant_id
            || request.current.action_id != request.work.action_id
            || request.candidate.tenant_id != request.current.tenant_id
            || request.candidate.action_id != request.current.action_id
            || request.candidate.generation != expected_candidate_generation
            || appended.generation() != expected_candidate_generation
            || appended.transition_id() != &request.transition_id
            || !exact_prefix
            || candidate_snapshot.schema_version != current_snapshot.schema_version
            || candidate_snapshot.plan != current_snapshot.plan
            || candidate_snapshot.execution_dispatch != current_snapshot.execution_dispatch
            || candidate_snapshot.dispatch_authorization_hash
                != current_snapshot.dispatch_authorization_hash
            || scheduler_owner != Some(&request.work.lease_owner_id)
            || scheduler_token != Some(request.work.fencing_token)
            || request.work.fencing_token == 0
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.candidate.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_scheduled_mutation_cas",
            &request_hash,
        )? {
            let durable = load_response_plan(
                &transaction,
                request.candidate.tenant_id.as_str(),
                request.candidate.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            let durable_snapshot =
                decode_response_snapshot(&durable).map_err(|_| PortError::integrity_failure())?;
            let durable_mutations = durable_snapshot.mutations.as_slice();
            let candidate_is_durable_prefix = candidate_mutations.len() <= durable_mutations.len()
                && &durable_mutations[..candidate_mutations.len()] == candidate_mutations;
            if !candidate_is_durable_prefix
                || durable.tenant_id != request.candidate.tenant_id
                || durable.action_id != request.candidate.action_id
                || durable.generation < request.candidate.generation
                || durable_snapshot.schema_version != candidate_snapshot.schema_version
                || durable_snapshot.plan != candidate_snapshot.plan
                || durable_snapshot.execution_dispatch != candidate_snapshot.execution_dispatch
                || durable_snapshot.dispatch_authorization_hash
                    != candidate_snapshot.dispatch_authorization_hash
            {
                return Err(PortError::integrity_failure());
            }
            let work_key = SchedulerWorkKey {
                tenant_id: request.work.tenant_id.clone(),
                action_id: request.work.action_id.clone(),
            };
            match load_scheduler_lease(&transaction, &work_key)? {
                Some(lease) => {
                    let lease_is_live = lease.lease_expires_at_unix_ms > trusted_now;
                    let validated = load_valid_scheduler_lease(
                        &transaction,
                        &lease.tenant_id,
                        lease.action_id.as_str(),
                        trusted_now,
                        lease_is_live,
                    )?
                    .ok_or_else(PortError::integrity_failure)?;
                    if validated != lease {
                        return Err(PortError::integrity_failure());
                    }
                    if lease.lease_owner_id != request.work.lease_owner_id
                        || lease.fencing_token != request.work.fencing_token
                    {
                        return Err(PortError::conflict());
                    }
                    if lease.lease_expires_at_unix_ms < request.work.lease_expires_at_unix_ms {
                        return Err(PortError::integrity_failure());
                    }
                    if !lease_is_live && !durable_snapshot.state.is_terminal() {
                        return Err(PortError::conflict());
                    }
                }
                None if !durable_snapshot.state.is_terminal() => {
                    return Err(PortError::conflict());
                }
                None => {}
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(durable);
        }

        validate_scheduler_work(&transaction, &request.work, trusted_now)?;
        let current = load_response_plan(
            &transaction,
            request.current.tenant_id.as_str(),
            request.current.action_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current != request.current {
            return Err(PortError::conflict());
        }
        if let ResponseMutationRecord::Transition(renewal) = appended {
            if renewal.from_state == ResponseState::Applying
                && renewal.to_state == ResponseState::Applying
            {
                let current_expiry = current_snapshot
                    .applying_lease_expires_at_unix_ms
                    .ok_or_else(PortError::integrity_failure)?;
                let exact_renewed_expiry = request
                    .work
                    .lease_expires_at_unix_ms
                    .min(current_snapshot.plan.expires_at_unix_ms);
                if renewal.cause != ResponseTransitionCause::ApplyingLeaseRenewed
                    || renewal.occurred_at_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
                    || trusted_now >= current_expiry
                    || renewal.occurred_at_unix_ms >= current_expiry
                    || renewal.applying_lease_expires_at_unix_ms != Some(exact_renewed_expiry)
                    || candidate_snapshot.applying_lease_expires_at_unix_ms
                        != Some(exact_renewed_expiry)
                    || candidate_snapshot.due_at_unix_ms != Some(exact_renewed_expiry)
                    || exact_renewed_expiry <= current_expiry
                {
                    return Err(PortError::conflict());
                }
            }
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_plans
                SET generation = ?4, state = ?5, body = ?6, body_hash = ?7, due_at = ?8
                WHERE action_id = ?1 AND tenant_id = ?2 AND generation = ?3
                "#,
                params![
                    request.candidate.action_id.as_str(),
                    request.candidate.tenant_id.as_str(),
                    to_i64(request.current.generation)?,
                    to_i64(request.candidate.generation)?,
                    request.candidate.state.as_str(),
                    request.candidate.canonical_body.as_bytes(),
                    request.candidate.body_hash.as_bytes().as_slice(),
                    request.candidate.due_at_unix_ms.map(to_i64).transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.candidate.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_scheduled_mutation_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.candidate.clone())
    }

    fn validate_lease_identity(
        &self,
        tenant_id: &TenantId,
        action_id: &ActionId,
        lease_owner_id: &LeaseOwnerId,
        fencing_token: u64,
    ) -> PortResult<()> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let connection = self.connection()?;
        validate_scheduler_lease_binding(
            &connection,
            tenant_id.as_str(),
            action_id.as_str(),
            lease_owner_id,
            fencing_token,
            trusted_now,
        )
    }

    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        if request.lease_expires_at_unix_ms <= request.work.lease_expires_at_unix_ms {
            return Err(PortError::invalid_data());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_renew",
            &request_hash,
        )? {
            let renewed = load_valid_scheduler_lease(
                &transaction,
                &request.work.tenant_id,
                request.work.action_id.as_str(),
                trusted_now,
                true,
            )?
            .ok_or_else(PortError::conflict)?;
            if renewed.lease_owner_id != request.work.lease_owner_id
                || renewed.fencing_token != request.work.fencing_token
            {
                return Err(PortError::conflict());
            }
            if renewed.lease_expires_at_unix_ms < request.lease_expires_at_unix_ms {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(renewed);
        }
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.lease_expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::invalid_data());
        }
        let current_plan = load_response_plan(
            &transaction,
            request.work.tenant_id.as_str(),
            request.work.action_id.as_str(),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let current_snapshot =
            decode_response_snapshot(&current_plan).map_err(|_| PortError::integrity_failure())?;
        if current_snapshot.state.is_terminal() {
            return Err(PortError::conflict());
        }
        validate_scheduler_work(&transaction, &request.work, trusted_now)?;
        let (claim_id, claim_ordinal_sql): (String, i64) = transaction
            .query_row(
                r#"
                SELECT claim_id, claim_ordinal
                FROM security_scheduler_leases
                WHERE tenant_id = ?1 AND action_id = ?2
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error)?;
        RecordId::new(claim_id.clone()).map_err(|_| PortError::integrity_failure())?;
        let lease_body_hash = scheduler_lease_body_hash(
            request.work.tenant_id.as_str(),
            request.work.action_id.as_str(),
            &claim_id,
            from_i64(claim_ordinal_sql)?,
            request.work.lease_owner_id.as_str(),
            request.lease_expires_at_unix_ms,
            request.work.fencing_token,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_scheduler_leases
                SET lease_expires_at = ?5, lease_body_hash = ?6
                WHERE tenant_id = ?1 AND action_id = ?2 AND lease_owner_id = ?3
                  AND fencing_token = ?4 AND lease_expires_at = ?7
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str(),
                    request.work.lease_owner_id.as_str(),
                    to_i64(request.work.fencing_token)?,
                    to_i64(request.lease_expires_at_unix_ms)?,
                    lease_body_hash.as_slice(),
                    to_i64(request.work.lease_expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_renew",
            &request_hash,
        )?;
        let renewed = ScheduledWork {
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            ..request.work.clone()
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(renewed)
    }

    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        let trusted_now = self.trusted_now_unix_ms()?;
        if request.first_failure_at_unix_ms > request.now_unix_ms {
            return Err(PortError::invalid_data());
        }
        let next_attempts = request
            .expected_attempts
            .checked_add(1)
            .ok_or_else(PortError::invalid_data)?;
        let request_hash = canonical_request_hash(request)?;
        let key = SchedulerWorkKey {
            tenant_id: request.work.tenant_id.clone(),
            action_id: request.work.action_id.clone(),
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_retry",
            &request_hash,
        )? {
            let stored =
                load_scheduler_retry(&transaction, &key)?.ok_or_else(PortError::conflict)?;
            if stored.attempts > next_attempts {
                return Err(PortError::conflict());
            }
            if stored.attempts < next_attempts
                || stored.last_error != request.error_code
                || stored.first_failure_at_unix_ms != request.first_failure_at_unix_ms
                || stored.not_before_unix_ms != request.not_before_unix_ms
                || stored.health_event_id != request.health_event_id
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.not_before_unix_ms <= trusted_now
        {
            return Err(PortError::invalid_data());
        }
        validate_scheduler_work(&transaction, &request.work, trusted_now)?;
        let current = load_scheduler_retry(&transaction, &key)?;
        let current_attempts = current.as_ref().map(|retry| retry.attempts).unwrap_or(0);
        if current_attempts != request.expected_attempts {
            return Err(PortError::conflict());
        }
        if let Some(current) = current.as_ref() {
            if current.first_failure_at_unix_ms != request.first_failure_at_unix_ms
                || current
                    .health_event_id
                    .as_ref()
                    .is_some_and(|event_id| Some(event_id) != request.health_event_id.as_ref())
                || current.health_event_delivered && request.health_event_id.is_none()
            {
                return Err(PortError::conflict());
            }
        } else if request.first_failure_at_unix_ms != request.now_unix_ms {
            return Err(PortError::invalid_data());
        }
        let health_event_delivered = current
            .as_ref()
            .is_some_and(|retry| retry.health_event_delivered);
        transaction
            .execute(
                r#"
                INSERT INTO security_scheduler_retries (
                    tenant_id, action_id, attempts, last_error, first_failure_at,
                    not_before, health_event_id, health_event_delivered
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                    attempts = excluded.attempts,
                    last_error = excluded.last_error,
                    first_failure_at = excluded.first_failure_at,
                    not_before = excluded.not_before,
                    health_event_id = excluded.health_event_id
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str(),
                    i64::from(next_attempts),
                    request.error_code.as_str(),
                    to_i64(request.first_failure_at_unix_ms)?,
                    to_i64(request.not_before_unix_ms)?,
                    request.health_event_id.as_ref().map(RecordId::as_str),
                    i64::from(health_event_delivered)
                ],
            )
            .map_err(sqlite_error)?;
        delete_scheduler_lease(&transaction, &request.work)?;
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_retry",
            &request_hash,
        )?;
        let retry = SchedulerRetryState {
            key,
            attempts: next_attempts,
            last_error: request.error_code.clone(),
            first_failure_at_unix_ms: request.first_failure_at_unix_ms,
            not_before_unix_ms: request.not_before_unix_ms,
            health_event_id: request.health_event_id.clone(),
            health_event_delivered,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(retry)
    }

    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_health_ack",
            &request_hash,
        )? {
            let stored = load_scheduler_retry(&transaction, &request.key)?
                .ok_or_else(PortError::conflict)?;
            if stored.health_event_id.as_ref() != Some(&request.event_id)
                || !stored.health_event_delivered
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        let current = load_scheduler_retry(&transaction, &request.key)?
            .ok_or_else(PortError::invalid_data)?;
        if current.health_event_id.as_ref() != Some(&request.event_id) {
            return Err(PortError::conflict());
        }
        if !current.health_event_delivered {
            let updated = transaction
                .execute(
                    r#"
                    UPDATE security_scheduler_retries
                    SET health_event_delivered = 1
                    WHERE tenant_id = ?1 AND action_id = ?2 AND health_event_id = ?3
                      AND health_event_delivered = 0
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.action_id.as_str(),
                        request.event_id.as_str()
                    ],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(PortError::conflict());
            }
        }
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_health_ack",
            &request_hash,
        )?;
        let stored = load_scheduler_retry(&transaction, &request.key)?
            .ok_or_else(PortError::integrity_failure)?;
        if !stored.health_event_delivered {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        let request_hash = canonical_request_hash(request)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_release",
            &request_hash,
        )? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        validate_scheduler_work(&transaction, &request.work, trusted_now)?;
        delete_scheduler_lease(&transaction, &request.work)?;
        if request.clear_retry_state {
            transaction
                .execute(
                    "DELETE FROM security_scheduler_retries WHERE tenant_id = ?1 AND action_id = ?2",
                    params![request.work.tenant_id.as_str(), request.work.action_id.as_str()],
                )
                .map_err(sqlite_error)?;
        }
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_release",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

impl ResponseDispatchStore for SqliteSecurityStateStore {
    fn ensure_dispatch_ready(&self) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT dispatches.dispatch_id, dispatches.commit_mode,
                       dispatches.authorization_body,
                       dispatches.authorization_body_hash,
                       dispatches.response_generation, dispatches.response_state,
                       dispatches.response_body, dispatches.response_body_hash,
                       dispatches.response_due_at, dispatches.initial_lease_owner_id,
                       dispatches.initial_lease_expires_at,
                       dispatches.initial_fencing_token, plans.generation,
                       leases.fencing_token
                FROM security_response_dispatches AS dispatches
                JOIN security_response_plans AS plans
                  ON plans.tenant_id = dispatches.tenant_id
                 AND plans.action_id = dispatches.action_id
                JOIN security_scheduler_leases AS leases
                  ON leases.tenant_id = dispatches.tenant_id
                 AND leases.action_id = dispatches.action_id
                LIMIT 0
                "#,
            )
            .map_err(|_| PortError::integrity_failure())?;
        let _ = statement
            .exists([])
            .map_err(|_| PortError::integrity_failure())?;
        drop(statement);
        let mut recovery_statement = transaction
            .prepare(
                r#"
                SELECT recovery_id, tenant_id, dispatch_id, action_id, request_hash,
                       outcome, lease_owner_id, lease_expires_at, fencing_token
                FROM security_response_dispatch_recoveries
                LIMIT 0
                "#,
            )
            .map_err(|_| PortError::integrity_failure())?;
        let _ = recovery_statement
            .exists([])
            .map_err(|_| PortError::integrity_failure())?;
        drop(recovery_statement);
        let mut receipt_cursor_statement = transaction
            .prepare(
                r#"
                SELECT tenant_id, action_id, plan_hash, generation, current_evidence_id
                FROM security_response_receipt_cursors
                LIMIT 0
                "#,
            )
            .map_err(|_| PortError::integrity_failure())?;
        let _ = receipt_cursor_statement
            .exists([])
            .map_err(|_| PortError::integrity_failure())?;
        drop(receipt_cursor_statement);
        let mut fence_statement = transaction
            .prepare(
                r#"
                SELECT dispatch_id, tenant_id, action_id, prepared_binding_body,
                       prepared_binding_hash, fenced_at
                FROM security_response_dispatch_fences
                LIMIT 0
                "#,
            )
            .map_err(|_| PortError::integrity_failure())?;
        let _ = fence_statement
            .exists([])
            .map_err(|_| PortError::integrity_failure())?;
        drop(fence_statement);
        validate_all_automatic_response_dispatch_fences(&transaction)?;
        let overlapping_identity = transaction
            .query_row(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM security_response_dispatch_fences AS fences
                    JOIN security_response_dispatches AS dispatches
                      ON dispatches.tenant_id = fences.tenant_id
                     AND (dispatches.action_id = fences.action_id
                          OR dispatches.dispatch_id = fences.dispatch_id)
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PortError::integrity_failure())?;
        if overlapping_identity {
            return Err(PortError::integrity_failure());
        }
        for statement in [
            "UPDATE security_response_dispatches SET initial_fencing_token = initial_fencing_token WHERE 0",
            "UPDATE security_response_dispatch_fences SET fenced_at = fenced_at WHERE 0",
            "UPDATE security_response_plans SET generation = generation WHERE 0",
            "UPDATE security_response_receipt_cursors SET generation = generation WHERE 0",
            "UPDATE security_scheduler_leases SET fencing_token = fencing_token WHERE 0",
            "UPDATE security_response_dispatch_recoveries SET fencing_token = fencing_token WHERE 0",
        ] {
            let changed = transaction
                .execute(statement, [])
                .map_err(|_| PortError::unavailable())?;
            if changed != 0 {
                return Err(PortError::integrity_failure());
            }
        }
        transaction.rollback().map_err(sqlite_error)
    }

    fn load_dispatch_work(&self, key: &SchedulerWorkKey) -> PortResult<Option<ScheduledWork>> {
        let connection = self.connection()?;
        load_scheduler_lease(&connection, key)
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        request: &AutomaticResponseDispatchFenceRequest,
    ) -> PortResult<AutomaticResponseDispatchFenceOutcome> {
        request
            .prepared_dispatch_binding
            .validate_for_plan(&request.response_plan)
            .map_err(|_| PortError::invalid_data())?;
        if !matches!(
            &request.response_plan.approval_requirement,
            ResponseApprovalRequirement::Automatic
        ) || !matches!(
            &request.prepared_dispatch_binding.approval,
            ResponseDispatchApproval::Automatic
        ) {
            return Err(PortError::invalid_data());
        }
        let (prepared_binding_body, binding_hash) =
            canonical_prepared_dispatch_binding(&request.prepared_dispatch_binding)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(committed) = load_response_dispatch_for_identity(
            &transaction,
            &request.prepared_dispatch_binding.tenant_id,
            &request.prepared_dispatch_binding.action_id,
            &request.prepared_dispatch_binding.dispatch_id,
        )? {
            let committed_binding = prepared_binding_from_response_dispatch(&committed);
            if committed_binding != request.prepared_dispatch_binding {
                return Err(PortError::conflict());
            }
            committed_binding
                .validate_for_plan(&request.response_plan)
                .map_err(|_| PortError::conflict())?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(AutomaticResponseDispatchFenceOutcome::Committed(Box::new(
                committed,
            )));
        }
        if let Some(existing) = load_automatic_response_dispatch_fence(
            &transaction,
            &request.prepared_dispatch_binding.tenant_id,
            &request.prepared_dispatch_binding.action_id,
            &request.prepared_dispatch_binding.dispatch_id,
        )? {
            if existing.prepared_dispatch_binding != request.prepared_dispatch_binding
                || existing.binding_hash != binding_hash
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(AutomaticResponseDispatchFenceOutcome::ExistingFence(
                existing,
            ));
        }
        let work_key = SchedulerWorkKey {
            tenant_id: request.prepared_dispatch_binding.tenant_id.clone(),
            action_id: request.prepared_dispatch_binding.action_id.clone(),
        };
        if load_response_plan(
            &transaction,
            work_key.tenant_id.as_str(),
            work_key.action_id.as_str(),
        )?
        .is_some()
            || load_scheduler_lease(&transaction, &work_key)?.is_some()
            || load_scheduler_retry(&transaction, &work_key)?.is_some()
        {
            return Err(PortError::conflict());
        }
        let fenced_at_unix_ms = self.trusted_now_unix_ms()?;
        if fenced_at_unix_ms == 0 {
            return Err(PortError::unavailable());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_dispatch_fences (
                    dispatch_id, tenant_id, action_id, prepared_binding_body,
                    prepared_binding_hash, fenced_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    request.prepared_dispatch_binding.dispatch_id.as_str(),
                    request.prepared_dispatch_binding.tenant_id.as_str(),
                    request.prepared_dispatch_binding.action_id.as_str(),
                    prepared_binding_body,
                    binding_hash.as_bytes().as_slice(),
                    to_i64(fenced_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        let record = AutomaticResponseDispatchFenceRecord {
            prepared_dispatch_binding: request.prepared_dispatch_binding.clone(),
            binding_hash,
            fenced_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(AutomaticResponseDispatchFenceOutcome::Fenced(record))
    }

    fn commit_dispatch(
        &self,
        request: &ResponseDispatchCommitRequest,
    ) -> PortResult<ResponseDispatchCommitOutcome> {
        let snapshot = validate_response_dispatch_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let prepared_dispatch_binding =
            prepared_binding_from_response_authorization(&request.authorization.body);
        if load_automatic_response_dispatch_fence(
            &transaction,
            &prepared_dispatch_binding.tenant_id,
            &prepared_dispatch_binding.action_id,
            &prepared_dispatch_binding.dispatch_id,
        )?
        .is_some()
        {
            return Err(PortError::conflict());
        }
        validate_attested_response_execution_dispatch(
            &transaction,
            &request.authorization.body.key.tenant_id,
            &request.authorization.body.action_id,
            &request.authorization.body.key.dispatch_id,
        )?;
        if load_response_dispatch_commit_mode(&transaction, &request.authorization.body.key)?
            .is_some_and(|mode| mode != request.mode)
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) =
            load_response_dispatch(&transaction, &request.authorization.body.key)?
        {
            if existing.authorization != request.authorization
                || existing.response_plan != request.response_plan
                || existing.initial_work.lease_owner_id != request.initial_lease.lease_owner_id
                || existing.initial_work.lease_expires_at_unix_ms
                    != request.initial_lease.lease_expires_at_unix_ms
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(ResponseDispatchCommitOutcome::Existing(existing));
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let invalid_commit_time = match request.mode {
            ResponseDispatchCommitMode::Fresh => {
                request
                    .authorization
                    .body
                    .authorized_at_unix_ms
                    .abs_diff(trusted_now)
                    > MAX_CLOCK_SKEW_MS
                    || request.initial_lease.lease_expires_at_unix_ms <= trusted_now
            }
            ResponseDispatchCommitMode::GovernedCommittedResume => {
                request.authorization.body.authorized_at_unix_ms > trusted_now
                    || trusted_now >= snapshot.plan.expires_at_unix_ms
                    || request.initial_lease.lease_expires_at_unix_ms <= trusted_now
            }
            ResponseDispatchCommitMode::GovernedCommittedExpiredResume => {
                request.authorization.body.authorized_at_unix_ms > trusted_now
                    || trusted_now < snapshot.plan.expires_at_unix_ms
            }
        };
        if invalid_commit_time {
            return Err(PortError::invalid_data());
        }
        if load_response_plan(
            &transaction,
            request.response_plan.tenant_id.as_str(),
            request.response_plan.action_id.as_str(),
        )?
        .is_some()
            || load_scheduler_lease(
                &transaction,
                &SchedulerWorkKey {
                    tenant_id: request.response_plan.tenant_id.clone(),
                    action_id: request.response_plan.action_id.clone(),
                },
            )?
            .is_some()
            || load_scheduler_retry(
                &transaction,
                &SchedulerWorkKey {
                    tenant_id: request.response_plan.tenant_id.clone(),
                    action_id: request.response_plan.action_id.clone(),
                },
            )?
            .is_some()
        {
            return Err(PortError::conflict());
        }
        let due_at_unix_ms = request
            .response_plan
            .due_at_unix_ms
            .ok_or_else(PortError::invalid_data)?;
        let fencing_token =
            next_scheduler_fencing_token(&transaction, request.response_plan.tenant_id.as_str())?;
        let initial_work = ScheduledWork {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
            lease_owner_id: request.initial_lease.lease_owner_id.clone(),
            lease_expires_at_unix_ms: request.initial_lease.lease_expires_at_unix_ms,
            fencing_token,
        };
        transaction
            .execute(
                r#"
                INSERT INTO security_response_plans (
                    action_id, tenant_id, generation, state, body, body_hash, due_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.response_plan.action_id.as_str(),
                    request.response_plan.tenant_id.as_str(),
                    to_i64(request.response_plan.generation)?,
                    request.response_plan.state.as_str(),
                    request.response_plan.canonical_body.as_bytes(),
                    request.response_plan.body_hash.as_bytes().as_slice(),
                    to_i64(due_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        if request.mode != ResponseDispatchCommitMode::GovernedCommittedExpiredResume {
            let lease_body_hash = scheduler_lease_body_hash(
                initial_work.tenant_id.as_str(),
                initial_work.action_id.as_str(),
                request.authorization.body.key.dispatch_id.as_str(),
                0,
                initial_work.lease_owner_id.as_str(),
                initial_work.lease_expires_at_unix_ms,
                initial_work.fencing_token,
            )?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token,
                        lease_body_hash
                    ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        initial_work.action_id.as_str(),
                        initial_work.tenant_id.as_str(),
                        request.authorization.body.key.dispatch_id.as_str(),
                        initial_work.lease_owner_id.as_str(),
                        to_i64(initial_work.lease_expires_at_unix_ms)?,
                        to_i64(initial_work.fencing_token)?,
                        lease_body_hash.as_slice()
                    ],
                )
                .map_err(sqlite_error)?;
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_dispatches (
                    dispatch_id, tenant_id, action_id, commit_mode, authorization_body,
                    authorization_body_hash, response_generation, response_state,
                    response_body, response_body_hash, response_due_at,
                    initial_lease_owner_id, initial_lease_expires_at,
                    initial_fencing_token
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
                params![
                    request.authorization.body.key.dispatch_id.as_str(),
                    request.authorization.body.key.tenant_id.as_str(),
                    request.authorization.body.action_id.as_str(),
                    response_dispatch_commit_mode(request.mode),
                    request.authorization.canonical_body.as_bytes(),
                    request.authorization.body_hash.as_bytes().as_slice(),
                    to_i64(request.response_plan.generation)?,
                    request.response_plan.state.as_str(),
                    request.response_plan.canonical_body.as_bytes(),
                    request.response_plan.body_hash.as_bytes().as_slice(),
                    to_i64(due_at_unix_ms)?,
                    initial_work.lease_owner_id.as_str(),
                    to_i64(initial_work.lease_expires_at_unix_ms)?,
                    to_i64(initial_work.fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        let record = ResponseDispatchRecord {
            authorization: request.authorization.clone(),
            response_plan: request.response_plan.clone(),
            initial_work,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(ResponseDispatchCommitOutcome::Committed(record))
    }

    fn load_dispatch(&self, key: &ResponseDispatchKey) -> PortResult<ResponseDispatchLoadOutcome> {
        let connection = self.connection()?;
        Ok(match load_response_dispatch(&connection, key)? {
            Some(record) => ResponseDispatchLoadOutcome::Found(Box::new(record)),
            None => ResponseDispatchLoadOutcome::Missing,
        })
    }

    fn recover_dispatch_work(
        &self,
        request: &ResponseDispatchRecoveryRequest,
    ) -> PortResult<ResponseDispatchRecoveryOutcome> {
        let expected_fencing_token = request
            .expected_fencing_token
            .filter(|token| *token > 0)
            .ok_or_else(PortError::invalid_data)?;
        let trusted_now = self.trusted_now_unix_ms()?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) =
            load_response_dispatch_recovery(&transaction, request, &request_hash)?
        {
            let recorded_work = match &existing {
                ResponseDispatchRecoveryOutcome::LiveLease(work)
                | ResponseDispatchRecoveryOutcome::Takeover(work) => work,
            };
            let durable_work = load_valid_scheduler_lease(
                &transaction,
                &request.key.tenant_id,
                request.action_id.as_str(),
                trusted_now,
                true,
            )?
            .ok_or_else(PortError::conflict)?;
            if durable_work.lease_owner_id != recorded_work.lease_owner_id
                || durable_work.fencing_token != recorded_work.fencing_token
            {
                return Err(PortError::conflict());
            }
            if durable_work.lease_expires_at_unix_ms < recorded_work.lease_expires_at_unix_ms {
                return Err(PortError::integrity_failure());
            }
            let refreshed = match existing {
                ResponseDispatchRecoveryOutcome::LiveLease(_) => {
                    ResponseDispatchRecoveryOutcome::LiveLease(durable_work)
                }
                ResponseDispatchRecoveryOutcome::Takeover(_) => {
                    ResponseDispatchRecoveryOutcome::Takeover(durable_work)
                }
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(refreshed);
        }
        let dispatch = load_response_dispatch(&transaction, &request.key)?
            .ok_or_else(PortError::invalid_data)?;
        if dispatch.authorization.body.action_id != request.action_id
            || dispatch.response_plan.action_id != request.action_id
        {
            return Err(PortError::conflict());
        }
        let current = load_response_plan(
            &transaction,
            request.key.tenant_id.as_str(),
            request.action_id.as_str(),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let snapshot =
            decode_response_snapshot(&current).map_err(|_| PortError::integrity_failure())?;
        if snapshot.state != ResponseState::Applying
            || snapshot.plan.plan_hash != dispatch.authorization.body.plan_hash
        {
            return Err(PortError::conflict());
        }
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.lease_expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::invalid_data());
        }
        let work_key = SchedulerWorkKey {
            tenant_id: request.key.tenant_id.clone(),
            action_id: request.action_id.clone(),
        };
        let current_lease = load_scheduler_lease(&transaction, &work_key)?;
        let outcome = if let Some(live) = current_lease
            .as_ref()
            .filter(|lease| lease.lease_expires_at_unix_ms > trusted_now)
        {
            let validated = load_valid_scheduler_lease(
                &transaction,
                &request.key.tenant_id,
                request.action_id.as_str(),
                trusted_now,
                true,
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if validated != *live {
                return Err(PortError::integrity_failure());
            }
            if request.lease_owner_id != live.lease_owner_id
                || expected_fencing_token != live.fencing_token
            {
                return Err(PortError::conflict());
            }
            ResponseDispatchRecoveryOutcome::LiveLease(live.clone())
        } else {
            if let Some(stale) = &current_lease {
                let validated = load_valid_scheduler_lease(
                    &transaction,
                    &request.key.tenant_id,
                    request.action_id.as_str(),
                    trusted_now,
                    false,
                )?
                .ok_or_else(PortError::integrity_failure)?;
                if validated != *stale {
                    return Err(PortError::integrity_failure());
                }
            }
            if current
                .due_at_unix_ms
                .is_none_or(|due_at| due_at > trusted_now)
                || load_scheduler_retry(&transaction, &work_key)?
                    .is_some_and(|retry| retry.not_before_unix_ms > trusted_now)
            {
                return Err(PortError::conflict());
            }
            let observed_fencing_token = current_lease
                .as_ref()
                .map(|lease| lease.fencing_token)
                .unwrap_or(dispatch.initial_work.fencing_token);
            if expected_fencing_token != observed_fencing_token {
                return Err(PortError::conflict());
            }
            let fencing_token =
                next_scheduler_fencing_token(&transaction, request.key.tenant_id.as_str())?;
            if fencing_token <= observed_fencing_token {
                return Err(PortError::integrity_failure());
            }
            let work = ScheduledWork {
                tenant_id: request.key.tenant_id.clone(),
                action_id: request.action_id.clone(),
                lease_owner_id: request.lease_owner_id.clone(),
                lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
                fencing_token,
            };
            let lease_body_hash = scheduler_lease_body_hash(
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                request.recovery_id.as_str(),
                0,
                work.lease_owner_id.as_str(),
                work.lease_expires_at_unix_ms,
                work.fencing_token,
            )?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token,
                        lease_body_hash
                    ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7)
                    ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                        claim_id = excluded.claim_id,
                        claim_ordinal = excluded.claim_ordinal,
                        lease_owner_id = excluded.lease_owner_id,
                        lease_expires_at = excluded.lease_expires_at,
                        fencing_token = excluded.fencing_token,
                        lease_body_hash = excluded.lease_body_hash
                    "#,
                    params![
                        work.action_id.as_str(),
                        work.tenant_id.as_str(),
                        request.recovery_id.as_str(),
                        work.lease_owner_id.as_str(),
                        to_i64(work.lease_expires_at_unix_ms)?,
                        to_i64(work.fencing_token)?,
                        lease_body_hash.as_slice()
                    ],
                )
                .map_err(sqlite_error)?;
            ResponseDispatchRecoveryOutcome::Takeover(work)
        };
        record_response_dispatch_recovery(&transaction, request, &request_hash, &outcome)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(outcome)
    }
}

include!("part_06_response_helpers.inc");
