#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    body_hash, canonical_json_bytes, canonical_request_hash, decode_digest,
    decode_response_snapshot, from_i64, load_response_plan, load_scheduler_lease,
    load_scheduler_retry, load_valid_scheduler_lease, next_scheduler_fencing_token, params,
    scheduler_lease_body_hash, sha256, sqlite_error, to_i64,
    validate_attested_response_execution_dispatch, validate_canonical_json_body, ActionId,
    AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRecord,
    AutomaticResponseDispatchFenceRequest, CanonicalBody, Connection, Digest32, OptionalExtension,
    PortError, PortResult, PreparedActiveResponseDispatchBinding, RecordId,
    ResponseApprovalRequirement, ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode, ResponseDispatchCommitOutcome,
    ResponseDispatchCommitRequest, ResponseDispatchKey, ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecord, ResponseDispatchRecoveryOutcome,
    ResponseDispatchRecoveryRequest, ResponseDispatchStore, ResponseMutationRecord,
    ResponsePlanRecord, ResponseSnapshot, ResponseState, ResponseTransitionCause, ScheduledWork,
    SchedulerWorkKey, SqliteSecurityStateStore, TenantId, Transaction, TransactionBehavior,
    MAX_CLOCK_SKEW_MS, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};

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
        let fenced_at_unix_ms = self.trusted_now_in_transaction(&transaction)?;
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
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        chio_core::canonical::UntrustedJsonText::from_wire(
            request.authorization.canonical_body.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
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
    let normalized_bytes =
        canonical_json_bytes(&normalized_snapshot).map_err(|_| PortError::invalid_data())?;
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
        || execution_dispatch.executor_authority_id != decoded_authorization.executor_authority_id
        || execution_dispatch.executor_authority_generation
            != decoded_authorization.executor_authority_generation
        || execution_dispatch.authorization_capability_hash
            != decoded_authorization.authorization_capability_hash
        || execution_dispatch.governed_intent_hash != decoded_authorization.governed_intent_hash
        || execution_dispatch.policy_decision_hash != decoded_authorization.policy_decision_hash
        || execution_dispatch.approval != decoded_authorization.approval
        || execution_dispatch.authorized_at_unix_ms != decoded_authorization.authorized_at_unix_ms
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
    ) && !matches!(
        (
            &snapshot.plan.approval_requirement,
            &decoded_authorization.approval,
        ),
        (
            ResponseApprovalRequirement::Governed { .. },
            ResponseDispatchApproval::Governed { .. }
        )
    ) {
        return Err(PortError::invalid_data());
    }
    validate_initial_dispatch_history(&snapshot, &decoded_authorization)?;
    Ok(snapshot)
}

pub(super) fn load_response_dispatch(
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
        chio_core::canonical::UntrustedJsonText::from_wire(
            canonical_authorization.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
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
    let binding = chio_core::canonical::UntrustedJsonText::from_wire(&body, 64 * 1024 * 1024)
        .and_then(|input| input.decode_signed::<PreparedActiveResponseDispatchBinding>())
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
