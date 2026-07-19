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
        if request.max_claims == 0
            || request.max_claims > MAX_SCHEDULER_CLAIMS
            || request.lease_expires_at_unix_ms <= trusted_now
        {
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
            let fencing_token =
                next_scheduler_fencing_token(&transaction, request.tenant_id.as_str())?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                        claim_id = excluded.claim_id,
                        claim_ordinal = excluded.claim_ordinal,
                        lease_owner_id = excluded.lease_owner_id,
                        lease_expires_at = excluded.lease_expires_at,
                        fencing_token = excluded.fencing_token
                    "#,
                    params![
                        action_id,
                        request.tenant_id.as_str(),
                        request.claim_id.as_str(),
                        to_i64(claim_ordinal as u64)?,
                        request.lease_owner_id.as_str(),
                        to_i64(request.lease_expires_at_unix_ms)?,
                        to_i64(fencing_token)?
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
            transaction.commit().map_err(sqlite_error)?;
            return Ok(request.candidate.clone());
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
        let trusted_now = self.trusted_now_unix_ms()?;
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.lease_expires_at_unix_ms <= trusted_now
            || request.lease_expires_at_unix_ms <= request.work.lease_expires_at_unix_ms
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
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_renew",
            &request_hash,
        )? {
            let renewed = load_scheduler_lease(
                &transaction,
                &SchedulerWorkKey {
                    tenant_id: request.work.tenant_id.clone(),
                    action_id: request.work.action_id.clone(),
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if renewed.lease_owner_id != request.work.lease_owner_id
                || renewed.fencing_token != request.work.fencing_token
                || renewed.lease_expires_at_unix_ms != request.lease_expires_at_unix_ms
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(renewed);
        }
        validate_scheduler_work(&transaction, &request.work, trusted_now)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_scheduler_leases
                SET lease_expires_at = ?5
                WHERE tenant_id = ?1 AND action_id = ?2 AND lease_owner_id = ?3
                  AND fencing_token = ?4
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str(),
                    request.work.lease_owner_id.as_str(),
                    to_i64(request.work.fencing_token)?,
                    to_i64(request.lease_expires_at_unix_ms)?
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
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.not_before_unix_ms <= trusted_now
            || request.first_failure_at_unix_ms > request.now_unix_ms
        {
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
            let stored = load_scheduler_retry(&transaction, &key)?
                .ok_or_else(PortError::integrity_failure)?;
            if stored.attempts != next_attempts
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
                .ok_or_else(PortError::integrity_failure)?;
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
        )
        {
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
            return Ok(AutomaticResponseDispatchFenceOutcome::ExistingFence(existing));
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
        if load_response_dispatch_commit_mode(
            &transaction,
            &request.authorization.body.key,
        )?
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
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token
                    ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6)
                    "#,
                    params![
                        initial_work.action_id.as_str(),
                        initial_work.tenant_id.as_str(),
                        request.authorization.body.key.dispatch_id.as_str(),
                        initial_work.lease_owner_id.as_str(),
                        to_i64(initial_work.lease_expires_at_unix_ms)?,
                        to_i64(initial_work.fencing_token)?
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
        if let Some(existing) =
            load_response_dispatch_recovery(&transaction, request, &request_hash)?
        {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
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
        let trusted_now = self.trusted_now_unix_ms()?;
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
            if request.lease_owner_id != live.lease_owner_id
                || expected_fencing_token != live.fencing_token
            {
                return Err(PortError::conflict());
            }
            ResponseDispatchRecoveryOutcome::LiveLease(live.clone())
        } else {
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
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token
                    ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6)
                    ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                        claim_id = excluded.claim_id,
                        claim_ordinal = excluded.claim_ordinal,
                        lease_owner_id = excluded.lease_owner_id,
                        lease_expires_at = excluded.lease_expires_at,
                        fencing_token = excluded.fencing_token
                    "#,
                    params![
                        work.action_id.as_str(),
                        work.tenant_id.as_str(),
                        request.recovery_id.as_str(),
                        work.lease_owner_id.as_str(),
                        to_i64(work.lease_expires_at_unix_ms)?,
                        to_i64(work.fencing_token)?
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
