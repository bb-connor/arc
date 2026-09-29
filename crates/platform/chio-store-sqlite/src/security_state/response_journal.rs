use super::validate_response_snapshot_lifecycle;
use super::ActionId;
use super::CanonicalBody;
use super::CreateOutcome;
use super::EffectId;
use super::LeaseOwnerId;
use super::OpaqueReceiptRef;
use super::PortError;
use super::PortResult;
use super::RecordId;
use super::ResponseCasRequest;
use super::ResponseEffectCasRequest;
use super::ResponseEffectKey;
use super::ResponseEffectRecord;
use super::ResponsePlanKey;
use super::ResponsePlanRecord;
use super::ResponseReceiptCursor;
use super::ResponseReceiptCursorCasRequest;
use super::ResponseStore;
use super::ScheduledWork;
use super::SchedulerClaimRequest;
use super::LINEAGE_FENCE_RENEWAL_MARGIN_MS;
use super::ResponseMutationRecord;
use super::ResponseSnapshot;
use super::RESPONSE_STATE_SCHEMA_VERSION;
use super::params;
use super::Connection;
use super::OptionalExtension;
use super::TransactionBehavior;
use super::SqliteSecurityStateStore;
# [cfg (target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::sqlite_error;
use super::to_i64;
use super::from_i64;
use super::validate_canonical_json_body;
use super::decode_digest;
use super::canonical_request_hash;
use super::validate_encrypted_blob_reference;
use super::MAX_SCHEDULER_CLAIMS;
use super::MAX_CLOCK_SKEW_MS;
use super::scheduler_lease_body_hash;
use super::load_valid_scheduler_lease;
use super::load_scheduler_claim;
use super::next_scheduler_fencing_token;
use super::validate_scheduler_fence;
use super::validate_scheduler_lease_binding;
use super::transition_status;
use super::record_transition;


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
            && candidate_mutations.get(..current_mutations.len()) == Some(current_mutations);
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        if request.max_claims == 0 || request.max_claims > MAX_SCHEDULER_CLAIMS {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        let renewal_cutoff = trusted_now
            .checked_add(LINEAGE_FENCE_RENEWAL_MARGIN_MS)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(chio_security_types::clock::ClockError::Overflow)?;
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
                    renewal_cutoff,
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
                        renewal_cutoff,
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
                    to_i64(crate::integer::count(claimed.len()))?,
                    trusted_now_sql
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(claimed)
    }
}

pub(super) fn decode_response_snapshot(record: &ResponsePlanRecord) -> PortResult<ResponseSnapshot> {
    validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
    let snapshot: ResponseSnapshot = chio_core::canonical::UntrustedJsonText::from_wire(
        record.canonical_body.as_bytes(),
        64 * 1024 * 1024,
    )
    .and_then(|input| input.decode_signed())
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

pub(super) fn response_mutation_scheduler_fence(
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

pub(super) fn load_response_plan(
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
