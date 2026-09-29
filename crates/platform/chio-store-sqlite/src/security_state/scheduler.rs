use super::canonical_json_bytes;
use super::ActionId;
use super::ErrorCode;
use super::LeaseOwnerId;
use super::PortError;
use super::PortResult;
use super::RecordId;
use super::ResponseDispatchKey;
use super::ResponsePlanRecord;
use super::ResponseScheduledMutationCasRequest;
use super::ResponseSchedulerStore;
use super::ScheduledWork;
use super::SchedulerClaimRequest;
use super::SchedulerHealthAckRequest;
use super::SchedulerLeaseReleaseRequest;
use super::SchedulerLeaseRenewRequest;
use super::SchedulerRetryRequest;
use super::SchedulerRetryState;
use super::SchedulerWorkKey;
use super::TenantId;
use super::ResponseMutationRecord;
use super::ResponseState;
use super::ResponseTransitionCause;
use super::params;
use super::Connection;
use super::OptionalExtension;
use super::Transaction;
use super::TransactionBehavior;
use super::Serialize;
use super::SqliteSecurityStateStore;
# [cfg (target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::sqlite_error;
use super::to_i64;
use super::from_i64;
use super::body_hash;
use super::validate_canonical_json_body;
use super::canonical_request_hash;
use super::load_response_dispatch;
use super::decode_response_snapshot;
use super::response_mutation_scheduler_fence;
use super::load_response_plan;
use super::transition_status;
use super::record_transition;

pub(super) const MAX_SCHEDULER_CLAIMS: u32 = 1_024;
pub(super) const MAX_CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Serialize)]
pub(super) struct SchedulerLeaseBody<'a> {
    schema_version: u32,
    tenant_id: &'a str,
    action_id: &'a str,
    claim_id: &'a str,
    claim_ordinal: u64,
    lease_owner_id: &'a str,
    lease_expires_at_unix_ms: u64,
    fencing_token: u64,
}

pub(super) fn scheduler_lease_body_hash(
    tenant_id: &str,
    action_id: &str,
    claim_id: &str,
    claim_ordinal: u64,
    lease_owner_id: &str,
    lease_expires_at_unix_ms: u64,
    fencing_token: u64,
) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(&SchedulerLeaseBody {
        schema_version: 1,
        tenant_id,
        action_id,
        claim_id,
        claim_ordinal,
        lease_owner_id,
        lease_expires_at_unix_ms,
        fencing_token,
    })
    .map_err(|_| PortError::integrity_failure())?;
    Ok(body_hash(canonical.as_ref()))
}

pub(super) fn load_valid_scheduler_lease(
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
                    i64::from(max_leases)
                        .checked_add(1)
                        .ok_or_else(PortError::invalid_data)?,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut durable_leases = Vec::new();
        for row in rows {
            durable_leases.push(row.map_err(sqlite_error)?);
        }
        drop(statement);
        let terminal_remaining = durable_leases.len() > crate::integer::checked::<_, usize>(max_leases)?;
        durable_leases.truncate(crate::integer::checked::<_, usize>(max_leases)?);
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

impl ResponseSchedulerStore for SqliteSecurityStateStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        let connection = self.connection()?;
        load_scheduler_retry(&connection, key)
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        validate_scheduler_work(&transaction, work, trusted_now)?;
        transaction.commit().map_err(sqlite_error)
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
            && candidate_mutations.get(..current_mutations.len()) == Some(current_mutations);
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
                && durable_mutations.get(..candidate_mutations.len()) == Some(candidate_mutations);
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        validate_scheduler_lease_binding(
            &transaction,
            tenant_id.as_str(),
            action_id.as_str(),
            lease_owner_id,
            fencing_token,
            trusted_now,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        if request.lease_expires_at_unix_ms <= request.work.lease_expires_at_unix_ms {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
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

pub(super) fn load_scheduler_retry(
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

pub(super) fn load_scheduler_lease(
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
    let stored = load_valid_scheduler_lease(
        connection,
        &work.tenant_id,
        work.action_id.as_str(),
        trusted_now_unix_ms,
        true,
    )?
    .ok_or_else(PortError::conflict)?;
    if stored != *work {
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

pub(super) fn load_scheduler_claim(
    connection: &Connection,
    request: &SchedulerClaimRequest,
    request_hash: &[u8; 32],
    trusted_now: u64,
) -> PortResult<Option<Vec<ScheduledWork>>> {
    type StoredClaim = (Vec<u8>, String, i64, i64, i64);
    let stored: Option<StoredClaim> = connection
        .query_row(
            r#"
            SELECT request_hash, lease_owner_id, lease_expires_at,
                   result_count, committed_at
            FROM security_scheduler_claims
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            params![request.tenant_id.as_str(), request.claim_id.as_str()],
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
    let Some((stored_hash, stored_owner, stored_expiry, stored_count, committed_at)) = stored
    else {
        return Ok(None);
    };
    let stored_expiry = from_i64(stored_expiry)?;
    if committed_at < 0 {
        return Err(PortError::integrity_failure());
    }
    let committed_at = from_i64(committed_at)?;
    if stored_hash.as_slice() != request_hash
        || stored_owner != request.lease_owner_id.as_str()
        || stored_expiry != request.lease_expires_at_unix_ms
    {
        return Err(PortError::conflict());
    }
    if committed_at > trusted_now || committed_at >= stored_expiry {
        return Err(PortError::integrity_failure());
    }
    let expected_count =
        usize::try_from(from_i64(stored_count)?).map_err(|_| PortError::integrity_failure())?;
    let requested_limit =
        usize::try_from(request.max_claims).map_err(|_| PortError::integrity_failure())?;
    if expected_count > requested_limit {
        return Err(PortError::integrity_failure());
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT action_id, claim_ordinal, lease_owner_id,
                   lease_expires_at, fencing_token
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
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut stored_work = Vec::with_capacity(expected_count);
    for row in rows {
        let (action_id, claim_ordinal, lease_owner_id, lease_expires_at, fencing_token) =
            row.map_err(sqlite_error)?;
        stored_work.push((
            action_id,
            claim_ordinal,
            lease_owner_id,
            lease_expires_at,
            fencing_token,
        ));
    }
    drop(statement);
    if stored_work.len() < expected_count {
        return Err(PortError::conflict());
    }
    if stored_work.len() > expected_count {
        return Err(PortError::integrity_failure());
    }
    let mut claimed = Vec::with_capacity(expected_count);
    for (expected_ordinal, row) in stored_work.into_iter().enumerate() {
        let (action_id, claim_ordinal, lease_owner_id, lease_expires_at, fencing_token) = row;
        let claim_ordinal = from_i64(claim_ordinal)?;
        if claim_ordinal
            != u64::try_from(expected_ordinal).map_err(|_| PortError::integrity_failure())?
            || lease_owner_id != request.lease_owner_id.as_str()
            || from_i64(lease_expires_at)? < stored_expiry
        {
            return Err(PortError::integrity_failure());
        }
        let work = ScheduledWork {
            tenant_id: request.tenant_id.clone(),
            action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
            lease_owner_id: request.lease_owner_id.clone(),
            lease_expires_at_unix_ms: from_i64(lease_expires_at)?,
            fencing_token: from_i64(fencing_token)?,
        };
        let validated = load_valid_scheduler_lease(
            connection,
            &work.tenant_id,
            work.action_id.as_str(),
            trusted_now,
            true,
        )?
        .ok_or_else(PortError::integrity_failure)?;
        if validated != work {
            return Err(PortError::integrity_failure());
        }
        claimed.push(work);
    }
    Ok(Some(claimed))
}

pub(super) fn next_scheduler_fencing_token(transaction: &Transaction<'_>, tenant_id: &str) -> PortResult<u64> {
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

pub(super) fn validate_scheduler_fence(
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

pub(super) fn validate_scheduler_lease_binding(
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
