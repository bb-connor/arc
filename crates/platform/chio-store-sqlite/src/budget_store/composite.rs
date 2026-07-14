use super::*;
use rusqlite::{params, Connection, Transaction};

mod cumulative_model;
mod event_projection;
mod model;
mod transitions;
mod validation;

use cumulative_model::*;
use model::*;
use transitions::*;
use validation::*;

impl SqliteBudgetStore {
    pub(crate) fn composite_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let usage = load_quota_state(&transaction, key)?.map(|state| state.usage());
        transaction.rollback()?;
        Ok(usage)
    }

    pub(crate) fn composite_cumulative_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        self.cumulative_approval_operation_projection(operation_id)
            .map(|projection| projection.map(|(usage, _)| usage))
    }

    /// Returns an operation's latest cumulative usage and durable mutation event.
    pub fn cumulative_approval_operation_projection(
        &self,
        operation_id: &str,
    ) -> Result<Option<(BudgetCumulativeApprovalUsage, BudgetMutationRecord)>, BudgetStoreError>
    {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .query_row(
                r#"
                SELECT operation.operation_id, (
                    SELECT event.event_id
                    FROM budget_event_cumulative_approval AS cumulative
                    JOIN budget_mutation_events AS event
                      ON event.event_id = cumulative.event_id
                    WHERE cumulative.operation_id = operation.operation_id
                    ORDER BY event.event_seq DESC
                    LIMIT 1
                )
                FROM budget_cumulative_approval_operations AS operation
                WHERE operation.operation_id = ?1
                "#,
                params![operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((stored_operation_id, event_id)) = row else {
            transaction.rollback()?;
            return Ok(None);
        };
        let event_id = event_id.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "cumulative approval operation `{stored_operation_id}` has no durable event"
            ))
        })?;
        let event =
            Self::load_projected_mutation_event(&transaction, &event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "cumulative approval operation `{stored_operation_id}` lost its event"
                ))
            })?;
        let usage = event
            .cumulative_approval
            .clone()
            .filter(|usage| usage.operation_id == stored_operation_id)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "cumulative approval operation `{stored_operation_id}` lost its projection"
                ))
            })?;
        transaction.rollback()?;
        Ok(Some((usage, event)))
    }

    pub(super) fn authorize_composite_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        request.validate()?;
        let quotas = normalized_quotas(&request)?;
        validate_composite_sqlite_range(&request, &quotas)?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget hold_id is missing".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget event_id is missing".to_string())
        })?;
        let admission = request.admission_binding.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite admission binding is missing".to_string())
        })?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(existing) = Self::load_mutation_event(&transaction, event_id)? {
            let stored = load_authorization_request(&transaction, &existing)?;
            self.validate_persisted_authority(
                &transaction,
                event_id,
                stored.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            let mut normalized_request = request.clone();
            normalized_request.authority = stored.authority.clone();
            if self.serving_owner.is_some() {
                normalized_request
                    .admission_binding
                    .as_mut()
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "composite authorization replay lost admission binding".to_string(),
                        )
                    })?
                    .last_observed_revocation = stored
                    .admission_binding
                    .as_ref()
                    .and_then(|binding| binding.last_observed_revocation.clone());
            }
            if stored != normalized_request {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{event_id}` was reused for a different mutation"
                )));
            }
            let decision = self.authorization_decision_from_event(&transaction, &existing)?;
            transaction.rollback()?;
            return Ok(decision);
        }
        let grant_quota_index = i64::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("grant_index does not fit sqlite range".to_string())
        })?;
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("grant_index does not fit quota range".to_string())
        })?;
        let durable_grant_quota_exists = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_invocation_quotas
                WHERE profile = 'chio.grant-invocation.v1'
                  AND owner_id = ?1 AND grant_index = ?2
            )
            "#,
            params![&request.capability_id, grant_quota_index],
            |row| row.get::<_, bool>(0),
        )?;
        let request_includes_grant_quota = quotas.iter().any(|quota| {
            quota.key == BudgetQuotaKey::grant(request.capability_id.clone(), grant_index)
        });
        let legacy_grant_limit =
            legacy_grant_quota_limit(&transaction, &request.capability_id, request.grant_index)?;
        if durable_grant_quota_exists && !request_includes_grant_quota {
            return Err(BudgetStoreError::Invariant(format!(
                "structured authorization omitted durable grant quota for `{}` grant {}",
                request.capability_id, request.grant_index
            )));
        }
        if let Some(legacy_limit) = legacy_grant_limit {
            let requested = quotas.iter().find(|quota| {
                quota.key == BudgetQuotaKey::grant(request.capability_id.clone(), grant_index)
            });
            if requested.map(|quota| quota.max_invocations) != Some(legacy_limit) {
                return Err(BudgetStoreError::Invariant(format!(
                    "structured authorization must preserve legacy grant quota {legacy_limit} for `{}` grant {}",
                    request.capability_id, request.grant_index
                )));
            }
        }
        let hold_identity_exists = Self::load_hold(&transaction, hold_id)?.is_some()
            || transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE hold_id = ?1)",
                params![hold_id],
                |row| row.get::<_, bool>(0),
            )?;
        if hold_identity_exists {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` was reused for a different authorization"
            )));
        }
        self.validate_observed_revocation(&transaction, admission)?;
        let mut revoked_member = false;
        if self.serving_owner.is_some() {
            for capability_id in admission.revocation_set.ids() {
                revoked_member |= transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                    params![capability_id],
                    |row| row.get::<_, bool>(0),
                )?;
            }
        }
        let operation_exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE operation_id = ?1)",
            params![&admission.operation_id],
            |row| row.get::<_, bool>(0),
        )?;
        if operation_exists {
            return Err(BudgetStoreError::Invariant(format!(
                "budget operation `{}` was reused for a different authorization",
                admission.operation_id
            )));
        }

        let current =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        let committed = checked_committed_cost_units(
            current.total_cost_exposed,
            current.total_cost_realized_spend,
        )?;
        let requested_total = committed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let mut allowed = !revoked_member
            && request
                .max_cost_per_invocation
                .is_none_or(|max| request.requested_exposure_units <= max)
            && request
                .max_total_cost_units
                .is_none_or(|max| requested_total <= max);
        let mut quota_before = Vec::with_capacity(quotas.len());
        for quota in &quotas {
            let state = load_quota_state(&transaction, &quota.key)?;
            match state {
                Some(state) => {
                    if state.maximum != quota.max_invocations {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget quota `{}` maximum changed from {} to {}",
                            quota.key.owner_id, state.maximum, quota.max_invocations
                        )));
                    }
                    let used = state.reserved.checked_add(state.captured).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved + captured quota count overflowed u32".to_string(),
                        )
                    })?;
                    allowed &= used < state.maximum;
                    quota_before.push(state);
                }
                None => {
                    let is_grant_quota = quota.key
                        == BudgetQuotaKey::grant(request.capability_id.clone(), grant_index);
                    let mut state = QuotaState::new(quota);
                    if is_grant_quota && current.invocation_count != 0 {
                        if legacy_grant_limit != Some(quota.max_invocations) {
                            return Err(BudgetStoreError::Invariant(
                                "cannot define a grant quota after untracked invocations"
                                    .to_string(),
                            ));
                        }
                        if current.invocation_count > quota.max_invocations {
                            return Err(BudgetStoreError::Invariant(format!(
                                "legacy usage for `{}` grant {} exceeds its grant quota",
                                request.capability_id, request.grant_index
                            )));
                        }
                        state.captured = current.invocation_count;
                    }
                    allowed &= state.captured < quota.max_invocations;
                    quota_before.push(state);
                }
            }
        }

        let cumulative_before = request
            .cumulative_approval
            .as_ref()
            .map(|cumulative| load_or_validate_cumulative(&transaction, cumulative))
            .transpose()?;
        let cumulative_state = request
            .cumulative_approval
            .as_ref()
            .zip(cumulative_before.as_ref())
            .map(|(cumulative, account)| {
                let prospective = account
                    .reserved
                    .checked_add(account.captured)
                    .and_then(|used| used.checked_add(cumulative.requested_authorized.units))
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "cumulative authorized units overflowed u64".to_string(),
                        )
                    })?;
                Ok::<_, BudgetStoreError>(if prospective >= cumulative.effective_threshold.units {
                    BudgetCumulativeApprovalState::PendingApproval
                } else {
                    BudgetCumulativeApprovalState::Authorized
                })
            })
            .transpose()?;

        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let recorded_at = unix_now();
        let mut usage_after = current.clone();
        let mut quota_after = quota_before.clone();
        let mut cumulative_after = cumulative_before.clone();
        if allowed {
            usage_after.invocation_count =
                usage_after.invocation_count.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow("invocation count overflowed u32".to_string())
                })?;
            usage_after.total_cost_exposed = usage_after
                .total_cost_exposed
                .checked_add(request.requested_exposure_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow("total cost exposure overflowed u64".to_string())
                })?;
            usage_after.updated_at = recorded_at;
            usage_after.seq = event_seq;
            write_usage(&transaction, &usage_after)?;

            Self::create_hold(
                &transaction,
                hold_id,
                &request.capability_id,
                request.grant_index,
                request.requested_exposure_units,
                request.authority.as_ref(),
            )?;
            write_hold_projection(
                &transaction,
                hold_id,
                admission,
                quotas.len(),
                cumulative_state,
                request.requested_exposure_units,
            )?;
            for (quota, state) in quotas.iter().zip(&mut quota_after) {
                state.reserved = state.reserved.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "reserved invocation quota overflowed u32".to_string(),
                    )
                })?;
                state.version = state.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "invocation quota version overflowed u64".to_string(),
                    )
                })?;
                write_quota_state(&transaction, state)?;
                write_hold_quota(&transaction, hold_id, quota)?;
            }
            write_hold_admission_members(&transaction, hold_id, admission)?;
            if let (Some(cumulative), Some(state), Some(account)) = (
                request.cumulative_approval.as_ref(),
                cumulative_state,
                cumulative_after.as_mut(),
            ) {
                account.reserved = account
                    .reserved
                    .checked_add(cumulative.requested_authorized.units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved cumulative approval overflowed u64".to_string(),
                        )
                    })?;
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                write_cumulative_account(&transaction, account)?;
                write_cumulative_operation(
                    &transaction,
                    hold_id,
                    cumulative,
                    state,
                    account.version,
                )?;
            }
        }

        let outcome = match (allowed, cumulative_state) {
            (false, _) => BudgetAuthorizationOutcome::Denied,
            (true, Some(BudgetCumulativeApprovalState::PendingApproval)) => {
                BudgetAuthorizationOutcome::ApprovalRequired
            }
            (true, _) => BudgetAuthorizationOutcome::Authorized,
        };
        let authorization_kind = if quotas.is_empty() && request.cumulative_approval.is_none() {
            BudgetMutationKind::AuthorizeExposure
        } else {
            BudgetMutationKind::ReserveInvocation
        };
        let event = Self::append_mutation_event(
            &transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            authorization_kind,
            match outcome {
                BudgetAuthorizationOutcome::Denied => Some(false),
                BudgetAuthorizationOutcome::ApprovalRequired => None,
                BudgetAuthorizationOutcome::Authorized => Some(true),
            },
            event_seq,
            allowed.then_some(usage_after.seq),
            request.requested_exposure_units,
            0,
            request.max_invocations,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            usage_after.invocation_count,
            usage_after.total_cost_exposed,
            usage_after.total_cost_realized_spend,
        )?;
        write_authorization_event_projection(
            &transaction,
            &event.event_id,
            admission,
            outcome,
            &quotas,
            &quota_before,
            &quota_after,
            request.cumulative_approval.as_ref(),
            cumulative_state,
            cumulative_before.as_ref(),
            cumulative_after.as_ref(),
            !request.invocation_quotas.is_empty(),
            request.requested_exposure_units,
        )?;
        self.append_joint_commit(&transaction, authorization_kind, event_id, event_seq)?;
        let decision = authorization_decision(
            self,
            request,
            outcome,
            event_seq,
            usage_after,
            quota_after,
            cumulative_state,
            cumulative_after,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(decision)
    }

    fn authorization_decision_from_event(
        &self,
        transaction: &Transaction<'_>,
        event: &BudgetMutationRecord,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let hold_id = event.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite authorization lost hold_id".to_string())
        })?;
        if let Some(hold) = load_structured_hold(transaction, hold_id)? {
            if hold.invocation_state == BudgetInvocationState::Reversed {
                return Err(BudgetStoreError::Invariant(
                    "budget authorization replay references a terminally reversed hold".to_string(),
                ));
            }
            if hold.invocation_state == BudgetInvocationState::Captured {
                return captured_authorization_decision(self, transaction, &hold);
            }
        }
        let latest = latest_hold_event_seq(transaction, hold_id)?.unwrap_or(0);
        if latest != event.event_seq {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` authorization event was superseded"
            )));
        }
        decision_from_persisted_event(self, transaction, event)
    }

    fn validate_observed_revocation(
        &self,
        transaction: &Transaction<'_>,
        admission: &BudgetAdmissionBinding,
    ) -> Result<(), BudgetStoreError> {
        let Some(observation) = admission.last_observed_revocation.as_ref() else {
            return Ok(());
        };
        let owner = self.serving_owner.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "revocation commit metadata requires a joint sqlite serving owner".to_string(),
            )
        })?;
        let authority_head = transaction.query_row(
            "SELECT head_index FROM admission_authority_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let authority_head = u64::try_from(authority_head).map_err(|_| {
            BudgetStoreError::Invariant("negative sqlite authority commit index".to_string())
        })?;
        if observation.authority.authority_id != owner.fence.store_uuid
            || observation.authority.lease_epoch != owner.fence.owner_epoch
            || observation.authority.lease_id != owner.fence.lease_id
            || observation.guarantee_level != BudgetGuaranteeLevel::SingleNodeAtomic
            || observation.commit_index != authority_head
        {
            return Err(BudgetStoreError::Invariant(
                "fresh revocation commit metadata does not match the active sqlite authority head"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_joint_authority(
        &self,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let owner = self.serving_owner.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "structured sqlite mutations require a provisioned serving owner".to_string(),
            )
        })?;
        let expected = BudgetEventAuthority {
            authority_id: owner.fence.store_uuid.clone(),
            lease_id: owner.fence.lease_id.clone(),
            lease_epoch: owner.fence.owner_epoch,
        };
        if authority != Some(&expected) {
            return Err(BudgetStoreError::Invariant(
                "structured sqlite mutation authority does not match the active serving owner"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_persisted_authority(
        &self,
        connection: &Connection,
        identity: &str,
        persisted: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let Some(owner) = self.serving_owner.as_ref() else {
            SqliteBudgetStore::validate_hold_authority(identity, persisted, requested)?;
            return Ok(());
        };
        self.validate_joint_authority(requested)?;
        let Some(persisted) = persisted else {
            return Err(BudgetStoreError::Invariant(format!(
                "budget authority record `{identity}` has no serving-owner fence"
            )));
        };
        if persisted.authority_id != owner.fence.store_uuid {
            return Err(BudgetStoreError::Invariant(format!(
                "budget authority record `{identity}` is outside the active serving-owner fence"
            )));
        }
        crate::serving_owner::verify_historical_budget_authority(connection, persisted).map_err(
            |_| {
                BudgetStoreError::Invariant(format!(
                    "budget authority record `{identity}` is outside durable serving lease history"
                ))
            },
        )?;
        Ok(())
    }
}
