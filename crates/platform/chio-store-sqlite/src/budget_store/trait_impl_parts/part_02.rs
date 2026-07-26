include!("main_extensions.inc");

impl BudgetStore for SqliteBudgetStore {
    fn authority_profile(&self) -> chio_kernel::BudgetStoreProfile {
        self.authority_profile
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn supports_durable_atomic_payment_journal(&self) -> bool {
        self.authority_profile == chio_kernel::BudgetStoreProfile::SingleNodeDurable
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_increment_with_event_id(capability_id, grant_index, max_invocations, None)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        Ok(self
            .try_charge_cost_with_ids_and_authority_outcome(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
                authority,
            )?
            .allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReverseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            let event_id = event_id.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "reverse replay matched an event without event_id".to_string(),
                )
            })?;
            let (event_seq, usage_seq) = transaction.query_row(
                r#"
                SELECT event_seq, usage_seq
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    Ok((
                        budget_u64_from_row(row, 0, "reverse event sequence")?,
                        optional_budget_u64_from_row(row, 1, "reverse usage sequence")?,
                    ))
                },
            )?;
            if usage_seq != Some(event_seq) {
                return Err(BudgetStoreError::Invariant(format!(
                    "reverse event `{event_id}` does not own its usage transition"
                )));
            }
            let live_projection = transaction
                .query_row(
                    r#"
                    SELECT invocation_count, total_cost_exposed,
                           total_cost_realized_spend, seq
                    FROM capability_grant_budgets
                    WHERE capability_id = ?1 AND grant_index = ?2
                    "#,
                    params![capability_id, grant_index as i64],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "invocation_count")?,
                            budget_u64_from_row(row, 1, "total_cost_exposed")?,
                            budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                            budget_u64_from_row(row, 3, "legacy projection sequence")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "reverse event `{event_id}` lost its legacy projection"
                    ))
                })?;
            checked_committed_cost_units(live_projection.1, live_projection.2)?;
            let quota_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
            let persisted_maximum = transaction
                .query_row(
                    r#"
                    SELECT max_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![
                        quota_key.profile().as_str(),
                        quota_key.owner_id(),
                        grant_index as i64,
                    ],
                    |row| budget_u32_from_row(row, 0, "quota max_invocations"),
                )
                .optional()?;
            let maximum = if let Some(maximum) = persisted_maximum {
                maximum
            } else {
                SqliteBudgetStore::compatibility_invocation_quota_maximum(
                    &transaction,
                    capability_id,
                    grant_index,
                )?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "reverse event `{event_id}` lost its invocation quota"
                    ))
                })?
            };
            let compatibility_quota =
                BudgetInvocationQuota::from_persisted_parts(quota_key, maximum)?;
            SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                &transaction,
                std::slice::from_ref(&compatibility_quota),
                compatibility_quota.key(),
                live_projection.0,
                SqliteInvocationQuotaMutationContext {
                    mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                    action: SqliteInvocationQuotaMutationAction::Replay,
                    event_seq: live_projection.3.max(event_seq),
                    updated_at: unix_now(),
                },
            )?;
            if let Some(hold_id) = hold_id {
                let hold =
                    SqliteBudgetStore::load_hold(&transaction, hold_id)?.ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "reverse event `{event_id}` lost budget hold `{hold_id}`"
                        ))
                    })?;
                if hold.disposition != HoldDisposition::Reversed
                    || hold.remaining_exposure_units != 0
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "reverse event `{event_id}` diverged from budget hold `{hold_id}`"
                    )));
                }
            }
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend, seq
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                        budget_u64_from_row(row, 3, "legacy projection sequence")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend, projection_seq)) =
            current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_exposed".to_string(),
            ));
        }
        let compatibility_maximum = SqliteBudgetStore::compatibility_invocation_quota_maximum(
            &transaction,
            capability_id,
            grant_index,
        )?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "missing compatibility invocation quota during reversal".to_string(),
            )
        })?;

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        let updated_at = unix_now();
        let compatibility_quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant(capability_id, grant_index)?,
            compatibility_maximum,
        )?;
        SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&compatibility_quota),
            compatibility_quota.key(),
            invocation_count,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Replay,
                event_seq: projection_seq,
                updated_at,
            },
        )?;
        let quota_mutation = SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&compatibility_quota),
            compatibility_quota.key(),
            invocation_count,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Reverse,
                event_seq: seq,
                updated_at,
            },
        )?;
        let invocation_count_after = quota_mutation.primary_count_after;
        SqliteBudgetStore::compare_and_persist_legacy_projection(
            &transaction,
            SqliteLegacyProjectionMutation {
                capability_id,
                grant_index,
                expected: Some(SqliteLegacyProjectionState {
                    invocation_count,
                    total_cost_exposed,
                    total_cost_realized_spend,
                    seq: projection_seq,
                }),
                after: SqliteLegacyProjectionState {
                    invocation_count: invocation_count_after,
                    total_cost_exposed: new_total_cost_exposed,
                    total_cost_realized_spend,
                    seq,
                },
                updated_at,
            },
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reversed,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReverseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count_after,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units < cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
            let remaining = hold.remaining_exposure_units - cost_units;
            let disposition = if remaining == 0 {
                HoldDisposition::Released
            } else {
                HoldDisposition::Open
            };
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                remaining,
                disposition,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReconcileSpend,
            capability_id,
            grant_index,
            hold_id,
            authority,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle more exposure than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - exposed_cost_units;
        let new_total_cost_realized_spend = total_cost_realized_spend
            .checked_add(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_cost_units overflowed u64".to_string(),
                )
            })?;

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
                new_total_cost_realized_spend as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reconciled,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReconcileSpend,
            None,
            seq,
            Some(seq),
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            new_total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request
            .invocation_admission_evidence()
            .is_some_and(|evidence| evidence.partition_escrow_evidence().is_some())
        {
            return Err(BudgetStoreError::Invariant(
                "direct SQLite budget authority cannot admit partition escrow evidence".to_string(),
            ));
        }
        if request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "snapshot-derived authorization requires the committed replay operation"
                    .to_string(),
            ));
        }
        validate_payment_journal_authorization_binding(
            request.payment_journal.as_ref(),
            request.admission_operation.as_ref(),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.requested_exposure_units,
        )?;
        let payment_journal = request.payment_journal.clone();
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            let (input, aggregate_family_evidence) = sqlite_composite_authorize_parts(&request)?;
            return self.authorize_composite_hold_with_journal(
                input,
                aggregate_family_evidence,
                payment_journal.as_ref(),
            );
        }
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::AuthorizeExposure,
        );
        self.try_charge_cost_with_ids_authority_and_journal_outcome(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
            payment_journal.as_ref(),
        )?;
        load_authorize_decision_for_event(self, &event_id)
    }

    fn replay_budget_authorization(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request
            .invocation_admission_evidence()
            .is_some_and(|evidence| evidence.partition_escrow_evidence().is_some())
        {
            return Err(BudgetStoreError::Invariant(
                "direct SQLite budget authority cannot replay partition escrow evidence"
                    .to_string(),
            ));
        }
        if !request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires a snapshot-derived authorization request".to_string(),
            ));
        }
        if request.payment_journal.is_some() {
            return Err(BudgetStoreError::Invariant(
                "committed authorization replay must not create a payment journal row".to_string(),
            ));
        }
        let (input, aggregate_family_evidence) = sqlite_composite_authorize_parts(&request)?;
        self.replay_composite_hold(input, aggregate_family_evidence)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_composite_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        self.query_composite_invocation_capture(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        if self.has_composite_authorization(request.hold_id.as_deref())? {
            return self.reverse_composite_budget_hold(request);
        }
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReverseExposure,
        );
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReverseExposure,
            BudgetMonetaryHoldState::Reversed,
        )
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        if self.has_composite_authorization(request.hold_id.as_deref())? {
            return self.release_composite_budget_hold(request);
        }
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReleaseExposure,
        );
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReleaseExposure,
            BudgetMonetaryHoldState::Released,
        )
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        if self.has_composite_authorization(request.hold_id.as_deref())? {
            return self.settle_composite_budget_hold(request, false);
        }
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReconcileSpend,
        );
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryHoldState::Reconciled,
        )
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        if self.has_composite_authorization(request.hold_id.as_deref())? {
            return self.settle_composite_budget_hold(request, true);
        }
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        let grant_index_i64 = i64::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Overflow("budget grant index exceeds SQLite INTEGER".to_string())
        })?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            request.event_id.as_deref(),
            BudgetMutationKind::CaptureExposure,
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.exposed_cost_units,
            request.realized_spend_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "captured budget retry is missing its persisted event_id".to_string(),
                )
            })?;
            let record = SqliteBudgetStore::load_mutation_event(&transaction, event_id)?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "captured budget event `{event_id}` disappeared during retry"
                    ))
                })?;
            transaction.rollback()?;
            return capture_decision_from_record(self, &record);
        }

        if let Some(hold_id) = request.hold_id.as_deref() {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                &request.capability_id,
                request.grant_index,
            )?;
            if hold.remaining_exposure_units != request.exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match captured exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                request.authority.as_ref(),
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![request.capability_id, grant_index_i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };
        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot capture charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < request.exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot capture more exposure than total_cost_exposed".to_string(),
            ));
        }

        let total_cost_exposed_after = total_cost_exposed - request.exposed_cost_units;
        let total_cost_realized_spend_after = total_cost_realized_spend
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_spend_units overflowed u64".to_string(),
                )
            })?;
        let committed_cost_units_after = checked_committed_cost_units(
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        let seq = allocate_budget_replication_seq(&transaction)?;
        let seq_i64 = i64::try_from(seq).map_err(|_| {
            BudgetStoreError::Overflow("budget sequence exceeds SQLite INTEGER".to_string())
        })?;
        let total_cost_exposed_after_i64 =
            i64::try_from(total_cost_exposed_after).map_err(|_| {
                BudgetStoreError::Overflow(
                    "captured exposure total exceeds SQLite INTEGER".to_string(),
                )
            })?;
        let total_cost_realized_spend_after_i64 = i64::try_from(total_cost_realized_spend_after)
            .map_err(|_| {
                BudgetStoreError::Overflow(
                    "captured realized spend exceeds SQLite INTEGER".to_string(),
                )
            })?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                grant_index_i64,
                unix_now(),
                seq_i64,
                total_cost_exposed_after_i64,
                total_cost_realized_spend_after_i64,
            ],
        )?;
        if let Some(hold_id) = request.hold_id.as_deref() {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    &request.capability_id,
                    request.grant_index,
                )?
                .authority
                .as_ref(),
                request.authority.as_ref(),
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Captured,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureExposure,
            None,
            seq,
            Some(seq),
            request.exposed_cost_units,
            request.realized_spend_units,
            None,
            None,
            None,
            invocation_count,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        transaction.commit()?;

        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Captured,
            revocation_set: None,
            metadata: BudgetCommitMetadata {
                authority: request.authority,
                guarantee_level: self.budget_guarantee_level(),
                budget_profile: self.budget_authority_profile(),
                metering_profile: self.budget_metering_profile(),
                budget_commit_index: Some(seq),
                event_id: request.event_id,
                partition_escrow_evidence: None,
            },
        })
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit as i64], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.connection()?
            .query_row(
                r#"
                SELECT
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch,
                operation_id,
                request_binding_hash
            FROM budget_mutation_events
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                grant_index.map(|value| value as i64),
                limit as i64
            ],
            mutation_record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let record = SqliteBudgetStore::load_exact_mutation_event(&transaction, event_id)?;
        transaction.commit()?;
        Ok(record)
    }

    sqlite_budget_store_main_extensions!();
}

include!("main_extension_helpers.inc");

fn sqlite_composite_authorize_parts(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<
    (
        SqliteCompositeAuthorizeInput,
        Option<SqliteAggregateFamilyEvidence>,
    ),
    BudgetStoreError,
> {
    if request.max_invocations.is_some() {
        return Err(BudgetStoreError::Invariant(
            "composite budget hold must not also present legacy max_invocations".to_string(),
        ));
    }
    let evidence = request.invocation_admission_evidence().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "composite budget hold requires verified invocation admission".to_string(),
        )
    })?;
    let mut authorization_artifact_digests = Vec::with_capacity(2);
    if let Some(digest) = evidence.supplemental_artifact_digest() {
        authorization_artifact_digests.push(digest.to_string());
    }
    if let Some(escrow) = evidence.partition_escrow_evidence() {
        authorization_artifact_digests.push(escrow.digest().map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "partition escrow admission evidence digest failed: {error}"
            ))
        })?);
    }
    authorization_artifact_digests.sort();
    authorization_artifact_digests.dedup();
    let aggregate_family_evidence = match (
        evidence.aggregate_root_capability_id(),
        evidence.aggregate_binding_digest(),
    ) {
        (Some(root_capability_id), Some(root_binding_digest)) => {
            Some(SqliteAggregateFamilyEvidence {
                root_capability_id: root_capability_id.to_string(),
                root_binding_digest: root_binding_digest.to_string(),
            })
        }
        (None, None) => None,
        _ => {
            return Err(BudgetStoreError::Invariant(
                "aggregate family admission evidence is incomplete".to_string(),
            ));
        }
    };
    let hold_id = request.hold_id.clone().ok_or_else(|| {
        BudgetStoreError::Invariant("composite budget hold requires hold_id".to_string())
    })?;
    let event_id = request.event_id.clone().ok_or_else(|| {
        BudgetStoreError::Invariant("composite budget hold requires event_id".to_string())
    })?;
    let admission_operation = request.admission_operation.as_ref().ok_or_else(|| {
        BudgetStoreError::Invariant(
            "composite budget hold requires an admission operation binding".to_string(),
        )
    })?;
    Ok((
        SqliteCompositeAuthorizeInput {
            operation_id: admission_operation.operation_id().to_string(),
            request_binding_hash: admission_operation.request_binding_hash().to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            requested_exposure_units: request.requested_exposure_units,
            max_cost_per_invocation: request.max_cost_per_invocation,
            max_total_cost_units: request.max_total_cost_units,
            hold_id,
            event_id,
            authority: request.authority.clone(),
            invocation_quotas: evidence.quotas().to_vec(),
            revocation_set: evidence.revocation_set().clone(),
            authorization_artifact_digests,
            partition_escrow_evidence: evidence
                .partition_escrow_evidence()
                .map(PartitionEscrowCommitEvidence::from_admission_evidence)
                .transpose()?,
        },
        aggregate_family_evidence,
    ))
}

fn effective_hold_event_id(requested: Option<&str>, kind: BudgetMutationKind) -> String {
    requested.map_or_else(
        || format!("sqlite-budget-{}-{}", kind.as_str(), uuid::Uuid::now_v7()),
        ToOwned::to_owned,
    )
}

fn load_authorize_decision_for_event(
    store: &SqliteBudgetStore,
    event_id: &str,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let record =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` disappeared after authorization"
            ))
        })?;
    transaction.rollback()?;
    authorize_decision_from_record(store, &record)
}

fn authorize_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    if record.kind != BudgetMutationKind::AuthorizeExposure {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not a persisted authorization",
            record.event_id
        )));
    }
    let allowed = record.allowed.ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "budget authorization event `{}` is missing its frozen decision",
            record.event_id
        ))
    })?;
    let committed_cost_units_after = checked_committed_cost_units(
        record.total_cost_exposed_after,
        record.total_cost_realized_spend_after,
    )?;
    let metadata = BudgetCommitMetadata {
        authority: record.authority.clone(),
        guarantee_level: store.budget_guarantee_level(),
        budget_profile: store.budget_authority_profile(),
        metering_profile: store.budget_metering_profile(),
        budget_commit_index: Some(record.event_seq),
        event_id: Some(record.event_id.clone()),
        partition_escrow_evidence: None,
    };
    if allowed {
        let monetary_state = if record.exposure_units > 0
            || record.max_cost_per_invocation.is_some()
            || record.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        Ok(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: record.hold_id.clone(),
                authorized_exposure_units: record.exposure_units,
                committed_cost_units_after,
                invocation_count_after: record.invocation_count_after,
                invocation_counts_after: record.invocation_counts_after.clone(),
                invocation_state: BudgetInvocationReservationState::Absent,
                monetary_state,
                revocation_set: record.revocation_set.clone(),
                metadata,
            },
        ))
    } else {
        Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
            hold_id: record.hold_id.clone(),
            attempted_exposure_units: record.exposure_units,
            committed_cost_units_after,
            invocation_count_after: record.invocation_count_after,
            invocation_counts_after: record.invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Denied,
            monetary_state: BudgetMonetaryHoldState::None,
            revocation_set: record.revocation_set.clone(),
            metadata,
        }))
    }
}

fn load_hold_decision_for_event(
    store: &SqliteBudgetStore,
    event_id: &str,
    expected_kind: BudgetMutationKind,
    expected_monetary_state: BudgetMonetaryHoldState,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let record =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` disappeared after its hold transition"
            ))
        })?;
    transaction.rollback()?;
    hold_decision_from_record(store, &record, expected_kind, expected_monetary_state)
}

fn hold_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
    expected_kind: BudgetMutationKind,
    expected_monetary_state: BudgetMonetaryHoldState,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    if record.kind != expected_kind || record.monetary_state != expected_monetary_state {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not the expected persisted hold transition",
            record.event_id
        )));
    }
    Ok(BudgetHoldMutationDecision {
        hold_id: record.hold_id.clone(),
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after: record.invocation_counts_after.clone(),
        invocation_state: record.invocation_state,
        monetary_state: record.monetary_state,
        revocation_set: record.revocation_set.clone(),
        metadata: BudgetCommitMetadata {
            authority: record.authority.clone(),
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: record.usage_seq,
            event_id: Some(record.event_id.clone()),
            partition_escrow_evidence: None,
        },
    })
}

fn capture_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
    if record.kind != BudgetMutationKind::CaptureExposure
        || record.monetary_state != BudgetMonetaryHoldState::Captured
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not a captured monetary hold",
            record.event_id
        )));
    }
    hold_decision_from_record(
        store,
        record,
        BudgetMutationKind::CaptureExposure,
        BudgetMonetaryHoldState::Captured,
    )
}
