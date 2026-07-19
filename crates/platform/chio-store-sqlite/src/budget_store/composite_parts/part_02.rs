impl SqliteBudgetStore {
    pub(super) fn has_composite_authorization(
        &self,
        hold_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let Some(hold_id) = hold_id else {
            return Ok(false);
        };
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM budget_composite_authorizations WHERE hold_id = ?1",
                params![hold_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn authorize_composite_hold(
        &self,
        request: SqliteCompositeAuthorizeInput,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.authorize_composite_hold_with_optional_family_evidence(request, None)
    }

    pub fn authorize_aggregate_family_composite_hold(
        &self,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: SqliteAggregateFamilyEvidence,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.authorize_composite_hold_with_optional_family_evidence(
            request,
            Some(aggregate_family_evidence),
        )
    }

    fn authorize_composite_hold_with_optional_family_evidence(
        &self,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::authorize_composite_hold_in_transaction_with_optional_family_evidence(
            &transaction,
            request,
            aggregate_family_evidence,
        )?;
        transaction.commit()?;
        Ok(decision)
    }

    pub(super) fn authorize_composite_hold_with_journal(
        &self,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
        journal: Option<&chio_kernel::payment::PaymentJournalRecord>,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let admission_operation = BudgetAdmissionOperationBinding::new(
            request.operation_id.clone(),
            request.request_binding_hash.clone(),
        )?;
        validate_payment_journal_authorization_binding(
            journal,
            Some(&admission_operation),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            Some(&request.hold_id),
            request.requested_exposure_units,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::authorize_composite_hold_in_transaction_with_optional_family_evidence(
            &transaction,
            request,
            aggregate_family_evidence,
        )?;
        if matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)) {
            if let Some(journal) = journal {
                insert_payment_journal_tx(&transaction, journal, true)?;
            }
        }
        transaction.commit()?;
        Ok(decision)
    }

    pub fn authorize_composite_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        Self::authorize_composite_hold_in_transaction_with_optional_family_evidence(
            transaction,
            request,
            None,
        )
    }

    pub fn authorize_aggregate_family_composite_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: SqliteAggregateFamilyEvidence,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        Self::authorize_composite_hold_in_transaction_with_optional_family_evidence(
            transaction,
            request,
            Some(aggregate_family_evidence),
        )
    }

    fn authorize_composite_hold_in_transaction_with_optional_family_evidence(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_authorize_composite_hold", || {
            Self::authorize_composite_hold_in_transaction_unchecked(
                transaction,
                request,
                aggregate_family_evidence,
            )
        })
    }

    fn authorize_composite_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        validate_composite_input(&request, aggregate_family_evidence.as_ref())?;

        if let Some(existing) = load_composite_authorization(transaction, &request.hold_id)? {
            let admission_operation = BudgetAdmissionOperationBinding::new(
                request.operation_id.clone(),
                request.request_binding_hash.clone(),
            )?;
            existing.admission_operation.validate_parts(
                &request.operation_id,
                &request.request_binding_hash,
                "composite authorization",
            )?;
            load_mutation_admission_operation(transaction, &existing.event_id)?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "composite authorization event `{}` omits admission ownership",
                        existing.event_id
                    ))
                })?
                .validate_binding(&admission_operation, "composite authorization event")?;
            load_composite_mutation_state(transaction, &existing.event_id)?
                .admission_operation
                .validate_binding(&admission_operation, "composite authorization snapshot")?;
            if existing.allowed {
                let base_hold = SqliteBudgetStore::load_hold(transaction, &request.hold_id)?
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "missing base budget hold `{}` for composite authorization",
                            request.hold_id
                        ))
                    })?;
                validate_base_hold_admission_operation(&base_hold, &admission_operation)?;
                load_composite_hold(transaction, &request.hold_id)?
                    .admission_operation
                    .validate_binding(&admission_operation, "composite hold")?;
            }
            if !existing.matches(&request, aggregate_family_evidence.as_ref()) {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{}` was reused for a different composite authorization",
                    request.hold_id
                )));
            }
            let decision = existing.into_decision();
            return Ok(decision);
        }
        if let Some(existing_hold_id) = transaction
            .query_row(
                "SELECT hold_id FROM budget_composite_authorizations WHERE event_id = ?1",
                params![request.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{}` is already claimed by hold `{existing_hold_id}`",
                request.event_id
            )));
        }
        if let Some(existing_hold_id) = transaction
            .query_row(
                "SELECT hold_id FROM budget_composite_authorizations WHERE operation_id = ?1 LIMIT 1",
                params![request.operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            if existing_hold_id != request.hold_id {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget operation_id `{}` is already claimed by hold `{existing_hold_id}`",
                    request.operation_id
                )));
            }
        }
        reject_legacy_namespace_collisions(transaction, &request)?;

        let legacy_usage = load_legacy_usage(transaction, &request)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged = Vec::with_capacity(request.invocation_quotas.len());
        let mut quota_exhausted = false;
        for quota in &request.invocation_quotas {
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let stored = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?;
            let (reserved, captured, exists) = match stored {
                Some((maximum, reserved, captured)) => {
                    if maximum != quota.max_invocations() {
                        return Err(BudgetStoreError::Conflict(format!(
                            "invocation quota `{}` was presented with a different maximum",
                            quota.key().owner_id()
                        )));
                    }
                    (reserved, captured, true)
                }
                None => (
                    0,
                    if quota.key() == &primary_key {
                        legacy_usage.0
                    } else {
                        0
                    },
                    false,
                ),
            };
            let count = reserved.checked_add(captured).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved invocations + captured invocations overflowed u32".to_string(),
                )
            })?;
            if count > quota.max_invocations() {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key().owner_id()
                )));
            }
            if count == quota.max_invocations() {
                quota_exhausted = true;
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved,
                captured,
                exists,
            });
        }
        let primary_before = staged
            .iter()
            .find(|entry| entry.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .reserved
            .checked_add(
                staged
                    .iter()
                    .find(|entry| entry.quota.key() == &primary_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant("missing primary quota counter".to_string())
                    })?
                    .captured,
            )
            .ok_or_else(|| {
                BudgetStoreError::Overflow("primary invocation count overflowed u32".to_string())
            })?;
        if primary_before != legacy_usage.0 {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite invocation quota".to_string(),
            ));
        }

        let committed_before = checked_committed_cost_units(legacy_usage.1, legacy_usage.2)?;
        let committed_if_allowed = committed_before
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let exposed_if_allowed = legacy_usage
            .1
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total exposed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let monetary_denied = request
            .max_cost_per_invocation
            .is_some_and(|maximum| request.requested_exposure_units > maximum)
            || request
                .max_total_cost_units
                .is_some_and(|maximum| committed_if_allowed > maximum);
        let allowed = !quota_exhausted && !monetary_denied;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();

        if allowed {
            for entry in &mut staged {
                entry.reserved = entry.reserved.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "reserved invocation count overflowed u32".to_string(),
                    )
                })?;
            }
        }
        persist_quota_rows(transaction, &staged, event_seq, now)?;

        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        for usage in &invocation_counts_after {
            usage.validate()?;
        }
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Authorized
        } else {
            BudgetInvocationReservationState::Denied
        };
        let monetary_present = request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some();
        let monetary_state = if allowed && monetary_present {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let committed_cost_units_after = if allowed {
            committed_if_allowed
        } else {
            committed_before
        };
        let exposed_after = if allowed {
            exposed_if_allowed
        } else {
            legacy_usage.1
        };

        if allowed {
            upsert_legacy_projection(
                transaction,
                &request,
                primary_count_after,
                exposed_after,
                legacy_usage.2,
                event_seq,
                now,
            )?;
            SqliteBudgetStore::create_hold_with_admission_operation(
                transaction,
                BudgetHoldCreateInput {
                    hold_id: &request.hold_id,
                    capability_id: &request.capability_id,
                    grant_index: request.grant_index,
                    authorized_exposure_units: request.requested_exposure_units,
                    authority: request.authority.as_ref(),
                    admission_operation: Some(BudgetAdmissionOperationParts::new(
                        &request.operation_id,
                        &request.request_binding_hash,
                    )),
                },
            )?;
            transaction.execute(
                r#"
                INSERT INTO budget_composite_holds (
                    hold_id, operation_id, request_binding_hash,
                    invocation_state, monetary_state,
                    revocation_set_digest, revocation_ids_json,
                    remaining_exposure_units, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    request.hold_id,
                    request.operation_id,
                    request.request_binding_hash,
                    invocation_state.as_str(),
                    monetary_state.as_str(),
                    request.revocation_set.digest(),
                    serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
                        BudgetStoreError::Invariant(format!(
                            "failed to encode canonical revocation set: {error}"
                        ))
                    })?,
                    sqlite_integer_from_u64(
                        request.requested_exposure_units,
                        "composite remaining exposure"
                    )?,
                    now,
                ],
            )?;
        }

        SqliteBudgetStore::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id: Some(&request.event_id),
                hold_id: Some(&request.hold_id),
                authority: request.authority.as_ref(),
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                kind: BudgetMutationKind::ReserveInvocations,
                allowed: Some(allowed),
                event_seq,
                usage_seq: allowed.then_some(event_seq),
                exposure_units: request.requested_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: request.max_cost_per_invocation,
                max_total_cost_units: request.max_total_cost_units,
                invocation_count_after: primary_count_after,
                total_cost_exposed_after: exposed_after,
                total_cost_realized_spend_after: legacy_usage.2,
                admission_operation: Some(BudgetAdmissionOperationParts::new(
                    &request.operation_id,
                    &request.request_binding_hash,
                )),
            },
        )?;
        persist_composite_authorization(
            transaction,
            &request,
            aggregate_family_evidence.as_ref(),
            allowed,
            invocation_state,
            monetary_state,
            committed_cost_units_after,
            primary_count_after,
            event_seq,
            now,
            &invocation_counts_after,
        )?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_managed_grants (
                capability_id, grant_index, first_hold_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(capability_id, grant_index) DO NOTHING
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                request.hold_id,
            ],
        )?;
        let metadata = composite_metadata(
            request.authority.clone(),
            allowed.then_some(event_seq),
            request.event_id.clone(),
        );
        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: Some(request.hold_id),
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: primary_count_after,
                    invocation_counts_after,
                    invocation_state,
                    monetary_state,
                    revocation_set: Some(request.revocation_set),
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: Some(request.hold_id),
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after,
                invocation_state,
                monetary_state,
                revocation_set: Some(request.revocation_set),
                metadata,
            }))
        }
    }
}

fn validate_composite_input(
    request: &SqliteCompositeAuthorizeInput,
    aggregate_family_evidence: Option<&SqliteAggregateFamilyEvidence>,
) -> Result<(), BudgetStoreError> {
    BudgetAdmissionOperationBinding::new(
        request.operation_id.clone(),
        request.request_binding_hash.clone(),
    )?;
    if request.hold_id.is_empty() || request.event_id.is_empty() {
        return Err(BudgetStoreError::Invariant(
            "composite budget authorization requires hold_id and event_id".to_string(),
        ));
    }
    if request.invocation_quotas.is_empty()
        || request.invocation_quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
    {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget authorization requires 1 to {MAX_INVOCATION_QUOTAS_PER_ADMISSION} invocation quotas"
        )));
    }
    let mut previous: Option<&BudgetQuotaKey> = None;
    let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
    let mut primary_count = 0usize;
    for quota in &request.invocation_quotas {
        quota.validate()?;
        if previous.is_some_and(|key| key >= quota.key()) {
            return Err(BudgetStoreError::Invariant(
                "budget invocation quotas must be strictly sorted without duplicate keys"
                    .to_string(),
            ));
        }
        previous = Some(quota.key());
        if quota.key().profile() == BudgetQuotaProfile::GrantInvocation {
            if quota.key() != &primary_key {
                return Err(BudgetStoreError::Invariant(
                    "composite budget hold has an ambiguous grant invocation quota".to_string(),
                ));
            }
            primary_count += 1;
        }
    }
    if primary_count != 1 {
        return Err(BudgetStoreError::Invariant(
            "composite budget hold requires exactly one matched grant invocation quota".to_string(),
        ));
    }
    let mut family_root_owner_id = None;
    for quota in &request.invocation_quotas {
        if quota.key().profile() == BudgetQuotaProfile::AggregateFamilyInvocation
            && family_root_owner_id
                .replace(quota.key().owner_id())
                .is_some()
        {
            return Err(BudgetStoreError::Invariant(
                "composite budget authorization has multiple aggregate-family quotas".to_string(),
            ));
        }
    }
    let has_family_quota = family_root_owner_id.is_some();
    match (has_family_quota, aggregate_family_evidence) {
        (true, Some(aggregate_family_evidence)) => {
            let root_capability_id = aggregate_family_evidence.root_capability_id.as_str();
            let root_binding_digest = aggregate_family_evidence.root_binding_digest.as_str();
            if root_capability_id.is_empty()
                || root_capability_id.len() > 512
                || root_capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(BudgetStoreError::Invariant(
                    "aggregate root capability ID is empty, oversized, or contains NUL".to_string(),
                ));
            }
            if root_binding_digest.len() != 64
                || !root_binding_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(BudgetStoreError::Invariant(
                    "aggregate root binding digest must be lowercase SHA-256 hex".to_string(),
                ));
            }
            if request
                .revocation_set
                .ids()
                .binary_search_by(|candidate| {
                    candidate.as_bytes().cmp(root_capability_id.as_bytes())
                })
                .is_err()
            {
                return Err(BudgetStoreError::Invariant(
                    "canonical revocation set omits the aggregate root capability".to_string(),
                ));
            }
        }
        (true, None) => {
            return Err(BudgetStoreError::Invariant(
                "aggregate family quota requires root capability ID and binding digest evidence"
                    .to_string(),
            ));
        }
        (false, None) => {}
        (false, Some(_)) => {
            return Err(BudgetStoreError::Invariant(
                "aggregate root evidence requires an aggregate family quota".to_string(),
            ));
        }
    }
    request.revocation_set.validate().map_err(|error| {
        BudgetStoreError::Invariant(format!("invalid canonical revocation set: {error}"))
    })?;
    if request
        .revocation_set
        .ids()
        .binary_search(&request.capability_id)
        .is_err()
    {
        return Err(BudgetStoreError::Invariant(
            "canonical revocation set omits the leaf capability".to_string(),
        ));
    }
    sqlite_integer_from_u64(
        u64::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Overflow("composite grant index exceeds u64".to_string())
        })?,
        "composite grant index",
    )?;
    sqlite_integer_from_u64(request.requested_exposure_units, "composite exposure")?;
    request
        .max_cost_per_invocation
        .map(|value| sqlite_integer_from_u64(value, "composite per-invocation maximum"))
        .transpose()?;
    request
        .max_total_cost_units
        .map(|value| sqlite_integer_from_u64(value, "composite total maximum"))
        .transpose()?;
    if request.authorization_artifact_digests.len()
        > MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION
        || request.authorization_artifact_digests.iter().any(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        || request
            .authorization_artifact_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(BudgetStoreError::Invariant(
            "authorization artifact digests are invalid, unsorted, or duplicated".to_string(),
        ));
    }
    if let Some(authority) = &request.authority {
        sqlite_integer_from_u64(authority.lease_epoch, "composite lease epoch")?;
    }
    Ok(())
}

fn reject_legacy_namespace_collisions(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
) -> Result<(), BudgetStoreError> {
    let hold_collision = transaction
        .query_row(
            r#"
            SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
            UNION ALL
            SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
            LIMIT 1
            "#,
            params![request.hold_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if hold_collision {
        return Err(BudgetStoreError::Conflict(format!(
            "budget hold `{}` collides with a legacy hold",
            request.hold_id
        )));
    }
    let event_collision = transaction
        .query_row(
            "SELECT 1 FROM budget_mutation_events WHERE event_id = ?1",
            params![request.event_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if event_collision {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{}` collides with an existing event",
            request.event_id
        )));
    }
    Ok(())
}

fn load_legacy_usage(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
) -> Result<(u32, u64, u64), BudgetStoreError> {
    load_legacy_usage_for_identity(transaction, &request.capability_id, request.grant_index)
}

fn load_legacy_usage_for_identity(
    transaction: &rusqlite::Transaction<'_>,
    capability_id: &str,
    grant_index: usize,
) -> Result<(u32, u64, u64), BudgetStoreError> {
    Ok(transaction
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
        .optional()?
        .unwrap_or((0, 0, 0)))
}

fn load_live_quota_usages(
    transaction: &rusqlite::Transaction<'_>,
    members: &[BudgetInvocationQuotaUsage],
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    members
        .iter()
        .map(|member| {
            let quota = &member.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum changed",
                    quota.key().owner_id()
                )));
            }
            let usage = BudgetInvocationQuotaUsage {
                quota: quota.clone(),
                reserved_invocations_after: reserved,
                captured_invocations_after: captured,
            };
            usage.validate()?;
            Ok(usage)
        })
        .collect()
}

fn quota_storage_key(key: &BudgetQuotaKey) -> Result<(&str, &str, i64), BudgetStoreError> {
    key.validate()?;
    let grant_index_key = key.grant_index().map_or(-1_i64, i64::from);
    Ok((key.profile().as_str(), key.owner_id(), grant_index_key))
}

fn persist_quota_rows(
    transaction: &rusqlite::Transaction<'_>,
    staged: &[StagedQuota],
    event_seq: u64,
    now: i64,
) -> Result<(), BudgetStoreError> {
    let event_seq = sqlite_integer_from_u64(event_seq, "composite quota sequence")?;
    for entry in staged {
        let (profile, owner_id, grant_index_key) = quota_storage_key(entry.quota.key())?;
        if entry.exists {
            transaction.execute(
                r#"
                UPDATE budget_invocation_quota_usage
                SET reserved_invocations = ?4,
                    captured_invocations = ?5,
                    updated_at = ?6,
                    seq = ?7
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                "#,
                params![
                    profile,
                    owner_id,
                    grant_index_key,
                    i64::from(entry.reserved),
                    i64::from(entry.captured),
                    now,
                    event_seq,
                ],
            )?;
        } else {
            transaction.execute(
                r#"
                INSERT INTO budget_invocation_quota_usage (
                    profile, owner_id, grant_index_key, max_invocations,
                    reserved_invocations, captured_invocations, updated_at, seq
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    profile,
                    owner_id,
                    grant_index_key,
                    i64::from(entry.quota.max_invocations()),
                    i64::from(entry.reserved),
                    i64::from(entry.captured),
                    now,
                    event_seq,
                ],
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_legacy_projection(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
    invocation_count: u32,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
    event_seq: u64,
    now: i64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        r#"
        INSERT INTO capability_grant_budgets (
            capability_id, grant_index, invocation_count, updated_at, seq,
            total_cost_exposed, total_cost_realized_spend
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(capability_id, grant_index) DO UPDATE SET
            invocation_count = excluded.invocation_count,
            updated_at = excluded.updated_at,
            seq = excluded.seq,
            total_cost_exposed = excluded.total_cost_exposed,
            total_cost_realized_spend = excluded.total_cost_realized_spend
        "#,
        params![
            request.capability_id,
            request.grant_index as i64,
            i64::from(invocation_count),
            now,
            sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            sqlite_integer_from_u64(total_cost_exposed, "composite exposed total")?,
            sqlite_integer_from_u64(total_cost_realized_spend, "composite realized-spend total")?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_composite_authorization(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
    aggregate_family_evidence: Option<&SqliteAggregateFamilyEvidence>,
    allowed: bool,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    event_seq: u64,
    now: i64,
    usages: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    let revocation_ids_json =
        serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "failed to encode canonical revocation set: {error}"
            ))
        })?;
    transaction.execute(
        r#"
        INSERT INTO budget_composite_authorizations (
            hold_id, event_id, operation_id, request_binding_hash,
            capability_id, grant_index,
            requested_exposure_units, max_cost_per_invocation, max_total_cost_units,
            authority_id, lease_id, lease_epoch, allowed,
            invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json,
            aggregate_root_capability_id, aggregate_root_binding_digest,
            committed_cost_units_after, invocation_count_after,
            event_seq, created_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
            ?22, ?23
        )
        "#,
        params![
            request.hold_id,
            request.event_id,
            request.operation_id,
            request.request_binding_hash,
            request.capability_id,
            request.grant_index as i64,
            sqlite_integer_from_u64(request.requested_exposure_units, "composite exposure")?,
            request
                .max_cost_per_invocation
                .map(|value| sqlite_integer_from_u64(value, "composite per-invocation maximum"))
                .transpose()?,
            request
                .max_total_cost_units
                .map(|value| sqlite_integer_from_u64(value, "composite total maximum"))
                .transpose()?,
            request
                .authority
                .as_ref()
                .map(|value| value.authority_id.as_str()),
            request
                .authority
                .as_ref()
                .map(|value| value.lease_id.as_str()),
            request
                .authority
                .as_ref()
                .map(|value| sqlite_integer_from_u64(value.lease_epoch, "composite lease epoch"))
                .transpose()?,
            if allowed { 1_i64 } else { 0_i64 },
            invocation_state.as_str(),
            monetary_state.as_str(),
            request.revocation_set.digest(),
            revocation_ids_json,
            aggregate_family_evidence.map(|evidence| evidence.root_capability_id.as_str()),
            aggregate_family_evidence.map(|evidence| evidence.root_binding_digest.as_str()),
            sqlite_integer_from_u64(committed_cost_units_after, "composite committed cost total")?,
            i64::from(invocation_count_after),
            sqlite_integer_from_u64(event_seq, "composite event sequence")?,
            now,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_authorization_quotas (
                hold_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                request.hold_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    for (position, digest) in request.authorization_artifact_digests.iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_composite_authorization_artifacts (
                hold_id, position, artifact_digest
            ) VALUES (?1, ?2, ?3)
            "#,
            params![request.hold_id, position as i64, digest],
        )?;
    }
    transaction.execute(
        r#"
        INSERT INTO budget_composite_mutation_snapshots (
            event_id, operation_id, request_binding_hash,
            invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            request.event_id,
            request.operation_id,
            request.request_binding_hash,
            invocation_state.as_str(),
            monetary_state.as_str(),
            request.revocation_set.digest(),
            serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "failed to encode canonical revocation set: {error}"
                ))
            })?,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_mutation_quota_snapshots (
                event_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                request.event_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    Ok(())
}

fn persist_composite_mutation_snapshot(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: &CanonicalRevocationSet,
    usages: &[BudgetInvocationQuotaUsage],
    admission_operation: &BudgetAdmissionOperationBinding,
) -> Result<(), BudgetStoreError> {
    let revocation_ids_json = serde_json::to_string(revocation_set.ids()).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "failed to encode canonical revocation set: {error}"
        ))
    })?;
    transaction.execute(
        r#"
        INSERT INTO budget_composite_mutation_snapshots (
            event_id, operation_id, request_binding_hash,
            invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            event_id,
            admission_operation.operation_id(),
            admission_operation.request_binding_hash(),
            invocation_state.as_str(),
            monetary_state.as_str(),
            revocation_set.digest(),
            revocation_ids_json,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        usage.validate()?;
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_mutation_quota_snapshots (
                event_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                event_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    Ok(())
}

fn load_composite_capture_decision(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    request: &BudgetCaptureInvocationRequest,
) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
    let admission_operation = required_admission_operation(
        request.admission_operation.as_ref(),
        "composite invocation capture",
    )?;
    let Some(record) = SqliteBudgetStore::load_mutation_event(transaction, event_id)? else {
        return Ok(None);
    };
    load_mutation_admission_operation(transaction, event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite mutation event `{event_id}` omits admission ownership"
            ))
        })?
        .validate_binding(admission_operation, "composite mutation event")?;
    if record.kind != BudgetMutationKind::CaptureInvocations
        || record.hold_id != request.hold_id
        || record.capability_id != request.capability_id
        || record.grant_index as usize != request.grant_index
        || record.authority != request.authority
        || record.allowed.is_some()
        || record.exposure_units != 0
        || record.realized_spend_units != 0
    {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{event_id}` was reused for a different invocation capture"
        )));
    }
    let state = load_composite_mutation_state(transaction, event_id)?;
    state
        .admission_operation
        .validate_binding(admission_operation, "composite mutation snapshot")?;
    if state.invocation_state != BudgetInvocationReservationState::Captured {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` has a non-captured invocation snapshot"
        )));
    }
    let invocation_counts_after = load_mutation_quota_snapshots(transaction, event_id)?;
    let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
    let primary_count_after = invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key() == &primary_key)
        .ok_or_else(|| BudgetStoreError::Invariant("missing primary quota snapshot".to_string()))?
        .invocation_count_after()?;
    if primary_count_after != record.invocation_count_after {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` primary quota snapshot diverged"
        )));
    }
    Ok(Some(BudgetHoldMutationDecision {
        hold_id: record.hold_id,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after,
        invocation_state: state.invocation_state,
        monetary_state: state.monetary_state,
        revocation_set: Some(state.revocation_set),
        metadata: composite_metadata(record.authority, Some(record.event_seq), record.event_id),
    }))
}

#[allow(clippy::too_many_arguments)]
fn load_composite_transition_decision(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    expected_kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    authority: Option<&BudgetEventAuthority>,
    exposure_units: u64,
    realized_spend_units: u64,
    admission_operation: &BudgetAdmissionOperationBinding,
) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
    let Some(record) = SqliteBudgetStore::load_mutation_event(transaction, event_id)? else {
        return Ok(None);
    };
    load_mutation_admission_operation(transaction, event_id)?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite mutation event `{event_id}` omits admission ownership"
            ))
        })?
        .validate_binding(admission_operation, "composite mutation event")?;
    if record.kind != expected_kind
        || record.hold_id.as_deref() != Some(hold_id)
        || record.capability_id != capability_id
        || record.grant_index as usize != grant_index
        || record.authority.as_ref() != authority
        || record.allowed.is_some()
        || record.exposure_units != exposure_units
        || record.realized_spend_units != realized_spend_units
    {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{event_id}` was reused for a different composite transition"
        )));
    }
    let state = load_composite_mutation_state(transaction, event_id)?;
    state
        .admission_operation
        .validate_binding(admission_operation, "composite mutation snapshot")?;
    let invocation_counts_after = load_mutation_quota_snapshots(transaction, event_id)?;
    let primary_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
    let primary_count_after = invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key() == &primary_key)
        .ok_or_else(|| BudgetStoreError::Invariant("missing primary quota snapshot".to_string()))?
        .invocation_count_after()?;
    if primary_count_after != record.invocation_count_after {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` primary quota snapshot diverged"
        )));
    }
    Ok(Some(BudgetHoldMutationDecision {
        hold_id: record.hold_id,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after,
        invocation_state: state.invocation_state,
        monetary_state: state.monetary_state,
        revocation_set: Some(state.revocation_set),
        metadata: composite_metadata(record.authority, record.usage_seq, record.event_id),
    }))
}

fn load_composite_hold(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json,
                   operation_id, request_binding_hash
            FROM budget_composite_holds
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
    stored_composite_state(row.0, row.1, row.2, row.3, row.4, row.5, "composite hold")
}

fn load_composite_mutation_state(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json,
                   operation_id, request_binding_hash
            FROM budget_composite_mutation_snapshots
            WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "missing composite state snapshot for event `{event_id}`"
            ))
        })?;
    stored_composite_state(
        row.0,
        row.1,
        row.2,
        row.3,
        row.4,
        row.5,
        "composite mutation snapshot",
    )
}

fn load_mutation_admission_operation(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
) -> Result<Option<StoredAdmissionOperation>, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT operation_id, request_binding_hash
            FROM budget_mutation_events
            WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?;
    row.map(|(operation_id, request_binding_hash)| {
        StoredAdmissionOperation::from_columns(
            operation_id,
            request_binding_hash,
            "composite mutation event",
        )
    })
    .transpose()
}

fn stored_composite_state(
    invocation_state: String,
    monetary_state: String,
    revocation_set_digest: String,
    revocation_ids_json: String,
    operation_id: Option<String>,
    request_binding_hash: Option<String>,
    subject: &str,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let invocation_state =
        BudgetInvocationReservationState::parse(&invocation_state).ok_or_else(|| {
            BudgetStoreError::Invariant("unknown persisted invocation state".to_string())
        })?;
    let monetary_state = BudgetMonetaryHoldState::parse(&monetary_state).ok_or_else(|| {
        BudgetStoreError::Invariant("unknown persisted monetary state".to_string())
    })?;
    let ids = serde_json::from_str::<Vec<String>>(&revocation_ids_json).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation members: {error}"
        ))
    })?;
    let revocation_set = CanonicalRevocationSet::from_persisted_parts(ids, revocation_set_digest)
        .map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation set: {error}"
        ))
    })?;
    Ok(StoredCompositeHold {
        admission_operation: StoredAdmissionOperation::from_columns(
            operation_id,
            request_binding_hash,
            subject,
        )?,
        invocation_state,
        monetary_state,
        revocation_set,
    })
}

fn load_composite_authorization(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Option<StoredCompositeAuthorization>, BudgetStoreError> {
    type StoredRow = (
        String,
        String,
        String,
        usize,
        u64,
        Option<u64>,
        Option<u64>,
        Option<BudgetEventAuthority>,
        bool,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        u64,
        u32,
        u64,
        Option<String>,
        Option<String>,
    );
    let row: Option<StoredRow> = transaction
        .query_row(
            r#"
            SELECT hold_id, event_id, capability_id, grant_index,
                   requested_exposure_units, max_cost_per_invocation,
                   max_total_cost_units, authority_id, lease_id, lease_epoch,
                   allowed, invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json,
                   aggregate_root_capability_id, aggregate_root_binding_digest,
                   committed_cost_units_after, invocation_count_after, event_seq,
                   operation_id, request_binding_hash
            FROM budget_composite_authorizations
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    budget_usize_from_row(row, 3, "composite grant_index")?,
                    budget_u64_from_row(row, 4, "composite requested_exposure_units")?,
                    optional_budget_u64_from_row(row, 5, "composite max_cost_per_invocation")?,
                    optional_budget_u64_from_row(row, 6, "composite max_total_cost_units")?,
                    sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?,
                    row.get::<_, i64>(10)? != 0,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    budget_u64_from_row(row, 17, "composite committed_cost_units_after")?,
                    budget_u32_from_row(row, 18, "composite invocation_count_after")?,
                    budget_u64_from_row(row, 19, "composite event_seq")?,
                    row.get(20)?,
                    row.get(21)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let invocation_state = BudgetInvocationReservationState::parse(&row.9).ok_or_else(|| {
        BudgetStoreError::Invariant(format!("unknown persisted invocation state `{}`", row.9))
    })?;
    let monetary_state = BudgetMonetaryHoldState::parse(&row.10).ok_or_else(|| {
        BudgetStoreError::Invariant(format!("unknown persisted monetary state `{}`", row.10))
    })?;
    let ids = serde_json::from_str::<Vec<String>>(&row.12).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation members: {error}"
        ))
    })?;
    let revocation_set =
        CanonicalRevocationSet::from_persisted_parts(ids, row.11).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "invalid persisted canonical revocation set: {error}"
            ))
        })?;
    let invocation_counts_after = load_authorization_quota_snapshots(transaction, hold_id)?;
    let authorization_artifact_digests = load_authorization_artifact_digests(transaction, hold_id)?;
    let authorization = StoredCompositeAuthorization {
        admission_operation: StoredAdmissionOperation::from_columns(
            row.18,
            row.19,
            "composite authorization",
        )?,
        hold_id: row.0,
        event_id: row.1,
        capability_id: row.2,
        grant_index: row.3,
        requested_exposure_units: row.4,
        max_cost_per_invocation: row.5,
        max_total_cost_units: row.6,
        authority: row.7,
        allowed: row.8,
        invocation_state,
        monetary_state,
        revocation_set,
        aggregate_root_capability_id: row.13,
        aggregate_root_binding_digest: row.14,
        committed_cost_units_after: row.15,
        invocation_count_after: row.16,
        event_seq: row.17,
        invocation_counts_after,
        authorization_artifact_digests,
    };
    let recovered = authorization.authorization_input()?;
    validate_composite_input(
        &recovered.authorization,
        recovered.aggregate_family_evidence.as_ref(),
    )?;
    Ok(Some(authorization))
}

fn load_authorization_artifact_digests(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Vec<String>, BudgetStoreError> {
    let mut statement = transaction.prepare(
        r#"
        SELECT position, artifact_digest
        FROM budget_composite_authorization_artifacts
        WHERE hold_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![hold_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if rows.len() > MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted authorization artifact count exceeds the limit".to_string(),
        ));
    }
    let mut digests = Vec::with_capacity(rows.len());
    for (expected_position, (position, digest)) in rows.into_iter().enumerate() {
        if position != expected_position as i64
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BudgetStoreError::Invariant(
                "persisted authorization artifacts are malformed".to_string(),
            ));
        }
        digests.push(digest);
    }
    if digests.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BudgetStoreError::Invariant(
            "persisted authorization artifact digests are unsorted or duplicated".to_string(),
        ));
    }
    Ok(digests)
}

fn load_authorization_quota_snapshots(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    type QuotaRow = (i64, String, String, i64, u32, u32, u32);
    let mut statement = transaction.prepare(
        r#"
        SELECT position, profile, owner_id, grant_index_key, max_invocations,
               reserved_invocations_after, captured_invocations_after
        FROM budget_composite_authorization_quotas
        WHERE hold_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![hold_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                budget_u32_from_row(row, 4, "snapshot max_invocations")?,
                budget_u32_from_row(row, 5, "snapshot reserved_invocations_after")?,
                budget_u32_from_row(row, 6, "snapshot captured_invocations_after")?,
            ))
        })?
        .collect::<Result<Vec<QuotaRow>, _>>()?;
    drop(statement);
    if rows.is_empty() || rows.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted composite authorization has an invalid quota count".to_string(),
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(
            |(
                expected_position,
                (position, profile, owner_id, grant_index_key, maximum, reserved, captured),
            )| {
                if position != expected_position as i64 {
                    return Err(BudgetStoreError::Invariant(
                        "persisted composite quota positions are not contiguous".to_string(),
                    ));
                }
                let profile = BudgetQuotaProfile::parse(&profile).ok_or_else(|| {
                    BudgetStoreError::Invariant("unknown persisted quota profile".to_string())
                })?;
                let grant_index = if grant_index_key == -1 {
                    None
                } else {
                    Some(u32::try_from(grant_index_key).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "persisted quota grant index is out of range".to_string(),
                        )
                    })?)
                };
                let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, grant_index)?;
                let quota = BudgetInvocationQuota::from_persisted_parts(key, maximum)?;
                let usage = BudgetInvocationQuotaUsage {
                    quota,
                    reserved_invocations_after: reserved,
                    captured_invocations_after: captured,
                };
                usage.validate()?;
                Ok(usage)
            },
        )
        .collect()
}

fn load_mutation_quota_snapshots(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    type QuotaRow = (i64, String, String, i64, u32, u32, u32);
    let mut statement = transaction.prepare(
        r#"
        SELECT position, profile, owner_id, grant_index_key, max_invocations,
               reserved_invocations_after, captured_invocations_after
        FROM budget_composite_mutation_quota_snapshots
        WHERE event_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![event_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                budget_u32_from_row(row, 4, "snapshot max_invocations")?,
                budget_u32_from_row(row, 5, "snapshot reserved_invocations_after")?,
                budget_u32_from_row(row, 6, "snapshot captured_invocations_after")?,
            ))
        })?
        .collect::<Result<Vec<QuotaRow>, _>>()?;
    drop(statement);
    hydrate_quota_snapshot_rows(rows)
}

fn hydrate_quota_snapshot_rows(
    rows: Vec<(i64, String, String, i64, u32, u32, u32)>,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    if rows.is_empty() || rows.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted composite mutation has an invalid quota count".to_string(),
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(
            |(
                expected_position,
                (position, profile, owner_id, grant_index_key, maximum, reserved, captured),
            )| {
                if position != expected_position as i64 {
                    return Err(BudgetStoreError::Invariant(
                        "persisted composite quota positions are not contiguous".to_string(),
                    ));
                }
                let profile = BudgetQuotaProfile::parse(&profile).ok_or_else(|| {
                    BudgetStoreError::Invariant("unknown persisted quota profile".to_string())
                })?;
                let grant_index = if grant_index_key == -1 {
                    None
                } else {
                    Some(u32::try_from(grant_index_key).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "persisted quota grant index is out of range".to_string(),
                        )
                    })?)
                };
                let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, grant_index)?;
                let quota = BudgetInvocationQuota::from_persisted_parts(key, maximum)?;
                let usage = BudgetInvocationQuotaUsage {
                    quota,
                    reserved_invocations_after: reserved,
                    captured_invocations_after: captured,
                };
                usage.validate()?;
                Ok(usage)
            },
        )
        .collect()
}

fn composite_metadata(
    authority: Option<BudgetEventAuthority>,
    budget_commit_index: Option<u64>,
    event_id: String,
) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority,
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
        metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
        budget_commit_index,
        event_id: Some(event_id),
    }
}
