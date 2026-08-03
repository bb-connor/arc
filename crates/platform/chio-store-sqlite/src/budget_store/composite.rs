include!("composite_parts/part_01.rs");
include!("composite_parts/part_02.rs");

fn sqlite_persisted_composite_request(
    request: &SqliteCompositeAuthorizeInput,
    quota_exhausted: bool,
) -> Result<SqliteCompositeAuthorizeInput, BudgetStoreError> {
    let mut persisted = request.clone();
    if quota_exhausted {
        if persisted.requested_exposure_units > i64::MAX as u64 {
            persisted.requested_exposure_units = 0;
        }
        if persisted
            .max_cost_per_invocation
            .is_some_and(|value| value > i64::MAX as u64)
        {
            persisted.max_cost_per_invocation = None;
        }
        if persisted
            .max_total_cost_units
            .is_some_and(|value| value > i64::MAX as u64)
        {
            persisted.max_total_cost_units = None;
        }
    }
    sqlite_integer_from_u64(persisted.requested_exposure_units, "composite exposure")?;
    persisted
        .max_cost_per_invocation
        .map(|value| sqlite_integer_from_u64(value, "composite per-invocation maximum"))
        .transpose()?;
    persisted
        .max_total_cost_units
        .map(|value| sqlite_integer_from_u64(value, "composite total maximum"))
        .transpose()?;
    Ok(persisted)
}

impl SqliteBudgetStore {
    pub(super) fn load_exact_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        let Some(mut record) = Self::load_mutation_event(transaction, event_id)? else {
            return Ok(None);
        };
        let companion_rows = transaction.query_row(
            r#"
            SELECT
                EXISTS(
                    SELECT 1 FROM budget_composite_mutation_snapshots
                    WHERE event_id = ?1
                ),
                EXISTS(
                    SELECT 1 FROM budget_composite_mutation_quota_snapshots
                    WHERE event_id = ?1
                )
            "#,
            params![event_id],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
        )?;
        let Some(admission_operation) = record.admission_operation.as_ref() else {
            if companion_rows != (false, false) {
                return Err(BudgetStoreError::Invariant(format!(
                    "legacy budget event `{event_id}` has composite companion state"
                )));
            }
            return Ok(Some(record));
        };
        if !matches!(
            record.kind,
            BudgetMutationKind::ReserveInvocations
                | BudgetMutationKind::CaptureInvocations
                | BudgetMutationKind::ReverseInvocations
                | BudgetMutationKind::CaptureExposure
                | BudgetMutationKind::ReleaseExposure
                | BudgetMutationKind::ReconcileSpend
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "operation-owned budget event `{event_id}` has unsupported mutation kind"
            )));
        }
        if companion_rows != (true, true) {
            return Err(BudgetStoreError::Invariant(format!(
                "operation-owned budget event `{event_id}` omits exact companion state"
            )));
        }
        load_mutation_admission_operation(transaction, event_id)?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "operation-owned budget event `{event_id}` omits admission ownership"
                ))
            })?
            .validate_binding(admission_operation, "budget mutation event")?;
        let state = load_composite_mutation_state(transaction, event_id)?;
        state
            .admission_operation
            .validate_binding(admission_operation, "budget mutation snapshot")?;
        let invocation_counts_after = load_mutation_quota_snapshots(transaction, event_id)?;
        let primary_key =
            BudgetQuotaKey::grant(&record.capability_id, record.grant_index as usize)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "operation-owned budget event `{event_id}` omits its primary quota snapshot"
                ))
            })?
            .invocation_count_after()?;
        if primary_count_after != record.invocation_count_after {
            return Err(BudgetStoreError::Invariant(format!(
                "operation-owned budget event `{event_id}` primary quota snapshot diverged"
            )));
        }
        record.invocation_counts_after = invocation_counts_after;
        record.invocation_state = state.invocation_state;
        record.monetary_state = state.monetary_state;
        record.revocation_set = Some(state.revocation_set);
        Ok(Some(record))
    }

    pub(super) fn invocation_quota_attempt_is_allowed(
        quota_exhausted: bool,
        external_denied: bool,
    ) -> bool {
        !quota_exhausted && !external_denied
    }

    fn authorize_composite_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<SqliteAggregateFamilyEvidence>,
        existing_only: bool,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        validate_composite_input(&request, aggregate_family_evidence.as_ref())?;
        validate_partition_escrow_input(transaction, &request)?;

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
            validate_composite_managed_grant_marker(
                transaction,
                &request.capability_id,
                request.grant_index,
            )?;
            let legacy_usage = load_legacy_usage(transaction, &request)?;
            let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
            SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                transaction,
                &request.invocation_quotas,
                &primary_key,
                legacy_usage.0,
                SqliteInvocationQuotaMutationContext {
                    mode: SqliteInvocationQuotaMutationMode::Reserve,
                    action: SqliteInvocationQuotaMutationAction::Replay,
                    event_seq: existing.event_seq,
                    updated_at: unix_now(),
                },
            )?;
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
        if existing_only {
            let partial_namespace = transaction
                .query_row(
                    r#"
                    SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
                    UNION ALL
                    SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
                    UNION ALL
                    SELECT 1 FROM budget_composite_holds WHERE hold_id = ?1
                    UNION ALL
                    SELECT 1 FROM budget_mutation_events WHERE event_id = ?2
                    LIMIT 1
                    "#,
                    params![request.hold_id, request.event_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if partial_namespace {
                return Err(BudgetStoreError::Invariant(format!(
                    "authorization replay for hold `{}` or event `{}` has partial or cross-namespace state",
                    request.hold_id, request.event_id
                )));
            }
            return Err(BudgetStoreError::MissingCommittedReplay(format!(
                "no authorization is committed for hold `{}` and event `{}`",
                request.hold_id, request.event_id
            )));
        }
        reject_legacy_namespace_collisions(transaction, &request)?;

        let legacy_usage = load_legacy_usage(transaction, &request)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let committed_before = checked_committed_cost_units(legacy_usage.1, legacy_usage.2)?;
        let committed_if_allowed = committed_before.checked_add(request.requested_exposure_units);
        let exposed_if_allowed = legacy_usage.1.checked_add(request.requested_exposure_units);
        let monetary_denied = request
            .max_cost_per_invocation
            .is_some_and(|maximum| request.requested_exposure_units > maximum)
            || request.max_total_cost_units.is_some_and(|maximum| {
                committed_if_allowed.is_none_or(|committed| committed > maximum)
            });
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        let quota_mutation = SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            transaction,
            &request.invocation_quotas,
            &primary_key,
            legacy_usage.0,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::Reserve,
                action: SqliteInvocationQuotaMutationAction::Attempt {
                    external_denied: monetary_denied,
                },
                event_seq,
                updated_at: now,
            },
        )?;
        let allowed = quota_mutation.allowed;
        let persisted_request =
            sqlite_persisted_composite_request(&request, quota_mutation.quota_exhausted)?;
        let invocation_counts_after = quota_mutation.invocation_counts_after;
        let primary_count_after = quota_mutation.primary_count_after;
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
        let (committed_cost_units_after, exposed_after) = if allowed {
            let committed = committed_if_allowed.ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
            let exposed = exposed_if_allowed.ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total exposed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
            (committed, exposed)
        } else {
            (committed_before, legacy_usage.1)
        };

        if allowed {
            SqliteBudgetStore::compare_and_persist_legacy_projection(
                transaction,
                SqliteLegacyProjectionMutation {
                    capability_id: &request.capability_id,
                    grant_index: request.grant_index,
                    expected: legacy_usage.3.map(|seq| SqliteLegacyProjectionState {
                        invocation_count: legacy_usage.0,
                        total_cost_exposed: legacy_usage.1,
                        total_cost_realized_spend: legacy_usage.2,
                        seq,
                    }),
                    after: SqliteLegacyProjectionState {
                        invocation_count: primary_count_after,
                        total_cost_exposed: exposed_after,
                        total_cost_realized_spend: legacy_usage.2,
                        seq: event_seq,
                    },
                    updated_at: now,
                },
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
                exposure_units: persisted_request.requested_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: persisted_request.max_cost_per_invocation,
                max_total_cost_units: persisted_request.max_total_cost_units,
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
            &persisted_request,
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
        persist_composite_managed_grant_marker(transaction, &request)?;
        let metadata = composite_metadata(
            request.authority.clone(),
            Some(event_seq),
            request.event_id.clone(),
            request.partition_escrow_evidence.clone(),
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
                attempted_exposure_units: persisted_request.requested_exposure_units,
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
