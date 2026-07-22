include!("composite_parts/part_01.rs");
include!("composite_parts/part_02.rs");

impl SqliteBudgetStore {
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
