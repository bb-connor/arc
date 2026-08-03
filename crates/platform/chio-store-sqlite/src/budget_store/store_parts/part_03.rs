#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SqliteInvocationQuotaMutationMode {
    Reserve,
    CaptureCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SqliteInvocationQuotaMutationAction {
    Attempt { external_denied: bool },
    Replay,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SqliteInvocationQuotaMutationContext {
    pub(super) mode: SqliteInvocationQuotaMutationMode,
    pub(super) action: SqliteInvocationQuotaMutationAction,
    pub(super) event_seq: u64,
    pub(super) updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SqliteLegacyProjectionState {
    pub(super) invocation_count: u32,
    pub(super) total_cost_exposed: u64,
    pub(super) total_cost_realized_spend: u64,
    pub(super) seq: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SqliteLegacyProjectionMutation<'a> {
    pub(super) capability_id: &'a str,
    pub(super) grant_index: usize,
    pub(super) expected: Option<SqliteLegacyProjectionState>,
    pub(super) after: SqliteLegacyProjectionState,
    pub(super) updated_at: i64,
}

#[derive(Debug)]
pub(super) struct SqliteInvocationQuotaMutationOutcome {
    pub(super) allowed: bool,
    pub(super) quota_exhausted: bool,
    pub(super) invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    pub(super) primary_count_after: u32,
}

#[derive(Debug)]
struct SqliteStagedInvocationQuota {
    quota: BudgetInvocationQuota,
    before_reserved: u32,
    before_captured: u32,
    reserved: u32,
    captured: u32,
    exists: bool,
}

impl SqliteBudgetStore {
    pub(super) fn ensure_open_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<SqliteBudgetHold, BudgetStoreError> {
        let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Conflict(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if hold.disposition != HoldDisposition::Open {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` is no longer open"
            )));
        }
        Ok(hold)
    }

    pub(super) fn validate_hold_authority(
        hold_id: &str,
        current: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match (current, requested) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` was created without authority lease metadata"
            ))),
            (Some(_), None) => Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` requires authority lease metadata"
            ))),
            (Some(current), Some(requested)) => {
                if current.authority_id != requested.authority_id {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` authority_id does not match the open lease"
                    )));
                }
                if requested.lease_id != current.lease_id {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` lease_id does not match the open lease epoch"
                    )));
                }
                if requested.lease_epoch < current.lease_epoch {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` authority lease epoch regressed"
                    )));
                }
                if requested.lease_epoch > current.lease_epoch {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` authority lease epoch advanced beyond the open lease"
                    )));
                }
                Ok(Some(requested.clone()))
            }
        }
    }

    fn existing_increment_outcome(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<Option<SqliteBudgetIncrementOutcome>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    max_invocations,
                    invocation_count_after,
                    event_seq,
                    usage_seq,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        budget_usize_from_row(row, 1, "grant_index")?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        optional_budget_u32_from_row(row, 4, "max_invocations")?,
                        budget_u32_from_row(row, 5, "invocation_count_after")?,
                        budget_u64_from_row(row, 6, "event_seq")?,
                        optional_budget_u64_from_row(row, 7, "usage_seq")?,
                        sqlite_budget_event_authority(row.get(8)?, row.get(9)?, row.get(10)?)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_max_invocations,
            existing_invocation_count,
            existing_event_seq,
            existing_usage_seq,
            existing_authority,
        )) = existing
        else {
            return Ok(None);
        };
        let mutation_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == BudgetMutationKind::IncrementInvocation.as_str()
            && existing_max_invocations == max_invocations
            && existing_authority.as_ref() == authority;
        if !mutation_matches {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        let existing_allowed = existing_allowed.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "persisted increment event `{event_id}` omits its decision"
            ))
        })?;
        let allowed = match existing_allowed {
            0 => false,
            1 => true,
            other => {
                return Err(BudgetStoreError::Invariant(format!(
                    "persisted increment event `{event_id}` has invalid decision `{other}`"
                )));
            }
        };
        if (allowed && existing_usage_seq != Some(existing_event_seq))
            || (!allowed && existing_usage_seq.is_some())
        {
            return Err(BudgetStoreError::Invariant(format!(
                "persisted increment event `{event_id}` has inconsistent usage sequence"
            )));
        }
        Ok(Some(SqliteBudgetIncrementOutcome {
            allowed,
            invocation_count: existing_invocation_count,
            event_seq: existing_event_seq,
        }))
    }

    pub(super) fn sqlite_like_prefix_pattern(prefix: &str) -> String {
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for ch in prefix.chars() {
            match ch {
                '\\' | '%' | '_' => {
                    pattern.push('\\');
                    pattern.push(ch);
                }
                _ => pattern.push(ch),
            }
        }
        pattern.push('%');
        pattern
    }

    pub(super) fn rollback_event_exists(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
        hold_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        exposure_units: u64,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let rollback_prefix = format!("{event_id}:rollback:");
        let rollback_prefix_pattern = Self::sqlite_like_prefix_pattern(&rollback_prefix);
        let candidate_exists = transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_mutation_events
                WHERE event_id LIKE ?1 ESCAPE '\'
                  AND kind = ?2
                LIMIT 1
                "#,
                params![
                    rollback_prefix_pattern,
                    BudgetMutationKind::ReverseExposure.as_str()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !candidate_exists {
            return Ok(false);
        }
        let grant_index = i64::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Overflow(
                "budget rollback grant index exceeds SQLite INTEGER".to_string(),
            )
        })?;
        let exposure_units = sqlite_integer_from_u64(exposure_units, "budget rollback exposure")?;
        let lease_epoch = authority
            .map(|value| sqlite_integer_from_u64(value.lease_epoch, "budget rollback lease epoch"))
            .transpose()?;
        Ok(transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_mutation_events AS rollback
                WHERE rollback.event_id LIKE ?1 ESCAPE '\'
                  AND rollback.kind = ?2
                  AND rollback.allowed IS NULL
                  AND rollback.hold_id IS ?3
                  AND rollback.capability_id = ?4
                  AND rollback.grant_index = ?5
                  AND rollback.exposure_units = ?6
                  AND rollback.realized_spend_units = 0
                  AND rollback.max_invocations IS NULL
                  AND rollback.max_exposure_per_invocation IS NULL
                  AND rollback.max_total_exposure_units IS NULL
                  AND rollback.authority_id IS ?7
                  AND rollback.lease_id IS ?8
                  AND rollback.lease_epoch IS ?9
                  AND rollback.usage_seq = rollback.event_seq
                  AND (
                      rollback.event_seq > (
                          SELECT authorization.event_seq
                          FROM budget_mutation_events AS authorization
                          WHERE authorization.event_id = ?10
                            AND authorization.kind = ?11
                            AND authorization.allowed = 1
                      )
                      OR (
                          NOT EXISTS (
                              SELECT 1
                              FROM budget_mutation_events AS authorization
                              WHERE authorization.event_id = ?10
                          )
                          AND EXISTS (
                              SELECT 1
                              FROM budget_authorization_claims AS claim
                              WHERE claim.event_id = ?10
                                AND claim.hold_id IS ?3
                                AND claim.capability_id = ?4
                                AND claim.grant_index = ?5
                                AND claim.requested_exposure_units = ?6
                                AND claim.authority_id IS ?7
                                AND claim.lease_id IS ?8
                                AND claim.lease_epoch IS ?9
                                AND claim.allowed = 1
                                AND rollback.recorded_at >= claim.created_at
                          )
                      )
                  )
                LIMIT 1
                "#,
                params![
                    rollback_prefix_pattern,
                    BudgetMutationKind::ReverseExposure.as_str(),
                    hold_id,
                    capability_id,
                    grant_index,
                    exposure_units,
                    authority.map(|value| value.authority_id.as_str()),
                    authority.map(|value| value.lease_id.as_str()),
                    lease_epoch,
                    event_id,
                    BudgetMutationKind::AuthorizeExposure.as_str(),
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn rolled_back_authorize_can_be_replaced(
        transaction: &rusqlite::Transaction<'_>,
        existing: &BudgetMutationRecord,
        replacement: &BudgetMutationRecord,
    ) -> Result<bool, BudgetStoreError> {
        if existing.kind != BudgetMutationKind::AuthorizeExposure
            || replacement.kind != BudgetMutationKind::AuthorizeExposure
            || existing.allowed != Some(true)
            || replacement.allowed != Some(true)
        {
            return Ok(false);
        }
        let same_mutation_scope = existing.hold_id == replacement.hold_id
            && existing.admission_operation == replacement.admission_operation
            && existing.capability_id == replacement.capability_id
            && existing.grant_index == replacement.grant_index
            && existing.exposure_units == replacement.exposure_units
            && existing.realized_spend_units == replacement.realized_spend_units
            && existing.max_invocations == replacement.max_invocations
            && existing.max_cost_per_invocation == replacement.max_cost_per_invocation
            && existing.max_total_cost_units == replacement.max_total_cost_units;
        if !same_mutation_scope {
            return Ok(false);
        }
        Self::rollback_event_exists(
            transaction,
            &existing.event_id,
            existing.hold_id.as_deref(),
            &existing.capability_id,
            existing.grant_index as usize,
            existing.exposure_units,
            existing.authority.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn existing_event_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        kind: BudgetMutationKind,
        capability_id: &str,
        grant_index: usize,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<Option<Option<bool>>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
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
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    let existing_authority =
                        sqlite_budget_event_authority(row.get(13)?, row.get(14)?, row.get(15)?)?;
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        budget_usize_from_row(row, 2, "grant_index")?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        budget_u64_from_row(row, 5, "exposure_units")?,
                        budget_u64_from_row(row, 6, "realized_spend_units")?,
                        optional_budget_u32_from_row(row, 7, "max_invocations")?,
                        optional_budget_u64_from_row(row, 8, "max_exposure_per_invocation")?,
                        optional_budget_u64_from_row(row, 9, "max_total_exposure_units")?,
                        budget_u32_from_row(row, 10, "invocation_count_after")?,
                        budget_u64_from_row(row, 11, "total_cost_exposed_after")?,
                        budget_u64_from_row(row, 12, "total_cost_realized_spend_after")?,
                        existing_authority,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_hold_id,
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_exposure_units,
            existing_realized_spend_units,
            existing_max_invocations,
            existing_max_exposure_per_invocation,
            existing_max_total_exposure_units,
            existing_invocation_count_after,
            existing_total_cost_exposed_after,
            existing_total_cost_realized_spend_after,
            existing_authority,
        )) = existing
        else {
            return Ok(None);
        };
        let max_invocations_matches = existing_max_invocations == max_invocations;
        let max_per_matches = existing_max_exposure_per_invocation == max_cost_per_invocation;
        let max_total_matches = existing_max_total_exposure_units == max_total_cost_units;
        let mutation_scope_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == kind.as_str()
            && existing_hold_id.as_deref() == hold_id
            && existing_exposure_units == exposure_units
            && existing_realized_spend_units == realized_spend_units
            && max_invocations_matches
            && max_per_matches
            && max_total_matches;
        let authority_matches = existing_authority.as_ref() == authority;
        let existing_allowed = existing_allowed.map(|value| value > 0);
        let rollback_exists = kind == BudgetMutationKind::AuthorizeExposure
            && existing_allowed == Some(true)
            && Self::rollback_event_exists(
                transaction,
                event_id,
                existing_hold_id.as_deref(),
                &existing_capability_id,
                existing_grant_index,
                existing_exposure_units,
                existing_authority.as_ref(),
            )?;
        if !mutation_scope_matches || (!authority_matches && !rollback_exists) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        if rollback_exists {
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
            let usage_matches = current.is_some_and(
                |(invocation_count, total_cost_exposed, total_cost_realized_spend)| {
                    invocation_count == existing_invocation_count_after
                        && total_cost_exposed == existing_total_cost_exposed_after
                        && total_cost_realized_spend == existing_total_cost_realized_spend_after
                },
            );
            let hold_matches = match hold_id {
                Some(hold_id) => Self::load_hold(transaction, hold_id)?.is_some_and(|hold| {
                    hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == exposure_units
                        && hold.remaining_exposure_units == exposure_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                }),
                None => true,
            };
            if usage_matches && hold_matches {
                return Ok(Some(existing_allowed));
            }
            // This is a GENUINE rollback-retry: the rolled-back authorize is
            // deleted and the caller re-appends it under a fresh higher seq. Record
            // the freed seq as abandoned/tombstoned BEFORE the delete so the global
            // contiguous ack head treats it as filled and does not stall cluster-
            // wide at the resulting hole. This recording is deliberately ONLY at the
            // rollback-retry site (not the AFTER DELETE trigger), so that a data-loss
            // delete still caps the head (fail-closed). Never over-counts: the
            // abandoned seq's write was superseded, so no live write targets it.
            let abandoned_seq: Option<i64> = transaction
                .query_row(
                    "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                    params![event_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )?;
            if let Some(seq) = abandoned_seq {
                if seq > 0 {
                    transaction.execute(
                        "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                        params![seq],
                    )?;
                }
            }
            Self::reset_budget_ack_head_watermark(transaction)?;
            if let Some(hold_id) = hold_id {
                transaction.execute(
                    "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                    params![hold_id],
                )?;
            }
            return Ok(None);
        }
        Ok(Some(existing_allowed))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        capability_id: &str,
        grant_index: usize,
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        event_seq: u64,
        usage_seq: Option<u64>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        invocation_count_after: u32,
        total_cost_exposed_after: u64,
        total_cost_realized_spend_after: u64,
    ) -> Result<(), BudgetStoreError> {
        Self::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id,
                hold_id,
                authority,
                capability_id,
                grant_index,
                kind,
                allowed,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                admission_operation: None,
            },
        )
    }

    pub(super) fn append_mutation_event_with_admission_operation(
        transaction: &rusqlite::Transaction<'_>,
        input: BudgetMutationEventInput<'_>,
    ) -> Result<(), BudgetStoreError> {
        let BudgetMutationEventInput {
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            kind,
            allowed,
            event_seq,
            usage_seq,
            exposure_units,
            realized_spend_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            admission_operation,
        } = input;
        let event_id = match event_id {
            Some(event_id) => event_id.to_string(),
            None => Self::generated_event_id(transaction)?,
        };
        let sqlite_integer = |value: u64, label: &str| {
            i64::try_from(value)
                .map_err(|_| BudgetStoreError::Overflow(format!("{label} exceeds SQLite INTEGER")))
        };
        let grant_index = i64::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Overflow("budget grant index exceeds SQLite INTEGER".to_string())
        })?;
        let event_seq = sqlite_integer(event_seq, "budget event sequence")?;
        let usage_seq = usage_seq
            .map(|value| sqlite_integer(value, "budget usage sequence"))
            .transpose()?;
        let exposure_units = sqlite_integer(exposure_units, "budget exposure")?;
        let realized_spend_units = sqlite_integer(realized_spend_units, "budget realized spend")?;
        let max_cost_per_invocation = max_cost_per_invocation
            .map(|value| sqlite_integer(value, "budget per-invocation maximum"))
            .transpose()?;
        let max_total_cost_units = max_total_cost_units
            .map(|value| sqlite_integer(value, "budget total maximum"))
            .transpose()?;
        let total_cost_exposed_after =
            sqlite_integer(total_cost_exposed_after, "budget exposure total")?;
        let total_cost_realized_spend_after = sqlite_integer(
            total_cost_realized_spend_after,
            "budget realized-spend total",
        )?;
        let lease_epoch = authority
            .map(|value| sqlite_integer(value.lease_epoch, "budget lease epoch"))
            .transpose()?;
        let operation_id = admission_operation.map(|operation| operation.operation_id);
        let request_binding_hash =
            admission_operation.map(|operation| operation.request_binding_hash);
        transaction.execute(
            r#"
            INSERT INTO budget_mutation_events (
                event_id,
                hold_id,
                operation_id,
                request_binding_hash,
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
                lease_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)
            "#,
            params![
                event_id,
                hold_id,
                operation_id,
                request_binding_hash,
                capability_id,
                grant_index,
                kind.as_str(),
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                unix_now(),
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations.map(i64::from),
                max_cost_per_invocation,
                max_total_cost_units,
                i64::from(invocation_count_after),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch,
            ],
        )?;
        Ok(())
    }

    pub(super) fn reject_composite_managed_grant(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<(), BudgetStoreError> {
        let managed = transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_composite_managed_grants
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if managed {
            return Err(BudgetStoreError::Invariant(format!(
                "grant `{capability_id}` requires composite invocation admission"
            )));
        }
        Ok(())
    }

    pub(super) fn compare_and_mutate_invocation_quotas(
        transaction: &rusqlite::Transaction<'_>,
        quotas: &[BudgetInvocationQuota],
        primary_key: &BudgetQuotaKey,
        primary_usage_count: u32,
        context: SqliteInvocationQuotaMutationContext,
    ) -> Result<SqliteInvocationQuotaMutationOutcome, BudgetStoreError> {
        let SqliteInvocationQuotaMutationContext {
            mode,
            action,
            event_seq,
            updated_at,
        } = context;
        if matches!(
            mode,
            SqliteInvocationQuotaMutationMode::CaptureCompatibility
        ) && (quotas.len() != 1 || quotas[0].key() != primary_key)
        {
            return Err(BudgetStoreError::Invariant(
                "compatibility capture requires exactly one primary grant quota".to_string(),
            ));
        }
        let mut staged = Vec::with_capacity(quotas.len());
        let mut quota_exhausted = false;
        for quota in quotas {
            quota.validate()?;
            let grant_index_key = quota.key().grant_index().map_or(-1_i64, i64::from);
            let persisted = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![
                        quota.key().profile().as_str(),
                        quota.key().owner_id(),
                        grant_index_key,
                    ],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?;
            let (reserved, captured, exists) = match persisted {
                Some((stored_maximum, reserved, captured)) => {
                    if stored_maximum != quota.max_invocations() {
                        return Err(BudgetStoreError::Invariant(format!(
                            "invocation quota `{}` was presented with a different maximum",
                            quota.key().owner_id()
                        )));
                    }
                    (reserved, captured, true)
                }
                None => {
                    if mode == SqliteInvocationQuotaMutationMode::Reserve
                        && action == SqliteInvocationQuotaMutationAction::Replay
                    {
                        return Err(BudgetStoreError::Invariant(format!(
                            "composite replay is missing invocation quota authority for `{}`",
                            quota.key().owner_id()
                        )));
                    }
                    if mode == SqliteInvocationQuotaMutationMode::CaptureCompatibility
                        && action == SqliteInvocationQuotaMutationAction::Replay
                    {
                        let grant_index = quota.key().grant_index().ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "compatibility quota is missing its grant index".to_string(),
                            )
                        })?;
                        Self::reject_composite_managed_grant(
                            transaction,
                            quota.key().owner_id(),
                            usize::try_from(grant_index).map_err(|_| {
                                BudgetStoreError::Invariant(
                                    "compatibility quota grant index does not fit usize"
                                        .to_string(),
                                )
                            })?,
                        )?;
                    }
                    if action == SqliteInvocationQuotaMutationAction::Reverse {
                        return Err(BudgetStoreError::Invariant(format!(
                            "invocation quota `{}` must be migrated before reversal",
                            quota.key().owner_id()
                        )));
                    }
                    (
                        0,
                        if quota.key() == primary_key {
                            primary_usage_count
                        } else {
                            0
                        },
                        false,
                    )
                }
            };
            let current_count = reserved.checked_add(captured).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved invocations + captured invocations overflowed u32".to_string(),
                )
            })?;
            if current_count > quota.max_invocations() {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key().owner_id()
                )));
            }
            if matches!(
                mode,
                SqliteInvocationQuotaMutationMode::CaptureCompatibility
            ) && !matches!(action, SqliteInvocationQuotaMutationAction::Replay)
                && reserved != 0
            {
                return Err(BudgetStoreError::Invariant(
                    "compatibility capture cannot mutate reserved invocation authority".to_string(),
                ));
            }
            quota_exhausted |= current_count == quota.max_invocations();
            staged.push(SqliteStagedInvocationQuota {
                quota: quota.clone(),
                before_reserved: reserved,
                before_captured: captured,
                reserved,
                captured,
                exists,
            });
        }
        let primary_before = staged
            .iter()
            .find(|entry| entry.quota.key() == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .reserved
            .checked_add(
                staged
                    .iter()
                    .find(|entry| entry.quota.key() == primary_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant("missing primary quota counter".to_string())
                    })?
                    .captured,
            )
            .ok_or_else(|| {
                BudgetStoreError::Overflow("primary invocation count overflowed u32".to_string())
            })?;
        if primary_before != primary_usage_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from structured invocation quota".to_string(),
            ));
        }

        let allowed = match action {
            SqliteInvocationQuotaMutationAction::Attempt { external_denied } => {
                let allowed =
                    Self::invocation_quota_attempt_is_allowed(quota_exhausted, external_denied);
                if allowed {
                    for entry in &mut staged {
                        match mode {
                            SqliteInvocationQuotaMutationMode::Reserve => {
                                entry.reserved =
                                    entry.reserved.checked_add(1).ok_or_else(|| {
                                        BudgetStoreError::Overflow(
                                            "reserved invocation count overflowed u32".to_string(),
                                        )
                                    })?;
                            }
                            SqliteInvocationQuotaMutationMode::CaptureCompatibility => {
                                entry.captured =
                                    entry.captured.checked_add(1).ok_or_else(|| {
                                        BudgetStoreError::Overflow(
                                            "captured invocation count overflowed u32".to_string(),
                                        )
                                    })?;
                            }
                        }
                    }
                }
                allowed
            }
            SqliteInvocationQuotaMutationAction::Replay => false,
            SqliteInvocationQuotaMutationAction::Reverse => {
                if mode != SqliteInvocationQuotaMutationMode::CaptureCompatibility {
                    return Err(BudgetStoreError::Invariant(
                        "only compatibility capture authority can be reversed".to_string(),
                    ));
                }
                for entry in &mut staged {
                    entry.captured = entry.captured.checked_sub(1).ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "compatibility capture has no reversible invocation".to_string(),
                        )
                    })?;
                }
                true
            }
        };

        let event_seq = sqlite_integer_from_u64(event_seq, "invocation quota sequence")?;
        for entry in &staged {
            let grant_index_key = entry.quota.key().grant_index().map_or(-1_i64, i64::from);
            if entry.exists {
                if !allowed {
                    continue;
                }
                let updated = transaction.execute(
                    r#"
                    UPDATE budget_invocation_quota_usage
                    SET reserved_invocations = ?4,
                        captured_invocations = ?5,
                        updated_at = ?6,
                        seq = ?7
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                      AND max_invocations = ?8
                      AND reserved_invocations = ?9
                      AND captured_invocations = ?10
                    "#,
                    params![
                        entry.quota.key().profile().as_str(),
                        entry.quota.key().owner_id(),
                        grant_index_key,
                        i64::from(entry.reserved),
                        i64::from(entry.captured),
                        updated_at,
                        event_seq,
                        i64::from(entry.quota.max_invocations()),
                        i64::from(entry.before_reserved),
                        i64::from(entry.before_captured),
                    ],
                )?;
                if updated != 1 {
                    return Err(BudgetStoreError::Invariant(format!(
                        "invocation quota `{}` changed during mutation",
                        entry.quota.key().owner_id()
                    )));
                }
            } else {
                let inserted = transaction.execute(
                    r#"
                    INSERT INTO budget_invocation_quota_usage (
                        profile, owner_id, grant_index_key, max_invocations,
                        reserved_invocations, captured_invocations, updated_at, seq
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        entry.quota.key().profile().as_str(),
                        entry.quota.key().owner_id(),
                        grant_index_key,
                        i64::from(entry.quota.max_invocations()),
                        i64::from(entry.reserved),
                        i64::from(entry.captured),
                        updated_at,
                        event_seq,
                    ],
                )?;
                if inserted != 1 {
                    return Err(BudgetStoreError::Invariant(format!(
                        "invocation quota `{}` was not inserted exactly once",
                        entry.quota.key().owner_id()
                    )));
                }
            }
        }

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
            .find(|usage| usage.quota.key() == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        Ok(SqliteInvocationQuotaMutationOutcome {
            allowed,
            quota_exhausted,
            invocation_counts_after,
            primary_count_after,
        })
    }

    pub(super) fn compare_and_persist_legacy_projection(
        transaction: &rusqlite::Transaction<'_>,
        mutation: SqliteLegacyProjectionMutation<'_>,
    ) -> Result<(), BudgetStoreError> {
        let SqliteLegacyProjectionMutation {
            capability_id,
            grant_index,
            expected,
            after,
            updated_at,
        } = mutation;
        let after_seq = sqlite_integer_from_u64(after.seq, "legacy projection sequence")?;
        if let Some(expected) = expected {
            let updated = transaction.execute(
                r#"
                UPDATE capability_grant_budgets
                SET invocation_count = ?3,
                    updated_at = ?4,
                    seq = ?5,
                    total_cost_exposed = ?6,
                    total_cost_realized_spend = ?7
                WHERE capability_id = ?1 AND grant_index = ?2
                  AND invocation_count = ?8
                  AND total_cost_exposed = ?9
                  AND total_cost_realized_spend = ?10
                  AND seq = ?11
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    i64::from(after.invocation_count),
                    updated_at,
                    after_seq,
                    sqlite_integer_from_u64(
                        after.total_cost_exposed,
                        "legacy projection exposed total",
                    )?,
                    sqlite_integer_from_u64(
                        after.total_cost_realized_spend,
                        "legacy projection realized-spend total",
                    )?,
                    i64::from(expected.invocation_count),
                    sqlite_integer_from_u64(
                        expected.total_cost_exposed,
                        "expected legacy projection exposed total",
                    )?,
                    sqlite_integer_from_u64(
                        expected.total_cost_realized_spend,
                        "expected legacy projection realized-spend total",
                    )?,
                    sqlite_integer_from_u64(expected.seq, "expected legacy projection sequence")?,
                ],
            )?;
            if updated != 1 {
                return Err(BudgetStoreError::Invariant(format!(
                    "legacy budget projection `{capability_id}` changed during quota mutation"
                )));
            }
            return Ok(());
        }
        let inserted = transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id, grant_index, invocation_count, updated_at, seq,
                total_cost_exposed, total_cost_realized_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                capability_id,
                grant_index as i64,
                i64::from(after.invocation_count),
                updated_at,
                after_seq,
                sqlite_integer_from_u64(
                    after.total_cost_exposed,
                    "legacy projection exposed total",
                )?,
                sqlite_integer_from_u64(
                    after.total_cost_realized_spend,
                    "legacy projection realized-spend total",
                )?,
            ],
        )?;
        if inserted != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "legacy budget projection `{capability_id}` was not inserted exactly once"
            )));
        }
        Ok(())
    }

    pub(super) fn compatibility_invocation_quota_maximum(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<u32>, BudgetStoreError> {
        Self::reject_composite_managed_grant(transaction, capability_id, grant_index)?;
        let quota_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
        let grant_index_key = i64::from(quota_key.grant_index().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "grant invocation quota is missing its grant index".to_string(),
            )
        })?);
        let persisted = transaction
            .query_row(
                r#"
                SELECT max_invocations
                FROM budget_invocation_quota_usage
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                "#,
                params![
                    quota_key.profile().as_str(),
                    quota_key.owner_id(),
                    grant_index_key
                ],
                |row| budget_u32_from_row(row, 0, "quota max_invocations"),
            )
            .optional()?;
        if persisted.is_some() {
            return Ok(persisted);
        }
        let historical_maximum = transaction
            .query_row(
                r#"
                SELECT max_invocations
                FROM budget_mutation_events
                WHERE capability_id = ?1 AND grant_index = ?2
                  AND kind IN (?3, ?4)
                ORDER BY event_seq ASC
                LIMIT 1
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    BudgetMutationKind::IncrementInvocation.as_str(),
                    BudgetMutationKind::AuthorizeExposure.as_str(),
                ],
                |row| optional_budget_u32_from_row(row, 0, "historical max_invocations"),
            )
            .optional()?;
        Ok(Some(historical_maximum.flatten().unwrap_or(u32::MAX)))
    }

    pub fn try_increment_with_event_id(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::increment_invocation_in_transaction_inner(
            &transaction,
            capability_id,
            grant_index,
            max_invocations,
            event_id,
            None,
        )?;
        transaction.commit()?;
        Ok(outcome.allowed)
    }

    /// Apply one invocation increment inside the admission consensus transaction.
    ///
    /// `event_id` is the durable consensus operation ID, and `authority` is the
    /// leader authority frozen into the canonical command. Reapplying the exact
    /// committed entry returns its stored outcome without incrementing again.
    pub fn increment_invocation_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: &str,
        authority: &BudgetEventAuthority,
    ) -> Result<SqliteBudgetIncrementOutcome, BudgetStoreError> {
        Self::increment_invocation_in_transaction_inner(
            transaction,
            capability_id,
            grant_index,
            max_invocations,
            Some(event_id),
            Some(authority),
        )
    }

    fn increment_invocation_in_transaction_inner(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<SqliteBudgetIncrementOutcome, BudgetStoreError> {
        let existing_event = Self::existing_increment_outcome(
            transaction,
            event_id,
            capability_id,
            grant_index,
            max_invocations,
            authority,
        )?;
        let (legacy_invocation_count, legacy_usage_seq) = transaction
            .query_row(
                r#"
                SELECT invocation_count, seq
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "usage sequence")?,
                    ))
                },
            )
            .optional()?
            .unwrap_or((0, 0));
        SqliteBudgetStore::reject_composite_managed_grant(
            transaction,
            capability_id,
            grant_index,
        )?;
        if let Some(outcome) = existing_event {
            let quota = BudgetInvocationQuota::from_persisted_parts(
                BudgetQuotaKey::grant(capability_id, grant_index)?,
                max_invocations.unwrap_or(u32::MAX),
            )?;
            Self::compare_and_mutate_invocation_quotas(
                transaction,
                std::slice::from_ref(&quota),
                quota.key(),
                legacy_invocation_count,
                SqliteInvocationQuotaMutationContext {
                    mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                    action: SqliteInvocationQuotaMutationAction::Replay,
                    event_seq: outcome.event_seq.max(legacy_usage_seq),
                    updated_at: unix_now(),
                },
            )?;
            return Ok(outcome);
        }

        let current: Option<(u32, u64, u64, u64)> = transaction
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
        let expected_projection = current.map(
            |(invocation_count, total_cost_exposed, total_cost_realized_spend, seq)| {
                SqliteLegacyProjectionState {
                    invocation_count,
                    total_cost_exposed,
                    total_cost_realized_spend,
                    seq,
                }
            },
        );
        let (current, total_cost_exposed, total_cost_realized_spend, _) =
            current.unwrap_or((0, 0, 0, 0));
        if max_invocations.is_none() && current == u32::MAX {
            return Err(BudgetStoreError::Overflow(
                "unbounded invocation counter exhausted u32".to_string(),
            ));
        }
        let updated_at = unix_now();
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant(capability_id, grant_index)?,
            max_invocations.unwrap_or(u32::MAX),
        )?;
        let mutation = Self::compare_and_mutate_invocation_quotas(
            transaction,
            std::slice::from_ref(&quota),
            quota.key(),
            current,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Attempt {
                    external_denied: false,
                },
                event_seq,
                updated_at,
            },
        )?;
        if mutation.allowed {
            Self::compare_and_persist_legacy_projection(
                transaction,
                SqliteLegacyProjectionMutation {
                    capability_id,
                    grant_index,
                    expected: expected_projection,
                    after: SqliteLegacyProjectionState {
                        invocation_count: mutation.primary_count_after,
                        total_cost_exposed,
                        total_cost_realized_spend,
                        seq: event_seq,
                    },
                    updated_at,
                },
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            transaction,
            event_id,
            None,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::IncrementInvocation,
            Some(mutation.allowed),
            event_seq,
            mutation.allowed.then_some(event_seq),
            0,
            0,
            max_invocations,
            None,
            None,
            mutation.primary_count_after,
            total_cost_exposed,
            total_cost_realized_spend,
        )?;
        Ok(SqliteBudgetIncrementOutcome {
            allowed: mutation.allowed,
            invocation_count: mutation.primary_count_after,
            event_seq,
        })
    }
}

fn reject_volatile_database_path(path: &Path) -> Result<(), BudgetStoreError> {
    let path = path.to_string_lossy();
    let lower = path.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path.is_empty() || path == ":memory:" || memory_uri || lower.starts_with("file::memory:") {
        return Err(BudgetStoreError::Invariant(
            "volatile SQLite budget-store paths are not durable; use open_in_memory for an explicitly ephemeral store"
                .to_string(),
        ));
    }
    Ok(())
}
