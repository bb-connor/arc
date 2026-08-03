impl SqliteBudgetStore {
    pub fn delete_mutation_event(&self, event_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params![event_id],
        )?;
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_hold(&self, hold_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn hold_authority(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let authority = Self::load_hold(&transaction, hold_id)?.and_then(|hold| hold.authority);
        transaction.rollback()?;
        Ok(authority)
    }

    pub fn authorization_authority_source(
        &self,
        hold_id: Option<&str>,
        event_id: &str,
    ) -> Result<SqliteBudgetAuthorizationAuthority, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;

        let source = if let Some(claim) = hold_id
            .map(|hold_id| Self::load_authorization_claim(&transaction, hold_id))
            .transpose()?
            .flatten()
        {
            let compensated = claim.allowed == Some(true)
                && Self::rollback_event_exists(
                    &transaction,
                    &claim.event_id,
                    hold_id,
                    &claim.capability_id,
                    claim.grant_index,
                    claim.requested_exposure_units,
                    claim.authority.as_ref(),
                )?;
            if compensated {
                SqliteBudgetAuthorizationAuthority::Current
            } else {
                SqliteBudgetAuthorizationAuthority::Persisted(claim.authority)
            }
        } else if let Some(event) = Self::load_mutation_event(&transaction, event_id)? {
            let compensated = event.kind == BudgetMutationKind::AuthorizeExposure
                && event.allowed == Some(true)
                && Self::rollback_event_exists(
                    &transaction,
                    &event.event_id,
                    event.hold_id.as_deref(),
                    &event.capability_id,
                    event.grant_index as usize,
                    event.exposure_units,
                    event.authority.as_ref(),
                )?;
            if compensated {
                SqliteBudgetAuthorizationAuthority::Current
            } else {
                SqliteBudgetAuthorizationAuthority::Persisted(event.authority)
            }
        } else {
            SqliteBudgetAuthorizationAuthority::Current
        };

        transaction.rollback()?;
        Ok(source)
    }

    pub(super) fn authorization_authority_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        if let Some(claim) = hold_id
            .map(|hold_id| Self::load_authorization_claim(transaction, hold_id))
            .transpose()?
            .flatten()
        {
            let compensated = claim.allowed == Some(true)
                && Self::rollback_event_exists(
                    transaction,
                    &claim.event_id,
                    hold_id,
                    &claim.capability_id,
                    claim.grant_index,
                    claim.requested_exposure_units,
                    claim.authority.as_ref(),
                )?;
            if !compensated {
                return Self::persisted_authorization_authority(authority_mode, claim.authority);
            }
            return Self::replacement_authorization_authority(
                authority_mode,
                claim.authority.as_ref(),
            );
        }

        if let Some(event) = event_id
            .map(|event_id| Self::load_mutation_event(transaction, event_id))
            .transpose()?
            .flatten()
        {
            let compensated = event.kind == BudgetMutationKind::AuthorizeExposure
                && event.allowed == Some(true)
                && Self::rollback_event_exists(
                    transaction,
                    &event.event_id,
                    event.hold_id.as_deref(),
                    &event.capability_id,
                    event.grant_index as usize,
                    event.exposure_units,
                    event.authority.as_ref(),
                )?;
            if !compensated {
                return Self::persisted_authorization_authority(authority_mode, event.authority);
            }
            return Self::replacement_authorization_authority(
                authority_mode,
                event.authority.as_ref(),
            );
        }

        Self::replacement_authorization_authority(authority_mode, None)
    }

    fn persisted_authorization_authority(
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
        persisted_authority: Option<BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        if let SqliteBudgetAuthorizationAuthorityMode::CallerPinned(requested_authority) =
            authority_mode
        {
            if requested_authority != &persisted_authority {
                return Err(BudgetStoreError::Invariant(
                    "persisted budget authorization authority changed on retry".to_string(),
                ));
            }
        }
        Ok(persisted_authority)
    }

    fn replacement_authorization_authority(
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
        previous_authority: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match authority_mode {
            SqliteBudgetAuthorizationAuthorityMode::CallerPinned(requested_authority) => {
                if previous_authority.is_some() && requested_authority.is_none() {
                    return Err(BudgetStoreError::Invariant(
                        "compensated HA authorization cannot rebind without current authority metadata"
                            .to_string(),
                    ));
                }
                Ok(requested_authority.clone())
            }
            SqliteBudgetAuthorizationAuthorityMode::ServerCurrent(current_authority) => {
                Self::resolved_current_authority(current_authority, previous_authority)
            }
        }
    }

    fn resolved_current_authority(
        current_authority: &SqliteBudgetCurrentAuthority,
        previous_authority: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let SqliteBudgetCurrentAuthority::Resolved(current_authority) = current_authority else {
            return Err(BudgetStoreError::Invariant(
                "current budget authority is required for a new or compensated authorization"
                    .to_string(),
            ));
        };
        if previous_authority.is_some() && current_authority.is_none() {
            return Err(BudgetStoreError::Invariant(
                "compensated HA authorization cannot rebind without current authority metadata"
                    .to_string(),
            ));
        }
        Ok(current_authority.clone())
    }

    pub fn import_mutation_record(
        &self,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::import_mutation_record_in_transaction(&transaction, record)?;
        Self::validate_imported_event_invocation_authority(&transaction, record, None, None)?;
        transaction.commit()?;
        Ok(())
    }

    fn import_mutation_record_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let sqlite_record = ImportedMutationSqlIntegers::try_from_record(record)?;
        Self::validate_imported_mutation_shape(record)?;
        let event_seq_is_abandoned = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_abandoned_event_seqs WHERE seq = ?1
                UNION ALL
                SELECT 1
                FROM budget_abandoned_event_ranges
                WHERE start_seq <= ?1 AND end_seq >= ?1
            )
            "#,
            params![sqlite_record.event_seq],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        if event_seq_is_abandoned {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event sequence {} was already recorded as abandoned",
                record.event_seq
            )));
        }

        let mut replacement_event_seq = None;
        let duplicate_event =
            if let Some(existing) = Self::load_mutation_event(transaction, &record.event_id)? {
                if Self::same_imported_mutation(&existing, record) {
                    true
                } else if record.event_seq > existing.event_seq
                    && Self::rolled_back_authorize_can_be_replaced(transaction, &existing, record)?
                {
                    replacement_event_seq = Some((
                        existing.event_seq,
                        sqlite_integer_from_u64(
                            existing.event_seq,
                            "superseded budget event sequence",
                        )?,
                    ));
                    false
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event_id `{}` was reused for a different mutation",
                        record.event_id
                    )));
                }
            } else {
                false
            };

        if record.kind == BudgetMutationKind::AuthorizeExposure {
            let allowed = record.allowed.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "imported authorization mutation is missing its frozen decision".to_string(),
                )
            })?;
            if let Some(hold_id) = record.hold_id.as_deref() {
                Self::claim_authorization_attempt(
                    transaction,
                    hold_id,
                    &record.event_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    record.exposure_units,
                    record.max_invocations,
                    record.max_cost_per_invocation,
                    record.max_total_cost_units,
                    record.authority.as_ref(),
                    Some(allowed),
                )?;
            }
        }

        raise_budget_replication_seq_floor(transaction, record.event_seq)?;
        if let Some(usage_seq) = record.usage_seq {
            raise_budget_replication_seq_floor(transaction, usage_seq)?;
        }
        if duplicate_event {
            return Ok(());
        }

        if let Some((existing_event_seq, sqlite_existing_event_seq)) = replacement_event_seq {
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![record.event_id],
            )?;
            if existing_event_seq > 0 && existing_event_seq != record.event_seq {
                transaction.execute(
                    "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                    params![sqlite_existing_event_seq],
                )?;
            }
            Self::reset_budget_ack_head_watermark(transaction)?;
            if let Some(hold_id) = record.hold_id.as_deref() {
                transaction.execute(
                    "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                    params![hold_id],
                )?;
            }
        }

        Self::insert_imported_mutation_event(transaction, record, &sqlite_record)?;
        Self::apply_imported_hold_state(transaction, record)?;
        Ok(())
    }

    /// Insert one imported mutation event row verbatim. Shared by the new-event
    /// import path and the follower rollback-retry REPLACE path (which deletes the
    /// superseded row and tombstones its seq before re-inserting the leader's
    /// re-appended event under its fresh higher event_seq). A plain INSERT is
    /// deliberate and fail-closed: the unique event_seq index rejects a corrupt
    /// stream that reused a seq for a different event rather than silently masking
    /// it.
    fn insert_imported_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
        sqlite_record: &ImportedMutationSqlIntegers,
    ) -> Result<(), BudgetStoreError> {
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
                record.event_id,
                record.hold_id,
                record
                    .admission_operation
                    .as_ref()
                    .map(BudgetAdmissionOperationBinding::operation_id),
                record
                    .admission_operation
                    .as_ref()
                    .map(BudgetAdmissionOperationBinding::request_binding_hash),
                record.capability_id,
                i64::from(record.grant_index),
                record.kind.as_str(),
                record.allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                record.recorded_at,
                sqlite_record.event_seq,
                sqlite_record.usage_seq,
                sqlite_record.exposure_units,
                sqlite_record.realized_spend_units,
                record.max_invocations.map(i64::from),
                sqlite_record.max_cost_per_invocation,
                sqlite_record.max_total_cost_units,
                i64::from(record.invocation_count_after),
                sqlite_record.total_cost_exposed_after,
                sqlite_record.total_cost_realized_spend_after,
                record.authority.as_ref().map(|value| value.authority_id.as_str()),
                record.authority.as_ref().map(|value| value.lease_id.as_str()),
                sqlite_record.lease_epoch,
            ],
        )?;
        Ok(())
    }

    fn validate_imported_mutation_shape(
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        if !record.invocation_counts_after.is_empty()
            || record.revocation_set.is_some()
            || (record.kind == BudgetMutationKind::AuthorizeExposure && record.allowed.is_none())
            || matches!(
                record.kind,
                BudgetMutationKind::ReserveInvocations
                    | BudgetMutationKind::CaptureInvocations
                    | BudgetMutationKind::ReverseInvocations
            )
        {
            return Err(BudgetStoreError::Invariant(
                "legacy SQLite schema cannot import composite budget mutations".to_string(),
            ));
        }

        let expected_invocation_state = match record.kind {
            BudgetMutationKind::IncrementInvocation => {
                if record.allowed == Some(false) {
                    BudgetInvocationReservationState::Denied
                } else {
                    BudgetInvocationReservationState::Captured
                }
            }
            BudgetMutationKind::ReverseExposure => BudgetInvocationReservationState::Reversed,
            BudgetMutationKind::AuthorizeExposure
            | BudgetMutationKind::CaptureExposure
            | BudgetMutationKind::ReleaseExposure
            | BudgetMutationKind::ReconcileSpend
            | BudgetMutationKind::ExpireHold => BudgetInvocationReservationState::Absent,
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => {
                return Err(BudgetStoreError::Invariant(
                    "legacy SQLite schema cannot import composite budget mutations".to_string(),
                ));
            }
        };
        let expected_monetary_state = match record.kind {
            BudgetMutationKind::AuthorizeExposure
                if record.allowed != Some(false) && record.exposure_units > 0 =>
            {
                BudgetMonetaryHoldState::Exposed
            }
            BudgetMutationKind::CaptureExposure => BudgetMonetaryHoldState::Captured,
            BudgetMutationKind::ReverseExposure if record.exposure_units == 0 => {
                BudgetMonetaryHoldState::None
            }
            BudgetMutationKind::ReverseExposure => BudgetMonetaryHoldState::Reversed,
            BudgetMutationKind::ReleaseExposure => BudgetMonetaryHoldState::Released,
            BudgetMutationKind::ReconcileSpend => BudgetMonetaryHoldState::Reconciled,
            BudgetMutationKind::ExpireHold => BudgetMonetaryHoldState::Released,
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {
                BudgetMonetaryHoldState::None
            }
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => {
                return Err(BudgetStoreError::Invariant(
                    "legacy SQLite schema cannot import composite budget mutations".to_string(),
                ));
            }
        };
        if record.invocation_state != expected_invocation_state
            || record.monetary_state != expected_monetary_state
        {
            return Err(BudgetStoreError::Invariant(
                "imported budget mutation state does not match its persisted legacy projection"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn same_imported_mutation(
        existing: &BudgetMutationRecord,
        imported: &BudgetMutationRecord,
    ) -> bool {
        existing.event_id == imported.event_id
            && existing.hold_id == imported.hold_id
            && existing.admission_operation == imported.admission_operation
            && existing.capability_id == imported.capability_id
            && existing.grant_index == imported.grant_index
            && existing.kind == imported.kind
            && existing.allowed == imported.allowed
            && existing.recorded_at == imported.recorded_at
            && existing.event_seq == imported.event_seq
            && existing.usage_seq == imported.usage_seq
            && existing.exposure_units == imported.exposure_units
            && existing.realized_spend_units == imported.realized_spend_units
            && existing.max_invocations == imported.max_invocations
            && existing.max_cost_per_invocation == imported.max_cost_per_invocation
            && existing.max_total_cost_units == imported.max_total_cost_units
            && existing.invocation_count_after == imported.invocation_count_after
            && existing.invocation_counts_after == imported.invocation_counts_after
            && existing.invocation_state == imported.invocation_state
            && existing.monetary_state == imported.monetary_state
            && existing.revocation_set == imported.revocation_set
            && existing.total_cost_exposed_after == imported.total_cost_exposed_after
            && existing.total_cost_realized_spend_after == imported.total_cost_realized_spend_after
            && existing.authority == imported.authority
    }

    pub fn list_usages_after(
        &self,
        limit: usize,
        after_seq: Option<u64>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let after_seq = after_seq
            .map(|value| sqlite_integer_from_u64(value, "budget usage cursor"))
            .transpose()?;
        let limit = i64::try_from(limit).map_err(|_| {
            BudgetStoreError::Overflow(
                "budget usage page limit exceeds SQLite INTEGER".to_string(),
            )
        })?;
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
            WHERE (?1 IS NULL OR seq > ?1)
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq, limit], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_all_usages(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
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
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            "#,
        )?;
        let rows = statement.query_map([], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Page the captured-only grant quota projections maintained by legacy
    /// compatibility mutations. The full `(seq, owner_id, grant_index)` cursor
    /// prevents equal-sequence rows from being skipped during snapshot paging.
    pub fn list_compatibility_invocation_quota_usages_after(
        &self,
        limit: usize,
        after: Option<&BudgetInvocationQuotaUsageRecord>,
    ) -> Result<Vec<BudgetInvocationQuotaUsageRecord>, BudgetStoreError> {
        if let Some(after) = after {
            after.validate_compatibility_projection()?;
        }
        let sqlite_limit = i64::try_from(limit).map_err(|_| {
            BudgetStoreError::Overflow(
                "invocation quota replication page limit exceeds SQLite INTEGER".to_string(),
            )
        })?;
        let after_seq = after
            .map(|record| {
                sqlite_integer_from_u64(record.seq, "invocation quota replication cursor")
            })
            .transpose()?;
        let after_owner_id = after.map(|record| record.usage.quota.key().owner_id());
        let after_grant_index = after
            .map(|record| {
                record.usage.quota.key().grant_index().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "invocation quota replication cursor is missing grant_index".to_string(),
                    )
                })
            })
            .transpose()?
            .map(i64::from);

        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT quota.profile, quota.owner_id, quota.grant_index_key,
                   quota.max_invocations, quota.reserved_invocations,
                   quota.captured_invocations, quota.updated_at, quota.seq
            FROM budget_invocation_quota_usage AS quota
            WHERE quota.profile = 'chio.grant-invocation.v1'
              AND NOT EXISTS (
                  SELECT 1
                  FROM budget_composite_managed_grants AS managed
                  WHERE managed.capability_id = quota.owner_id
                    AND managed.grant_index = quota.grant_index_key
              )
              AND (
                  ?1 IS NULL
                  OR quota.seq > ?1
                  OR (quota.seq = ?1 AND quota.owner_id > ?2)
                  OR (
                      quota.seq = ?1
                      AND quota.owner_id = ?2
                      AND quota.grant_index_key > ?3
                  )
              )
            ORDER BY quota.seq ASC, quota.owner_id ASC, quota.grant_index_key ASC
            LIMIT ?4
            "#,
        )?;
        let rows = statement
            .query_map(
                params![after_seq, after_owner_id, after_grant_index, sqlite_limit],
                RawQuotaRow::from_sql,
            )?
            .collect::<Result<Vec<RawQuotaRow>, _>>()?;
        rows.into_iter()
            .map(Self::hydrate_compatibility_invocation_quota_usage)
            .collect()
    }

    pub fn get_compatibility_invocation_quota_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetInvocationQuotaUsageRecord>, BudgetStoreError> {
        let grant_index = u32::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let connection = self.connection()?;
        Self::load_compatibility_invocation_quota_usage(&connection, capability_id, grant_index)
    }

    fn load_compatibility_invocation_quota_usage(
        connection: &Connection,
        capability_id: &str,
        grant_index: u32,
    ) -> Result<Option<BudgetInvocationQuotaUsageRecord>, BudgetStoreError> {
        let row = connection
            .query_row(
                r#"
                SELECT quota.profile, quota.owner_id, quota.grant_index_key,
                       quota.max_invocations, quota.reserved_invocations,
                       quota.captured_invocations, quota.updated_at, quota.seq
                FROM budget_invocation_quota_usage AS quota
                WHERE quota.profile = 'chio.grant-invocation.v1'
                  AND quota.owner_id = ?1
                  AND quota.grant_index_key = ?2
                  AND NOT EXISTS (
                      SELECT 1
                      FROM budget_composite_managed_grants AS managed
                      WHERE managed.capability_id = quota.owner_id
                        AND managed.grant_index = quota.grant_index_key
                  )
                "#,
                params![capability_id, i64::from(grant_index)],
                RawQuotaRow::from_sql,
            )
            .optional()?;
        row.map(Self::hydrate_compatibility_invocation_quota_usage)
            .transpose()
    }

    fn hydrate_compatibility_invocation_quota_usage(
        row: RawQuotaRow,
    ) -> Result<BudgetInvocationQuotaUsageRecord, BudgetStoreError> {
        let RawQuotaRow {
            profile,
            owner_id,
            grant_index_key,
            maximum,
            reserved,
            captured,
            updated_at,
            seq,
        } = row;
        let profile = BudgetQuotaProfile::parse(&profile).ok_or_else(|| {
            BudgetStoreError::Invariant("unknown persisted quota profile".to_string())
        })?;
        let grant_index = u32::try_from(grant_index_key).map_err(|_| {
            BudgetStoreError::Invariant(
                "persisted compatibility quota grant index is out of range".to_string(),
            )
        })?;
        let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, Some(grant_index))?;
        let quota = BudgetInvocationQuota::from_persisted_parts(key, maximum)?;
        let record = BudgetInvocationQuotaUsageRecord {
            usage: BudgetInvocationQuotaUsage {
                quota,
                reserved_invocations_after: reserved,
                captured_invocations_after: captured,
            },
            updated_at,
            seq,
        };
        record.validate_compatibility_projection()?;
        Ok(record)
    }

    pub fn list_mutation_events_after_seq(
        &self,
        limit: usize,
        after_event_seq: u64,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let after_event_seq =
            sqlite_integer_from_u64(after_event_seq, "budget mutation event cursor")?;
        let limit = i64::try_from(limit).map_err(|_| {
            BudgetStoreError::Overflow(
                "budget mutation event page limit exceeds SQLite INTEGER".to_string(),
            )
        })?;
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
            WHERE event_seq > ?1
            ORDER BY event_seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_event_seq, limit], mutation_record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn generated_event_id(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<String, BudgetStoreError> {
        let count =
            transaction.query_row("SELECT COUNT(*) FROM budget_mutation_events", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(format!(
            "sqlite-budget-event-{}-{}",
            unix_now(),
            count.max(0) + 1
        ))
    }

    pub(super) fn load_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<Option<SqliteBudgetHold>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    authorized_exposure_units,
                    remaining_exposure_units,
                    invocation_count_debited,
                    disposition,
                    reserved_until,
                    authority_id,
                    lease_id,
                    lease_epoch,
                    operation_id,
                    request_binding_hash
                FROM budget_authorization_holds
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(6)?;
                    let authority =
                        sqlite_budget_event_authority(row.get(8)?, row.get(9)?, row.get(10)?)?;
                    Ok(SqliteBudgetHold {
                        hold_id: row.get(0)?,
                        capability_id: row.get(1)?,
                        grant_index: budget_usize_from_row(row, 2, "grant_index")?,
                        authorized_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "authorized_exposure_units",
                        )?,
                        remaining_exposure_units: budget_u64_from_row(
                            row,
                            4,
                            "remaining_exposure_units",
                        )?,
                        invocation_count_debited: row.get::<_, i64>(5)? > 0,
                        disposition: HoldDisposition::parse(&disposition).ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?,
                        reserved_until: row.get(7)?,
                        authority,
                        operation_id: row.get(11)?,
                        request_binding_hash: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn load_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        transaction
            .query_row(
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
                WHERE event_id = ?1
                "#,
                params![event_id],
                mutation_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn create_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        Self::create_hold_with_admission_operation(
            transaction,
            BudgetHoldCreateInput {
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                authority,
                admission_operation: None,
            },
        )
    }

    pub(super) fn create_hold_with_admission_operation(
        transaction: &rusqlite::Transaction<'_>,
        input: BudgetHoldCreateInput<'_>,
    ) -> Result<(), BudgetStoreError> {
        let BudgetHoldCreateInput {
            hold_id,
            capability_id,
            grant_index,
            authorized_exposure_units,
            authority,
            admission_operation,
        } = input;
        let grant_index = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Overflow("grant_index exceeds u32 range".to_string()))?;
        let authorized_exposure_units = sqlite_integer_from_u64(
            authorized_exposure_units,
            "authorized hold exposure",
        )?;
        let lease_epoch = authority
            .map(|value| sqlite_integer_from_u64(value.lease_epoch, "budget hold lease epoch"))
            .transpose()?;
        let now = unix_now();
        let operation_id = admission_operation.map(|operation| operation.operation_id);
        let request_binding_hash =
            admission_operation.map(|operation| operation.request_binding_hash);
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                operation_id,
                request_binding_hash,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12, ?12)
            "#,
            params![
                hold_id,
                operation_id,
                request_binding_hash,
                capability_id,
                i64::from(grant_index),
                authorized_exposure_units,
                authorized_exposure_units,
                HoldDisposition::Open.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch,
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn update_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let remaining_exposure_units =
            sqlite_integer_from_u64(remaining_exposure_units, "remaining hold exposure")?;
        let lease_epoch = authority
            .map(|value| sqlite_integer_from_u64(value.lease_epoch, "budget hold lease epoch"))
            .transpose()?;
        transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = ?2,
                disposition = ?3,
                authority_id = ?4,
                lease_id = ?5,
                lease_epoch = ?6,
                updated_at = ?7
            WHERE hold_id = ?1
            "#,
            params![
                hold_id,
                remaining_exposure_units,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch,
                unix_now(),
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn upsert_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        Self::upsert_hold_with_admission_operation(
            transaction,
            BudgetHoldUpsertInput {
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                disposition,
                authority,
                admission_operation: None,
            },
        )
    }

    pub(super) fn upsert_hold_with_admission_operation(
        transaction: &rusqlite::Transaction<'_>,
        input: BudgetHoldUpsertInput<'_>,
    ) -> Result<(), BudgetStoreError> {
        let BudgetHoldUpsertInput {
            hold_id,
            capability_id,
            grant_index,
            authorized_exposure_units,
            remaining_exposure_units,
            disposition,
            authority,
            admission_operation,
        } = input;
        let grant_index_sql = u32::try_from(grant_index)
            .map(i64::from)
            .map_err(|_| BudgetStoreError::Overflow("grant_index exceeds u32 range".to_string()))?;
        let authorized_exposure_units = sqlite_integer_from_u64(
            authorized_exposure_units,
            "authorized hold exposure",
        )?;
        let remaining_exposure_units =
            sqlite_integer_from_u64(remaining_exposure_units, "remaining hold exposure")?;
        let lease_epoch = authority
            .map(|value| sqlite_integer_from_u64(value.lease_epoch, "budget hold lease epoch"))
            .transpose()?;
        if let Some(existing) = Self::load_hold(transaction, hold_id)? {
            let stored = (
                existing.operation_id.as_deref(),
                existing.request_binding_hash.as_deref(),
            );
            let requested = admission_operation
                .map(|operation| (operation.operation_id, operation.request_binding_hash));
            let matches = match (stored, requested) {
                ((None, None), None) => true,
                ((Some(operation_id), Some(request_binding_hash)), Some(requested)) => {
                    (operation_id, request_binding_hash) == requested
                }
                _ => false,
            };
            if !matches {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` admission ownership changed"
                )));
            }
        }
        let now = unix_now();
        let operation_id = admission_operation.map(|operation| operation.operation_id);
        let request_binding_hash =
            admission_operation.map(|operation| operation.request_binding_hash);
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                operation_id,
                request_binding_hash,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12, ?12)
            ON CONFLICT(hold_id) DO UPDATE SET
                operation_id = excluded.operation_id,
                request_binding_hash = excluded.request_binding_hash,
                capability_id = excluded.capability_id,
                grant_index = excluded.grant_index,
                authorized_exposure_units = excluded.authorized_exposure_units,
                remaining_exposure_units = excluded.remaining_exposure_units,
                invocation_count_debited = excluded.invocation_count_debited,
                disposition = excluded.disposition,
                authority_id = excluded.authority_id,
                lease_id = excluded.lease_id,
                lease_epoch = excluded.lease_epoch,
                updated_at = excluded.updated_at
            "#,
            params![
                hold_id,
                operation_id,
                request_binding_hash,
                capability_id,
                grant_index_sql,
                authorized_exposure_units,
                remaining_exposure_units,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch,
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn delete_hold_if_exists(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn claim_authorization_attempt(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        event_id: &str,
        capability_id: &str,
        grant_index: usize,
        requested_exposure_units: u64,
        max_invocations: Option<u32>,
        max_exposure_per_invocation: Option<u64>,
        max_total_exposure_units: Option<u64>,
        authority: Option<&BudgetEventAuthority>,
        allowed: Option<bool>,
    ) -> Result<(Option<bool>, bool), BudgetStoreError> {
        let grant_index_i64 = sqlite_integer_from_u64(
            u64::try_from(grant_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "budget authorization claim grant index exceeds u64".to_string(),
                )
            })?,
            "budget authorization claim grant index",
        )?;
        let requested_exposure_i64 = sqlite_integer_from_u64(
            requested_exposure_units,
            "budget authorization claim exposure",
        )?;
        let max_exposure_i64 = max_exposure_per_invocation
            .map(|value| {
                sqlite_integer_from_u64(value, "budget authorization claim per-invocation maximum")
            })
            .transpose()?;
        let max_total_i64 = max_total_exposure_units
            .map(|value| sqlite_integer_from_u64(value, "budget authorization claim total maximum"))
            .transpose()?;
        let lease_epoch_i64 = authority
            .map(|value| {
                sqlite_integer_from_u64(value.lease_epoch, "budget authorization claim lease epoch")
            })
            .transpose()?;

        let composite_authorization_exists = transaction
            .query_row(
                "SELECT 1 FROM budget_composite_authorizations WHERE hold_id = ?1",
                params![hold_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if composite_authorization_exists {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` belongs to a composite authorization"
            )));
        }

        let existing = Self::load_authorization_claim(transaction, hold_id)?;

        if let Some(existing) = existing {
            let mut rollback_rebind = false;
            let request_matches = existing.event_id == event_id
                && existing.capability_id == capability_id
                && existing.grant_index == grant_index
                && existing.requested_exposure_units == requested_exposure_units
                && existing.max_invocations == max_invocations
                && existing.max_exposure_per_invocation == max_exposure_per_invocation
                && existing.max_total_exposure_units == max_total_exposure_units;
            if !request_matches {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` authorization claim was reused for a different event or input"
                )));
            }
            if let Some(requested_allowed) = allowed {
                if existing
                    .allowed
                    .is_some_and(|existing_allowed| existing_allowed != requested_allowed)
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authorization decision changed"
                    )));
                }
            }
            if existing.authority.as_ref() != authority {
                let fenced_rollback_rebind = existing.allowed == Some(true)
                    && Self::rollback_event_exists(
                        transaction,
                        event_id,
                        Some(hold_id),
                        capability_id,
                        grant_index,
                        requested_exposure_units,
                        existing.authority.as_ref(),
                    )?;
                if !fenced_rollback_rebind {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authorization authority changed"
                    )));
                }
                transaction.execute(
                    r#"
                    UPDATE budget_authorization_claims
                    SET authority_id = ?2,
                        lease_id = ?3,
                        lease_epoch = ?4
                    WHERE hold_id = ?1
                    "#,
                    params![
                        hold_id,
                        authority.map(|value| value.authority_id.as_str()),
                        authority.map(|value| value.lease_id.as_str()),
                        lease_epoch_i64,
                    ],
                )?;
                rollback_rebind = true;
            }
            if let Some(allowed) = allowed {
                transaction.execute(
                    "UPDATE budget_authorization_claims SET allowed = ?2 WHERE hold_id = ?1 AND allowed IS NULL",
                    params![hold_id, if allowed { 1_i64 } else { 0_i64 }],
                )?;
            }
            return Ok((existing.allowed, rollback_rebind));
        }

        let event_claimed_by: Option<String> = transaction
            .query_row(
                "SELECT hold_id FROM budget_authorization_claims WHERE event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_hold_id) = event_claimed_by {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` is already claimed by hold `{existing_hold_id}`"
            )));
        }
        let legacy_hold_exists = transaction
            .query_row(
                "SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![hold_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if legacy_hold_exists {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` already occupies an unclaimed hold namespace"
            )));
        }

        transaction.execute(
            r#"
            INSERT INTO budget_authorization_claims (
                hold_id,
                event_id,
                capability_id,
                grant_index,
                requested_exposure_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                authority_id,
                lease_id,
                lease_epoch,
                allowed,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                hold_id,
                event_id,
                capability_id,
                grant_index_i64,
                requested_exposure_i64,
                max_invocations.map(i64::from),
                max_exposure_i64,
                max_total_i64,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch_i64,
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                unix_now(),
            ],
        )?;
        Ok((None, false))
    }

    fn load_authorization_claim(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<Option<StoredAuthorizationClaim>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    capability_id,
                    grant_index,
                    requested_exposure_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    authority_id,
                    lease_id,
                    lease_epoch,
                    allowed
                FROM budget_authorization_claims
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    Ok(StoredAuthorizationClaim {
                        event_id: row.get(0)?,
                        capability_id: row.get(1)?,
                        grant_index: budget_usize_from_row(row, 2, "claim grant_index")?,
                        requested_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "claim requested_exposure_units",
                        )?,
                        max_invocations: optional_budget_u32_from_row(
                            row,
                            4,
                            "claim max_invocations",
                        )?,
                        max_exposure_per_invocation: optional_budget_u64_from_row(
                            row,
                            5,
                            "claim max_exposure_per_invocation",
                        )?,
                        max_total_exposure_units: optional_budget_u64_from_row(
                            row,
                            6,
                            "claim max_total_exposure_units",
                        )?,
                        authority: sqlite_budget_event_authority(
                            row.get(7)?,
                            row.get(8)?,
                            row.get(9)?,
                        )?,
                        allowed: row.get::<_, Option<i64>>(10)?.map(|value| value != 0),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn apply_imported_hold_state(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            return Ok(());
        };

        match record.kind {
            BudgetMutationKind::IncrementInvocation => Ok(()),
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => Err(BudgetStoreError::Invariant(
                "legacy SQLite schema cannot import composite budget mutations".to_string(),
            )),
            BudgetMutationKind::AuthorizeExposure => {
                if record.allowed == Some(true) {
                    Self::upsert_hold_with_admission_operation(
                        transaction,
                        BudgetHoldUpsertInput {
                            hold_id,
                            capability_id: &record.capability_id,
                            grant_index: record.grant_index as usize,
                            authorized_exposure_units: record.exposure_units,
                            remaining_exposure_units: record.exposure_units,
                            disposition: HoldDisposition::Open,
                            authority: record.authority.as_ref(),
                            admission_operation: record
                                .admission_operation
                                .as_ref()
                                .map(BudgetAdmissionOperationParts::from_binding),
                        },
                    )
                } else {
                    Self::delete_hold_if_exists(transaction, hold_id)
                }
            }
            BudgetMutationKind::ReleaseExposure => {
                let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing release event"
                    ))
                })?;
                if hold.capability_id != record.capability_id
                    || hold.grant_index != record.grant_index as usize
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match capability/grant"
                    )));
                }
                let remaining = hold
                    .remaining_exposure_units
                    .checked_sub(record.exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` cannot release more than remaining exposure"
                        ))
                    })?;
                let disposition = if remaining == 0 {
                    HoldDisposition::Released
                } else {
                    HoldDisposition::Open
                };
                Self::upsert_hold_with_admission_operation(
                    transaction,
                    BudgetHoldUpsertInput {
                        hold_id,
                        capability_id: &record.capability_id,
                        grant_index: record.grant_index as usize,
                        authorized_exposure_units: hold.authorized_exposure_units,
                        remaining_exposure_units: remaining,
                        disposition,
                        authority: record.authority.as_ref().or(hold.authority.as_ref()),
                        admission_operation: record
                            .admission_operation
                            .as_ref()
                            .map(BudgetAdmissionOperationParts::from_binding),
                    },
                )
            }
            BudgetMutationKind::ReverseExposure => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold_with_admission_operation(
                    transaction,
                    BudgetHoldUpsertInput {
                        hold_id,
                        capability_id: &record.capability_id,
                        grant_index: record.grant_index as usize,
                        authorized_exposure_units,
                        remaining_exposure_units: 0,
                        disposition: HoldDisposition::Reversed,
                        authority: record.authority.as_ref(),
                        admission_operation: record
                            .admission_operation
                            .as_ref()
                            .map(BudgetAdmissionOperationParts::from_binding),
                    },
                )
            }
            BudgetMutationKind::ReconcileSpend => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold_with_admission_operation(
                    transaction,
                    BudgetHoldUpsertInput {
                        hold_id,
                        capability_id: &record.capability_id,
                        grant_index: record.grant_index as usize,
                        authorized_exposure_units,
                        remaining_exposure_units: 0,
                        disposition: HoldDisposition::Reconciled,
                        authority: record.authority.as_ref(),
                        admission_operation: record
                            .admission_operation
                            .as_ref()
                            .map(BudgetAdmissionOperationParts::from_binding),
                    },
                )
            }
            BudgetMutationKind::CaptureExposure => {
                let existing = Self::load_hold(transaction, hold_id)?;
                let authorized_exposure_units = if let Some(hold) = existing.as_ref() {
                    if hold.capability_id != record.capability_id
                        || hold.grant_index != record.grant_index as usize
                    {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` does not match capability/grant"
                        )));
                    }
                    if hold.disposition != HoldDisposition::Open {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` is no longer open"
                        )));
                    }
                    if hold.remaining_exposure_units != record.exposure_units {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` does not match captured exposure"
                        )));
                    }
                    Self::validate_hold_authority(
                        hold_id,
                        hold.authority.as_ref(),
                        record.authority.as_ref(),
                    )?;
                    hold.authorized_exposure_units
                } else {
                    record.exposure_units
                };
                Self::upsert_hold_with_admission_operation(
                    transaction,
                    BudgetHoldUpsertInput {
                        hold_id,
                        capability_id: &record.capability_id,
                        grant_index: record.grant_index as usize,
                        authorized_exposure_units,
                        remaining_exposure_units: 0,
                        disposition: HoldDisposition::Captured,
                        authority: record
                            .authority
                            .as_ref()
                            .or_else(|| existing.as_ref().and_then(|hold| hold.authority.as_ref())),
                        admission_operation: record
                            .admission_operation
                            .as_ref()
                            .map(BudgetAdmissionOperationParts::from_binding),
                    },
                )
            }
            BudgetMutationKind::ExpireHold => {
                let existing = Self::load_hold(transaction, hold_id)?;
                let authorized_exposure_units = existing
                    .as_ref()
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold_with_admission_operation(
                    transaction,
                    BudgetHoldUpsertInput {
                        hold_id,
                        capability_id: &record.capability_id,
                        grant_index: record.grant_index as usize,
                        authorized_exposure_units,
                        remaining_exposure_units: 0,
                        disposition: HoldDisposition::Expired,
                        authority: record
                            .authority
                            .as_ref()
                            .or_else(|| existing.as_ref().and_then(|hold| hold.authority.as_ref())),
                        admission_operation: record
                            .admission_operation
                            .as_ref()
                            .map(BudgetAdmissionOperationParts::from_binding),
                    },
                )
            }
        }
    }
}
