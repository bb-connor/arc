fn validate_declassification_evidence_schema(connection: &Connection) -> PortResult<()> {
    const EXPECTED_SCHEMA_DIGEST_HEX: &str =
        "83c3175ea1984bf501f554ac29bf7d279b858b06a8cc343cedc8571a681c867f";
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(sqlite_error)?;
    if foreign_key_check
        .query([])
        .map_err(sqlite_error)?
        .next()
        .map_err(sqlite_error)?
        .is_some()
    {
        return Err(PortError::integrity_failure());
    }
    drop(foreign_key_check);

    for (table, expected_sql) in [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(PortError::integrity_failure());
        }
    }

    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, sql
            FROM sqlite_master
            WHERE sql IS NOT NULL AND (
                name LIKE 'security_declassification_%'
                OR tbl_name IN (
                    'security_declassification_lifecycle',
                    'security_declassification_uses',
                    'security_declassification_evidence_identity',
                    'security_declassification_receipt_outbox',
                    'security_declassification_tombstones'
                )
                OR (
                    type = 'trigger'
                    AND instr(lower(sql), 'security_declassification_') > 0
                )
            )
            ORDER BY type, name
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let canonical = rows
        .into_iter()
        .map(|(object_type, name, sql)| format!("{object_type}|{name}|{}", normalize_sql(&sql)))
        .collect::<Vec<_>>()
        .join("\n");
    if hex::encode(sha256(canonical.as_bytes()).as_bytes()) != EXPECTED_SCHEMA_DIGEST_HEX {
        return Err(PortError::integrity_failure());
    }

    let lifecycle: (i64, String, i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT schema_version, readiness_cursor, reconciliation_active,
                   live_dispatch_sealed, compaction_active
            FROM security_declassification_lifecycle WHERE singleton = 1
            "#,
            [],
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
        .map_err(sqlite_error)?;
    if lifecycle.0 != 2
        || lifecycle.1 != DECLASSIFICATION_READINESS_CURSOR
        || !matches!(lifecycle.2, 0 | 1)
        || !matches!(lifecycle.3, 0 | 1)
        || lifecycle.4 != 0
        || (lifecycle.2 == 1 && lifecycle.3 == 1)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_declassification_evidence_integrity(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, grant_id FROM security_declassification_uses ORDER BY tenant_id, grant_id",
        )
        .map_err(sqlite_error)?;
    let mut use_rows = statement.query([]).map_err(sqlite_error)?;
    let mut expected_evidence_count = 0_u64;
    while let Some(row) = use_rows.next().map_err(sqlite_error)? {
        let tenant_id = row.get::<_, String>(0).map_err(sqlite_error)?;
        let grant_id = row.get::<_, String>(1).map_err(sqlite_error)?;
        let query = DeclassificationUseQuery {
            tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
            grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
        };
        let use_record = load_declassification_use_record(connection, &query)?
            .ok_or_else(PortError::integrity_failure)?;
        let use_transition = load_declassification_use_transition(connection, &query)?
            .ok_or_else(PortError::integrity_failure)?;
        let consumption = load_declassification_evidence_record(
            connection,
            &DeclassificationEvidenceQuery {
                tenant_id: query.tenant_id.clone(),
                grant_id: query.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        expected_evidence_count = expected_evidence_count
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        if consumption.request_hash != use_record.request_hash
            || consumption.state != DeclassificationUseState::ConsumedPendingDispatch
            || consumption.transition_binding != use_record.consumption_binding
            || consumption.predecessor_evidence_id.is_some()
            || consumption.receipt.occurred_at_unix_ms != use_record.consumed_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        let outcome = load_declassification_evidence_record(
            connection,
            &DeclassificationEvidenceQuery {
                tenant_id: query.tenant_id,
                grant_id: query.grant_id,
                phase: DeclassificationEvidencePhase::Outcome,
            },
        )?;
        match use_record.state {
            DeclassificationUseState::ConsumedPendingDispatch => {
                if use_transition.is_some() || outcome.is_some() {
                    return Err(PortError::integrity_failure());
                }
            }
            DeclassificationUseState::Released
            | DeclassificationUseState::DispatchFailed
            | DeclassificationUseState::OutcomeUnknown => {
                let outcome = outcome.ok_or_else(PortError::integrity_failure)?;
                expected_evidence_count = expected_evidence_count
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
                let recovery_predecessor_matches = outcome
                    .transition_binding
                    .recovery_predecessor()
                    .is_none_or(|(evidence_id, transition_id)| {
                        evidence_id == &consumption.receipt.evidence_id
                            && transition_id == &consumption.receipt.transition_id
                    });
                if outcome.request_hash != use_record.request_hash
                    || outcome.state != use_record.state
                    || use_record.outcome_binding.as_ref() != Some(&outcome.transition_binding)
                    || outcome.predecessor_evidence_id.as_ref()
                        != Some(&consumption.receipt.evidence_id)
                    || use_transition.as_ref() != Some(&outcome.receipt.transition_id)
                    || !recovery_predecessor_matches
                    || (outcome.acknowledged && !consumption.acknowledged)
                    || outcome.receipt.occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms
                {
                    return Err(PortError::integrity_failure());
                }
                let consumption_body = decode_declassification_receipt(&consumption.receipt)
                    .map_err(|()| PortError::integrity_failure())?;
                let outcome_body = decode_declassification_receipt(&outcome.receipt)
                    .map_err(|()| PortError::integrity_failure())?;
                let (
                    ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body),
                    ActiveDefenseReceiptBody::DeclassificationOutcome(outcome_body),
                ) = (consumption_body, outcome_body)
                else {
                    return Err(PortError::integrity_failure());
                };
                if consumption_body.grant_hash != outcome_body.grant_hash
                    || consumption_body.grant_id != outcome_body.grant_id
                    || consumption_body.request_hash != outcome_body.request_hash
                    || consumption_body.policy != outcome_body.policy
                {
                    return Err(PortError::integrity_failure());
                }
            }
        }
    }
    drop(use_rows);
    drop(statement);
    let evidence_count = connection
        .query_row(
            "SELECT COUNT(*) FROM security_declassification_receipt_outbox",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    if from_i64(evidence_count)? != expected_evidence_count {
        return Err(PortError::integrity_failure());
    }
    let mismatched_identity_count = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_declassification_receipt_outbox AS evidence
            LEFT JOIN security_declassification_evidence_identity AS identity_record
              ON identity_record.tenant_id = evidence.tenant_id
             AND identity_record.evidence_id = evidence.evidence_id
            WHERE identity_record.evidence_id IS NULL
               OR identity_record.transition_id != evidence.transition_id
               OR identity_record.tenant_id != evidence.tenant_id
               OR identity_record.grant_id != evidence.grant_id
               OR identity_record.phase != evidence.phase
               OR identity_record.body_hash != evidence.body_hash
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let tombstone_count = connection
        .query_row(
            "SELECT COUNT(*) FROM security_declassification_tombstones",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let simultaneous_live_tombstone_count = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_declassification_uses AS use_record
            INNER JOIN security_declassification_tombstones AS tombstone
              ON tombstone.tenant_id = use_record.tenant_id
             AND tombstone.grant_id = use_record.grant_id
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let invalid_tombstone_count = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_declassification_tombstones AS tombstone
            LEFT JOIN security_declassification_evidence_identity AS consumption
              ON consumption.tenant_id = tombstone.tenant_id
             AND consumption.evidence_id = tombstone.consumption_evidence_id
            LEFT JOIN security_declassification_evidence_identity AS outcome
              ON outcome.tenant_id = tombstone.tenant_id
             AND outcome.evidence_id = tombstone.outcome_evidence_id
            WHERE consumption.evidence_id IS NULL
               OR outcome.evidence_id IS NULL
               OR consumption.transition_id != tombstone.consumption_transition_id
               OR consumption.tenant_id != tombstone.tenant_id
               OR consumption.grant_id != tombstone.grant_id
               OR consumption.phase != 'consumption'
               OR consumption.body_hash != tombstone.consumption_body_hash
               OR outcome.transition_id != tombstone.outcome_transition_id
               OR outcome.tenant_id != tombstone.tenant_id
               OR outcome.grant_id != tombstone.grant_id
               OR outcome.phase != 'outcome'
               OR outcome.body_hash != tombstone.outcome_body_hash
               OR tombstone.consumption_occurred_at <= 0
               OR tombstone.outcome_occurred_at < tombstone.consumption_occurred_at
               OR tombstone.policy_hash = zeroblob(32)
               OR tombstone.consumption_sink_record_hash = zeroblob(32)
               OR tombstone.outcome_sink_record_hash = zeroblob(32)
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let identity_count = connection
        .query_row(
            "SELECT COUNT(*) FROM security_declassification_evidence_identity",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let expected_identity_count = evidence_count
        .checked_add(
            tombstone_count
                .checked_mul(2)
                .ok_or_else(PortError::integrity_failure)?,
        )
        .ok_or_else(PortError::integrity_failure)?;
    if mismatched_identity_count != 0
        || simultaneous_live_tombstone_count != 0
        || invalid_tombstone_count != 0
        || identity_count != expected_identity_count
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl DeclassificationEvidenceCommitStore for SqliteSecurityStateStore {
    fn ensure_declassification_evidence_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        validate_declassification_evidence_schema(&connection)?;
        validate_declassification_evidence_integrity(&connection)
    }

    fn declassification_evidence_readiness_cursor(&self) -> PortResult<RecordId> {
        self.ensure_declassification_evidence_ready()?;
        RecordId::new(DECLASSIFICATION_READINESS_CURSOR).map_err(PortError::from)
    }

    fn begin_declassification_reconciliation(&self) -> PortResult<()> {
        let connection = self.connection()?;
        let updated = connection
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET reconciliation_active = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    fn end_declassification_reconciliation(&self) -> PortResult<()> {
        let connection = self.connection()?;
        let updated = connection
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET reconciliation_active = 0
                WHERE singleton = 1 AND reconciliation_active = 1
                  AND live_dispatch_sealed = 0 AND compaction_active = 0
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    fn seal_declassification_live_dispatch(&self) -> PortResult<()> {
        let connection = self.connection()?;
        let lifecycle: (i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_declassification_lifecycle WHERE singleton = 1
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        if lifecycle == (0, 1, 0) {
            return Ok(());
        }
        if lifecycle != (0, 0, 0) {
            return Err(PortError::conflict());
        }
        let updated = connection
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET live_dispatch_sealed = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 0 AND compaction_active = 0
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
    ) -> PortResult<DeclassificationConsume> {
        validate_declassification_consumption_evidence(request)?;
        let retain_until_unix_ms =
            declassification_retain_until_unix_ms(request.consumption.grant_expires_at_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let live_dispatch: (i64, i64, i64) = transaction
            .query_row(
                r#"
                SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_declassification_lifecycle WHERE singleton = 1
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        if live_dispatch != (0, 1, 0) {
            return Err(PortError::conflict());
        }
        let query = DeclassificationUseQuery {
            tenant_id: request.consumption.tenant_id.clone(),
            grant_id: request.consumption.grant_id.clone(),
        };
        let evidence_query = DeclassificationEvidenceQuery {
            tenant_id: request.consumption.tenant_id.clone(),
            grant_id: request.consumption.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Consumption,
        };
        let tombstoned: i64 = transaction
            .query_row(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM security_declassification_tombstones
                    WHERE tenant_id = ?1 AND grant_id = ?2
                )
                "#,
                params![
                    request.consumption.tenant_id.as_str(),
                    request.consumption.grant_id.as_str(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if tombstoned != 0 {
            return Err(PortError::conflict());
        }
        let existing_use = load_declassification_use_record(&transaction, &query)?;
        let existing_evidence =
            load_declassification_evidence_record(&transaction, &evidence_query)?;
        match (existing_use, existing_evidence) {
            (None, None) => {
                transaction
                    .execute(
                        r#"
                        INSERT INTO security_declassification_uses (
                            grant_id, tenant_id, request_hash, state, consumed_at,
                            grant_expires_at, retain_until, consumption_binding
                        ) VALUES (
                            ?1, ?2, ?3, 'consumed_pending_dispatch', ?4, ?5, ?6, ?7
                        )
                        "#,
                        params![
                            request.consumption.grant_id.as_str(),
                            request.consumption.tenant_id.as_str(),
                            request.consumption.request_hash.as_bytes().as_slice(),
                            to_i64(request.consumption.consumed_at_unix_ms)?,
                            to_i64(request.consumption.grant_expires_at_unix_ms)?,
                            to_i64(retain_until_unix_ms)?,
                            encode_declassification_binding(&request.transition_binding)?,
                        ],
                    )
                    .map_err(sqlite_error)?;
                insert_declassification_evidence(
                    &transaction,
                    &DeclassificationEvidenceCommit {
                        tenant_id: &request.consumption.tenant_id,
                        grant_id: &request.consumption.grant_id,
                        phase: DeclassificationEvidencePhase::Consumption,
                        request_hash: request.consumption.request_hash,
                        state: DeclassificationUseState::ConsumedPendingDispatch,
                        transition_binding: &request.transition_binding,
                        predecessor_evidence_id: None,
                        receipt: &request.receipt,
                    },
                )?;
                transaction.commit().map_err(sqlite_error)?;
                Ok(DeclassificationConsume::Consumed)
            }
            (Some(use_record), Some(evidence_record)) => {
                if use_record.request_hash != request.consumption.request_hash
                    || use_record.consumed_at_unix_ms != request.consumption.consumed_at_unix_ms
                    || use_record.grant_expires_at_unix_ms
                        != request.consumption.grant_expires_at_unix_ms
                    || use_record.retain_until_unix_ms != retain_until_unix_ms
                    || use_record.consumption_binding != request.transition_binding
                    || !declassification_evidence_matches(
                        &evidence_record,
                        &DeclassificationEvidenceCommit {
                            tenant_id: &request.consumption.tenant_id,
                            grant_id: &request.consumption.grant_id,
                            phase: DeclassificationEvidencePhase::Consumption,
                            request_hash: request.consumption.request_hash,
                            state: DeclassificationUseState::ConsumedPendingDispatch,
                            transition_binding: &request.transition_binding,
                            predecessor_evidence_id: None,
                            receipt: &request.receipt,
                        },
                    )
                {
                    return Err(PortError::conflict());
                }
                let state = use_record.state;
                transaction.commit().map_err(sqlite_error)?;
                Ok(DeclassificationConsume::AlreadyConsumed {
                    request_hash: request.consumption.request_hash,
                    state,
                })
            }
            (Some(_), None) | (None, Some(_)) => Err(PortError::integrity_failure()),
        }
    }

    fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()> {
        validate_declassification_outcome_evidence(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let lifecycle: (i64, i64, i64) = transaction
            .query_row(
                r#"
                SELECT reconciliation_active, live_dispatch_sealed, compaction_active
                FROM security_declassification_lifecycle WHERE singleton = 1
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        let lifecycle_valid = if request.transition_binding.is_live_dispatch_binding() {
            lifecycle == (0, 1, 0)
        } else {
            lifecycle == (1, 0, 0)
        };
        if !lifecycle_valid {
            return Err(PortError::conflict());
        }
        let use_query = DeclassificationUseQuery {
            tenant_id: request.outcome.tenant_id.clone(),
            grant_id: request.outcome.grant_id.clone(),
        };
        let consumption_query = DeclassificationEvidenceQuery {
            tenant_id: request.outcome.tenant_id.clone(),
            grant_id: request.outcome.grant_id.clone(),
            phase: DeclassificationEvidencePhase::Consumption,
        };
        let outcome_query = DeclassificationEvidenceQuery {
            phase: DeclassificationEvidencePhase::Outcome,
            ..consumption_query.clone()
        };
        let existing_use = load_declassification_use_record(&transaction, &use_query)?;
        let existing_consumption =
            load_declassification_evidence_record(&transaction, &consumption_query)?;
        let existing_outcome = load_declassification_evidence_record(&transaction, &outcome_query)?;
        let Some(use_record) = existing_use else {
            return if existing_consumption.is_some() || existing_outcome.is_some() {
                Err(PortError::integrity_failure())
            } else {
                Err(PortError::invalid_data())
            };
        };
        if use_record.request_hash != request.outcome.request_hash {
            return Err(PortError::conflict());
        }
        let Some(consumption) = existing_consumption else {
            return Err(PortError::integrity_failure());
        };
        if consumption.request_hash != request.outcome.request_hash
            || consumption.receipt.evidence_id != request.predecessor_evidence_id
        {
            return Err(PortError::conflict());
        }
        if let Some((predecessor_evidence_id, predecessor_transition_id)) =
            request.transition_binding.recovery_predecessor()
        {
            if predecessor_evidence_id != &consumption.receipt.evidence_id
                || predecessor_transition_id != &consumption.receipt.transition_id
            {
                return Err(PortError::conflict());
            }
        }
        if request.receipt.occurred_at_unix_ms < consumption.receipt.occurred_at_unix_ms {
            return Err(PortError::invalid_data());
        }
        let consumption_body = decode_declassification_receipt(&consumption.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let outcome_body = decode_declassification_receipt(&request.receipt)
            .map_err(|()| PortError::invalid_data())?;
        let (
            ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body),
            ActiveDefenseReceiptBody::DeclassificationOutcome(outcome_body),
        ) = (consumption_body, outcome_body)
        else {
            return Err(PortError::integrity_failure());
        };
        if consumption_body.grant_hash != outcome_body.grant_hash
            || consumption_body.grant_id != outcome_body.grant_id
            || consumption_body.request_hash != outcome_body.request_hash
            || consumption_body.policy != outcome_body.policy
        {
            return Err(PortError::conflict());
        }
        let use_transition = load_declassification_use_transition(&transaction, &use_query)?
            .ok_or_else(PortError::integrity_failure)?;
        if let Some(existing) = existing_outcome {
            if use_record.state != request.outcome.new_state
                || use_transition.as_ref() != Some(&request.outcome.transition_id)
                || use_record.outcome_binding.as_ref() != Some(&request.transition_binding)
                || !declassification_evidence_matches(
                    &existing,
                    &DeclassificationEvidenceCommit {
                        tenant_id: &request.outcome.tenant_id,
                        grant_id: &request.outcome.grant_id,
                        phase: DeclassificationEvidencePhase::Outcome,
                        request_hash: request.outcome.request_hash,
                        state: request.outcome.new_state,
                        transition_binding: &request.transition_binding,
                        predecessor_evidence_id: Some(&request.predecessor_evidence_id),
                        receipt: &request.receipt,
                    },
                )
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        if use_record.state != request.outcome.expected_state || use_transition.is_some() {
            return Err(PortError::integrity_failure());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_declassification_uses
                SET state = ?4, transition_id = ?5, outcome_binding = ?6
                WHERE grant_id = ?1 AND tenant_id = ?2 AND request_hash = ?3
                  AND state = 'consumed_pending_dispatch' AND transition_id IS NULL
                "#,
                params![
                    request.outcome.grant_id.as_str(),
                    request.outcome.tenant_id.as_str(),
                    request.outcome.request_hash.as_bytes().as_slice(),
                    declassification_state_name(request.outcome.new_state),
                    request.outcome.transition_id.as_str(),
                    encode_declassification_binding(&request.transition_binding)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        insert_declassification_evidence(
            &transaction,
            &DeclassificationEvidenceCommit {
                tenant_id: &request.outcome.tenant_id,
                grant_id: &request.outcome.grant_id,
                phase: DeclassificationEvidencePhase::Outcome,
                request_hash: request.outcome.request_hash,
                state: request.outcome.new_state,
                transition_binding: &request.transition_binding,
                predecessor_evidence_id: Some(&request.predecessor_evidence_id),
                receipt: &request.receipt,
            },
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn load_declassification_use(
        &self,
        query: &DeclassificationUseQuery,
    ) -> PortResult<Option<DeclassificationUseRecord>> {
        let connection = self.connection()?;
        load_declassification_use_record(&connection, query)
    }

    fn load_declassification_evidence(
        &self,
        query: &DeclassificationEvidenceQuery,
    ) -> PortResult<Option<DeclassificationEvidenceRecord>> {
        let connection = self.connection()?;
        load_declassification_evidence_record(&connection, query)
    }

    fn load_pending_declassification_evidence(
        &self,
        query: &DeclassificationEvidencePendingQuery,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        let connection = self.connection()?;
        load_pending_declassification_evidence_records(
            &connection,
            Some(&query.tenant_id),
            Some(&query.grant_id),
            query.now_unix_ms,
            query.max_records,
        )
    }

    fn load_pending_declassification_evidence_batch(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        let connection = self.connection()?;
        load_pending_declassification_evidence_records(
            &connection,
            None,
            None,
            now_unix_ms,
            max_records,
        )
    }

    fn load_stranded_declassification_consumptions_batch(
        &self,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        if max_records == 0 || max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
            return Err(PortError::invalid_data());
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT
                    evidence.tenant_id, evidence.grant_id, evidence.phase,
                    evidence.phase_ordinal, evidence.request_hash, evidence.state,
                    evidence.transition_binding, evidence.evidence_type,
                    evidence.evidence_id, evidence.canonical_body, evidence.body_hash,
                    evidence.transition_id, evidence.occurred_at,
                    evidence.predecessor_evidence_id, evidence.acknowledged,
                    evidence.acknowledged_at, evidence.durable_sink_record_hash,
                    evidence.attempts,
                    evidence.next_attempt_at, evidence.last_error_code
                FROM security_declassification_receipt_outbox AS evidence
                INNER JOIN security_declassification_uses AS use_record
                    ON use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_declassification_receipt_outbox AS outcome
                      WHERE outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )
                ORDER BY evidence.tenant_id ASC, evidence.grant_id ASC
                LIMIT ?1
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![i64::from(max_records)],
                declassification_evidence_row,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter()
            .map(decode_declassification_evidence_row)
            .collect()
    }

    fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let query = DeclassificationEvidenceQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            phase: request.phase,
        };
        let record = load_declassification_evidence_record(&transaction, &query)?
            .ok_or_else(PortError::invalid_data)?;
        if record.receipt.evidence_id != request.evidence_id
            || record.receipt.body_hash != request.body_hash
            || record.receipt.transition_id != request.transition_id
            || request.verified_at_unix_ms < record.receipt.occurred_at_unix_ms
            || request.durable_sink_record_hash == Digest32::new([0_u8; 32])
        {
            return Err(PortError::conflict());
        }
        if request.phase == DeclassificationEvidencePhase::Outcome {
            let predecessor = load_declassification_evidence_record(
                &transaction,
                &DeclassificationEvidenceQuery {
                    tenant_id: request.tenant_id.clone(),
                    grant_id: request.grant_id.clone(),
                    phase: DeclassificationEvidencePhase::Consumption,
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if record.predecessor_evidence_id.as_ref() != Some(&predecessor.receipt.evidence_id)
                || !predecessor.acknowledged
            {
                return Err(PortError::conflict());
            }
        }
        if record.acknowledged {
            if record.durable_sink_record_hash != Some(request.durable_sink_record_hash) {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_declassification_receipt_outbox
                SET acknowledged = 1, acknowledged_at = ?7,
                    durable_sink_record_hash = ?8
                WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3
                  AND evidence_id = ?4 AND body_hash = ?5 AND transition_id = ?6
                  AND acknowledged = 0
                "#,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    i64::from(request.phase.ordinal()),
                    request.evidence_id.as_str(),
                    request.body_hash.as_bytes().as_slice(),
                    request.transition_id.as_str(),
                    to_i64(request.verified_at_unix_ms)?,
                    request.durable_sink_record_hash.as_bytes().as_slice(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        transaction.commit().map_err(sqlite_error)
    }

    fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let query = DeclassificationEvidenceQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            phase: request.phase,
        };
        let record = load_declassification_evidence_record(&transaction, &query)?
            .ok_or_else(PortError::invalid_data)?;
        if record.acknowledged
            || record.receipt.evidence_id != request.evidence_id
            || record.receipt.body_hash != request.body_hash
            || record.receipt.transition_id != request.transition_id
            || request.failed_at_unix_ms < record.next_attempt_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        let attempts_after_failure = record
            .attempts
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let next_attempt_at_unix_ms = declassification_retry_deadline_unix_ms(
            request.failed_at_unix_ms,
            attempts_after_failure,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_declassification_receipt_outbox
                SET attempts = ?7, next_attempt_at = ?8, last_error_code = ?9
                WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3
                  AND evidence_id = ?4 AND body_hash = ?5 AND transition_id = ?6
                  AND acknowledged = 0 AND attempts = ?10
                "#,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    i64::from(request.phase.ordinal()),
                    request.evidence_id.as_str(),
                    request.body_hash.as_bytes().as_slice(),
                    request.transition_id.as_str(),
                    i64::from(attempts_after_failure),
                    to_i64(next_attempt_at_unix_ms)?,
                    request.error_code.as_str(),
                    i64::from(record.attempts),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let updated_record = load_declassification_evidence_record(&transaction, &query)?
            .ok_or_else(PortError::integrity_failure)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(updated_record)
    }

    fn load_declassification_compaction_candidates(
        &self,
        query: &DeclassificationCompactionQuery,
    ) -> PortResult<Vec<DeclassificationCompactionCandidate>> {
        if query.readiness_cursor.as_str() != DECLASSIFICATION_READINESS_CURSOR
            || query.max_records == 0
            || query.max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH
            || query.after_tenant_id.is_some() != query.after_grant_id.is_some()
        {
            return Err(PortError::invalid_data());
        }
        self.ensure_declassification_evidence_ready()?;
        let connection = self.connection()?;
        let rows = match (&query.after_tenant_id, &query.after_grant_id) {
            (Some(after_tenant), Some(after_grant)) => {
                let mut statement = connection
                    .prepare(
                        r#"
                        SELECT tenant_id, grant_id
                        FROM security_declassification_uses
                        WHERE state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?1
                          AND (tenant_id > ?2 OR (tenant_id = ?2 AND grant_id > ?3))
                        ORDER BY tenant_id, grant_id LIMIT ?4
                        "#,
                    )
                    .map_err(sqlite_error)?;
                let rows = statement
                    .query_map(
                        params![
                            to_i64(query.now_unix_ms)?,
                            after_tenant.as_str(),
                            after_grant.as_str(),
                            i64::from(query.max_records),
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(sqlite_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_error)?;
                rows
            }
            (None, None) => {
                let mut statement = connection
                    .prepare(
                        r#"
                        SELECT tenant_id, grant_id
                        FROM security_declassification_uses
                        WHERE state IN ('released', 'dispatch_failed')
                          AND retain_until <= ?1
                        ORDER BY tenant_id, grant_id LIMIT ?2
                        "#,
                    )
                    .map_err(sqlite_error)?;
                let rows = statement
                    .query_map(
                        params![to_i64(query.now_unix_ms)?, i64::from(query.max_records)],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(sqlite_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_error)?;
                rows
            }
            _ => return Err(PortError::invalid_data()),
        };
        rows.into_iter()
            .map(|(tenant_id, grant_id)| {
                let use_query = DeclassificationUseQuery {
                    tenant_id: TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
                };
                let use_record = load_declassification_use_record(&connection, &use_query)?
                    .ok_or_else(PortError::integrity_failure)?;
                let consumption = load_declassification_evidence_record(
                    &connection,
                    &DeclassificationEvidenceQuery {
                        tenant_id: use_query.tenant_id.clone(),
                        grant_id: use_query.grant_id.clone(),
                        phase: DeclassificationEvidencePhase::Consumption,
                    },
                )?
                .ok_or_else(PortError::integrity_failure)?;
                let outcome = load_declassification_evidence_record(
                    &connection,
                    &DeclassificationEvidenceQuery {
                        tenant_id: use_query.tenant_id,
                        grant_id: use_query.grant_id,
                        phase: DeclassificationEvidencePhase::Outcome,
                    },
                )?
                .ok_or_else(PortError::integrity_failure)?;
                if !consumption.acknowledged || !outcome.acknowledged {
                    return Err(PortError::conflict());
                }
                Ok(DeclassificationCompactionCandidate {
                    readiness_cursor: query.readiness_cursor.clone(),
                    use_record,
                    consumption,
                    outcome,
                })
            })
            .collect()
    }

    fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone> {
        if request.readiness_cursor.as_str() != DECLASSIFICATION_READINESS_CURSOR
            || !matches!(
                request.terminal_state,
                DeclassificationUseState::Released | DeclassificationUseState::DispatchFailed
            )
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let use_query = DeclassificationUseQuery {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
        };
        let use_record = load_declassification_use_record(&transaction, &use_query)?
            .ok_or_else(PortError::invalid_data)?;
        let consumption = load_declassification_evidence_record(
            &transaction,
            &DeclassificationEvidenceQuery {
                tenant_id: request.tenant_id.clone(),
                grant_id: request.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Consumption,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let outcome = load_declassification_evidence_record(
            &transaction,
            &DeclassificationEvidenceQuery {
                tenant_id: request.tenant_id.clone(),
                grant_id: request.grant_id.clone(),
                phase: DeclassificationEvidencePhase::Outcome,
            },
        )?
        .ok_or_else(PortError::integrity_failure)?;
        let use_transition = load_declassification_use_transition(&transaction, &use_query)?
            .ok_or_else(PortError::integrity_failure)?
            .ok_or_else(PortError::integrity_failure)?;
        let consumption_body = decode_declassification_receipt(&consumption.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let outcome_body = decode_declassification_receipt(&outcome.receipt)
            .map_err(|()| PortError::integrity_failure())?;
        let (
            ActiveDefenseReceiptBody::DeclassificationConsumption(consumption_body),
            ActiveDefenseReceiptBody::DeclassificationOutcome(outcome_body),
        ) = (consumption_body, outcome_body)
        else {
            return Err(PortError::integrity_failure());
        };
        let recovery_predecessor_matches = outcome
            .transition_binding
            .recovery_predecessor()
            .is_none_or(|(evidence_id, transition_id)| {
                evidence_id == &consumption.receipt.evidence_id
                    && transition_id == &consumption.receipt.transition_id
            });
        if use_record.request_hash != request.request_hash
            || use_record.state != request.terminal_state
            || use_record.consumption_binding != consumption.transition_binding
            || use_record.outcome_binding.as_ref() != Some(&outcome.transition_binding)
            || consumption.request_hash != use_record.request_hash
            || consumption.state != DeclassificationUseState::ConsumedPendingDispatch
            || consumption.receipt.occurred_at_unix_ms != use_record.consumed_at_unix_ms
            || outcome.request_hash != use_record.request_hash
            || outcome.state != use_record.state
            || outcome.transition_binding.terminal_state() != Some(use_record.state)
            || use_transition != outcome.receipt.transition_id
            || outcome.predecessor_evidence_id.as_ref() != Some(&consumption.receipt.evidence_id)
            || !recovery_predecessor_matches
            || request.compacted_at_unix_ms < use_record.retain_until_unix_ms
            || !consumption.acknowledged
            || !outcome.acknowledged
            || consumption.receipt.evidence_id != request.consumption_evidence_id
            || consumption.receipt.body_hash != request.consumption_body_hash
            || consumption.receipt.transition_id != request.consumption_transition_id
            || consumption.receipt.occurred_at_unix_ms != request.consumption_occurred_at_unix_ms
            || consumption.durable_sink_record_hash != Some(request.consumption_sink_record_hash)
            || outcome.receipt.evidence_id != request.outcome_evidence_id
            || outcome.receipt.body_hash != request.outcome_body_hash
            || outcome.receipt.transition_id != request.outcome_transition_id
            || outcome.receipt.occurred_at_unix_ms != request.outcome_occurred_at_unix_ms
            || outcome.durable_sink_record_hash != Some(request.outcome_sink_record_hash)
            || consumption_body.policy != outcome_body.policy
            || consumption_body.policy.policy_hash != request.policy_hash
        {
            return Err(PortError::conflict());
        }
        let activated = transaction
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET compaction_active = 1
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 0
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if activated != 1 {
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_declassification_tombstones (
                    tenant_id, grant_id, request_hash, terminal_state,
                    consumption_evidence_id, consumption_body_hash,
                    consumption_transition_id, consumption_occurred_at,
                    consumption_sink_record_hash, outcome_evidence_id,
                    outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                    outcome_sink_record_hash, policy_hash, compacted_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16
                )
                "#,
                params![
                    request.tenant_id.as_str(),
                    request.grant_id.as_str(),
                    request.request_hash.as_bytes().as_slice(),
                    declassification_state_name(request.terminal_state),
                    request.consumption_evidence_id.as_str(),
                    request.consumption_body_hash.as_bytes().as_slice(),
                    request.consumption_transition_id.as_str(),
                    to_i64(request.consumption_occurred_at_unix_ms)?,
                    request.consumption_sink_record_hash.as_bytes().as_slice(),
                    request.outcome_evidence_id.as_str(),
                    request.outcome_body_hash.as_bytes().as_slice(),
                    request.outcome_transition_id.as_str(),
                    to_i64(request.outcome_occurred_at_unix_ms)?,
                    request.outcome_sink_record_hash.as_bytes().as_slice(),
                    request.policy_hash.as_bytes().as_slice(),
                    to_i64(request.compacted_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        let deleted_evidence = transaction
            .execute(
                "DELETE FROM security_declassification_receipt_outbox WHERE tenant_id = ?1 AND grant_id = ?2",
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
            )
            .map_err(sqlite_error)?;
        let deleted_use = transaction
            .execute(
                "DELETE FROM security_declassification_uses WHERE tenant_id = ?1 AND grant_id = ?2",
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
            )
            .map_err(sqlite_error)?;
        if deleted_evidence != 2 || deleted_use != 1 {
            return Err(PortError::integrity_failure());
        }
        let deactivated = transaction
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET compaction_active = 0
                WHERE singleton = 1 AND reconciliation_active = 0
                  AND live_dispatch_sealed = 1 AND compaction_active = 1
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if deactivated != 1 {
            return Err(PortError::integrity_failure());
        }
        let tombstone = DeclassificationEvidenceTombstone {
            tenant_id: request.tenant_id.clone(),
            grant_id: request.grant_id.clone(),
            request_hash: request.request_hash,
            terminal_state: request.terminal_state,
            consumption_evidence_id: request.consumption_evidence_id.clone(),
            consumption_body_hash: request.consumption_body_hash,
            consumption_transition_id: request.consumption_transition_id.clone(),
            consumption_occurred_at_unix_ms: request.consumption_occurred_at_unix_ms,
            consumption_sink_record_hash: request.consumption_sink_record_hash,
            outcome_evidence_id: request.outcome_evidence_id.clone(),
            outcome_body_hash: request.outcome_body_hash,
            outcome_transition_id: request.outcome_transition_id.clone(),
            outcome_occurred_at_unix_ms: request.outcome_occurred_at_unix_ms,
            outcome_sink_record_hash: request.outcome_sink_record_hash,
            policy_hash: request.policy_hash,
            compacted_at_unix_ms: request.compacted_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(tombstone)
    }

    fn count_pending_declassification_evidence(&self) -> PortResult<u64> {
        let connection = self.connection()?;
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox WHERE acknowledged = 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?;
        from_i64(count)
    }

    fn count_stranded_declassification_consumptions(&self) -> PortResult<u64> {
        let connection = self.connection()?;
        let count = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM security_declassification_receipt_outbox AS evidence
                INNER JOIN security_declassification_uses AS use_record
                    ON use_record.tenant_id = evidence.tenant_id
                   AND use_record.grant_id = evidence.grant_id
                WHERE evidence.phase = 'consumption'
                  AND evidence.phase_ordinal = 0
                  AND use_record.state = 'consumed_pending_dispatch'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM security_declassification_receipt_outbox AS outcome
                      WHERE outcome.tenant_id = evidence.tenant_id
                        AND outcome.grant_id = evidence.grant_id
                        AND outcome.phase = 'outcome'
                        AND outcome.phase_ordinal = 1
                  )
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?;
        from_i64(count)
    }
}

fn load_lineage_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<(LineageFence, bool)>> {
    type StoredFence = (String, i64, Vec<u8>, i64, String, i64, i64, String);
    let stored: Option<StoredFence> = connection
        .query_row(
            r#"
            SELECT tenant_id, commit_index, affected_set_hash, fencing_token,
                   scheduler_lease_owner_id, scheduler_fencing_token, expires_at, state
            FROM security_lineage_fences WHERE tenant_id = ?1 AND action_id = ?2
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
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                tenant_id,
                commit_index,
                affected_set_hash,
                fencing_token,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                expires_at,
                state,
            )| {
                let active = match state.as_str() {
                    "active" => true,
                    "released" => false,
                    _ => return Err(PortError::integrity_failure()),
                };
                Ok((
                    LineageFence {
                        tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        action_id: ActionId::new(action_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        commit_index: from_i64(commit_index)?,
                        affected_set_hash: decode_digest(affected_set_hash)?,
                        fencing_token: from_i64(fencing_token)?,
                        scheduler_lease_owner_id: LeaseOwnerId::new(scheduler_lease_owner_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        scheduler_fencing_token: from_i64(scheduler_fencing_token)?,
                        expires_at_unix_ms: from_i64(expires_at)?,
                    },
                    active,
                ))
            },
        )
        .transpose()
}

impl LineageFenceStore for SqliteSecurityStateStore {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if request.scheduler_fencing_token == 0 || request.expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }
        let existing = load_lineage_fence(
            &transaction,
            request.tenant_id.as_str(),
            request.action_id.as_str(),
        )?;
        let fencing_token = if let Some((existing, active)) = existing.as_ref() {
            if !active {
                return Err(PortError::conflict());
            }
            if existing.commit_index != request.expected_commit_index
                || existing.affected_set_hash != request.expected_affected_set_hash
                || existing.scheduler_lease_owner_id != request.scheduler_lease_owner_id
                || existing.scheduler_fencing_token != request.scheduler_fencing_token
            {
                return Err(PortError::conflict());
            }
            if existing.expires_at_unix_ms > trusted_now {
                if existing.expires_at_unix_ms != request.expires_at_unix_ms {
                    return Err(PortError::conflict());
                }
                transaction.commit().map_err(sqlite_error)?;
                return Ok(existing.clone());
            }
            existing
                .fencing_token
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        } else {
            1
        };
        transaction
            .execute(
                r#"
                INSERT INTO security_lineage_fences (
                    action_id, tenant_id, commit_index, affected_set_hash,
                    fencing_token, scheduler_lease_owner_id, scheduler_fencing_token,
                    expires_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')
                ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                    fencing_token = excluded.fencing_token,
                    scheduler_lease_owner_id = excluded.scheduler_lease_owner_id,
                    scheduler_fencing_token = excluded.scheduler_fencing_token,
                    expires_at = excluded.expires_at,
                    state = 'active'
                "#,
                params![
                    request.action_id.as_str(),
                    request.tenant_id.as_str(),
                    to_i64(request.expected_commit_index)?,
                    request.expected_affected_set_hash.as_bytes().as_slice(),
                    to_i64(fencing_token)?,
                    request.scheduler_lease_owner_id.as_str(),
                    to_i64(request.scheduler_fencing_token)?,
                    to_i64(request.expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        let fence = LineageFence {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            commit_index: request.expected_commit_index,
            affected_set_hash: request.expected_affected_set_hash,
            fencing_token,
            scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: request.scheduler_fencing_token,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let connection = self.connection()?;
        let stored =
            load_lineage_fence(&connection, action.tenant_id.as_str(), action.id.as_str())?;
        let Some((fence, active)) = stored else {
            return Ok(None);
        };
        if !active || fence.expires_at_unix_ms <= trusted_now {
            return Ok(None);
        }
        Ok(Some(fence))
    }

    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        if renewal.fencing_token == 0
            || renewal.scheduler_fencing_token == 0
            || renewal.renewed_expires_at_unix_ms <= renewal.expected_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (existing, active) = load_lineage_fence(
            &transaction,
            renewal.tenant_id.as_str(),
            renewal.action_id.as_str(),
        )?
        .ok_or_else(PortError::conflict)?;
        if !active
            || existing.expires_at_unix_ms <= trusted_now
            || existing.fencing_token != renewal.fencing_token
            || existing.scheduler_lease_owner_id != renewal.scheduler_lease_owner_id
            || existing.scheduler_fencing_token != renewal.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if existing.expires_at_unix_ms == renewal.renewed_expires_at_unix_ms {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        if existing.expires_at_unix_ms != renewal.expected_expires_at_unix_ms {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_lineage_fences SET expires_at = ?6
                WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
                  AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
                  AND expires_at = ?7 AND state = 'active'
                "#,
                params![
                    renewal.tenant_id.as_str(),
                    renewal.action_id.as_str(),
                    to_i64(renewal.fencing_token)?,
                    renewal.scheduler_lease_owner_id.as_str(),
                    to_i64(renewal.scheduler_fencing_token)?,
                    to_i64(renewal.renewed_expires_at_unix_ms)?,
                    to_i64(renewal.expected_expires_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let renewed = LineageFence {
            expires_at_unix_ms: renewal.renewed_expires_at_unix_ms,
            ..existing
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(renewed)
    }

    fn takeover(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        if takeover.expected_fencing_token == 0
            || takeover.expected_scheduler_fencing_token == 0
            || takeover.successor_scheduler_fencing_token
                <= takeover.expected_scheduler_fencing_token
            || takeover.successor_expires_at_unix_ms < takeover.expected_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (existing, active) = load_lineage_fence(
            &transaction,
            takeover.tenant_id.as_str(),
            takeover.action_id.as_str(),
        )?
        .ok_or_else(PortError::conflict)?;
        if !active
            || existing.expires_at_unix_ms <= trusted_now
            || existing.fencing_token != takeover.expected_fencing_token
            || existing.scheduler_lease_owner_id != takeover.expected_scheduler_lease_owner_id
            || existing.scheduler_fencing_token != takeover.expected_scheduler_fencing_token
            || existing.expires_at_unix_ms != takeover.expected_expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        let successor_fencing_token = existing
            .fencing_token
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_lineage_fences
                SET fencing_token = ?9, scheduler_lease_owner_id = ?7,
                    scheduler_fencing_token = ?8, expires_at = ?6
                WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3
                  AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5
                  AND expires_at = ?10 AND state = 'active'
                "#,
                params![
                    takeover.tenant_id.as_str(),
                    takeover.action_id.as_str(),
                    to_i64(takeover.expected_fencing_token)?,
                    takeover.expected_scheduler_lease_owner_id.as_str(),
                    to_i64(takeover.expected_scheduler_fencing_token)?,
                    to_i64(takeover.successor_expires_at_unix_ms)?,
                    takeover.successor_scheduler_lease_owner_id.as_str(),
                    to_i64(takeover.successor_scheduler_fencing_token)?,
                    to_i64(successor_fencing_token)?,
                    to_i64(takeover.expected_expires_at_unix_ms)?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let successor = LineageFence {
            fencing_token: successor_fencing_token,
            scheduler_lease_owner_id: takeover.successor_scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: takeover.successor_scheduler_fencing_token,
            expires_at_unix_ms: takeover.successor_expires_at_unix_ms,
            ..existing
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(successor)
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing = load_lineage_fence(
            &transaction,
            release.tenant_id.as_str(),
            release.action_id.as_str(),
        )?;
        let Some((existing, active)) = existing else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        };
        if existing.fencing_token != release.fencing_token
            || existing.scheduler_lease_owner_id != release.scheduler_lease_owner_id
            || existing.scheduler_fencing_token != release.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if !active {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        if existing.expires_at_unix_ms <= trusted_now {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                "UPDATE security_lineage_fences SET state = 'released', expires_at = 0 WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3 AND scheduler_lease_owner_id = ?4 AND scheduler_fencing_token = ?5 AND state = 'active'",
                params![
                    release.tenant_id.as_str(),
                    release.action_id.as_str(),
                    to_i64(release.fencing_token)?,
                    release.scheduler_lease_owner_id.as_str(),
                    to_i64(release.scheduler_fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}
