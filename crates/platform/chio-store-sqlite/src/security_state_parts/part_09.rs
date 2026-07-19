struct StoredAttestedFindingResponseOutboxRow {
    tenant_id: String,
    batch_id: String,
    ordinal: i64,
    evidence_id: String,
    finding_id: String,
    finding_hash: Vec<u8>,
    action_id: String,
    reservation_id: String,
    planning_state: String,
    admission_state: String,
    completion_state: String,
    execution_dispatch_id: Option<String>,
    prepared_dispatch_binding: Option<Vec<u8>>,
    prepared_dispatch_binding_hash: Option<Vec<u8>>,
    completion_outcome: Option<String>,
    completion_evidence_id: Option<String>,
    completion_evidence_body_hash: Option<Vec<u8>>,
    plan_body: Option<Vec<u8>>,
    plan_body_hash: Option<Vec<u8>>,
    admission_artifact_ref: Option<String>,
    admission_artifact_digest: Option<Vec<u8>>,
    attempts: i64,
    next_attempt_at: i64,
    last_error_code: Option<String>,
}

fn response_planning_state(value: &str) -> PortResult<AttestedFindingResponsePlanningState> {
    match value {
        "pending" => Ok(AttestedFindingResponsePlanningState::Pending),
        "planned" => Ok(AttestedFindingResponsePlanningState::Planned),
        "failed" => Ok(AttestedFindingResponsePlanningState::Failed),
        _ => Err(PortError::integrity_failure()),
    }
}

fn response_planning_state_name(value: AttestedFindingResponsePlanningState) -> &'static str {
    match value {
        AttestedFindingResponsePlanningState::Pending => "pending",
        AttestedFindingResponsePlanningState::Planned => "planned",
        AttestedFindingResponsePlanningState::Failed => "failed",
    }
}

fn response_admission_state(value: &str) -> PortResult<AttestedFindingResponseAdmissionState> {
    match value {
        "pending" => Ok(AttestedFindingResponseAdmissionState::Pending),
        "prepared" => Ok(AttestedFindingResponseAdmissionState::Prepared),
        "rejected" => Ok(AttestedFindingResponseAdmissionState::Rejected),
        "expired" => Ok(AttestedFindingResponseAdmissionState::Expired),
        _ => Err(PortError::integrity_failure()),
    }
}

fn response_admission_state_name(value: AttestedFindingResponseAdmissionState) -> &'static str {
    match value {
        AttestedFindingResponseAdmissionState::Pending => "pending",
        AttestedFindingResponseAdmissionState::Prepared => "prepared",
        AttestedFindingResponseAdmissionState::Rejected => "rejected",
        AttestedFindingResponseAdmissionState::Expired => "expired",
    }
}

fn response_completion_state(value: &str) -> PortResult<AttestedFindingResponseCompletionState> {
    match value {
        "not_started" => Ok(AttestedFindingResponseCompletionState::NotStarted),
        "pending" => Ok(AttestedFindingResponseCompletionState::Pending),
        "outcome_unknown_after_dispatch" => {
            Ok(AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch)
        }
        "completed" => Ok(AttestedFindingResponseCompletionState::Completed),
        _ => Err(PortError::integrity_failure()),
    }
}

fn response_completion_state_name(value: AttestedFindingResponseCompletionState) -> &'static str {
    match value {
        AttestedFindingResponseCompletionState::NotStarted => "not_started",
        AttestedFindingResponseCompletionState::Pending => "pending",
        AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch => {
            "outcome_unknown_after_dispatch"
        }
        AttestedFindingResponseCompletionState::Completed => "completed",
    }
}

fn response_completion_outcome(
    value: &str,
) -> PortResult<AttestedFindingResponseCompletionOutcome> {
    match value {
        "activated" => Ok(AttestedFindingResponseCompletionOutcome::Activated),
        "failed_before_effect" => {
            Ok(AttestedFindingResponseCompletionOutcome::FailedBeforeEffect)
        }
        "rolled_back_after_partial" => {
            Ok(AttestedFindingResponseCompletionOutcome::RolledBackAfterPartial)
        }
        _ => Err(PortError::integrity_failure()),
    }
}

fn response_completion_outcome_name(
    value: AttestedFindingResponseCompletionOutcome,
) -> &'static str {
    match value {
        AttestedFindingResponseCompletionOutcome::Activated => "activated",
        AttestedFindingResponseCompletionOutcome::FailedBeforeEffect => "failed_before_effect",
        AttestedFindingResponseCompletionOutcome::RolledBackAfterPartial => {
            "rolled_back_after_partial"
        }
    }
}

fn validate_attested_finding_response_plan_publication(
    publication: &AttestedFindingResponsePlanPublication,
) -> PortResult<()> {
    let body = &publication.body;
    let plan = &body.response_plan;
    validate_canonical_json_body(&publication.canonical_body, &publication.body_hash)?;
    let canonical = canonical_json_bytes(body).map_err(|_| PortError::invalid_data())?;
    if body.schema_version != ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION
        || body.ordinal >= MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN
        || canonical.as_slice() != publication.canonical_body.as_bytes()
        || body.binding.tenant_id != plan.tenant_id
        || body.binding.action_id != plan.action_id
        || body.binding.evidence_id != plan.trigger_finding_receipt_id
        || body.binding.finding_id != plan.trigger_finding_id
        || body.binding.finding_hash != plan.trigger_finding_hash
    {
        return Err(PortError::integrity_failure());
    }
    plan.validate_shape()
        .map_err(|_| PortError::integrity_failure())
}

fn validate_attested_finding_response_outbox_record(
    record: &AttestedFindingResponseOutboxRecord,
) -> PortResult<()> {
    if record.ordinal >= MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN
        || record.attempts > chio_security_types::ports::ATTESTED_FINDING_RESPONSE_MAX_ATTEMPTS
        || record.binding.finding_hash.is_zero()
        || record
            .admission_artifact_digest
            .as_ref()
            .is_some_and(Digest32::is_zero)
        || record
            .completion_evidence_body_hash
            .as_ref()
            .is_some_and(Digest32::is_zero)
        || record
            .completion_evidence_id
            .as_ref()
            .is_some_and(|evidence_id| evidence_id.as_str().bytes().all(|byte| byte == b'0'))
        || record
            .execution_dispatch_id
            .as_ref()
            .is_some_and(|dispatch_id| dispatch_id.as_str().bytes().all(|byte| byte == b'0'))
    {
        return Err(PortError::integrity_failure());
    }
    let publication_valid = match (&record.planning_state, &record.publication) {
        (AttestedFindingResponsePlanningState::Pending, None)
        | (AttestedFindingResponsePlanningState::Failed, None) => {
            record.admission_artifact_digest.is_none()
        }
        (AttestedFindingResponsePlanningState::Planned, Some(publication)) => {
            validate_attested_finding_response_plan_publication(publication)?;
            publication.body.batch_id == record.batch_id
                && publication.body.ordinal == record.ordinal
                && publication.body.binding == record.binding
        }
        _ => false,
    };
    let prepared_binding_valid = match (
        record.prepared_dispatch_binding.as_ref(),
        record.execution_dispatch_id.as_ref(),
        record.publication.as_ref(),
    ) {
        (None, None, _) => true,
        (Some(binding), Some(dispatch_id), Some(publication)) => {
            binding
                .validate_for_plan(&publication.body.response_plan)
                .is_ok()
                && &binding.dispatch_id == dispatch_id
                && binding.tenant_id == record.binding.tenant_id
                && binding.action_id == record.binding.action_id
        }
        _ => false,
    };
    let execution_state_valid = match (
        record.admission_state,
        record.completion_state,
        record.execution_dispatch_id.as_ref(),
        record.prepared_dispatch_binding.as_ref(),
    ) {
        (
            AttestedFindingResponseAdmissionState::Pending,
            AttestedFindingResponseCompletionState::NotStarted,
            None,
            None,
        )
        | (
            AttestedFindingResponseAdmissionState::Rejected,
            AttestedFindingResponseCompletionState::NotStarted,
            None,
            None,
        ) => true,
        (
            AttestedFindingResponseAdmissionState::Expired,
            AttestedFindingResponseCompletionState::NotStarted,
            None,
            None,
        ) => true,
        (
            AttestedFindingResponseAdmissionState::Expired,
            AttestedFindingResponseCompletionState::NotStarted,
            Some(_),
            Some(_),
        ) => {
            matches!(
                record.planning_state,
                AttestedFindingResponsePlanningState::Planned
            ) && record.admission_artifact_digest.is_some()
        }
        (
            AttestedFindingResponseAdmissionState::Prepared,
            AttestedFindingResponseCompletionState::Pending
            | AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
            | AttestedFindingResponseCompletionState::Completed,
            Some(_),
            Some(_),
        ) => {
            matches!(
                record.planning_state,
                AttestedFindingResponsePlanningState::Planned
            ) && record.admission_artifact_digest.is_some()
        }
        _ => false,
    };
    let completion_evidence_valid = matches!(
        (
        record.completion_state,
        record.completion_outcome,
        record.completion_evidence_id.as_ref(),
        record.completion_evidence_body_hash.as_ref(),
        ),
        (
            AttestedFindingResponseCompletionState::Completed,
            Some(_),
            Some(_),
            Some(_),
        ) | (
            AttestedFindingResponseCompletionState::NotStarted
            | AttestedFindingResponseCompletionState::Pending
            | AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch,
            None,
            None,
            None,
        )
    );
    if !publication_valid
        || !prepared_binding_valid
        || !execution_state_valid
        || !completion_evidence_valid
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn read_attested_finding_response_outbox_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredAttestedFindingResponseOutboxRow> {
    Ok(StoredAttestedFindingResponseOutboxRow {
        tenant_id: row.get(0)?,
        batch_id: row.get(1)?,
        ordinal: row.get(2)?,
        evidence_id: row.get(3)?,
        finding_id: row.get(4)?,
        finding_hash: row.get(5)?,
        action_id: row.get(6)?,
        reservation_id: row.get(7)?,
        planning_state: row.get(8)?,
        admission_state: row.get(9)?,
        completion_state: row.get(10)?,
        execution_dispatch_id: row.get(11)?,
        prepared_dispatch_binding: row.get(12)?,
        prepared_dispatch_binding_hash: row.get(13)?,
        completion_outcome: row.get(14)?,
        completion_evidence_id: row.get(15)?,
        completion_evidence_body_hash: row.get(16)?,
        plan_body: row.get(17)?,
        plan_body_hash: row.get(18)?,
        admission_artifact_ref: row.get(19)?,
        admission_artifact_digest: row.get(20)?,
        attempts: row.get(21)?,
        next_attempt_at: row.get(22)?,
        last_error_code: row.get(23)?,
    })
}

const ATTESTED_FINDING_RESPONSE_OUTBOX_COLUMNS: &str = r#"
    tenant_id, batch_id, ordinal, evidence_id, finding_id, finding_hash,
    action_id, reservation_id, planning_state, admission_state,
    completion_state, execution_dispatch_id, prepared_dispatch_binding,
    prepared_dispatch_binding_hash, completion_outcome, completion_evidence_id,
    completion_evidence_body_hash, plan_body, plan_body_hash,
    admission_artifact_ref, admission_artifact_digest, attempts,
    next_attempt_at, last_error_code
"#;

fn decode_attested_finding_response_outbox_row(
    stored: StoredAttestedFindingResponseOutboxRow,
) -> PortResult<AttestedFindingResponseOutboxRecord> {
    let tenant_id = TenantId::new(stored.tenant_id).map_err(|_| PortError::integrity_failure())?;
    let batch_id = RecordId::new(stored.batch_id).map_err(|_| PortError::integrity_failure())?;
    let ordinal = u32::try_from(from_i64(stored.ordinal)?)
        .map_err(|_| PortError::integrity_failure())?;
    let binding = chio_security_types::ports::AttestedFindingBatchBinding {
        tenant_id,
        evidence_id: OpaqueReceiptRef::new(stored.evidence_id)
            .map_err(|_| PortError::integrity_failure())?,
        finding_id: RecordId::new(stored.finding_id)
            .map_err(|_| PortError::integrity_failure())?,
        finding_hash: decode_digest(stored.finding_hash)?,
        action_id: ActionId::new(stored.action_id)
            .map_err(|_| PortError::integrity_failure())?,
        reservation_id: RecordId::new(stored.reservation_id)
            .map_err(|_| PortError::integrity_failure())?,
    };
    let planning_state = response_planning_state(&stored.planning_state)?;
    let publication = match (
        stored.plan_body,
        stored.plan_body_hash,
        stored.admission_artifact_ref,
    ) {
        (None, None, None) => None,
        (Some(body), Some(body_hash), Some(artifact_ref)) => {
            let canonical_body =
                CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
            let body: AttestedFindingResponsePlanBody =
                serde_json::from_slice(canonical_body.as_bytes())
                    .map_err(|_| PortError::integrity_failure())?;
            let publication = AttestedFindingResponsePlanPublication {
                body,
                canonical_body,
                body_hash: decode_digest(body_hash)?,
            };
            validate_attested_finding_response_plan_publication(&publication)?;
            if publication.body.admission_artifact_ref.as_str() != artifact_ref {
                return Err(PortError::integrity_failure());
            }
            Some(publication)
        }
        _ => return Err(PortError::integrity_failure()),
    };
    let prepared_dispatch_binding = match (
        stored.prepared_dispatch_binding,
        stored.prepared_dispatch_binding_hash,
    ) {
        (None, None) => None,
        (Some(body), Some(body_hash)) => {
            let canonical_body =
                CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&canonical_body, &decode_digest(body_hash)?)
                .map_err(|_| PortError::integrity_failure())?;
            Some(
                serde_json::from_slice::<PreparedActiveResponseDispatchBinding>(
                    canonical_body.as_bytes(),
                )
                .map_err(|_| PortError::integrity_failure())?,
            )
        }
        _ => return Err(PortError::integrity_failure()),
    };
    let record = AttestedFindingResponseOutboxRecord {
        batch_id,
        ordinal,
        binding,
        publication,
        planning_state,
        admission_state: response_admission_state(&stored.admission_state)?,
        completion_state: response_completion_state(&stored.completion_state)?,
        execution_dispatch_id: stored
            .execution_dispatch_id
            .map(RecordId::new)
            .transpose()
            .map_err(|_| PortError::integrity_failure())?,
        prepared_dispatch_binding,
        completion_outcome: stored
            .completion_outcome
            .as_deref()
            .map(response_completion_outcome)
            .transpose()?,
        completion_evidence_id: stored
            .completion_evidence_id
            .map(OpaqueReceiptRef::new)
            .transpose()
            .map_err(|_| PortError::integrity_failure())?,
        completion_evidence_body_hash: stored
            .completion_evidence_body_hash
            .map(decode_digest)
            .transpose()?,
        admission_artifact_digest: stored
            .admission_artifact_digest
            .map(decode_digest)
            .transpose()?,
        attempts: from_i64(stored.attempts)?,
        next_attempt_at_unix_ms: from_i64(stored.next_attempt_at)?,
        last_error_code: stored
            .last_error_code
            .map(ErrorCode::new)
            .transpose()
            .map_err(|_| PortError::integrity_failure())?,
    };
    validate_attested_finding_response_outbox_record(&record)?;
    Ok(record)
}

fn load_attested_finding_response_outbox_record(
    connection: &Connection,
    key: &AttestedFindingResponseOutboxKey,
) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
    let sql = format!(
        "SELECT {ATTESTED_FINDING_RESPONSE_OUTBOX_COLUMNS} \
         FROM security_attested_finding_response_outbox \
         WHERE tenant_id = ?1 AND action_id = ?2"
    );
    connection
        .query_row(
            &sql,
            params![key.tenant_id.as_str(), key.action_id.as_str()],
            read_attested_finding_response_outbox_row,
        )
        .optional()
        .map_err(sqlite_error)?
        .map(decode_attested_finding_response_outbox_row)
        .transpose()
}

fn verify_response_outbox_batch_binding(
    connection: &Connection,
    record: &AttestedFindingResponseOutboxRecord,
) -> PortResult<()> {
    let batch = load_attested_finding_batch_record(
        connection,
        &AttestedFindingBatchKey {
            tenant_id: record.binding.tenant_id.clone(),
            batch_id: record.batch_id.clone(),
        },
    )?
    .ok_or_else(PortError::integrity_failure)?;
    let ordinal = usize::try_from(record.ordinal).map_err(|_| PortError::integrity_failure())?;
    if batch.body.bindings.as_slice().get(ordinal) != Some(&record.binding) {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_attested_finding_response_outbox_schema(connection: &Connection) -> PortResult<()> {
    if !table_definition_is_exact(
        connection,
        "security_attested_finding_response_outbox",
        ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "index",
        "security_attested_finding_response_outbox_due",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_immutable",
        ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_delete_rejected",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL,
    )? || table_has_foreign_key_violation(
        connection,
        "security_attested_finding_response_outbox",
    )? || !attested_finding_response_outbox_is_one_to_one(connection)? {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn scan_attested_finding_response_outbox(
    connection: &Connection,
    predicate: &str,
    now_unix_ms: u64,
    max_records: u32,
) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
    if max_records == 0 || max_records > MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN {
        return Err(PortError::invalid_data());
    }
    let sql = format!(
        "SELECT {ATTESTED_FINDING_RESPONSE_OUTBOX_COLUMNS} \
         FROM security_attested_finding_response_outbox \
         WHERE {predicate} AND next_attempt_at <= ?1 \
         ORDER BY CASE \
             WHEN completion_state = 'outcome_unknown_after_dispatch' THEN 0 \
             WHEN admission_state = 'prepared' THEN 1 \
             WHEN planning_state = 'planned' THEN 2 \
             ELSE 3 END ASC, rowid ASC \
         LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql).map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![to_i64(now_unix_ms)?, i64::from(max_records)],
            read_attested_finding_response_outbox_row,
        )
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?
        .into_iter()
        .map(|row| {
            let record = decode_attested_finding_response_outbox_row(row)?;
            verify_response_outbox_batch_binding(connection, &record)?;
            Ok(record)
        })
        .collect()
}

impl AttestedFindingResponseOutboxStore for SqliteSecurityStateStore {
    fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        validate_attested_finding_response_outbox_schema(&connection)?;
        let keys = {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT tenant_id, action_id
                    FROM security_attested_finding_response_outbox
                    ORDER BY tenant_id, action_id
                    "#,
                )
                .map_err(sqlite_error)?;
            let keys = statement
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            keys
        };
        for (tenant_id, action_id) in keys {
            let key = AttestedFindingResponseOutboxKey {
                tenant_id: TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                action_id: ActionId::new(action_id)
                    .map_err(|_| PortError::integrity_failure())?,
            };
            let record = load_attested_finding_response_outbox_record(&connection, &key)?
                .ok_or_else(PortError::integrity_failure)?;
            verify_response_outbox_batch_binding(&connection, &record)?;
        }
        Ok(())
    }

    fn publish_attested_finding_response_plan(
        &self,
        publication: &AttestedFindingResponsePlanPublication,
    ) -> PortResult<CreateOutcome> {
        validate_attested_finding_response_plan_publication(publication)?;
        let key = AttestedFindingResponseOutboxKey {
            tenant_id: publication.body.binding.tenant_id.clone(),
            action_id: publication.body.binding.action_id.clone(),
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let current = load_attested_finding_response_outbox_record(&transaction, &key)?
            .ok_or_else(PortError::integrity_failure)?;
        verify_response_outbox_batch_binding(&transaction, &current)?;
        if current.batch_id != publication.body.batch_id
            || current.ordinal != publication.body.ordinal
            || current.binding != publication.body.binding
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current.publication.as_ref() {
            if existing != publication {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        if current.planning_state != AttestedFindingResponsePlanningState::Pending
            || current.admission_state != AttestedFindingResponseAdmissionState::Pending
            || current.completion_state != AttestedFindingResponseCompletionState::NotStarted
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_attested_finding_response_outbox
                SET planning_state = 'planned', plan_body = ?1, plan_body_hash = ?2,
                    admission_artifact_ref = ?3, next_attempt_at = 0,
                    last_error_code = NULL
                WHERE tenant_id = ?4 AND action_id = ?5 AND planning_state = 'pending'
                "#,
                params![
                    publication.canonical_body.as_bytes(),
                    publication.body_hash.as_bytes().as_slice(),
                    publication.body.admission_artifact_ref.as_str(),
                    key.tenant_id.as_str(),
                    key.action_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let stored = load_attested_finding_response_outbox_record(&transaction, &key)?
            .ok_or_else(PortError::integrity_failure)?;
        if stored.publication.as_ref() != Some(publication) {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn load_attested_finding_response_outbox(
        &self,
        key: &AttestedFindingResponseOutboxKey,
    ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
        let connection = self.connection()?;
        let record = load_attested_finding_response_outbox_record(&connection, key)?;
        if let Some(record) = record.as_ref() {
            verify_response_outbox_batch_binding(&connection, record)?;
        }
        Ok(record)
    }

    fn scan_unplanned_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
        let connection = self.connection()?;
        scan_attested_finding_response_outbox(
            &connection,
            "planning_state = 'pending'",
            now_unix_ms,
            max_records,
        )
    }

    fn scan_incomplete_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
        let connection = self.connection()?;
        scan_attested_finding_response_outbox(
            &connection,
            "planning_state = 'planned' AND admission_state IN ('pending', 'prepared') \
             AND completion_state != 'completed'",
            now_unix_ms,
            max_records,
        )
    }

    fn transition_attested_finding_response_outbox(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        transition: AttestedFindingResponseOutboxTransition,
    ) -> PortResult<AttestedFindingResponseOutboxRecord> {
        validate_attested_finding_response_outbox_record(current)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let persisted = load_attested_finding_response_outbox_record(&transaction, &current.key())?
            .ok_or_else(PortError::integrity_failure)?;
        if persisted != *current {
            return Err(PortError::conflict());
        }
        let mut next = persisted;
        match transition {
            AttestedFindingResponseOutboxTransition::BeginAttempt {
                next_attempt_at_unix_ms,
            } => {
                if next.is_complete() {
                    return Err(PortError::conflict());
                }
                next.attempts = next
                    .attempts
                    .saturating_add(1)
                    .min(chio_security_types::ports::ATTESTED_FINDING_RESPONSE_MAX_ATTEMPTS);
                next.next_attempt_at_unix_ms = next_attempt_at_unix_ms;
            }
            AttestedFindingResponseOutboxTransition::RetryableFailure {
                next_attempt_at_unix_ms,
                error_code,
                outcome_unknown_after_dispatch,
            } => {
                if next.is_complete() {
                    return Err(PortError::conflict());
                }
                if outcome_unknown_after_dispatch {
                    if next.admission_state != AttestedFindingResponseAdmissionState::Prepared {
                        return Err(PortError::conflict());
                    }
                    next.completion_state =
                        AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch;
                }
                next.next_attempt_at_unix_ms = next_attempt_at_unix_ms;
                next.last_error_code = Some(error_code);
            }
            AttestedFindingResponseOutboxTransition::PlanningFailed { error_code } => {
                if next.planning_state != AttestedFindingResponsePlanningState::Pending {
                    return Err(PortError::conflict());
                }
                next.planning_state = AttestedFindingResponsePlanningState::Failed;
                next.admission_state = AttestedFindingResponseAdmissionState::Rejected;
                next.last_error_code = Some(error_code);
            }
            AttestedFindingResponseOutboxTransition::AdmissionRejected { error_code } => {
                if next.planning_state != AttestedFindingResponsePlanningState::Planned
                    || next.admission_state != AttestedFindingResponseAdmissionState::Pending
                {
                    return Err(PortError::conflict());
                }
                next.admission_state = AttestedFindingResponseAdmissionState::Rejected;
                next.last_error_code = Some(error_code);
            }
            AttestedFindingResponseOutboxTransition::ExpiredBeforeAdmission => {
                if next.planning_state != AttestedFindingResponsePlanningState::Planned
                    || next.admission_state != AttestedFindingResponseAdmissionState::Pending
                {
                    return Err(PortError::conflict());
                }
                next.admission_state = AttestedFindingResponseAdmissionState::Expired;
                next.last_error_code = Some(
                    ErrorCode::new("active_response.plan_expired")
                        .map_err(|_| PortError::integrity_failure())?,
                );
            }
            AttestedFindingResponseOutboxTransition::ExpiredAfterPreparedNeverCommitted => {
                if next.planning_state != AttestedFindingResponsePlanningState::Planned
                    || next.admission_state != AttestedFindingResponseAdmissionState::Prepared
                    || next.execution_dispatch_id.is_none()
                    || next.prepared_dispatch_binding.is_none()
                    || next.admission_artifact_digest.is_none()
                    || !matches!(
                        next.completion_state,
                        AttestedFindingResponseCompletionState::Pending
                            | AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
                    )
                {
                    return Err(PortError::conflict());
                }
                next.admission_state = AttestedFindingResponseAdmissionState::Expired;
                next.completion_state = AttestedFindingResponseCompletionState::NotStarted;
                next.last_error_code = Some(
                    ErrorCode::new("active_response.never_committed")
                        .map_err(|_| PortError::integrity_failure())?,
                );
            }
            AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                artifact_digest,
            } => {
                if next.planning_state != AttestedFindingResponsePlanningState::Planned
                    || next.admission_state != AttestedFindingResponseAdmissionState::Pending
                    || next.admission_artifact_digest.is_some()
                    || artifact_digest.is_zero()
                {
                    return Err(PortError::conflict());
                }
                next.admission_artifact_digest = Some(artifact_digest);
                next.last_error_code = None;
            }
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding,
            } => {
                let Some(publication) = next.publication.as_ref() else {
                    return Err(PortError::conflict());
                };
                if next.planning_state != AttestedFindingResponsePlanningState::Planned
                    || next.admission_state != AttestedFindingResponseAdmissionState::Pending
                    || next.admission_artifact_digest.is_none()
                    || next.execution_dispatch_id.is_some()
                    || next.prepared_dispatch_binding.is_some()
                    || prepared_dispatch_binding
                        .validate_for_plan(&publication.body.response_plan)
                        .is_err()
                    || prepared_dispatch_binding
                        .dispatch_id
                        .as_str()
                        .bytes()
                        .all(|byte| byte == b'0')
                {
                    return Err(PortError::conflict());
                }
                next.admission_state = AttestedFindingResponseAdmissionState::Prepared;
                next.completion_state = AttestedFindingResponseCompletionState::Pending;
                next.execution_dispatch_id = Some(prepared_dispatch_binding.dispatch_id.clone());
                next.prepared_dispatch_binding = Some(*prepared_dispatch_binding);
                next.last_error_code = None;
            }
            AttestedFindingResponseOutboxTransition::Completed {
                execution_dispatch_id,
                outcome,
                evidence_id,
                evidence_body_hash,
            } => {
                if next.admission_state != AttestedFindingResponseAdmissionState::Prepared
                    || next.execution_dispatch_id.as_ref() != Some(&execution_dispatch_id)
                    || evidence_body_hash.is_zero()
                    || evidence_id.as_str().bytes().all(|byte| byte == b'0')
                {
                    return Err(PortError::conflict());
                }
                next.completion_state = AttestedFindingResponseCompletionState::Completed;
                next.completion_outcome = Some(outcome);
                next.completion_evidence_id = Some(evidence_id);
                next.completion_evidence_body_hash = Some(evidence_body_hash);
                next.last_error_code = None;
            }
        }
        validate_attested_finding_response_outbox_record(&next)?;
        let prepared_dispatch_binding = next
            .prepared_dispatch_binding
            .as_ref()
            .map(canonical_json_bytes)
            .transpose()
            .map_err(|_| PortError::integrity_failure())?;
        if prepared_dispatch_binding
            .as_ref()
            .is_some_and(|body| body.len() > 1_048_576)
        {
            return Err(PortError::integrity_failure());
        }
        let prepared_dispatch_binding_hash = prepared_dispatch_binding
            .as_ref()
            .map(|body| body_hash(body.as_slice()));
        let updated = transaction
            .execute(
                r#"
                UPDATE security_attested_finding_response_outbox
                SET planning_state = ?1, admission_state = ?2, completion_state = ?3,
                    execution_dispatch_id = ?4, prepared_dispatch_binding = ?5,
                    prepared_dispatch_binding_hash = ?6, completion_outcome = ?7,
                    completion_evidence_id = ?8, completion_evidence_body_hash = ?9,
                    admission_artifact_digest = ?10, attempts = ?11,
                    next_attempt_at = ?12, last_error_code = ?13
                WHERE tenant_id = ?14 AND action_id = ?15
                "#,
                params![
                    response_planning_state_name(next.planning_state),
                    response_admission_state_name(next.admission_state),
                    response_completion_state_name(next.completion_state),
                    next.execution_dispatch_id.as_ref().map(RecordId::as_str),
                    prepared_dispatch_binding.as_deref(),
                    prepared_dispatch_binding_hash
                        .as_ref()
                        .map(|hash| hash.as_slice()),
                    next.completion_outcome.map(response_completion_outcome_name),
                    next.completion_evidence_id
                        .as_ref()
                        .map(OpaqueReceiptRef::as_str),
                    next.completion_evidence_body_hash
                        .as_ref()
                        .map(|hash| hash.as_bytes().as_slice()),
                    next.admission_artifact_digest
                        .as_ref()
                        .map(|hash| hash.as_bytes().as_slice()),
                    to_i64(next.attempts)?,
                    to_i64(next.next_attempt_at_unix_ms)?,
                    next.last_error_code.as_ref().map(ErrorCode::as_str),
                    next.binding.tenant_id.as_str(),
                    next.binding.action_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let stored = load_attested_finding_response_outbox_record(&transaction, &next.key())?
            .ok_or_else(PortError::integrity_failure)?;
        if stored != next {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn attested_finding_response_outbox_health(
        &self,
    ) -> PortResult<AttestedFindingResponseOutboxHealth> {
        let connection = self.connection()?;
        let values: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    COALESCE(SUM(CASE WHEN planning_state = 'pending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN planning_state = 'planned'
                        AND admission_state = 'pending' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN planning_state = 'planned'
                        AND admission_state = 'pending'
                        AND admission_artifact_digest IS NULL THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN completion_state = 'pending'
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN completion_state = 'outcome_unknown_after_dispatch'
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN planning_state = 'failed'
                        OR admission_state = 'rejected' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN admission_state = 'expired' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN completion_outcome = 'activated'
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN completion_outcome = 'failed_before_effect'
                        THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN completion_outcome = 'rolled_back_after_partial'
                        THEN 1 ELSE 0 END), 0)
                FROM security_attested_finding_response_outbox
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?, row.get(1)?, row.get(2)?,
                        row.get(3)?, row.get(4)?, row.get(5)?,
                        row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
        Ok(AttestedFindingResponseOutboxHealth {
            planning_pending: from_i64(values.0)?,
            admission_pending: from_i64(values.1)?,
            artifact_binding_pending: from_i64(values.2)?,
            completion_pending: from_i64(values.3)?,
            outcome_unknown_after_dispatch: from_i64(values.4)?,
            terminal_failed: from_i64(values.5)?,
            terminal_expired: from_i64(values.6)?,
            terminal_activated: from_i64(values.7)?,
            terminal_failed_before_effect: from_i64(values.8)?,
            terminal_rolled_back_after_partial: from_i64(values.9)?,
        })
    }
}
