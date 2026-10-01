fn trust_class_name(value: ProducerTrustClass) -> &'static str {
    match value {
        ProducerTrustClass::InternalDetector => "internal_detector",
        ProducerTrustClass::VerifiedReceipt => "verified_receipt",
    }
}

fn parse_trust_class(value: &str) -> PortResult<ProducerTrustClass> {
    match value {
        "internal_detector" => Ok(ProducerTrustClass::InternalDetector),
        "verified_receipt" => Ok(ProducerTrustClass::VerifiedReceipt),
        _ => Err(PortError::integrity_failure()),
    }
}

fn correlation_outcome_status_name(value: CorrelationOutcomeStatus) -> &'static str {
    match value {
        CorrelationOutcomeStatus::Accepted => "accepted",
        CorrelationOutcomeStatus::AdvisoryOnly => "advisory_only",
        CorrelationOutcomeStatus::Deferred => "deferred",
        CorrelationOutcomeStatus::Duplicate => "duplicate",
        CorrelationOutcomeStatus::Irrelevant => "irrelevant",
        CorrelationOutcomeStatus::Matched => "matched",
        CorrelationOutcomeStatus::Suppressed => "suppressed",
        CorrelationOutcomeStatus::TooLate => "too_late",
    }
}

fn parse_correlation_outcome_status(value: &str) -> PortResult<CorrelationOutcomeStatus> {
    match value {
        "accepted" => Ok(CorrelationOutcomeStatus::Accepted),
        "advisory_only" => Ok(CorrelationOutcomeStatus::AdvisoryOnly),
        "deferred" => Ok(CorrelationOutcomeStatus::Deferred),
        "duplicate" => Ok(CorrelationOutcomeStatus::Duplicate),
        "irrelevant" => Ok(CorrelationOutcomeStatus::Irrelevant),
        "matched" => Ok(CorrelationOutcomeStatus::Matched),
        "suppressed" => Ok(CorrelationOutcomeStatus::Suppressed),
        "too_late" => Ok(CorrelationOutcomeStatus::TooLate),
        _ => Err(PortError::integrity_failure()),
    }
}

fn append_verified_in_transaction(
    connection: &Connection,
    event: &VerifiedSecurityEvent,
) -> PortResult<EventAppend> {
    validate_canonical_json_body(&event.canonical_body, &event.body_hash)?;
    if let Some((tenant_id, event_class, body_hash)) = load_event_identity(
        connection,
        event.tenant_id.as_str(),
        event.event_id.as_str(),
    )? {
        if tenant_id != event.tenant_id.as_str()
            || event_class != "verified"
            || decode_digest(body_hash)? != event.body_hash
        {
            return Err(PortError::conflict());
        }
        let stored: (String, String, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT producer_id, trust_class, event_time, received_at, body, body_hash, evidence_hash FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2",
                params![event.tenant_id.as_str(), event.event_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .map_err(sqlite_error)?;
        let stored_body_hash = decode_digest(stored.5)?;
        let stored_body =
            CanonicalBody::new(stored.4.clone()).map_err(|_| PortError::integrity_failure())?;
        validate_canonical_json_body(&stored_body, &stored_body_hash)
            .map_err(|_| PortError::integrity_failure())?;
        if stored.0 != event.producer_id.as_str()
            || parse_trust_class(&stored.1)? != event.trust_class
            || from_i64(stored.2)? != event.event_time_unix_ms
            || from_i64(stored.3)? != event.received_at_unix_ms
            || stored.4.as_slice() != event.canonical_body.as_bytes()
            || stored_body_hash != event.body_hash
            || decode_digest(stored.6)? != event.evidence_hash
        {
            return Err(PortError::conflict());
        }
        return Ok(EventAppend::Duplicate);
    }
    insert_event_identity(
        connection,
        event.event_id.as_str(),
        event.tenant_id.as_str(),
        "verified",
        &event.body_hash,
    )?;
    connection
        .execute(
            r#"
            INSERT INTO security_verified_events (
                tenant_id, event_id, producer_id, trust_class, event_time, received_at,
                body, body_hash, evidence_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                event.tenant_id.as_str(),
                event.event_id.as_str(),
                event.producer_id.as_str(),
                trust_class_name(event.trust_class),
                to_i64(event.event_time_unix_ms)?,
                to_i64(event.received_at_unix_ms)?,
                event.canonical_body.as_bytes(),
                event.body_hash.as_bytes().as_slice(),
                event.evidence_hash.as_bytes().as_slice()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(EventAppend::Inserted)
}

fn index_partition_event_in_transaction(
    connection: &Connection,
    request: &CorrelationEventIndexRequest,
) -> PortResult<()> {
    let request_hash = canonical_request_hash(request)?;
    if transition_status(
        connection,
        request.key.tenant_id.as_str(),
        request.transition_id.as_str(),
        "correlation_event_index",
        &request_hash,
    )? {
        let indexed: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM security_correlation_events
                    WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
                      AND event_id = ?4
                )
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.rule_id.as_str(),
                    request.key.partition_hash.as_bytes().as_slice(),
                    request.event_id.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        return if indexed {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        };
    }
    let identity = load_event_identity(
        connection,
        request.key.tenant_id.as_str(),
        request.event_id.as_str(),
    )?
    .ok_or_else(PortError::invalid_data)?;
    if identity.1 != "verified" {
        return Err(PortError::conflict());
    }
    let event_time: i64 = connection
        .query_row(
            "SELECT event_time FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2",
            params![request.key.tenant_id.as_str(), request.event_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let event_time = from_i64(event_time)?;
    if load_correlation_partial(connection, &request.key)?
        .is_some_and(|partial| event_time <= partial.watermark_unix_ms)
    {
        return Err(PortError::conflict());
    }
    let existing_partition: Option<Vec<u8>> = connection
        .query_row(
            r#"
            SELECT partition_hash FROM security_correlation_events
            WHERE tenant_id = ?1 AND rule_id = ?2 AND event_id = ?3
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.rule_id.as_str(),
                request.event_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(partition_hash) = existing_partition {
        if decode_digest(partition_hash)? != request.key.partition_hash {
            return Err(PortError::conflict());
        }
    } else {
        connection
            .execute(
                r#"
                INSERT INTO security_correlation_events (
                    tenant_id, rule_id, partition_hash, event_id, transition_id
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.rule_id.as_str(),
                    request.key.partition_hash.as_bytes().as_slice(),
                    request.event_id.as_str(),
                    request.transition_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        bump_correlation_partition_head(connection, &request.key)?;
    }
    record_transition(
        connection,
        request.key.tenant_id.as_str(),
        request.transition_id.as_str(),
        "correlation_event_index",
        &request_hash,
    )
}

fn compare_and_swap_correlation_in_transaction(
    connection: &Connection,
    request: &CorrelationCasRequest,
) -> PortResult<CorrelationPartial> {
    if request.scan.tenant_id != request.partial.key.tenant_id
        || request.scan.rule_id != request.partial.key.rule_id
        || request.scan.partition_hash != request.partial.key.partition_hash
        || request.scan.through_event_time_unix_ms != request.partial.watermark_unix_ms
    {
        return Err(PortError::invalid_data());
    }
    validate_canonical_json_body(&request.partial.canonical_body, &request.partial.body_hash)?;
    let request_hash = canonical_request_hash(request)?;
    if transition_status(
        connection,
        request.partial.key.tenant_id.as_str(),
        request.transition_id.as_str(),
        "correlation_cas",
        &request_hash,
    )? {
        return load_correlation_partial(connection, &request.partial.key)?
            .ok_or_else(PortError::integrity_failure);
    }
    let partition_generation =
        load_correlation_partition_generation(connection, &request.partial.key)?;
    if partition_generation != request.observed_partition_generation {
        return Err(PortError::conflict());
    }
    let current = load_correlation_partial(connection, &request.partial.key)?;
    match (current.as_ref(), request.expected_generation) {
        (None, None) if request.partial.generation == 0 => {}
        (Some(current), Some(expected))
            if current.generation == expected
                && request.partial.watermark_unix_ms >= current.watermark_unix_ms
                && request.partial.generation
                    == expected
                        .checked_add(1)
                        .ok_or_else(PortError::integrity_failure)? => {}
        _ => return Err(PortError::conflict()),
    }
    let covers_next_interval = match current.as_ref() {
        None => {
            request.scan.after_event_time_unix_ms.is_none() && request.scan.after_event_id.is_none()
        }
        Some(current) => {
            request.scan.after_event_time_unix_ms == Some(current.watermark_unix_ms)
                && request.scan.after_event_id.is_none()
        }
    };
    if !covers_next_interval {
        return Err(PortError::conflict());
    }
    let (_, truncated) = scan_verified_partition(connection, &request.scan)?;
    if truncated {
        return Err(PortError::conflict());
    }
    connection
        .execute(
            r#"
            INSERT INTO security_correlation_partials (
                tenant_id, rule_id, partition_hash, generation, watermark,
                expires_at, body, body_hash, transition_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT (tenant_id, rule_id, partition_hash) DO UPDATE SET
                generation = excluded.generation,
                watermark = excluded.watermark,
                expires_at = excluded.expires_at,
                body = excluded.body,
                body_hash = excluded.body_hash,
                transition_id = excluded.transition_id
            "#,
            params![
                request.partial.key.tenant_id.as_str(),
                request.partial.key.rule_id.as_str(),
                request.partial.key.partition_hash.as_bytes().as_slice(),
                to_i64(request.partial.generation)?,
                to_i64(request.partial.watermark_unix_ms)?,
                to_i64(request.partial.expires_at_unix_ms)?,
                request.partial.canonical_body.as_bytes(),
                request.partial.body_hash.as_bytes().as_slice(),
                request.transition_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    record_transition(
        connection,
        request.partial.key.tenant_id.as_str(),
        request.transition_id.as_str(),
        "correlation_cas",
        &request_hash,
    )?;
    Ok(request.partial.clone())
}

fn validate_correlation_outcome_publication(
    publication: &CorrelationOutcomePublication,
) -> PortResult<()> {
    validate_canonical_json_body(&publication.canonical_body, &publication.body_hash)?;
    if publication
        .partition_hash
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || publication.status == CorrelationOutcomeStatus::Deferred
        || publication
        .rule_version_hash
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || publication
            .event_body_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || publication
            .event_evidence_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

type CorrelationOutcomeStorageRow = (
    Vec<u8>,
    String,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn load_correlation_outcome_record(
    connection: &Connection,
    key: &CorrelationOutcomeKey,
) -> PortResult<Option<CorrelationOutcomePublication>> {
    let stored: Option<CorrelationOutcomeStorageRow> = connection
        .query_row(
            r#"
            SELECT partition_hash, status, watermark, rule_version_hash,
                   event_body_hash, event_evidence_hash, body, body_hash
            FROM security_correlation_outcomes
            WHERE tenant_id = ?1 AND rule_id = ?2 AND event_id = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.event_id.as_str()
            ],
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
                partition_hash,
                status,
                watermark,
                rule_version_hash,
                event_body_hash,
                event_evidence_hash,
                body,
                body_hash,
            )| {
                let publication = CorrelationOutcomePublication {
                    key: key.clone(),
                    partition_hash: decode_digest(partition_hash)?,
                    status: parse_correlation_outcome_status(&status)?,
                    watermark_unix_ms: from_i64(watermark)?,
                    rule_version_hash: decode_digest(rule_version_hash)?,
                    event_body_hash: decode_digest(event_body_hash)?,
                    event_evidence_hash: decode_digest(event_evidence_hash)?,
                    canonical_body: CanonicalBody::new(body)
                        .map_err(|_| PortError::integrity_failure())?,
                    body_hash: decode_digest(body_hash)?,
                };
                validate_correlation_outcome_publication(&publication)
                    .map_err(|_| PortError::integrity_failure())?;
                validate_correlation_outcome_storage_binding(connection, &publication, false)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(publication)
            },
        )
        .transpose()
}

fn insert_correlation_outcome_record(
    connection: &Connection,
    publication: &CorrelationOutcomePublication,
) -> PortResult<()> {
    connection
        .execute(
            r#"
            INSERT INTO security_correlation_outcomes (
                tenant_id, rule_id, event_id, partition_hash, status, watermark,
                rule_version_hash, event_body_hash, event_evidence_hash, body, body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                publication.key.tenant_id.as_str(),
                publication.key.rule_id.as_str(),
                publication.key.event_id.as_str(),
                publication.partition_hash.as_bytes().as_slice(),
                correlation_outcome_status_name(publication.status),
                to_i64(publication.watermark_unix_ms)?,
                publication.rule_version_hash.as_bytes().as_slice(),
                publication.event_body_hash.as_bytes().as_slice(),
                publication.event_evidence_hash.as_bytes().as_slice(),
                publication.canonical_body.as_bytes(),
                publication.body_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn validate_correlation_outcome_storage_binding(
    connection: &Connection,
    outcome: &CorrelationOutcomePublication,
    require_live_late_proof: bool,
) -> PortResult<bool> {
    let verified: (Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            r#"
            SELECT body_hash, evidence_hash, event_time
            FROM security_verified_events
            WHERE tenant_id = ?1 AND event_id = ?2
            "#,
            params![outcome.key.tenant_id.as_str(), outcome.key.event_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    if decode_digest(verified.0)? != outcome.event_body_hash
        || decode_digest(verified.1)? != outcome.event_evidence_hash
    {
        return Err(PortError::integrity_failure());
    }
    let indexed: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_correlation_events
                WHERE tenant_id = ?1 AND rule_id = ?2 AND event_id = ?3
                  AND partition_hash = ?4
            )
            "#,
            params![
                outcome.key.tenant_id.as_str(),
                outcome.key.rule_id.as_str(),
                outcome.key.event_id.as_str(),
                outcome.partition_hash.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if indexed {
        return Ok(true);
    }
    if !matches!(
        outcome.status,
        CorrelationOutcomeStatus::Duplicate | CorrelationOutcomeStatus::TooLate
    ) {
        return Err(PortError::conflict());
    }
    if from_i64(verified.2)? > outcome.watermark_unix_ms {
        return Err(PortError::conflict());
    }
    if !require_live_late_proof {
        return Ok(false);
    }
    let partition = load_correlation_partial(
        connection,
        &CorrelationPartitionKey {
            tenant_id: outcome.key.tenant_id.clone(),
            rule_id: outcome.key.rule_id.clone(),
            partition_hash: outcome.partition_hash,
        },
    )?
    .ok_or_else(PortError::conflict)?;
    if outcome.watermark_unix_ms > partition.watermark_unix_ms {
        return Err(PortError::conflict());
    }
    Ok(false)
}

impl SecurityEventStore for SqliteSecurityStateStore {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission> {
        if request.event.tenant_id != request.index.key.tenant_id
            || request.event.event_id != request.index.event_id
            || request.capacity.as_ref().is_some_and(|capacity| {
                capacity.partial.key.tenant_id != request.event.tenant_id
                    || capacity.partial.key.rule_id != request.index.key.rule_id
            })
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let append = append_verified_in_transaction(&transaction, &request.event)?;
        let capacity = request
            .capacity
            .as_ref()
            .map(|capacity| compare_and_swap_correlation_in_transaction(&transaction, capacity))
            .transpose()?;
        index_partition_event_in_transaction(&transaction, &request.index)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CorrelationEventAdmission { append, capacity })
    }

    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let append = append_verified_in_transaction(&transaction, event)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(append)
    }

    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        validate_canonical_json_body(&event.canonical_body, &event.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some((tenant_id, event_class, body_hash)) = load_event_identity(
            &transaction,
            event.tenant_id.as_str(),
            event.event_id.as_str(),
        )? {
            if tenant_id != event.tenant_id.as_str()
                || event_class != "advisory"
                || decode_digest(body_hash)? != event.body_hash
            {
                return Err(PortError::conflict());
            }
            let stored: (String, i64, Vec<u8>, Vec<u8>) = transaction
                .query_row(
                    "SELECT producer_id, event_time, body, body_hash FROM security_advisory_events WHERE tenant_id = ?1 AND event_id = ?2",
                    params![event.tenant_id.as_str(), event.event_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(sqlite_error)?;
            let stored_body_hash = decode_digest(stored.3)?;
            let stored_body =
                CanonicalBody::new(stored.2.clone()).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&stored_body, &stored_body_hash)
                .map_err(|_| PortError::integrity_failure())?;
            if stored.0 != event.producer_id.as_str()
                || from_i64(stored.1)? != event.event_time_unix_ms
                || stored.2.as_slice() != event.canonical_body.as_bytes()
                || stored_body_hash != event.body_hash
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(EventAppend::Duplicate);
        }
        insert_event_identity(
            &transaction,
            event.event_id.as_str(),
            event.tenant_id.as_str(),
            "advisory",
            &event.body_hash,
        )?;
        transaction
            .execute(
                r#"
                INSERT INTO security_advisory_events (
                    tenant_id, event_id, producer_id, event_time, body, body_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    event.tenant_id.as_str(),
                    event.event_id.as_str(),
                    event.producer_id.as_str(),
                    to_i64(event.event_time_unix_ms)?,
                    event.canonical_body.as_bytes(),
                    event.body_hash.as_bytes().as_slice()
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(EventAppend::Inserted)
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        index_partition_event_in_transaction(&transaction, request)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let key = CorrelationPartitionKey {
            tenant_id: scan.tenant_id.clone(),
            rule_id: scan.rule_id.clone(),
            partition_hash: scan.partition_hash,
        };
        let partition_generation = load_correlation_partition_generation(&transaction, &key)?;
        let (events, truncated) = scan_verified_partition(&transaction, scan)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CorrelationScan {
            events,
            partition_generation,
            truncated,
        })
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        let connection = self.connection()?;
        load_correlation_partial(&connection, key)
    }

    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>> {
        let connection = self.connection()?;
        let event_time: Option<i64> = connection
            .query_row(
                r#"
                SELECT MAX(event.event_time)
                FROM security_correlation_events AS indexed
                JOIN security_verified_events AS event
                  ON event.tenant_id = indexed.tenant_id
                 AND event.event_id = indexed.event_id
                WHERE indexed.tenant_id = ?1
                  AND indexed.rule_id = ?2
                  AND indexed.partition_hash = ?3
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.rule_id.as_str(),
                    key.partition_hash.as_bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        event_time.map(from_i64).transpose()
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let partial = compare_and_swap_correlation_in_transaction(&transaction, request)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(partial)
    }

    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial> {
        validate_correlation_outcome_publication(&request.outcome)?;
        if request.outcome.key.tenant_id != request.correlation.partial.key.tenant_id
            || request.outcome.key.rule_id != request.correlation.partial.key.rule_id
            || request.outcome.key.tenant_id != request.correlation.scan.tenant_id
            || request.outcome.key.rule_id != request.correlation.scan.rule_id
            || request.outcome.partition_hash
                != request.correlation.partial.key.partition_hash
            || request.correlation.partial.key.partition_hash
                != request.correlation.scan.partition_hash
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) =
            load_correlation_outcome_record(&transaction, &request.outcome.key)?
        {
            if existing != request.outcome {
                return Err(PortError::conflict());
            }
            let request_hash = canonical_request_hash(&request.correlation)?;
            if !transition_status(
                &transaction,
                request.correlation.partial.key.tenant_id.as_str(),
                request.correlation.transition_id.as_str(),
                "correlation_cas",
                &request_hash,
            )? {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(request.correlation.partial.clone());
        }
        if !validate_correlation_outcome_storage_binding(&transaction, &request.outcome, true)? {
            return Err(PortError::integrity_failure());
        }
        let partial = compare_and_swap_correlation_in_transaction(
            &transaction,
            &request.correlation,
        )?;
        insert_correlation_outcome_record(&transaction, &request.outcome)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(partial)
    }

    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome> {
        validate_correlation_outcome_publication(outcome)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_correlation_outcome_record(&transaction, &outcome.key)? {
            if existing != *outcome {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        validate_correlation_outcome_storage_binding(&transaction, outcome, true)?;
        insert_correlation_outcome_record(&transaction, outcome)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>> {
        let connection = self.connection()?;
        load_correlation_outcome_record(&connection, key)
    }

    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_delete",
            &request_hash,
        )? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let deleted = transaction
            .execute(
                "DELETE FROM security_correlation_partials WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3 AND generation = ?4",
                params![
                    request.key.tenant_id.as_str(),
                    request.key.rule_id.as_str(),
                    request.key.partition_hash.as_bytes().as_slice(),
                    to_i64(request.expected_generation)?
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_delete",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

fn validate_correlation_ingress_binding(
    event: &UnverifiedSecurityEvent,
    verified: &VerifiedSecurityEvent,
) -> PortResult<()> {
    validate_canonical_json_body(&event.canonical_body, &event.body_hash)?;
    validate_correlation_source_evidence(
        verified.trust_class,
        &event.source_evidence,
        &verified.evidence_hash,
    )?;
    if event.tenant_id != verified.tenant_id
        || event.event_id != verified.event_id
        || event.producer_id != verified.producer_id
        || event.event_time_unix_ms != verified.event_time_unix_ms
        || event.received_at_unix_ms != verified.received_at_unix_ms
        || event.canonical_body != verified.canonical_body
        || event.body_hash != verified.body_hash
        || verified
            .evidence_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_correlation_source_evidence(
    trust_class: ProducerTrustClass,
    source_evidence: &CanonicalBody,
    expected_hash: &Digest32,
) -> PortResult<()> {
    let (canonical_source, domain) = match trust_class {
        ProducerTrustClass::InternalDetector => {
            let signed: SignedSecurityEvent =
                serde_json::from_slice(source_evidence.as_bytes())
                    .map_err(|_| PortError::invalid_data())?;
            (
                canonical_json_bytes(&signed).map_err(|_| PortError::invalid_data())?,
                EVENT_EVIDENCE_HASH_DOMAIN,
            )
        }
        ProducerTrustClass::VerifiedReceipt => {
            let receipt: ChioReceipt = serde_json::from_slice(source_evidence.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
            (
                canonical_json_bytes(&receipt).map_err(|_| PortError::invalid_data())?,
                RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN,
            )
        }
    };
    let mut preimage = Vec::with_capacity(domain.len() + canonical_source.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical_source);
    if canonical_source.as_slice() != source_evidence.as_bytes()
        || body_hash(&preimage).as_slice() != expected_hash.as_bytes()
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

type StoredCorrelationIngress = (
    String,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn load_correlation_ingress(
    connection: &Connection,
    tenant_id: &TenantId,
    event_id: &EventId,
) -> PortResult<Option<StoredCorrelationIngress>> {
    connection
        .query_row(
            r#"
            SELECT producer_id, event_time, received_at, body, body_hash,
                   source_evidence, evidence_hash, acknowledged
            FROM security_correlation_ingress
            WHERE tenant_id = ?1 AND event_id = ?2
            "#,
            params![tenant_id.as_str(), event_id.as_str()],
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
        .map_err(sqlite_error)
}

fn validate_stored_correlation_ingress(
    stored: &StoredCorrelationIngress,
    event: &UnverifiedSecurityEvent,
    evidence_hash: &Digest32,
) -> PortResult<bool> {
    let stored_body_hash = decode_digest(stored.4.clone())?;
    let stored_body =
        CanonicalBody::new(stored.3.clone()).map_err(|_| PortError::integrity_failure())?;
    validate_canonical_json_body(&stored_body, &stored_body_hash)
        .map_err(|_| PortError::integrity_failure())?;
    let stored_source =
        CanonicalBody::new(stored.5.clone()).map_err(|_| PortError::integrity_failure())?;
    let source_value: serde_json::Value = serde_json::from_slice(stored_source.as_bytes())
        .map_err(|_| PortError::integrity_failure())?;
    let canonical_source =
        canonical_json_bytes(&source_value).map_err(|_| PortError::integrity_failure())?;
    if canonical_source.as_slice() != stored_source.as_bytes()
        || stored.0 != event.producer_id.as_str()
        || from_i64(stored.1)? != event.event_time_unix_ms
        || from_i64(stored.2)? != event.received_at_unix_ms
        || stored_body != event.canonical_body
        || stored_body_hash != event.body_hash
        || stored_source != event.source_evidence
        || decode_digest(stored.6.clone())? != *evidence_hash
    {
        return Err(PortError::conflict());
    }
    match stored.7 {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PortError::integrity_failure()),
    }
}

impl CorrelationIngressStore for SqliteSecurityStateStore {
    fn ensure_correlation_ingress_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        validate_correlation_durable_schema(&connection)?;
        let invalid: bool = connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM security_correlation_ingress AS ingress
                    LEFT JOIN security_verified_events AS events
                      ON events.tenant_id = ingress.tenant_id
                     AND events.event_id = ingress.event_id
                    WHERE events.event_id IS NULL
                       OR ingress.producer_id != events.producer_id
                       OR ingress.event_time != events.event_time
                       OR ingress.received_at != events.received_at
                       OR ingress.body != events.body
                       OR ingress.body_hash != events.body_hash
                       OR ingress.evidence_hash != events.evidence_hash
                       OR ingress.acknowledged NOT IN (0, 1)
                )
                "#,
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if invalid {
            return Err(PortError::integrity_failure());
        }
        let mut statement = connection
            .prepare(
                r#"
                SELECT events.trust_class, ingress.source_evidence,
                       ingress.evidence_hash
                FROM security_correlation_ingress AS ingress
                INNER JOIN security_verified_events AS events
                  ON events.tenant_id = ingress.tenant_id
                 AND events.event_id = ingress.event_id
                ORDER BY ingress.sequence
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(sqlite_error)?;
        for row in rows {
            let (trust_class, source_evidence, evidence_hash) = row.map_err(sqlite_error)?;
            let source_evidence = CanonicalBody::new(source_evidence)
                .map_err(|_| PortError::integrity_failure())?;
            validate_correlation_source_evidence(
                parse_trust_class(&trust_class)?,
                &source_evidence,
                &decode_digest(evidence_hash)?,
            )
            .map_err(|_| PortError::integrity_failure())?;
        }
        drop(statement);
        let mut outcome_statement = connection
            .prepare(
                r#"
                SELECT tenant_id, rule_id, event_id
                FROM security_correlation_outcomes
                ORDER BY tenant_id, rule_id, event_id
                "#,
            )
            .map_err(sqlite_error)?;
        let outcome_keys = outcome_statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sqlite_error)?;
        for row in outcome_keys {
            let (tenant_id, rule_id, event_id) = row.map_err(sqlite_error)?;
            let key = CorrelationOutcomeKey {
                tenant_id: TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                rule_id: RuleId::new(rule_id).map_err(|_| PortError::integrity_failure())?,
                event_id: EventId::new(event_id).map_err(|_| PortError::integrity_failure())?,
            };
            if load_correlation_outcome_record(&connection, &key)?.is_none() {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(())
    }

    fn enqueue_verified_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<EventAppend> {
        validate_correlation_ingress_binding(event, verified)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let append = append_verified_in_transaction(&transaction, verified)?;
        if let Some(stored) =
            load_correlation_ingress(&transaction, &event.tenant_id, &event.event_id)?
        {
            validate_stored_correlation_ingress(&stored, event, &verified.evidence_hash)?;
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO security_correlation_ingress (
                        tenant_id, event_id, producer_id, event_time, received_at,
                        body, body_hash, source_evidence, evidence_hash, acknowledged
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)
                    "#,
                    params![
                        event.tenant_id.as_str(),
                        event.event_id.as_str(),
                        event.producer_id.as_str(),
                        to_i64(event.event_time_unix_ms)?,
                        to_i64(event.received_at_unix_ms)?,
                        event.canonical_body.as_bytes(),
                        event.body_hash.as_bytes().as_slice(),
                        event.source_evidence.as_bytes(),
                        verified.evidence_hash.as_bytes().as_slice(),
                    ],
                )
                .map_err(sqlite_error)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(append)
    }

    fn load_pending_correlation_events(
        &self,
        max_results: u32,
    ) -> PortResult<UnverifiedEventBatch> {
        if max_results == 0 || max_results > MAX_EVENT_SCAN_RESULTS {
            return Err(PortError::invalid_data());
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT tenant_id, event_id, producer_id, event_time, received_at,
                       body, body_hash, source_evidence, evidence_hash, acknowledged
                FROM security_correlation_ingress
                WHERE acknowledged = 0
                ORDER BY event_time, sequence
                LIMIT ?1
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![i64::from(max_results)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(sqlite_error)?;
        let mut events = Vec::new();
        for row in rows {
            let (
                tenant_id,
                event_id,
                producer_id,
                event_time,
                received_at,
                body,
                body_hash,
                source_evidence,
                evidence_hash,
                acknowledged,
            ) = row.map_err(sqlite_error)?;
            let stored = (
                producer_id.clone(),
                event_time,
                received_at,
                body.clone(),
                body_hash.clone(),
                source_evidence.clone(),
                evidence_hash.clone(),
                acknowledged,
            );
            let event = UnverifiedSecurityEvent {
                tenant_id: TenantId::new(tenant_id)
                    .map_err(|_| PortError::integrity_failure())?,
                event_id: EventId::new(event_id).map_err(|_| PortError::integrity_failure())?,
                producer_id: ProducerId::new(producer_id)
                    .map_err(|_| PortError::integrity_failure())?,
                event_time_unix_ms: from_i64(event_time)?,
                received_at_unix_ms: from_i64(received_at)?,
                canonical_body: CanonicalBody::new(body)
                    .map_err(|_| PortError::integrity_failure())?,
                body_hash: decode_digest(body_hash)?,
                source_evidence: CanonicalBody::new(source_evidence)
                    .map_err(|_| PortError::integrity_failure())?,
            };
            if validate_stored_correlation_ingress(
                &stored,
                &event,
                &decode_digest(evidence_hash)?,
            )? {
                return Err(PortError::integrity_failure());
            }
            events.push(event);
        }
        UnverifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())
    }

    fn validate_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<()> {
        validate_correlation_ingress_binding(event, verified)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if append_verified_in_transaction(&transaction, verified)? != EventAppend::Duplicate {
            return Err(PortError::integrity_failure());
        }
        let stored = load_correlation_ingress(&transaction, &event.tenant_id, &event.event_id)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_stored_correlation_ingress(&stored, event, &verified.evidence_hash)?;
        transaction.commit().map_err(sqlite_error)
    }

    fn acknowledge_correlated_event(&self, event: &UnverifiedSecurityEvent) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let stored = load_correlation_ingress(&transaction, &event.tenant_id, &event.event_id)?
            .ok_or_else(PortError::integrity_failure)?;
        let evidence_hash = decode_digest(stored.6.clone())?;
        let acknowledged = validate_stored_correlation_ingress(&stored, event, &evidence_hash)?;
        if !acknowledged {
            let updated = transaction
                .execute(
                    r#"
                    UPDATE security_correlation_ingress
                    SET acknowledged = 1
                    WHERE tenant_id = ?1 AND event_id = ?2 AND acknowledged = 0
                    "#,
                    params![event.tenant_id.as_str(), event.event_id.as_str()],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(PortError::conflict());
            }
        }
        transaction.commit().map_err(sqlite_error)
    }

    fn count_pending_correlation_events(&self) -> PortResult<u64> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM security_correlation_ingress WHERE acknowledged = 0",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        from_i64(count)
    }
}

fn scan_verified_partition(
    connection: &Connection,
    scan: &EventPartitionScan,
) -> PortResult<(VerifiedEventBatch, bool)> {
    if scan.max_results == 0
        || scan.max_results > MAX_EVENT_SCAN_RESULTS
        || scan.after_event_id.is_some() && scan.after_event_time_unix_ms.is_none()
        || scan
            .after_event_time_unix_ms
            .is_some_and(|after| scan.through_event_time_unix_ms < after)
    {
        return Err(PortError::invalid_data());
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT events.event_id, events.producer_id, events.trust_class,
                   events.event_time, events.received_at, events.body,
                   events.body_hash, events.evidence_hash
            FROM security_correlation_events AS correlation
            INNER JOIN security_verified_events AS events
                ON events.tenant_id = correlation.tenant_id
               AND events.event_id = correlation.event_id
            WHERE correlation.tenant_id = ?1 AND correlation.rule_id = ?2
              AND correlation.partition_hash = ?3
              AND (
                  ?4 IS NULL
                  OR (?4 IS NOT NULL AND ?5 IS NULL AND events.event_time > ?4)
                  OR (
                      ?4 IS NOT NULL AND ?5 IS NOT NULL
                      AND (
                          events.event_time > ?4
                          OR (events.event_time = ?4 AND events.event_id > ?5)
                      )
                  )
              )
              AND events.event_time <= ?6
            ORDER BY events.event_time, events.event_id
            LIMIT ?7
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                scan.tenant_id.as_str(),
                scan.rule_id.as_str(),
                scan.partition_hash.as_bytes().as_slice(),
                scan.after_event_time_unix_ms.map(to_i64).transpose()?,
                scan.after_event_id.as_ref().map(EventId::as_str),
                to_i64(scan.through_event_time_unix_ms)?,
                i64::from(scan.max_results) + 1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut events = Vec::new();
    for row in rows {
        let (event_id, producer_id, trust_class, event_time, received_at, body, hash, evidence) =
            row.map_err(sqlite_error)?;
        let body_hash = decode_digest(hash)?;
        let canonical_body =
            CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
        validate_canonical_json_body(&canonical_body, &body_hash)
            .map_err(|_| PortError::integrity_failure())?;
        events.push(VerifiedSecurityEvent {
            tenant_id: scan.tenant_id.clone(),
            event_id: EventId::new(event_id).map_err(|_| PortError::integrity_failure())?,
            producer_id: ProducerId::new(producer_id)
                .map_err(|_| PortError::integrity_failure())?,
            trust_class: parse_trust_class(&trust_class)?,
            event_time_unix_ms: from_i64(event_time)?,
            received_at_unix_ms: from_i64(received_at)?,
            canonical_body,
            body_hash,
            evidence_hash: decode_digest(evidence)?,
        });
    }
    let truncated = events.len() > scan.max_results as usize;
    if truncated {
        events.pop();
    }
    let events = VerifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())?;
    Ok((events, truncated))
}

fn load_correlation_partition_generation(
    connection: &Connection,
    key: &CorrelationPartitionKey,
) -> PortResult<u64> {
    let generation: Option<i64> = connection
        .query_row(
            r#"
            SELECT generation FROM security_correlation_partition_heads
            WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(generation.map(from_i64).transpose()?.unwrap_or(0))
}

fn bump_correlation_partition_head(
    connection: &Connection,
    key: &CorrelationPartitionKey,
) -> PortResult<u64> {
    let next = load_correlation_partition_generation(connection, key)?
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    connection
        .execute(
            r#"
            INSERT INTO security_correlation_partition_heads (
                tenant_id, rule_id, partition_hash, generation
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, rule_id, partition_hash) DO UPDATE SET
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice(),
                to_i64(next)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn load_event_identity(
    connection: &Connection,
    tenant_id: &str,
    event_id: &str,
) -> PortResult<Option<(String, String, Vec<u8>)>> {
    connection
        .query_row(
            "SELECT tenant_id, event_class, body_hash FROM security_event_ids WHERE tenant_id = ?1 AND event_id = ?2",
            params![tenant_id, event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn insert_event_identity(
    connection: &Connection,
    event_id: &str,
    tenant_id: &str,
    event_class: &str,
    hash: &Digest32,
) -> PortResult<()> {
    connection
        .execute(
            "INSERT INTO security_event_ids (event_id, tenant_id, event_class, body_hash) VALUES (?1, ?2, ?3, ?4)",
            params![event_id, tenant_id, event_class, hash.as_bytes().as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredCorrelation = (i64, i64, i64, Vec<u8>, Vec<u8>);

fn load_correlation_partial(
    connection: &Connection,
    key: &CorrelationPartitionKey,
) -> PortResult<Option<CorrelationPartial>> {
    let stored: Option<StoredCorrelation> = connection
        .query_row(
            r#"
            SELECT generation, watermark, expires_at, body, body_hash
            FROM security_correlation_partials
            WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice()
            ],
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
    stored
        .map(|(generation, watermark, expires_at, body, stored_hash)| {
            let body_hash = decode_digest(stored_hash)?;
            let canonical_body =
                CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&canonical_body, &body_hash)
                .map_err(|_| PortError::integrity_failure())?;
            Ok(CorrelationPartial {
                key: key.clone(),
                generation: from_i64(generation)?,
                watermark_unix_ms: from_i64(watermark)?,
                expires_at_unix_ms: from_i64(expires_at)?,
                canonical_body,
                body_hash,
            })
        })
        .transpose()
}

fn validate_attested_finding_batch_publication(
    publication: &AttestedFindingBatchPublication,
) -> PortResult<()> {
    validate_attested_finding_batch_body(&publication.body)?;
    validate_canonical_json_body(&publication.canonical_body, &publication.body_hash)?;
    let expected =
        canonical_json_bytes(&publication.body).map_err(|_| PortError::invalid_data())?;
    if expected.as_slice() != publication.canonical_body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn load_attested_finding_batch_record(
    connection: &Connection,
    key: &AttestedFindingBatchKey,
) -> PortResult<Option<AttestedFindingBatchPublication>> {
    let stored: Option<(String, i64, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            r#"
            SELECT tenant_id, item_count, body, body_hash
            FROM security_attested_finding_batches
            WHERE tenant_id = ?1 AND batch_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.batch_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((tenant_id, item_count, body, body_hash)) = stored else {
        return Ok(None);
    };
    let body_hash = decode_digest(body_hash)?;
    let canonical_body = CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
    let body: AttestedFindingBatchBody = serde_json::from_slice(canonical_body.as_bytes())
        .map_err(|_| PortError::integrity_failure())?;
    let publication = AttestedFindingBatchPublication {
        body,
        canonical_body,
        body_hash,
    };
    validate_attested_finding_batch_publication(&publication)
        .map_err(|_| PortError::integrity_failure())?;
    let expected_item_count = u64::try_from(publication.body.bindings.len())
        .map_err(|_| PortError::integrity_failure())?;
    if publication.body.tenant_id != key.tenant_id
        || publication.body.batch_id != key.batch_id
        || publication.body.tenant_id.as_str() != tenant_id
        || from_i64(item_count)? != expected_item_count
    {
        return Err(PortError::integrity_failure());
    }

    type StoredBinding = (i64, String, String, String, Vec<u8>, String, String);
    let mut statement = connection
        .prepare(
            r#"
            SELECT ordinal, tenant_id, evidence_id, finding_id, finding_hash,
                   action_id, reservation_id
            FROM security_attested_finding_batch_items
            WHERE tenant_id = ?1 AND batch_id = ?2
            ORDER BY ordinal ASC
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![key.tenant_id.as_str(), key.batch_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let stored_bindings = rows
        .collect::<Result<Vec<StoredBinding>, _>>()
        .map_err(sqlite_error)?;
    if stored_bindings.len() != publication.body.bindings.len() {
        return Err(PortError::integrity_failure());
    }
    for (expected_ordinal, (stored, expected)) in stored_bindings
        .iter()
        .zip(publication.body.bindings.as_slice())
        .enumerate()
    {
        let expected_ordinal =
            u64::try_from(expected_ordinal).map_err(|_| PortError::integrity_failure())?;
        if from_i64(stored.0)? != expected_ordinal
            || stored.1 != expected.tenant_id.as_str()
            || stored.2 != expected.evidence_id.as_str()
            || stored.3 != expected.finding_id.as_str()
            || decode_digest(stored.4.clone())? != expected.finding_hash
            || stored.5 != expected.action_id.as_str()
            || stored.6 != expected.reservation_id.as_str()
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(Some(publication))
}

fn validate_attested_response_execution_dispatch(
    connection: &Connection,
    tenant_id: &TenantId,
    action_id: &ActionId,
    dispatch_id: &RecordId,
) -> PortResult<()> {
    let stored_dispatch_id: Option<Option<String>> = connection
        .query_row(
            r#"
            SELECT execution_dispatch_id
            FROM security_attested_finding_response_outbox
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id.as_str(), action_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(stored_dispatch_id) = stored_dispatch_id else {
        return Ok(());
    };
    if stored_dispatch_id.as_deref() != Some(dispatch_id.as_str()) {
        return Err(PortError::conflict());
    }
    Ok(())
}

impl AttestedFindingBatchStore for SqliteSecurityStateStore {
    fn ensure_attested_finding_batches_ready(&self) -> PortResult<()> {
        let connection = self.connection()?;
        validate_attested_finding_batch_tenant_keys(&connection)?;
        for statement in [
            "SELECT COUNT(*) FROM security_attested_finding_batches WHERE 0",
            "SELECT COUNT(*) FROM security_attested_finding_batch_items WHERE 0",
        ] {
            connection
                .query_row(statement, [], |row| row.get::<_, i64>(0))
                .map_err(sqlite_error)?;
        }
        Ok(())
    }

    fn publish_attested_finding_batch(
        &self,
        publication: &AttestedFindingBatchPublication,
    ) -> PortResult<CreateOutcome> {
        validate_attested_finding_batch_publication(publication)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let key = AttestedFindingBatchKey {
            tenant_id: publication.body.tenant_id.clone(),
            batch_id: publication.body.batch_id.clone(),
        };
        if let Some(existing) = load_attested_finding_batch_record(&transaction, &key)? {
            if existing != *publication {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_attested_finding_batches (
                    batch_id, tenant_id, item_count, body, body_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    publication.body.batch_id.as_str(),
                    publication.body.tenant_id.as_str(),
                    to_i64(
                        u64::try_from(publication.body.bindings.len())
                            .map_err(|_| PortError::invalid_data())?
                    )?,
                    publication.canonical_body.as_bytes(),
                    publication.body_hash.as_bytes().as_slice(),
                ],
            )
            .map_err(sqlite_error)?;
        for (ordinal, binding) in publication.body.bindings.as_slice().iter().enumerate() {
            let ordinal = u64::try_from(ordinal).map_err(|_| PortError::invalid_data())?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_attested_finding_batch_items (
                        batch_id, ordinal, tenant_id, evidence_id, finding_id,
                        finding_hash, action_id, reservation_id
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        publication.body.batch_id.as_str(),
                        to_i64(ordinal)?,
                        binding.tenant_id.as_str(),
                        binding.evidence_id.as_str(),
                        binding.finding_id.as_str(),
                        binding.finding_hash.as_bytes().as_slice(),
                        binding.action_id.as_str(),
                        binding.reservation_id.as_str(),
                    ],
                )
                .map_err(sqlite_error)?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_attested_finding_response_outbox (
                        tenant_id, batch_id, ordinal, evidence_id, finding_id,
                        finding_hash, action_id, reservation_id, planning_state,
                        admission_state, completion_state
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                              'pending', 'pending', 'not_started')
                    "#,
                    params![
                        binding.tenant_id.as_str(),
                        publication.body.batch_id.as_str(),
                        to_i64(ordinal)?,
                        binding.evidence_id.as_str(),
                        binding.finding_id.as_str(),
                        binding.finding_hash.as_bytes().as_slice(),
                        binding.action_id.as_str(),
                        binding.reservation_id.as_str(),
                    ],
                )
                .map_err(sqlite_error)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn load_attested_finding_batch(
        &self,
        key: &AttestedFindingBatchKey,
    ) -> PortResult<Option<AttestedFindingBatchPublication>> {
        let connection = self.connection()?;
        load_attested_finding_batch_record(&connection, key)
    }
}
