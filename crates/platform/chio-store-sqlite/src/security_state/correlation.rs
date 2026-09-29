use super::*;


pub(super) fn correlation_outcome_status_name(value: CorrelationOutcomeStatus) -> &'static str {
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

pub(super) fn parse_correlation_outcome_status(value: &str) -> PortResult<CorrelationOutcomeStatus> {
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

pub(super) fn index_partition_event_in_transaction(
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

pub(super) fn compare_and_swap_correlation_in_transaction(
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

pub(super) fn validate_correlation_outcome_publication(
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

pub(super) type CorrelationOutcomeStorageRow = (
    Vec<u8>,
    String,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn load_correlation_outcome_record(
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

pub(super) fn insert_correlation_outcome_record(
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

pub(super) fn validate_correlation_outcome_storage_binding(
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
            params![
                outcome.key.tenant_id.as_str(),
                outcome.key.event_id.as_str()
            ],
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

pub(super) fn validate_correlation_ingress_binding(
    event: &UnverifiedSecurityEvent,
    verified: &SecurityEventVerificationRecord,
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

pub(super) fn validate_correlation_source_evidence(
    trust_class: ProducerTrustClass,
    source_evidence: &CanonicalBody,
    expected_hash: &Digest32,
) -> PortResult<()> {
    let (canonical_source, domain) = match trust_class {
        ProducerTrustClass::InternalDetector => {
            let signed: SignedSecurityEvent = chio_core::canonical::UntrustedJsonText::from_wire(
                source_evidence.as_bytes(),
                64 * 1024 * 1024,
            )
            .and_then(|input| input.decode_signed())
            .map_err(|_| PortError::invalid_data())?;
            (
                canonical_json_bytes(&signed).map_err(|_| PortError::invalid_data())?,
                EVENT_EVIDENCE_HASH_DOMAIN,
            )
        }
        ProducerTrustClass::VerifiedReceipt => {
            let receipt: ChioReceipt = chio_core::canonical::UntrustedJsonText::from_wire(
                source_evidence.as_bytes(),
                64 * 1024 * 1024,
            )
            .and_then(|input| input.decode_signed())
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

pub(super) type StoredCorrelationIngress = (String, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

pub(super) fn load_correlation_ingress(
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

pub(super) fn validate_stored_correlation_ingress(
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
    let source_value: serde_json::Value = chio_core::canonical::UntrustedJsonText::from_wire(
        stored_source.as_bytes(),
        64 * 1024 * 1024,
    )
    .and_then(|input| input.decode_signed())
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
            let source_evidence =
                CanonicalBody::new(source_evidence).map_err(|_| PortError::integrity_failure())?;
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
                tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
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
        verified: &SecurityEventVerificationRecord,
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
                tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
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
            if validate_stored_correlation_ingress(&stored, &event, &decode_digest(evidence_hash)?)?
            {
                return Err(PortError::integrity_failure());
            }
            events.push(event);
        }
        UnverifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())
    }

    fn validate_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &SecurityEventVerificationRecord,
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

pub(super) fn load_correlation_partition_generation(
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

pub(super) fn bump_correlation_partition_head(
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

pub(super) type StoredCorrelation = (i64, i64, i64, Vec<u8>, Vec<u8>);

pub(super) fn load_correlation_partial(
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
