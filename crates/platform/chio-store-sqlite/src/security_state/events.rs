#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    canonical_request_hash, compare_and_swap_correlation_in_transaction, decode_digest, from_i64,
    index_partition_event_in_transaction, insert_correlation_outcome_record,
    load_correlation_outcome_record, load_correlation_partial,
    load_correlation_partition_generation, params, record_transition, sqlite_error, to_i64,
    transition_status, validate_canonical_json_body, validate_correlation_outcome_publication,
    validate_correlation_outcome_storage_binding, AdvisorySecurityEvent, CanonicalBody, Connection,
    CorrelationCasRequest, CorrelationDeleteRequest, CorrelationEventAdmission,
    CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationOutcomeCommitRequest, CorrelationOutcomeKey, CorrelationOutcomePublication,
    CorrelationPartial, CorrelationPartitionKey, CorrelationScan, CreateOutcome, Digest32,
    EventAppend, EventId, EventPartitionScan, OptionalExtension, PortError, PortResult, ProducerId,
    ProducerTrustClass, SecurityEventStore, SecurityEventVerificationRecord,
    SqliteSecurityStateStore, TransactionBehavior, VerifiedEventBatch,
};

pub(super) const MAX_EVENT_SCAN_RESULTS: u32 = 4_096;
pub(super) const EVENT_EVIDENCE_HASH_DOMAIN: &[u8] = b"chio.verified-security-event-evidence.v1\0";
pub(super) const RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN: &[u8] =
    b"chio.verified-security-event-receipt-evidence.v1\0";

fn trust_class_name(value: ProducerTrustClass) -> &'static str {
    match value {
        ProducerTrustClass::InternalDetector => "internal_detector",
        ProducerTrustClass::VerifiedReceipt => "verified_receipt",
    }
}

pub(super) fn parse_trust_class(value: &str) -> PortResult<ProducerTrustClass> {
    match value {
        "internal_detector" => Ok(ProducerTrustClass::InternalDetector),
        "verified_receipt" => Ok(ProducerTrustClass::VerifiedReceipt),
        _ => Err(PortError::integrity_failure()),
    }
}

pub(super) fn append_verified_in_transaction(
    connection: &Connection,
    event: &SecurityEventVerificationRecord,
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

    fn append_verified(&self, event: &SecurityEventVerificationRecord) -> PortResult<EventAppend> {
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
            || request.outcome.partition_hash != request.correlation.partial.key.partition_hash
            || request.correlation.partial.key.partition_hash
                != request.correlation.scan.partition_hash
        {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_correlation_outcome_record(&transaction, &request.outcome.key)?
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
        let partial =
            compare_and_swap_correlation_in_transaction(&transaction, &request.correlation)?;
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

pub(super) fn scan_verified_partition(
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
        events.push(SecurityEventVerificationRecord {
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
    let truncated = events.len() > crate::integer::checked::<_, usize>(scan.max_results)?;
    if truncated {
        events.pop();
    }
    let events = VerifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())?;
    Ok((events, truncated))
}

pub(super) fn load_event_identity(
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
