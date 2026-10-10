#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    canonical_json_bytes, decode_digest, from_i64, params, sqlite_error, to_i64,
    validate_attested_finding_batch_body, validate_attested_finding_batch_tenant_keys,
    validate_canonical_json_body, ActionId, AttestedFindingBatchBody, AttestedFindingBatchKey,
    AttestedFindingBatchPublication, AttestedFindingBatchStore, CanonicalBody, Connection,
    CreateOutcome, OptionalExtension, PortError, PortResult, RecordId, SqliteSecurityStateStore,
    TenantId, TransactionBehavior,
};

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

pub(super) fn load_attested_finding_batch_record(
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
    let body: AttestedFindingBatchBody = chio_core::canonical::UntrustedJsonText::from_wire(
        canonical_body.as_bytes(),
        64 * 1024 * 1024,
    )
    .and_then(|input| input.decode_signed())
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

pub(super) fn validate_attested_response_execution_dispatch(
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
