fn load_flow_snapshot(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<FlowStateSnapshot>> {
    let epoch_exists = isolation_epoch_exists(connection, key)?;
    let principal = load_principal_label(connection, key)?;
    let lineage = load_lineage_label(connection, key)?;
    let session = load_session_label(connection, key)?;
    let session_membership = session_membership_exists(connection, key)?;
    let context_generation = load_context_generation(connection, key)?;
    if !epoch_exists {
        if principal.is_some()
            || session.is_some()
            || session_membership
            || context_generation.is_some()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(None);
    }
    if session.is_some() != session_membership {
        return Err(PortError::integrity_failure());
    }
    let (principal_label, principal_generation) =
        principal.ok_or_else(PortError::integrity_failure)?;
    let (lineage_label, lineage_generation) = lineage.ok_or_else(PortError::integrity_failure)?;
    let Some(context_generation) = context_generation else {
        if session.is_some() {
            return Err(PortError::integrity_failure());
        }
        let session_label = principal_label
            .join_restrictions(&lineage_label)
            .map_err(|_| PortError::integrity_failure())?;
        return Ok(Some(FlowStateSnapshot {
            key: key.clone(),
            principal_label,
            lineage_label,
            session_label,
            context_generation: principal_generation.max(lineage_generation),
        }));
    };
    let (stored_session_label, session_generation) =
        session.ok_or_else(PortError::integrity_failure)?;
    if principal_generation > context_generation
        || lineage_generation > context_generation
        || session_generation > context_generation
    {
        return Err(PortError::integrity_failure());
    }
    let session_label = stored_session_label
        .join_restrictions(&principal_label)
        .and_then(|label| label.join_restrictions(&lineage_label))
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Some(FlowStateSnapshot {
        key: key.clone(),
        principal_label,
        lineage_label,
        session_label,
        context_generation,
    }))
}

fn next_flow_generation(transaction: &Transaction<'_>, tenant_id: &str) -> PortResult<u64> {
    let sequence_generation: Option<i64> = transaction
        .query_row(
            "SELECT last_generation FROM security_flow_sequences WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored_generation: Option<i64> = transaction
        .query_row(
            r#"
            SELECT MAX(generation) FROM (
                SELECT generation FROM security_principal_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_lineage_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_session_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_flow_contexts WHERE tenant_id = ?1
            )
            "#,
            params![tenant_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = sequence_generation
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(stored_generation.map(from_i64).transpose()?.unwrap_or(0));
    let next = current
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_flow_sequences (tenant_id, last_generation)
            VALUES (?1, ?2)
            ON CONFLICT (tenant_id) DO UPDATE SET last_generation = excluded.last_generation
            "#,
            params![tenant_id, to_i64(next)?],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn invalidate_related_flow_contexts(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    generation: u64,
    principal_changed: bool,
    lineage_changed: bool,
    session_changed: bool,
) -> PortResult<()> {
    let generation = to_i64(generation)?;
    if principal_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?4
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    if lineage_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?3
                WHERE tenant_id = ?1 AND lineage_id = ?2
                "#,
                params![key.tenant_id.as_str(), key.lineage_id.as_str(), generation],
            )
            .map_err(sqlite_error)?;
    }
    if session_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?5
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.session_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn store_principal_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_principal_flow_state (
                tenant_id, principal_id, isolation_epoch_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (tenant_id, principal_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_lineage_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_lineage_flow_state (
                tenant_id, lineage_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (tenant_id, lineage_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_session_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_session_memberships (
                tenant_id, principal_id, session_id, isolation_epoch_id
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO NOTHING
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_session_flow_state (
                tenant_id, principal_id, session_id, isolation_epoch_id,
                label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_context_generation(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    generation: u64,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_flow_contexts (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
            )
            DO UPDATE SET generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn ensure_epoch_for_join(
    transaction: &Transaction<'_>,
    request: &FlowJoinRequest,
) -> PortResult<()> {
    let exact: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.lineage_id.as_str(),
                request.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if exact {
        if load_principal_label(transaction, &request.key)?.is_none()
            || load_lineage_label(transaction, &request.key)?.is_none()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(());
    }

    let principal_epoch_exists: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            )
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if principal_epoch_exists {
        if load_principal_label(transaction, &request.key)?.is_none() {
            return Err(PortError::integrity_failure());
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                )
                SELECT tenant_id, principal_id, ?3, isolation_epoch_id,
                       previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                       evidence_receipt_ref, ?5, effective_at
                FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?4
                ORDER BY lineage_id
                LIMIT 1
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.principal_id.as_str(),
                    request.key.lineage_id.as_str(),
                    request.key.isolation_epoch_id.as_str(),
                    request.transition_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(PortError::integrity_failure());
        }
        return Ok(());
    }
    let prior_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM security_isolation_epochs WHERE tenant_id = ?1 AND principal_id = ?2",
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if prior_count != 0 {
        return Err(PortError::invalid_data());
    }
    transaction
        .execute(
            r#"
            INSERT INTO security_isolation_epochs (
                tenant_id, principal_id, lineage_id, isolation_epoch_id,
                previous_isolation_epoch_id, evidence_hash, transition_id, effective_at
            ) VALUES (?1, ?2, ?3, ?4, NULL, zeroblob(32), ?5, 0)
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.lineage_id.as_str(),
                request.key.isolation_epoch_id.as_str(),
                request.transition_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

impl FlowStateStore for SqliteSecurityStateStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let connection = self.connection()?;
        load_flow_snapshot(&connection, key)
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "flow_join",
            &request_hash,
        )? {
            let snapshot = load_flow_snapshot(&transaction, &request.key)?
                .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        ensure_epoch_for_join(&transaction, request)?;
        let principal_stored = load_principal_label(&transaction, &request.key)?;
        let lineage_stored = load_lineage_label(&transaction, &request.key)?;
        let session_stored = load_session_label(&transaction, &request.key)?;
        let session_membership = session_membership_exists(&transaction, &request.key)?;
        let context_stored = load_context_generation(&transaction, &request.key)?;
        if session_stored.is_some() != session_membership
            || context_stored.is_some()
                && (principal_stored.is_none()
                    || lineage_stored.is_none()
                    || session_stored.is_none())
        {
            return Err(PortError::integrity_failure());
        }
        let principal_current = principal_stored
            .as_ref()
            .map(|value| value.0.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let lineage_current = lineage_stored
            .as_ref()
            .map(|value| value.0.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let session_current = match session_stored.as_ref() {
            Some(value) => value.0.clone(),
            None => principal_current
                .join_restrictions(&lineage_current)
                .map_err(|_| PortError::invalid_data())?,
        };
        let principal_label = principal_current
            .join_restrictions(&request.principal_join)
            .map_err(|_| PortError::invalid_data())?;
        let lineage_label = lineage_current
            .join_restrictions(&request.lineage_join)
            .map_err(|_| PortError::invalid_data())?;
        let session_label = session_current
            .join_restrictions(&request.session_join)
            .and_then(|label| label.join_restrictions(&principal_label))
            .and_then(|label| label.join_restrictions(&lineage_label))
            .map_err(|_| PortError::invalid_data())?;
        let principal_changed = principal_label != principal_current;
        let lineage_changed = lineage_label != lineage_current;
        let session_changed = session_label != session_current;
        let generation = next_flow_generation(&transaction, request.key.tenant_id.as_str())?;
        invalidate_related_flow_contexts(
            &transaction,
            &request.key,
            generation,
            principal_changed,
            lineage_changed,
            session_changed,
        )?;
        if principal_stored.is_none() || principal_changed {
            store_principal_label(&transaction, &request.key, &principal_label, generation)?;
        }
        if lineage_stored.is_none() || lineage_changed {
            store_lineage_label(&transaction, &request.key, &lineage_label, generation)?;
        }
        if session_stored.is_none() || session_changed {
            store_session_label(&transaction, &request.key, &session_label, generation)?;
        }
        store_context_generation(&transaction, &request.key, generation)?;
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "flow_join",
            &request_hash,
        )?;
        let snapshot = FlowStateSnapshot {
            key: request.key.clone(),
            principal_label,
            lineage_label,
            session_label,
            context_generation: generation,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot> {
        if transition.previous_isolation_epoch_id == transition.new_isolation_epoch_id
            || transition
                .verification_evidence_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(transition)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            transition.tenant_id.as_str(),
            transition.transition_id.as_str(),
            "isolation_epoch",
            &request_hash,
        )? {
            let key = FlowStateKey {
                tenant_id: transition.tenant_id.clone(),
                principal_id: transition.principal_id.clone(),
                lineage_id: transition.lineage_id.clone(),
                session_id: transition.new_session_id.clone(),
                isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            };
            let snapshot =
                load_flow_snapshot(&transaction, &key)?.ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        let verified_evidence = self.isolation_epoch_verifier.verify(transition)?;
        let prior_key = FlowStateKey {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            lineage_id: transition.lineage_id.clone(),
            session_id: transition.new_session_id.clone(),
            isolation_epoch_id: transition.previous_isolation_epoch_id.clone(),
        };
        if load_principal_label(&transaction, &prior_key)?.is_none() {
            return Err(PortError::invalid_data());
        }
        let key = FlowStateKey {
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            ..prior_key
        };
        if load_principal_label(&transaction, &key)?.is_some() {
            return Err(PortError::conflict());
        }
        let lineage_label = load_lineage_label(&transaction, &key)?
            .map(|value| value.0)
            .ok_or_else(PortError::integrity_failure)?;
        let generation = next_flow_generation(&transaction, transition.tenant_id.as_str())?;
        let principal_label = InformationLabel::bottom();
        let session_label = lineage_label.clone();
        transaction
            .execute(
                r#"
                INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    transition.tenant_id.as_str(),
                    transition.principal_id.as_str(),
                    transition.lineage_id.as_str(),
                    transition.new_isolation_epoch_id.as_str(),
                    transition.previous_isolation_epoch_id.as_str(),
                    transition.verification_evidence_hash.as_bytes().as_slice(),
                    verified_evidence.verifier_id.as_str(),
                    verified_evidence.receipt_ref.as_str(),
                    transition.transition_id.as_str(),
                    to_i64(transition.effective_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        store_principal_label(&transaction, &key, &principal_label, generation)?;
        store_session_label(&transaction, &key, &session_label, generation)?;
        store_context_generation(&transaction, &key, generation)?;
        record_transition(
            &transaction,
            transition.tenant_id.as_str(),
            transition.transition_id.as_str(),
            "isolation_epoch",
            &request_hash,
        )?;
        let snapshot = FlowStateSnapshot {
            key,
            principal_label,
            lineage_label,
            session_label,
            context_generation: generation,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let snapshot =
            load_flow_snapshot(&transaction, &request.key)?.ok_or_else(PortError::invalid_data)?;
        if snapshot.context_generation != request.expected_context_generation
            || request.expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::conflict());
        }
        let fence_hash = canonical_request_hash(request)?;
        let fence_id = RecordId::new(format!("ef:{}", hex::encode(fence_hash)))
            .map_err(|_| PortError::invalid_data())?;
        let existing: Option<(String, Vec<u8>, i64, i64)> = transaction
            .query_row(
                "SELECT fence_id, request_hash, context_generation, expires_at FROM security_egress_fences WHERE tenant_id = ?1 AND request_id = ?2",
                params![request.key.tenant_id.as_str(), request.request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((stored_id, stored_hash, stored_generation, stored_expiry)) = existing {
            if stored_id != fence_id.as_str()
                || decode_digest(stored_hash)? != request.request_hash
                || from_i64(stored_generation)? != request.expected_context_generation
                || from_i64(stored_expiry)? != request.expires_at_unix_ms
            {
                return Err(PortError::conflict());
            }
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO security_egress_fences (
                        fence_id, tenant_id, principal_id, lineage_id, session_id,
                        isolation_epoch_id, request_id, request_hash, context_generation, expires_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                    params![
                        fence_id.as_str(),
                        request.key.tenant_id.as_str(),
                        request.key.principal_id.as_str(),
                        request.key.lineage_id.as_str(),
                        request.key.session_id.as_str(),
                        request.key.isolation_epoch_id.as_str(),
                        request.request_id.as_str(),
                        request.request_hash.as_bytes().as_slice(),
                        to_i64(request.expected_context_generation)?,
                        to_i64(request.expires_at_unix_ms)?
                    ],
                )
                .map_err(sqlite_error)?;
        }
        let fence = EgressFence {
            fence_id,
            key: request.key.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash,
            context_generation: request.expected_context_generation,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let trusted_now = self.trusted_now_unix_ms()?;
        let connection = self.connection()?;
        validate_fence(&connection, fence, trusted_now)
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        type StoredFenceCommitment = (
            String,
            String,
            String,
            String,
            String,
            Vec<u8>,
            i64,
            i64,
            Option<String>,
            Option<i64>,
        );
        let existing: Option<StoredFenceCommitment> = transaction
            .query_row(
                r#"
                SELECT principal_id, lineage_id, session_id, isolation_epoch_id, request_id,
                       request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at
                FROM security_egress_fences WHERE tenant_id = ?1 AND fence_id = ?2
                "#,
                params![
                    commitment.fence.key.tenant_id.as_str(),
                    commitment.fence.fence_id.as_str()
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
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let existing = existing.ok_or_else(PortError::invalid_data)?;
        if existing.0 != commitment.fence.key.principal_id.as_str()
            || existing.1 != commitment.fence.key.lineage_id.as_str()
            || existing.2 != commitment.fence.key.session_id.as_str()
            || existing.3 != commitment.fence.key.isolation_epoch_id.as_str()
            || existing.4 != commitment.fence.request_id.as_str()
            || decode_digest(existing.5.clone())? != commitment.fence.request_hash
            || from_i64(existing.6)? != commitment.fence.context_generation
            || from_i64(existing.7)? != commitment.fence.expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        if let Some(existing_id) = existing.8 {
            let existing_time = existing
                .9
                .ok_or_else(PortError::integrity_failure)
                .and_then(from_i64)?;
            if existing_id != commitment.dispatch_commitment_id.as_str()
                || existing_time != commitment.committed_at_unix_ms
            {
                return Err(PortError::conflict());
            }
            let committed = CommittedEgressFence {
                fence_id: commitment.fence.fence_id.clone(),
                request_id: commitment.fence.request_id.clone(),
                request_hash: commitment.fence.request_hash,
                context_generation: commitment.fence.context_generation,
                dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
                committed_at_unix_ms: commitment.committed_at_unix_ms,
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(committed);
        }
        if existing.9.is_some() {
            return Err(PortError::integrity_failure());
        }
        let trusted_now = self.trusted_now_unix_ms()?;
        validate_fence(&transaction, &commitment.fence, trusted_now)?;
        if commitment.committed_at_unix_ms > commitment.fence.expires_at_unix_ms
            || commitment.committed_at_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
        {
            return Err(PortError::invalid_data());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_egress_fences
                SET dispatch_commitment_id = ?2, committed_at = ?3
                WHERE fence_id = ?1 AND tenant_id = ?4
                  AND dispatch_commitment_id IS NULL
                "#,
                params![
                    commitment.fence.fence_id.as_str(),
                    commitment.dispatch_commitment_id.as_str(),
                    to_i64(commitment.committed_at_unix_ms)?,
                    commitment.fence.key.tenant_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let committed = CommittedEgressFence {
            fence_id: commitment.fence.fence_id.clone(),
            request_id: commitment.fence.request_id.clone(),
            request_hash: commitment.fence.request_hash,
            context_generation: commitment.fence.context_generation,
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
            committed_at_unix_ms: commitment.committed_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(committed)
    }
}

fn validate_fence(
    connection: &Connection,
    fence: &EgressFence,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    type StoredFence = (
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        i64,
        i64,
    );
    let stored: Option<StoredFence> = connection
        .query_row(
            r#"
            SELECT tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id,
                   request_id, request_hash, context_generation, expires_at
            FROM security_egress_fences WHERE tenant_id = ?1 AND fence_id = ?2
            "#,
            params![fence.key.tenant_id.as_str(), fence.fence_id.as_str()],
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
                    row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        tenant,
        principal,
        lineage,
        session,
        epoch,
        request,
        request_hash,
        generation,
        expiry,
    )) = stored
    else {
        return Err(PortError::invalid_data());
    };
    if tenant != fence.key.tenant_id.as_str()
        || principal != fence.key.principal_id.as_str()
        || lineage != fence.key.lineage_id.as_str()
        || session != fence.key.session_id.as_str()
        || epoch != fence.key.isolation_epoch_id.as_str()
        || request != fence.request_id.as_str()
        || decode_digest(request_hash)? != fence.request_hash
        || from_i64(generation)? != fence.context_generation
        || from_i64(expiry)? != fence.expires_at_unix_ms
        || fence.expires_at_unix_ms <= trusted_now_unix_ms
    {
        return Err(PortError::conflict());
    }
    let current =
        load_flow_snapshot(connection, &fence.key)?.ok_or_else(PortError::integrity_failure)?;
    if current.context_generation != fence.context_generation {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn declassification_state_name(state: DeclassificationUseState) -> &'static str {
    match state {
        DeclassificationUseState::ConsumedPendingDispatch => "consumed_pending_dispatch",
        DeclassificationUseState::Released => "released",
        DeclassificationUseState::DispatchFailed => "dispatch_failed",
        DeclassificationUseState::OutcomeUnknown => "outcome_unknown",
    }
}

fn parse_declassification_state(value: &str) -> PortResult<DeclassificationUseState> {
    match value {
        "consumed_pending_dispatch" => Ok(DeclassificationUseState::ConsumedPendingDispatch),
        "released" => Ok(DeclassificationUseState::Released),
        "dispatch_failed" => Ok(DeclassificationUseState::DispatchFailed),
        "outcome_unknown" => Ok(DeclassificationUseState::OutcomeUnknown),
        _ => Err(PortError::integrity_failure()),
    }
}

fn encode_declassification_binding(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<Vec<u8>> {
    let canonical = canonical_json_bytes(binding).map_err(|_| PortError::invalid_data())?;
    if canonical.len() > 4_096 {
        return Err(PortError::invalid_data());
    }
    Ok(canonical)
}

fn decode_declassification_binding(bytes: &[u8]) -> PortResult<DeclassificationTransitionBinding> {
    if bytes.len() > 4_096 {
        return Err(PortError::integrity_failure());
    }
    let binding = serde_json::from_slice::<DeclassificationTransitionBinding>(bytes)
        .map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&binding).map_err(|_| PortError::integrity_failure())?;
    if canonical != bytes {
        return Err(PortError::integrity_failure());
    }
    Ok(binding)
}

fn validate_declassification_binding_identity(
    binding: &DeclassificationTransitionBinding,
    tenant_id: &TenantId,
    grant_id: &GrantId,
    request_hash: Digest32,
    receipt: &ReceiptAppendRequest,
    event_id: &EventId,
) -> PortResult<()> {
    let transition_id = derive_declassification_transition_id(binding)?;
    let expected_event_id = derive_declassification_event_id(binding)?;
    if binding.tenant_id() != tenant_id
        || binding.grant_id() != grant_id
        || binding.request_hash() != request_hash
        || receipt.transition_id != transition_id
        || *event_id != expected_event_id
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn declassification_phase_name(phase: DeclassificationEvidencePhase) -> &'static str {
    match phase {
        DeclassificationEvidencePhase::Consumption => "consumption",
        DeclassificationEvidencePhase::Outcome => "outcome",
    }
}

fn parse_declassification_phase(value: &str) -> PortResult<DeclassificationEvidencePhase> {
    match value {
        "consumption" => Ok(DeclassificationEvidencePhase::Consumption),
        "outcome" => Ok(DeclassificationEvidencePhase::Outcome),
        _ => Err(PortError::integrity_failure()),
    }
}

fn decode_declassification_receipt(
    receipt: &ReceiptAppendRequest,
) -> Result<ActiveDefenseReceiptBody, ()> {
    let body =
        serde_json::from_slice::<ActiveDefenseReceiptBody>(receipt.canonical_body.as_bytes())
            .map_err(|_| ())?;
    body.validate().map_err(|_| ())?;
    let canonical = canonical_json_bytes(&body).map_err(|_| ())?;
    let body_hash = body.body_digest().map_err(|_| ())?;
    let evidence_id = body.evidence_id().map_err(|_| ())?;
    if canonical.as_slice() != receipt.canonical_body.as_bytes()
        || body_hash != receipt.body_hash
        || evidence_id != receipt.evidence_id
        || body.header().tenant_id != receipt.tenant_id
        || body.header().transition_id != receipt.transition_id
        || body.header().occurred_at_unix_ms != receipt.occurred_at_unix_ms
        || body.kind().as_str() != receipt.evidence_type.as_str()
    {
        return Err(());
    }
    Ok(body)
}

fn validate_declassification_consumption_evidence(
    request: &DeclassificationConsumptionEvidenceCommit,
) -> PortResult<()> {
    let body = decode_declassification_receipt(&request.receipt)
        .map_err(|()| PortError::invalid_data())?;
    let ActiveDefenseReceiptBody::DeclassificationConsumption(body) = body else {
        return Err(PortError::invalid_data());
    };
    validate_declassification_binding_identity(
        &request.transition_binding,
        &request.consumption.tenant_id,
        &request.consumption.grant_id,
        request.consumption.request_hash,
        &request.receipt,
        &body.event_id,
    )?;
    if !request.transition_binding.is_consumption()
        || request.consumption.consumed_at_unix_ms == 0
        || request.consumption.grant_expires_at_unix_ms <= request.consumption.consumed_at_unix_ms
        || request.receipt.tenant_id != request.consumption.tenant_id
        || request.receipt.occurred_at_unix_ms != request.consumption.consumed_at_unix_ms
        || body.grant_id != request.consumption.grant_id
        || body.request_hash != request.consumption.request_hash
        || body.state != DeclassificationUseState::ConsumedPendingDispatch
        || !body.header.prior_receipt_ids.is_empty()
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_declassification_outcome_evidence(
    request: &DeclassificationOutcomeEvidenceCommit,
) -> PortResult<()> {
    let body = decode_declassification_receipt(&request.receipt)
        .map_err(|()| PortError::invalid_data())?;
    let ActiveDefenseReceiptBody::DeclassificationOutcome(body) = body else {
        return Err(PortError::invalid_data());
    };
    validate_declassification_binding_identity(
        &request.transition_binding,
        &request.outcome.tenant_id,
        &request.outcome.grant_id,
        request.outcome.request_hash,
        &request.receipt,
        &body.event_id,
    )?;
    if request.outcome.expected_state != DeclassificationUseState::ConsumedPendingDispatch
        || request.transition_binding.terminal_state() != Some(request.outcome.new_state)
        || request.outcome.transition_id != request.receipt.transition_id
        || request.receipt.tenant_id != request.outcome.tenant_id
        || request.predecessor_evidence_id == request.receipt.evidence_id
        || body.grant_id != request.outcome.grant_id
        || body.request_hash != request.outcome.request_hash
        || body.from_state != request.outcome.expected_state
        || body.to_state != request.outcome.new_state
        || body.header.prior_receipt_ids.as_slice()
            != core::slice::from_ref(&request.predecessor_evidence_id)
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn load_declassification_use_record(
    connection: &Connection,
    query: &DeclassificationUseQuery,
) -> PortResult<Option<DeclassificationUseRecord>> {
    type UseRow = (
        String,
        String,
        Vec<u8>,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
    );
    let row: Option<UseRow> = connection
        .query_row(
            r#"
            SELECT tenant_id, grant_id, request_hash, state, consumed_at,
                   grant_expires_at, retain_until, consumption_binding, outcome_binding
            FROM security_declassification_uses
            WHERE tenant_id = ?1 AND grant_id = ?2
            "#,
            params![query.tenant_id.as_str(), query.grant_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        tenant_id,
        grant_id,
        request_hash,
        state,
        consumed_at,
        grant_expires_at,
        retain_until,
        consumption_binding,
        outcome_binding,
    )) = row
    else {
        return Ok(None);
    };
    let record = DeclassificationUseRecord {
        tenant_id: TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?,
        grant_id: GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?,
        request_hash: decode_digest(request_hash)?,
        state: parse_declassification_state(&state)?,
        consumed_at_unix_ms: from_i64(consumed_at)?,
        grant_expires_at_unix_ms: from_i64(grant_expires_at)?,
        retain_until_unix_ms: from_i64(retain_until)?,
        consumption_binding: decode_declassification_binding(&consumption_binding)?,
        outcome_binding: outcome_binding
            .as_deref()
            .map(decode_declassification_binding)
            .transpose()?,
    };
    if record.tenant_id != query.tenant_id
        || record.grant_id != query.grant_id
        || !record.consumption_binding.is_consumption()
        || record.consumption_binding.tenant_id() != &record.tenant_id
        || record.consumption_binding.grant_id() != &record.grant_id
        || record.consumption_binding.request_hash() != record.request_hash
        || record.grant_expires_at_unix_ms <= record.consumed_at_unix_ms
        || declassification_retain_until_unix_ms(record.grant_expires_at_unix_ms)
            != Ok(record.retain_until_unix_ms)
        || (record.state == DeclassificationUseState::ConsumedPendingDispatch)
            != record.outcome_binding.is_none()
        || record.outcome_binding.as_ref().is_some_and(|binding| {
            binding.terminal_state() != Some(record.state)
                || binding.tenant_id() != &record.tenant_id
                || binding.grant_id() != &record.grant_id
                || binding.request_hash() != record.request_hash
        })
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(record))
}

type DeclassificationEvidenceRow = (
    String,
    String,
    String,
    i64,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    Option<String>,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    i64,
    Option<String>,
);

fn decode_declassification_evidence_row(
    row: DeclassificationEvidenceRow,
) -> PortResult<DeclassificationEvidenceRecord> {
    let (
        tenant_id,
        grant_id,
        phase,
        phase_ordinal,
        request_hash,
        state,
        transition_binding,
        evidence_type,
        evidence_id,
        canonical_body,
        body_hash,
        transition_id,
        occurred_at,
        predecessor_evidence_id,
        acknowledged,
        acknowledged_at,
        durable_sink_record_hash,
        attempts,
        next_attempt_at,
        last_error_code,
    ) = row;
    let phase = parse_declassification_phase(&phase)?;
    if from_i64(phase_ordinal)? != u64::from(phase.ordinal()) {
        return Err(PortError::integrity_failure());
    }
    let tenant_id = TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?;
    let grant_id = GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?;
    let request_hash = decode_digest(request_hash)?;
    let state = parse_declassification_state(&state)?;
    let transition_binding = decode_declassification_binding(&transition_binding)?;
    let canonical_body =
        CanonicalBody::new(canonical_body).map_err(|_| PortError::integrity_failure())?;
    let body_hash = decode_digest(body_hash)?;
    let predecessor_evidence_id = predecessor_evidence_id
        .map(OpaqueReceiptRef::new)
        .transpose()
        .map_err(|_| PortError::integrity_failure())?;
    let (acknowledged, durable_sink_record_hash) =
        match (acknowledged, acknowledged_at, durable_sink_record_hash) {
            (0, None, None) => (false, None),
            (1, Some(value), Some(hash)) if value >= occurred_at => {
                (true, Some(decode_digest(hash)?))
            }
            _ => return Err(PortError::integrity_failure()),
        };
    let attempts =
        u32::try_from(from_i64(attempts)?).map_err(|_| PortError::integrity_failure())?;
    let next_attempt_at_unix_ms = from_i64(next_attempt_at)?;
    let last_error_code = last_error_code
        .map(ErrorCode::new)
        .transpose()
        .map_err(|_| PortError::integrity_failure())?;
    if (attempts == 0) != last_error_code.is_none()
        || next_attempt_at_unix_ms < from_i64(occurred_at)?
    {
        return Err(PortError::integrity_failure());
    }
    let receipt = ReceiptAppendRequest {
        tenant_id: tenant_id.clone(),
        evidence_type: RecordId::new(evidence_type).map_err(|_| PortError::integrity_failure())?,
        evidence_id: OpaqueReceiptRef::new(evidence_id)
            .map_err(|_| PortError::integrity_failure())?,
        canonical_body,
        body_hash,
        transition_id: RecordId::new(transition_id).map_err(|_| PortError::integrity_failure())?,
        occurred_at_unix_ms: from_i64(occurred_at)?,
    };
    let body =
        decode_declassification_receipt(&receipt).map_err(|()| PortError::integrity_failure())?;
    let body_event_id = match &body {
        ActiveDefenseReceiptBody::DeclassificationConsumption(consumption) => &consumption.event_id,
        ActiveDefenseReceiptBody::DeclassificationOutcome(outcome) => &outcome.event_id,
        _ => return Err(PortError::integrity_failure()),
    };
    validate_declassification_binding_identity(
        &transition_binding,
        &tenant_id,
        &grant_id,
        request_hash,
        &receipt,
        body_event_id,
    )
    .map_err(|_| PortError::integrity_failure())?;
    if (phase == DeclassificationEvidencePhase::Consumption
        && (state != DeclassificationUseState::ConsumedPendingDispatch
            || predecessor_evidence_id.is_some()
            || !matches!(
                &body,
                ActiveDefenseReceiptBody::DeclassificationConsumption(consumption)
                    if consumption.grant_id == grant_id
                        && consumption.request_hash == request_hash
                        && consumption.state == state
                        && consumption.header.prior_receipt_ids.is_empty()
            )))
        || (phase == DeclassificationEvidencePhase::Outcome
            && (!matches!(
                state,
                DeclassificationUseState::Released
                    | DeclassificationUseState::DispatchFailed
                    | DeclassificationUseState::OutcomeUnknown
            ) || predecessor_evidence_id.is_none()
                || !matches!(
                    &body,
                    ActiveDefenseReceiptBody::DeclassificationOutcome(outcome)
                        if outcome.grant_id == grant_id
                            && outcome.request_hash == request_hash
                            && outcome.from_state
                                == DeclassificationUseState::ConsumedPendingDispatch
                            && outcome.to_state == state
                            && predecessor_evidence_id.as_ref().is_some_and(|predecessor| {
                                outcome.header.prior_receipt_ids.as_slice()
                                    == core::slice::from_ref(predecessor)
                            })
                )))
    {
        return Err(PortError::integrity_failure());
    }
    Ok(DeclassificationEvidenceRecord {
        tenant_id,
        grant_id,
        phase,
        request_hash,
        state,
        transition_binding,
        predecessor_evidence_id,
        receipt,
        acknowledged,
        durable_sink_record_hash,
        attempts,
        next_attempt_at_unix_ms,
        last_error_code,
    })
}

fn declassification_evidence_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DeclassificationEvidenceRow> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, i64>(3)?,
        row.get::<_, Vec<u8>>(4)?,
        row.get::<_, String>(5)?,
        row.get::<_, Vec<u8>>(6)?,
        row.get::<_, String>(7)?,
        row.get::<_, String>(8)?,
        row.get::<_, Vec<u8>>(9)?,
        row.get::<_, Vec<u8>>(10)?,
        row.get::<_, String>(11)?,
        row.get::<_, i64>(12)?,
        row.get::<_, Option<String>>(13)?,
        row.get::<_, i64>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<Vec<u8>>>(16)?,
        row.get::<_, i64>(17)?,
        row.get::<_, i64>(18)?,
        row.get::<_, Option<String>>(19)?,
    ))
}

const DECLASSIFICATION_EVIDENCE_COLUMNS: &str = r#"
    tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
    transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
    transition_id, occurred_at, predecessor_evidence_id, acknowledged,
    acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
    last_error_code
"#;

fn load_declassification_evidence_record(
    connection: &Connection,
    query: &DeclassificationEvidenceQuery,
) -> PortResult<Option<DeclassificationEvidenceRecord>> {
    let sql = format!(
        "SELECT {DECLASSIFICATION_EVIDENCE_COLUMNS} \
         FROM security_declassification_receipt_outbox \
         WHERE tenant_id = ?1 AND grant_id = ?2 AND phase_ordinal = ?3"
    );
    let row = connection
        .query_row(
            &sql,
            params![
                query.tenant_id.as_str(),
                query.grant_id.as_str(),
                i64::from(query.phase.ordinal())
            ],
            declassification_evidence_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(decode_declassification_evidence_row).transpose()
}

fn load_pending_declassification_evidence_records(
    connection: &Connection,
    tenant_id: Option<&TenantId>,
    grant_id: Option<&GrantId>,
    now_unix_ms: u64,
    max_records: u32,
) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
    if max_records == 0 || max_records > MAX_DECLASSIFICATION_EVIDENCE_BATCH {
        return Err(PortError::invalid_data());
    }
    let now = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
    let limit = i64::from(max_records);
    let rows = match (tenant_id, grant_id) {
        (Some(tenant_id), Some(grant_id)) => {
            let sql = format!(
                "SELECT {DECLASSIFICATION_EVIDENCE_COLUMNS} \
                 FROM security_declassification_receipt_outbox \
                 WHERE acknowledged = 0 AND next_attempt_at <= ?3 \
                   AND tenant_id = ?1 AND grant_id = ?2 \
                 ORDER BY next_attempt_at ASC, phase_ordinal ASC LIMIT ?4"
            );
            let mut statement = connection.prepare(&sql).map_err(sqlite_error)?;
            let rows = statement
                .query_map(
                    params![tenant_id.as_str(), grant_id.as_str(), now, limit],
                    declassification_evidence_row,
                )
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            rows
        }
        (None, None) => {
            let sql = format!(
                "SELECT {DECLASSIFICATION_EVIDENCE_COLUMNS} \
                 FROM security_declassification_receipt_outbox \
                 WHERE acknowledged = 0 AND next_attempt_at <= ?1 \
                   AND (phase = 'consumption' OR EXISTS ( \
                       SELECT 1 FROM security_declassification_receipt_outbox AS predecessor \
                       WHERE predecessor.tenant_id = security_declassification_receipt_outbox.tenant_id \
                         AND predecessor.grant_id = security_declassification_receipt_outbox.grant_id \
                         AND predecessor.phase = 'consumption' \
                         AND predecessor.acknowledged = 1 \
                   )) \
                 ORDER BY ROW_NUMBER() OVER ( \
                     PARTITION BY tenant_id \
                     ORDER BY next_attempt_at ASC, grant_id ASC, phase_ordinal ASC \
                 ) ASC, next_attempt_at ASC, tenant_id ASC, grant_id ASC, phase_ordinal ASC \
                 LIMIT ?2"
            );
            let mut statement = connection.prepare(&sql).map_err(sqlite_error)?;
            let rows = statement
                .query_map(params![now, limit], declassification_evidence_row)
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            rows
        }
        _ => return Err(PortError::invalid_data()),
    };
    rows.into_iter()
        .map(decode_declassification_evidence_row)
        .collect()
}

struct DeclassificationEvidenceCommit<'a> {
    tenant_id: &'a TenantId,
    grant_id: &'a GrantId,
    phase: DeclassificationEvidencePhase,
    request_hash: Digest32,
    state: DeclassificationUseState,
    transition_binding: &'a DeclassificationTransitionBinding,
    predecessor_evidence_id: Option<&'a OpaqueReceiptRef>,
    receipt: &'a ReceiptAppendRequest,
}

fn insert_declassification_evidence(
    transaction: &Transaction<'_>,
    evidence: &DeclassificationEvidenceCommit<'_>,
) -> PortResult<()> {
    let transition_binding = encode_declassification_binding(evidence.transition_binding)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                evidence.receipt.evidence_id.as_str(),
                evidence.receipt.transition_id.as_str(),
                evidence.tenant_id.as_str(),
                evidence.grant_id.as_str(),
                declassification_phase_name(evidence.phase),
                evidence.receipt.body_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_declassification_receipt_outbox (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body, body_hash,
                transition_id, occurred_at, predecessor_evidence_id, acknowledged,
                acknowledged_at, durable_sink_record_hash, attempts, next_attempt_at,
                last_error_code
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, 0, NULL, NULL, 0, ?13, NULL
            )
            "#,
            params![
                evidence.tenant_id.as_str(),
                evidence.grant_id.as_str(),
                declassification_phase_name(evidence.phase),
                i64::from(evidence.phase.ordinal()),
                evidence.request_hash.as_bytes().as_slice(),
                declassification_state_name(evidence.state),
                transition_binding,
                evidence.receipt.evidence_type.as_str(),
                evidence.receipt.evidence_id.as_str(),
                evidence.receipt.canonical_body.as_bytes(),
                evidence.receipt.body_hash.as_bytes().as_slice(),
                evidence.receipt.transition_id.as_str(),
                to_i64(evidence.receipt.occurred_at_unix_ms)?,
                evidence
                    .predecessor_evidence_id
                    .map(OpaqueReceiptRef::as_str),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn declassification_evidence_matches(
    record: &DeclassificationEvidenceRecord,
    expected: &DeclassificationEvidenceCommit<'_>,
) -> bool {
    record.tenant_id == *expected.tenant_id
        && record.grant_id == *expected.grant_id
        && record.phase == expected.phase
        && record.request_hash == expected.request_hash
        && record.state == expected.state
        && record.transition_binding == *expected.transition_binding
        && record.predecessor_evidence_id.as_ref() == expected.predecessor_evidence_id
        && record.receipt == *expected.receipt
}

fn load_declassification_use_transition(
    connection: &Connection,
    query: &DeclassificationUseQuery,
) -> PortResult<Option<Option<RecordId>>> {
    let value = connection
        .query_row(
            r#"
            SELECT transition_id
            FROM security_declassification_uses
            WHERE tenant_id = ?1 AND grant_id = ?2
            "#,
            params![query.tenant_id.as_str(), query.grant_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    value
        .map(|transition_id| {
            transition_id
                .map(RecordId::new)
                .transpose()
                .map_err(|_| PortError::integrity_failure())
        })
        .transpose()
}

fn normalize_sql(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut quote_terminator = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote_terminator {
            normalized.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped_terminator) = characters.next() {
                        normalized.push(escaped_terminator);
                    }
                } else {
                    quote_terminator = None;
                }
            }
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(character);
        quote_terminator = match character {
            '\'' | '"' | '`' => Some(character),
            '[' => Some(']'),
            _ => None,
        };
    }
    normalized
}
