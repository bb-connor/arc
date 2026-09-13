use super::*;

pub(super) fn ensure_epoch_for_join(
    transaction: &FlowMutation<'_>,
    request: &FlowJoinRequest,
) -> PortResult<()> {
    let exact: bool = transaction
        .query_row(
            sql::HAS_EPOCH,
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
        if load_principal_label(transaction.reader(), &request.key)?.is_none()
            || load_lineage_label(transaction.reader(), &request.key)?.is_none()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(());
    }

    let principal_epoch_exists: bool = transaction
        .query_row(
            sql::HAS_PRINCIPAL_EPOCH,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if principal_epoch_exists {
        if load_principal_label(transaction.reader(), &request.key)?.is_none() {
            return Err(PortError::integrity_failure());
        }
        let inserted = transaction
            .execute(
                sql::COPY_EPOCH,
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
            sql::COUNT_PRIOR_EPOCHS,
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
            sql::INSERT_GENESIS,
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

pub(super) fn validate_isolation_transition(
    transition: &IsolationEpochTransition,
) -> PortResult<()> {
    if transition.previous_isolation_epoch_id == transition.new_isolation_epoch_id
        || transition
            .verification_evidence_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

pub(super) fn load_isolation_transition(
    transaction: FlowReader<'_>,
    transition: &IsolationEpochTransition,
) -> PortResult<Option<FlowStateSnapshot>> {
    let request_hash = canonical_request_hash(transition)?;
    if !scoped_transition_status(
        transaction,
        transition.tenant_id.as_str(),
        transition.transition_id.as_str(),
        "isolation_epoch",
        &request_hash,
    )? {
        return Ok(None);
    }
    let key = FlowStateKey {
        tenant_id: transition.tenant_id.clone(),
        principal_id: transition.principal_id.clone(),
        lineage_id: transition.lineage_id.clone(),
        session_id: transition.new_session_id.clone(),
        isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
    };
    load_scoped_flow_snapshot(transaction, &key)?
        .map(Some)
        .ok_or_else(PortError::integrity_failure)
}

impl FlowMutation<'_> {
    pub(super) fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
        verified_evidence: &VerifiedIsolationEvidence,
    ) -> PortResult<FlowStateSnapshot> {
        validate_isolation_transition(transition)?;
        let request_hash = canonical_request_hash(transition)?;
        let transaction = self;
        if let Some(snapshot) = load_isolation_transition(transaction.reader(), transition)? {
            return Ok(snapshot);
        }
        let prior_key = FlowStateKey {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            lineage_id: transition.lineage_id.clone(),
            session_id: transition.new_session_id.clone(),
            isolation_epoch_id: transition.previous_isolation_epoch_id.clone(),
        };
        if load_principal_label(transaction.reader(), &prior_key)?.is_none() {
            return Err(PortError::invalid_data());
        }
        let key = FlowStateKey {
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            ..prior_key
        };
        if load_principal_label(transaction.reader(), &key)?.is_some() {
            return Err(PortError::conflict());
        }
        let lineage_label = load_lineage_label(transaction.reader(), &key)?
            .map(|value| value.0)
            .ok_or_else(PortError::integrity_failure)?;
        let generation = next_flow_generation(transaction, transition.tenant_id.as_str())?;
        let principal_label = InformationLabel::bottom();
        let session_label = lineage_label.clone();
        transaction
            .execute(
                sql::INSERT_EPOCH,
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
        store_principal_label(transaction, &key, &principal_label, generation)?;
        store_session_label(transaction, &key, &session_label, generation)?;
        store_context_generation(transaction, &key, generation)?;
        scoped_record_transition(
            transaction,
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
        Ok(snapshot)
    }
}
