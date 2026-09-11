//! Monotone label joins without an independent commit.

use super::*;

impl FlowMutation<'_> {
    pub(in crate::security_state) fn join(
        &self,
        request: &FlowJoinRequest,
    ) -> PortResult<FlowStateSnapshot> {
        let request_hash = canonical_request_hash(request)?;
        let transaction = self;
        if scoped_transition_status(
            transaction.reader(),
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "flow_join",
            &request_hash,
        )? {
            let snapshot = load_scoped_flow_snapshot(transaction.reader(), &request.key)?
                .ok_or_else(PortError::integrity_failure)?;
            return Ok(snapshot);
        }
        ensure_epoch_for_join(transaction, request)?;
        let principal_stored = load_principal_label(transaction.reader(), &request.key)?;
        let lineage_stored = load_lineage_label(transaction.reader(), &request.key)?;
        let session_stored = load_session_label(transaction.reader(), &request.key)?;
        let session_membership = session_membership_exists(transaction.reader(), &request.key)?;
        let context_stored = load_context_generation(transaction.reader(), &request.key)?;
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
        let generation = next_flow_generation(transaction, request.key.tenant_id.as_str())?;
        invalidate_related_flow_contexts(
            transaction,
            &request.key,
            generation,
            principal_changed,
            lineage_changed,
            session_changed,
        )?;
        if principal_stored.is_none() || principal_changed {
            store_principal_label(transaction, &request.key, &principal_label, generation)?;
        }
        if lineage_stored.is_none() || lineage_changed {
            store_lineage_label(transaction, &request.key, &lineage_label, generation)?;
        }
        if session_stored.is_none() || session_changed {
            store_session_label(transaction, &request.key, &session_label, generation)?;
        }
        store_context_generation(transaction, &request.key, generation)?;
        scoped_record_transition(
            transaction,
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
        Ok(snapshot)
    }
}
