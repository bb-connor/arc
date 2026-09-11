use super::egress_history::{from_request, Lookup, RetainedEgressFence};
use super::*;

impl FlowMutation<'_> {
    pub(in crate::security_state) fn acquire_egress_fence(
        &self,
        request: &EgressFenceRequest,
        read_time: impl FnOnce() -> PortResult<u64>,
    ) -> PortResult<EgressFence> {
        let transaction = self;
        let trusted_now = read_time()?;
        let snapshot = load_scoped_flow_snapshot(transaction.reader(), &request.key)?
            .ok_or_else(PortError::invalid_data)?;
        if snapshot.context_generation != request.expected_context_generation
            || request.expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::conflict());
        }
        let fence = from_request(request)?;
        let existing = RetainedEgressFence::load(
            transaction.reader(),
            &request.key.tenant_id,
            Lookup::Request(&request.request_id),
        )?;
        if let Some(existing) = existing {
            if existing.fence != fence {
                return Err(PortError::conflict());
            }
        } else {
            transaction
                .execute(
                    sql::INSERT_FENCE,
                    params![
                        fence.fence_id.as_str(),
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
        Ok(fence)
    }

    pub(in crate::security_state) fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
        read_time: impl FnOnce() -> PortResult<u64>,
    ) -> PortResult<CommittedEgressFence> {
        let transaction = self;
        let existing = RetainedEgressFence::load(
            transaction.reader(),
            &commitment.fence.key.tenant_id,
            Lookup::Fence(&commitment.fence.fence_id),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if existing.fence != commitment.fence {
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
        if let Some(existing) = existing.commitment {
            if existing != committed {
                return Err(PortError::conflict());
            }
            return Ok(existing);
        }
        let trusted_now = read_time()?;
        validate_current_fence(
            transaction.reader(),
            &existing.fence,
            &commitment.fence,
            trusted_now,
        )?;
        if commitment.committed_at_unix_ms > commitment.fence.expires_at_unix_ms
            || commitment.committed_at_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
        {
            return Err(PortError::invalid_data());
        }
        let updated = transaction
            .execute(
                sql::COMMIT_FENCE,
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
        Ok(committed)
    }
}

pub(super) fn validate_fence(
    connection: FlowReader<'_>,
    fence: &EgressFence,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    let stored = RetainedEgressFence::load(
        connection,
        &fence.key.tenant_id,
        Lookup::Fence(&fence.fence_id),
    )?
    .ok_or_else(PortError::invalid_data)?;
    validate_current_fence(connection, &stored.fence, fence, trusted_now_unix_ms)
}

fn validate_current_fence(
    connection: FlowReader<'_>,
    stored: &EgressFence,
    fence: &EgressFence,
    trusted_now_unix_ms: u64,
) -> PortResult<()> {
    if stored != fence || fence.expires_at_unix_ms <= trusted_now_unix_ms {
        return Err(PortError::conflict());
    }
    let current = load_scoped_flow_snapshot(connection, &fence.key)?
        .ok_or_else(PortError::integrity_failure)?;
    if current.context_generation != fence.context_generation {
        return Err(PortError::conflict());
    }
    Ok(())
}
