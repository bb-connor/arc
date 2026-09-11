//! Closed egress commands and exact row policies, not mutation authority.
use super::*;
use rusqlite::types::{Value, ValueRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum NativeEgressCommand {
    Acquire(EgressFenceRequest),
    Commit(EgressFenceCommit),
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "result",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum NativeEgressResult {
    Acquired(EgressFence),
    Committed(CommittedEgressFence),
}

impl NativeEgressCommand {
    pub(crate) fn phase(&self) -> &'static str {
        match self {
            Self::Acquire(_) => "acquired",
            Self::Commit(_) => "committed",
        }
    }

    pub(crate) fn fence(&self) -> PortResult<EgressFence> {
        let fence = match self {
            Self::Acquire(plan) => flow_state::planned_native_egress_fence(plan)?,
            Self::Commit(commitment) => {
                let fence = &commitment.fence;
                let expected = flow_state::planned_native_egress_fence(&EgressFenceRequest {
                    key: fence.key.clone(),
                    request_id: fence.request_id.clone(),
                    request_hash: fence.request_hash,
                    expected_context_generation: fence.context_generation,
                    expires_at_unix_ms: fence.expires_at_unix_ms,
                })?;
                if &expected != fence
                    || commitment.committed_at_unix_ms == 0
                    || commitment.committed_at_unix_ms > fence.expires_at_unix_ms
                {
                    return Err(PortError::invalid_data());
                }
                expected
            }
        };
        if !(1..=9_007_199_254_740_991).contains(&fence.context_generation)
            || !(1..=9_007_199_254_740_991).contains(&fence.expires_at_unix_ms)
        {
            return Err(PortError::invalid_data());
        }
        Ok(fence)
    }

    pub(crate) fn expected_result(&self) -> PortResult<NativeEgressResult> {
        let fence = self.fence()?;
        match self {
            Self::Acquire(_) => Ok(NativeEgressResult::Acquired(fence)),
            Self::Commit(commitment) => Ok(NativeEgressResult::Committed(CommittedEgressFence {
                fence_id: fence.fence_id,
                request_id: fence.request_id,
                request_hash: fence.request_hash,
                context_generation: fence.context_generation,
                dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
                committed_at_unix_ms: commitment.committed_at_unix_ms,
            })),
        }
    }

    /// Recheck the same temporal contract when reading immutable history.
    pub(crate) fn validate_observation(&self, trusted_now: u64) -> PortResult<()> {
        if self.fence()?.expires_at_unix_ms <= trusted_now {
            return Err(PortError::conflict());
        }
        if let Self::Commit(commitment) = self {
            if commitment.committed_at_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS {
                return Err(PortError::invalid_data());
            }
        }
        Ok(())
    }

    /// Exactly one fence may be inserted or committed. No update to another
    /// field, nested row, deletion, imported fence adoption or label mutation.
    pub(crate) fn validate_change(&self, change: &NativeRowChange) -> PortResult<()> {
        if change.table != "security_egress_fences" {
            return Err(PortError::integrity_failure());
        }
        let fence = self.fence()?;
        let pending = row_image(&fence, None)?;
        let (before, after) = match self {
            Self::Acquire(_) => (None, pending),
            Self::Commit(commitment) => (Some(pending), row_image(&fence, Some(commitment))?),
        };
        if change.before != before || change.after.as_deref() != Some(after.as_str()) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}

fn row_image(fence: &EgressFence, commitment: Option<&EgressFenceCommit>) -> PortResult<String> {
    let mut values = vec![
        Value::Text(fence.fence_id.as_str().into()),
        Value::Text(fence.key.tenant_id.as_str().into()),
        Value::Text(fence.key.principal_id.as_str().into()),
        Value::Text(fence.key.lineage_id.as_str().into()),
        Value::Text(fence.key.session_id.as_str().into()),
        Value::Text(fence.key.isolation_epoch_id.as_str().into()),
        Value::Text(fence.request_id.as_str().into()),
        Value::Blob(fence.request_hash.as_bytes().to_vec()),
        Value::Integer(to_i64(fence.context_generation)?),
        Value::Integer(to_i64(fence.expires_at_unix_ms)?),
    ];
    if let Some(commitment) = commitment {
        values.push(Value::Text(
            commitment.dispatch_commitment_id.as_str().into(),
        ));
        values.push(Value::Integer(to_i64(commitment.committed_at_unix_ms)?));
    } else {
        values.extend([Value::Null, Value::Null]);
    }
    let refs = values.iter().map(ValueRef::from).collect::<Vec<_>>();
    String::from_utf8(
        encode_retained_security_values("security_egress_fences", &refs)
            .map_err(|_| PortError::integrity_failure())?,
    )
    .map_err(|_| PortError::integrity_failure())
}
