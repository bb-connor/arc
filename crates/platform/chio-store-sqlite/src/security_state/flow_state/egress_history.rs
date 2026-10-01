//! Decode complete historical fences without turning history into live authority.

use super::*;
use chio_security_types::ports::{IsolationEpochId, LineageId, RequestId, SessionId};
use chio_security_types::PrincipalId;
use rusqlite::{types::ValueRef, Row};

/// Private decoded storage, not a verified admission owner or execution permit.
pub(super) struct RetainedEgressFence {
    pub(super) fence: EgressFence,
    pub(super) commitment: Option<CommittedEgressFence>,
}

pub(super) enum Lookup<'a> {
    Fence(&'a RecordId),
    Request(&'a RequestId),
}

pub(super) fn from_request(request: &EgressFenceRequest) -> PortResult<EgressFence> {
    let hash = canonical_request_hash(request)?;
    Ok(EgressFence {
        fence_id: RecordId::new(format!("ef:{}", hex::encode(hash)))
            .map_err(|_| PortError::invalid_data())?,
        key: request.key.clone(),
        request_id: request.request_id.clone(),
        request_hash: request.request_hash,
        context_generation: request.expected_context_generation,
        expires_at_unix_ms: request.expires_at_unix_ms,
    })
}

impl RetainedEgressFence {
    pub(super) fn load(
        connection: FlowReader<'_>,
        tenant: &TenantId,
        lookup: Lookup<'_>,
    ) -> PortResult<Option<Self>> {
        let (query, value) = match lookup {
            Lookup::Fence(id) => (sql::LOAD_FENCE, id.as_str()),
            Lookup::Request(id) => (sql::LOAD_REQUEST_FENCE, id.as_str()),
        };
        connection
            .query_row(query, params![tenant.as_str(), value], |row| {
                Ok(Self::decode(row))
            })
            .optional()
            .map_err(sqlite_error)?
            .transpose()
    }

    fn decode(row: &Row<'_>) -> PortResult<Self> {
        let values = (0..12)
            .map(|index| row.get_ref(index))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_error)?;
        Self::decode_values(&values)
    }

    fn decode_values(values: &[ValueRef<'_>]) -> PortResult<Self> {
        fn invalid<T>(_: T) -> PortError {
            PortError::integrity_failure()
        }
        if values.len() != 12 {
            return Err(PortError::integrity_failure());
        }
        let fence_id = RecordId::new(text(values, 0)?).map_err(invalid)?;
        let key = FlowStateKey {
            tenant_id: TenantId::new(text(values, 1)?).map_err(invalid)?,
            principal_id: PrincipalId::new(text(values, 2)?).map_err(invalid)?,
            lineage_id: LineageId::new(text(values, 3)?).map_err(invalid)?,
            session_id: SessionId::new(text(values, 4)?).map_err(invalid)?,
            isolation_epoch_id: IsolationEpochId::new(text(values, 5)?).map_err(invalid)?,
        };
        let request = EgressFenceRequest {
            key,
            request_id: RequestId::new(text(values, 6)?).map_err(invalid)?,
            request_hash: Digest32::new(
                values[7]
                    .as_blob()
                    .map_err(invalid)?
                    .try_into()
                    .map_err(invalid)?,
            ),
            expected_context_generation: from_i64(values[8].as_i64().map_err(invalid)?)?,
            expires_at_unix_ms: from_i64(values[9].as_i64().map_err(invalid)?)?,
        };
        if request.expected_context_generation == 0 || request.expires_at_unix_ms == 0 {
            return Err(PortError::integrity_failure());
        }
        let fence = from_request(&request).map_err(invalid)?;
        if fence.fence_id != fence_id {
            return Err(PortError::integrity_failure());
        }
        let id = match values[10] {
            ValueRef::Null => None,
            _ => Some(RecordId::new(text(values, 10)?).map_err(invalid)?),
        };
        let time = match values[11] {
            ValueRef::Null => None,
            value => Some(value.as_i64().map_err(invalid)?),
        };
        let commitment = match (id, time) {
            (None, None) => None,
            (Some(dispatch_commitment_id), Some(time)) => {
                let committed_at_unix_ms = from_i64(time)?;
                // Preserve the existing receipt-time skew contract, which
                // allows the recorded timestamp to equal the fence deadline.
                // Fresh execution still requires observed time < expiry.
                if committed_at_unix_ms > fence.expires_at_unix_ms {
                    return Err(PortError::integrity_failure());
                }
                Some(CommittedEgressFence {
                    fence_id: fence.fence_id.clone(),
                    request_id: fence.request_id.clone(),
                    request_hash: fence.request_hash,
                    context_generation: fence.context_generation,
                    dispatch_commitment_id,
                    committed_at_unix_ms,
                })
            }
            _ => return Err(PortError::integrity_failure()),
        };
        Ok(Self { fence, commitment })
    }
}

fn text<'row>(values: &[ValueRef<'row>], column: usize) -> PortResult<&'row str> {
    let value = values[column]
        .as_str()
        .map_err(|_| PortError::integrity_failure())?;
    // All fence identifiers use the existing 256-byte domain bound. Check the
    // borrowed SQLite cell before the validated constructors allocate a String.
    if value.len() > 256 {
        return Err(PortError::integrity_failure());
    }
    Ok(value)
}

pub(in super::super) fn verify_retained_egress_values(values: &[ValueRef<'_>]) -> PortResult<()> {
    RetainedEgressFence::decode_values(values).map(|_| ())
}

pub(in super::super) fn verify_retained_egress_history(connection: &Connection) -> PortResult<()> {
    verify_scoped_egress_history(FlowReader::legacy(connection))
}

pub(super) fn verify_scoped_egress_history(reader: FlowReader<'_>) -> PortResult<()> {
    reader.visit(sql::ALL_FENCES, |row| {
        let stored = RetainedEgressFence::decode(row)?;
        let current = load_scoped_flow_snapshot(reader, &stored.fence.key)?
            .ok_or_else(PortError::integrity_failure)?;
        // Taint may have advanced since acquisition. Retain stale or expired
        // fences as history, but do not admit a future generation or orphan.
        if stored.fence.context_generation > current.context_generation {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    })
}
