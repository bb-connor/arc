use crate::types::representation;
use crate::{DisclosureIntent, HostSnapshot, RecoveryError};
use chio_flow::{canonical_request_hash, ResolvedFlowRequest};
use chio_security_types::ports::{BoundedVec, RecordId, RequestId};

pub fn resolved_request(
    intent: &DisclosureIntent,
    host: &HostSnapshot,
    now_unix_ms: u64,
) -> Result<ResolvedFlowRequest, RecoveryError> {
    Ok(ResolvedFlowRequest {
        request_id: RequestId::new(intent.operation_id.as_str()).map_err(representation)?,
        request_hash: canonical_request_hash(&intent.canonical_request)
            .map_err(RecoveryError::Grant)?,
        transition_id: RecordId::new(format!("input-{}", intent.operation_id.as_str()))
            .map_err(representation)?,
        state: host.flow.clone(),
        payload_label: intent.payload_label.clone(),
        operator_input_floor: host.input_floor.clone(),
        runtime_egress: true,
        capability_id: intent.capability_id.clone(),
        agent_id: intent.agent_id.clone(),
        tool_name: intent.tool_name.clone(),
        destination_id: intent.destination.clone(),
        purpose: intent.purpose.clone(),
        effective_declassification_purposes: host.policy_purposes.clone(),
        trusted_declassification_authorities: host.trusted_authorities.clone(),
        now_unix_ms,
        declassification: None,
        policy_clearances: BoundedVec::new(host.policy_clearances.clone())
            .map_err(representation)?,
        manifest: host.manifest.clone(),
        fence_expires_at_unix_ms: now_unix_ms
            .checked_add(30_000)
            .ok_or_else(|| representation("clock overflow"))?,
    })
}
