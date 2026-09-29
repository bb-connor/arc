use super::CanonicalBody;
use super::Digest32;
use super::EffectRequest;
use super::EffectResultQuery;
use super::PortError;
use super::PortResult;
use super::Serialize;



pub(super) const EFFECT_COMMAND_ID_PREFIX: &str = "response_effect_command:";

pub(super) fn effect_query_from_request(request: &EffectRequest) -> EffectResultQuery {
    EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
        contribution_hash: request.contribution_hash,
    }
}

pub(super) fn verify_contribution_hash(body: &CanonicalBody, declared: Digest32) -> PortResult<()> {
    if Digest32::new(*chio_core::sha256(body.as_bytes()).as_bytes()) != declared {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn domain_hash(value: &[u8], body: &impl Serialize) -> PortResult<Digest32> {
    let canonical =
        chio_core::canonical_json_bytes(body).map_err(|_| PortError::integrity_failure())?;
    let mut bytes = Vec::with_capacity(value.len().saturating_add(canonical.len()));
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(&canonical);
    Ok(Digest32::new(*chio_core::sha256(&bytes).as_bytes()))
}
