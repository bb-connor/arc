//! Post-commit observations for response assurance and diagnostics.
//!
//! These metadata-only events do not confer authority or replace durable evidence.
//! Call only after commit and after releasing the connection guard. Concurrent
//! callers can observe commits in a different order; consumers must use generations.
use chio_security_types::ports::{EffectOperation, ResponsePlanRecord, SessionThrottleCommand};

pub(super) fn response_committed(record: &ResponsePlanRecord, first_generation: u64) {
    tracing::debug!(target: "chio::response_lifecycle",
        boundary = "response_commit",
        tenant_id = record.tenant_id.as_str(), action_id = record.action_id.as_str(),
        first_generation, generation = record.generation, state = record.state.as_str(),
        body_hash = hex::encode(record.body_hash.as_bytes()));
}

pub(super) fn throttle_committed(command: &SessionThrottleCommand) {
    let request = &command.request;
    tracing::debug!(target: "chio::response_lifecycle",
        boundary = "effect_commit", backend = "session_throttle",
        tenant_id = request.tenant_id.as_str(), action_id = request.action_id.as_str(),
        effect_id = request.effect_id.as_str(), idempotency_key = request.idempotency_key.as_str(),
        plan_hash = hex::encode(request.plan_hash.as_bytes()),
        operation = match request.operation { EffectOperation::Apply => "apply", EffectOperation::Remove => "remove" },
        resulting_version_hash = hex::encode(command.result.resulting_version_hash.as_bytes()),
        applied = command.result.applied);
}
