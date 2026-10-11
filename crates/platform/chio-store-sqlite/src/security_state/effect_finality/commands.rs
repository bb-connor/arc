use super::*;

// Preserve the existing owning canonical readers' historical payload bound.
const MAX_AUTHENTICATED_COMMAND_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests;

pub(super) fn project(
    request: EffectRequest,
    result: EffectResult,
    snapshot: Option<Vec<u8>>,
) -> PortResult<VerifiedCommand> {
    let request_bytes =
        canonical_json_bytes(&request).map_err(|_| PortError::integrity_failure())?;
    let result_bytes = canonical_json_bytes(&result).map_err(|_| PortError::integrity_failure())?;
    if request_bytes.len() > MAX_AUTHENTICATED_COMMAND_BYTES
        || result_bytes.len() > MAX_AUTHENTICATED_COMMAND_BYTES
        || snapshot
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_AUTHENTICATED_COMMAND_BYTES)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(VerifiedCommand {
        request,
        result,
        request_hash: Digest32::new(body_hash(&request_bytes)),
        result_hash: Digest32::new(body_hash(&result_bytes)),
        snapshot_hash: snapshot.map(|bytes| Digest32::new(body_hash(&bytes))),
    })
}

pub(super) fn load(
    connection: &Connection,
    kind: ResponseEffectKind,
    tenant: &str,
    key: &str,
) -> PortResult<Option<VerifiedCommand>> {
    use crate::security_state::{
        capability_set_suspension as suspension, containment, egress_restriction as egress,
        issuance_freeze as issuance, session_throttle as throttle,
    };
    match kind {
        ResponseEffectKind::SuspendSession => {
            containment::load_containment_overlay_command(connection, tenant, key)?
                .map(|command| {
                    containment::validate_stored_containment_overlay_command(&command)?;
                    let bytes = canonical_json_bytes(&command.resulting_snapshot)
                        .map_err(|_| PortError::integrity_failure())?;
                    project(command.request, command.result, Some(bytes))
                })
                .transpose()
        }
        ResponseEffectKind::RestrictEgress => {
            egress::load_egress_restriction_command(connection, tenant, key)?
                .map(|command| {
                    egress::validate_stored_egress_restriction_command(&command)?;
                    project(command.request, command.result, None)
                })
                .transpose()
        }
        ResponseEffectKind::ThrottleSession => {
            throttle::load_session_throttle_command(connection, tenant, key)?
                .map(|command| {
                    throttle::validate_stored_session_throttle_command(&command)?;
                    let bytes = canonical_json_bytes(&command.resulting_snapshot)
                        .map_err(|_| PortError::integrity_failure())?;
                    project(command.request, command.result, Some(bytes))
                })
                .transpose()
        }
        ResponseEffectKind::SuspendCapabilitySet => {
            suspension::load_command(connection, tenant, key)?
                .map(|command| {
                    suspension::validate_stored_command(&command)?;
                    let bytes = canonical_json_bytes(&command.resulting_snapshot)
                        .map_err(|_| PortError::integrity_failure())?;
                    project(command.request, command.result, Some(bytes))
                })
                .transpose()
        }
        ResponseEffectKind::FreezeIssuance => {
            issuance::load_finality_command(connection, tenant, key)?
                .map(|command| {
                    let bytes = canonical_json_bytes(&command.resulting_snapshot)
                        .map_err(|_| PortError::integrity_failure())?;
                    project(command.request, command.result, Some(bytes))
                })
                .transpose()
        }
        ResponseEffectKind::EscalateAlert => Err(PortError::invalid_data()),
    }
}

pub(super) fn journal_table(kind: ResponseEffectKind) -> PortResult<&'static str> {
    match kind {
        ResponseEffectKind::SuspendSession => Ok("security_containment_overlay_commands"),
        ResponseEffectKind::RestrictEgress => Ok("security_egress_restriction_commands"),
        ResponseEffectKind::ThrottleSession => Ok("security_session_throttle_commands"),
        ResponseEffectKind::SuspendCapabilitySet => {
            Ok("security_capability_set_suspension_commands")
        }
        ResponseEffectKind::FreezeIssuance => Ok("security_issuance_freeze_commands"),
        ResponseEffectKind::EscalateAlert => Err(PortError::invalid_data()),
    }
}
