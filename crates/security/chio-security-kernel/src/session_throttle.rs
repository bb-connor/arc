use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
use chio_security_types::ports::{
    empty_session_throttle_snapshot, session_throttle_version_hash,
    session_throttle_window_identity, validate_session_throttle_snapshot, PortError, RecordId,
    SessionThrottleConsumeRequest, SessionThrottleDecision, SessionThrottleKey,
    SessionThrottleSnapshot, SessionThrottleStore,
};
use serde::Serialize;

use crate::tripwire::{SecurityClock, SystemSecurityClock};
use crate::MissingContextPolicy;

const GUARD_NAME: &str = "chio-session-throttle";
const INVOCATION_DOMAIN: &[u8] = b"chio.session-throttle-invocation.v1\0";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InvocationCommitment<'a> {
    schema_version: u8,
    tenant_id: &'a str,
    session_id: &'a str,
    request_id: &'a str,
    capability_id: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    arguments: &'a serde_json::Value,
}

/// Fail-closed session throttle guard for the synchronous kernel guard path.
pub struct SessionThrottleGuard {
    throttles: Arc<dyn SessionThrottleStore>,
    clock: Arc<dyn SecurityClock>,
    missing_context: MissingContextPolicy,
}

impl SessionThrottleGuard {
    #[must_use]
    pub fn new(
        throttles: Arc<dyn SessionThrottleStore>,
        clock: Arc<dyn SecurityClock>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self {
            throttles,
            clock,
            missing_context,
        }
    }

    #[must_use]
    pub fn with_system_clock(
        throttles: Arc<dyn SessionThrottleStore>,
        missing_context: MissingContextPolicy,
    ) -> Self {
        Self::new(throttles, Arc::new(SystemSecurityClock), missing_context)
    }

    fn deny(reason: &str) -> GuardDecision {
        GuardDecision::deny(vec![GuardEvidence {
            guard_name: GUARD_NAME.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        }])
    }

    fn invocation_id(
        guard_context: &GuardContext<'_>,
        key: &SessionThrottleKey,
    ) -> Result<RecordId, PortError> {
        let commitment = InvocationCommitment {
            schema_version: 1,
            tenant_id: key.tenant_id.as_str(),
            session_id: key.session_id.as_str(),
            request_id: guard_context.request.request_id.as_str(),
            capability_id: guard_context.request.capability.id.as_str(),
            server_id: guard_context.request.server_id.as_str(),
            tool_name: guard_context.request.tool_name.as_str(),
            arguments: &guard_context.request.arguments,
        };
        let canonical =
            chio_core::canonical_json_bytes(&commitment).map_err(|_| PortError::invalid_data())?;
        let mut preimage =
            Vec::with_capacity(INVOCATION_DOMAIN.len().saturating_add(canonical.len()));
        preimage.extend_from_slice(INVOCATION_DOMAIN);
        preimage.extend_from_slice(&canonical);
        let digest = chio_core::sha256(&preimage);
        RecordId::new(format!(
            "session_throttle_invocation:{}",
            encode_hex(digest.as_bytes())
        ))
        .map_err(PortError::from)
    }

    fn load_snapshot(
        &self,
        key: &SessionThrottleKey,
    ) -> Result<SessionThrottleSnapshot, PortError> {
        match self.throttles.load_session_throttles(key)? {
            Some(snapshot) => {
                validate_session_throttle_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_session_throttle_snapshot(key.clone()),
        }
    }

    fn validate_decision(
        request: &SessionThrottleConsumeRequest,
        snapshot: &SessionThrottleSnapshot,
        decision: &SessionThrottleDecision,
    ) -> Result<(), PortError> {
        if decision.key != request.key
            || decision.generation != snapshot.generation
            || decision.current_version_hash != session_throttle_version_hash(snapshot)?
            || decision.windows.len() != snapshot.contributions.len()
        {
            return Err(PortError::integrity_failure());
        }
        let mut exhausted = false;
        for (contribution, usage) in snapshot
            .contributions
            .as_slice()
            .iter()
            .zip(decision.windows.as_slice())
        {
            let identity = session_throttle_window_identity(
                &request.key,
                &contribution.effect_id,
                contribution.limits,
                request.observed_at_unix_ms,
            )?;
            if usage.effect_id != contribution.effect_id
                || usage.identity != identity
                || usage.max_invocations != contribution.limits.max_invocations
                || usage.consumed_before > usage.max_invocations
                || usage.consumed_after > usage.max_invocations
            {
                return Err(PortError::integrity_failure());
            }
            if decision.allowed {
                let valid_replay = usage.replayed && usage.consumed_before == usage.consumed_after;
                let valid_new = !usage.replayed
                    && usage.consumed_after
                        == usage
                            .consumed_before
                            .checked_add(1)
                            .ok_or_else(PortError::integrity_failure)?;
                if !valid_replay && !valid_new {
                    return Err(PortError::integrity_failure());
                }
            } else {
                if usage.consumed_before != usage.consumed_after {
                    return Err(PortError::integrity_failure());
                }
                exhausted |= !usage.replayed && usage.consumed_before >= usage.max_invocations;
            }
        }
        if !decision.allowed && !exhausted {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}

impl Guard for SessionThrottleGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn evaluate(&self, guard_context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let Some(context) = guard_context
            .security_context()
            .map(|security| security.as_v1())
        else {
            return Ok(if self.missing_context.denies() {
                Self::deny("authoritative session context is missing")
            } else {
                GuardDecision::allow()
            });
        };
        let key = SessionThrottleKey {
            tenant_id: context.tenant_id().clone(),
            session_id: context.session_id().clone(),
        };
        let observed_at_unix_ms = match self.clock.now_unix_ms() {
            Ok(value) if value != 0 => value,
            Ok(_) | Err(_) => return Ok(Self::deny("session throttle clock failed")),
        };
        let invocation_id = match Self::invocation_id(guard_context, &key) {
            Ok(value) => value,
            Err(_) => return Ok(Self::deny("session throttle invocation binding failed")),
        };
        let request = SessionThrottleConsumeRequest {
            key: key.clone(),
            invocation_id,
            observed_at_unix_ms,
        };
        let decision = match self.throttles.consume_session_invocation(&request) {
            Ok(value) => value,
            Err(_) => return Ok(Self::deny("session throttle consumption failed")),
        };
        let snapshot = match self.load_snapshot(&key) {
            Ok(value) => value,
            Err(_) => return Ok(Self::deny("session throttle verification failed")),
        };
        if Self::validate_decision(&request, &snapshot, &decision).is_err() {
            return Ok(Self::deny("session throttle result failed validation"));
        }
        if !decision.allowed {
            return Ok(Self::deny("session invocation rate limit exhausted"));
        }
        Ok(GuardDecision::allow())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
