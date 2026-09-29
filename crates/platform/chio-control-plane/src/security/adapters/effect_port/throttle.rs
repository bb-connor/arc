use super::{
    effect_query_from_request, empty_session_throttle_snapshot, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, validate_request_binding, validate_session_throttle_snapshot,
    verify_contribution_hash, Arc, CanonicalBody, EffectExecutionStatus, EffectOperation,
    EffectRequest, EffectResult, EffectResultQuery, PortError, PortResult, ResponseEffectBackend,
    ResponseEffectKind, ResponseTarget, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleRemoveRequest, SessionThrottleSnapshot, SessionThrottleStore, TenantId,
};

/// Exact `ThrottleSession` backend backed by independent durable windows.
///
/// Each effect contributes its own `(window_ms, max_invocations)` constraint.
/// The enforcement store evaluates their conjunction and never rounds multiple
/// contributions into one weaker scalar rate.
pub struct SessionThrottleBackend {
    throttles: Arc<dyn SessionThrottleStore>,
}

impl SessionThrottleBackend {
    #[must_use]
    pub fn new(throttles: Arc<dyn SessionThrottleStore>) -> Self {
        Self { throttles }
    }

    fn key(&self, tenant_id: &TenantId, target: &ResponseTarget) -> PortResult<SessionThrottleKey> {
        let ResponseTarget::Session { session_id } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(SessionThrottleKey {
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
        })
    }

    fn load_snapshot(&self, key: &SessionThrottleKey) -> PortResult<SessionThrottleSnapshot> {
        match self.throttles.load_session_throttles(key)? {
            Some(snapshot) => {
                validate_session_throttle_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_session_throttle_snapshot(key.clone()),
        }
    }

    fn reconcile_result(&self, request: &EffectRequest) -> PortResult<Option<EffectResult>> {
        match self
            .throttles
            .load_session_throttle_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_throttle_effect_result(request.operation, &request.effect_id, &result) {
                    return Err(PortError::integrity_failure());
                }
                Ok(Some(result))
            }
            EffectExecutionStatus::NotExecuted => Ok(None),
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                Err(PortError::integrity_failure())
            }
        }
    }

    fn verify_committed(
        &self,
        request: &EffectRequest,
        key: &SessionThrottleKey,
        predicted: &SessionThrottleSnapshot,
        result: &EffectResult,
    ) -> PortResult<()> {
        let stored = self
            .throttles
            .load_session_throttles(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_session_throttle_snapshot(&stored, key)?;
        if &stored != predicted || self.reconcile_result(request)?.as_ref() != Some(result) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: SessionThrottleKey,
        limits: SessionThrottleLimits,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = SessionThrottleContribution {
            effect_id: request.effect_id.clone(),
            limits,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        } else if session_throttle_version_hash(&current)? != request.expected_version_hash {
            return Err(PortError::conflict());
        }
        let predicted =
            predict_session_throttle_apply(&current, &desired, request.scheduler_fencing_token)?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: session_throttle_installed_version_hash(&key, &desired)?,
            applied: true,
        };
        let applied = match self
            .throttles
            .apply_session_throttle(&SessionThrottleApplyRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                contribution: desired,
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: SessionThrottleCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            }) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_session_throttle_snapshot(&applied, &key)?;
        if applied != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: SessionThrottleKey,
        limits: SessionThrottleLimits,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = SessionThrottleContribution {
            effect_id: request.effect_id.clone(),
            limits,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if session_throttle_installed_version_hash(&key, &desired)? != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        }
        let predicted = predict_session_throttle_remove(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: session_throttle_version_hash(&predicted)?,
            applied: false,
        };
        let removed = match self
            .throttles
            .remove_session_throttle(&SessionThrottleRemoveRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                effect_id: request.effect_id.clone(),
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: SessionThrottleCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            }) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_session_throttle_snapshot(&removed, &key)?;
        if removed != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }
}

impl ResponseEffectBackend for SessionThrottleBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::ThrottleSession
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.throttles.ensure_session_throttles_ready()
    }

    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
        validate_request_binding(
            &request.tenant_id,
            request.effect_kind,
            &request.target,
            request.plan_expires_at_unix_ms,
            request.scheduler_fencing_token,
            &request.idempotency_key,
        )?;
        if request.effect_kind != ResponseEffectKind::ThrottleSession {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let limits = decode_session_throttle_limits(&request.canonical_contribution)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        if let Some(result) = self.reconcile_result(request)? {
            return Ok(result);
        }
        match request.operation {
            EffectOperation::Apply => self.execute_apply(request, key, limits),
            EffectOperation::Remove => self.execute_remove(request, key, limits),
        }
    }

    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        validate_request_binding(
            &query.tenant_id,
            query.effect_kind,
            &query.target,
            query.plan_expires_at_unix_ms,
            query.scheduler_fencing_token,
            &query.idempotency_key,
        )?;
        if query.effect_kind != ResponseEffectKind::ThrottleSession {
            return Err(PortError::invalid_data());
        }
        self.key(&query.tenant_id, &query.target)?;
        let status = self.throttles.load_session_throttle_result(query)?;
        match &status {
            EffectExecutionStatus::Completed { result }
                if !valid_throttle_effect_result(query.operation, &query.effect_id, result) =>
            {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::NotExecuted | EffectExecutionStatus::Completed { .. } => {}
        }
        Ok(status)
    }
}

pub(super) fn decode_session_throttle_limits(
    body: &CanonicalBody,
) -> PortResult<SessionThrottleLimits> {
    let limits: SessionThrottleLimits =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(|error| {
                PortError::with_source(
                    chio_security_types::ports::PortErrorKind::InvalidData,
                    error.code(),
                    error,
                )
            })?;
    limits.validate()?;
    let canonical =
        chio_core::canonical_json_bytes(&limits).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(limits)
}

pub(super) fn valid_throttle_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}
