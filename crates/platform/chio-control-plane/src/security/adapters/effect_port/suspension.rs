use super::Arc;
use super::capability_set_suspension_installed_version_hash;
use super::capability_set_suspension_version_hash;
use super::empty_capability_set_suspension_snapshot;
use super::predict_capability_set_suspension_apply;
use super::predict_capability_set_suspension_remove;
use super::response_affected_set_hash;
use super::validate_capability_set_suspension_snapshot;
use super::CanonicalBody;
use super::CapabilitySetSuspensionApplyRequest;
use super::CapabilitySetSuspensionCommand;
use super::CapabilitySetSuspensionContribution;
use super::CapabilitySetSuspensionKey;
use super::CapabilitySetSuspensionRemoveRequest;
use super::CapabilitySetSuspensionSnapshot;
use super::CapabilitySetSuspensionSpec;
use super::CapabilitySetSuspensionStore;
use super::Digest32;
use super::EffectExecutionStatus;
use super::EffectOperation;
use super::EffectRequest;
use super::EffectResult;
use super::EffectResultQuery;
use super::PortError;
use super::PortResult;
use super::TenantId;
use super::ResponseEffectKind;
use super::ResponseTarget;
use super::ResponseEffectBackend;
use super::validate_request_binding;
use super::effect_query_from_request;
use super::verify_contribution_hash;



/// Exact `SuspendCapabilitySet` backend backed by immutable affected sets.
///
/// Every contribution carries the complete sorted set committed by the target
/// hash. Overlapping actions compose as a union at enforcement time, while a
/// remove deletes only the matching action and effect contribution.
pub struct CapabilitySetSuspensionBackend {
    suspensions: Arc<dyn CapabilitySetSuspensionStore>,
}

impl CapabilitySetSuspensionBackend {
    #[must_use]
    pub fn new(suspensions: Arc<dyn CapabilitySetSuspensionStore>) -> Self {
        Self { suspensions }
    }

    fn key(
        &self,
        tenant_id: &TenantId,
        target: &ResponseTarget,
    ) -> PortResult<CapabilitySetSuspensionKey> {
        let ResponseTarget::CapabilitySet { affected_set_hash } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(CapabilitySetSuspensionKey {
            tenant_id: tenant_id.clone(),
            affected_set_hash: *affected_set_hash,
        })
    }

    fn load_snapshot(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        match self.suspensions.load_capability_set_suspensions(key)? {
            Some(snapshot) => {
                validate_capability_set_suspension_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_capability_set_suspension_snapshot(key.clone()),
        }
    }

    fn reconcile_result(&self, request: &EffectRequest) -> PortResult<Option<EffectResult>> {
        match self
            .suspensions
            .load_capability_set_suspension_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_capability_set_suspension_result(
                    request.operation,
                    &request.effect_id,
                    &result,
                ) {
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
        key: &CapabilitySetSuspensionKey,
        predicted: &CapabilitySetSuspensionSnapshot,
        result: &EffectResult,
    ) -> PortResult<()> {
        let stored = self
            .suspensions
            .load_capability_set_suspensions(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_capability_set_suspension_snapshot(&stored, key)?;
        if &stored != predicted || self.reconcile_result(request)?.as_ref() != Some(result) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: CapabilitySetSuspensionKey,
        spec: CapabilitySetSuspensionSpec,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let contribution = CapabilitySetSuspensionContribution {
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            affected_ids: spec.affected_ids,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if let Some(existing) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.action_id && entry.effect_id == request.effect_id
        }) {
            if existing != &contribution {
                return Err(PortError::conflict());
            }
        } else if capability_set_suspension_version_hash(&current)? != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        let predicted = predict_capability_set_suspension_apply(
            &current,
            &contribution,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: capability_set_suspension_installed_version_hash(
                &key,
                &contribution,
            )?,
            applied: true,
        };
        let applied = match self.suspensions.apply_capability_set_suspension(
            &CapabilitySetSuspensionApplyRequest {
                key: key.clone(),
                contribution,
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: CapabilitySetSuspensionCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            },
        ) {
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
        validate_capability_set_suspension_snapshot(&applied, &key)?;
        if applied != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: CapabilitySetSuspensionKey,
        spec: CapabilitySetSuspensionSpec,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let contribution = CapabilitySetSuspensionContribution {
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            affected_ids: spec.affected_ids,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if capability_set_suspension_installed_version_hash(&key, &contribution)?
            != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.action_id && entry.effect_id == request.effect_id
        }) {
            if existing != &contribution {
                return Err(PortError::conflict());
            }
        }
        let predicted = predict_capability_set_suspension_remove(
            &current,
            &request.action_id,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: capability_set_suspension_version_hash(&predicted)?,
            applied: false,
        };
        let removed = match self.suspensions.remove_capability_set_suspension(
            &CapabilitySetSuspensionRemoveRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                effect_id: request.effect_id.clone(),
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: CapabilitySetSuspensionCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            },
        ) {
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
        validate_capability_set_suspension_snapshot(&removed, &key)?;
        if removed != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }
}

impl ResponseEffectBackend for CapabilitySetSuspensionBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::SuspendCapabilitySet
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.suspensions.ensure_capability_set_suspensions_ready()
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
        if request.effect_kind != ResponseEffectKind::SuspendCapabilitySet {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let spec = decode_capability_set_suspension_spec(&request.canonical_contribution)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        if response_affected_set_hash(&request.tenant_id, &spec.affected_ids)?
            != key.affected_set_hash
        {
            return Err(PortError::invalid_data());
        }
        if let Some(result) = self.reconcile_result(request)? {
            return Ok(result);
        }
        match request.operation {
            EffectOperation::Apply => self.execute_apply(request, key, spec),
            EffectOperation::Remove => self.execute_remove(request, key, spec),
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
        if query.effect_kind != ResponseEffectKind::SuspendCapabilitySet {
            return Err(PortError::invalid_data());
        }
        let key = self.key(&query.tenant_id, &query.target)?;
        let status = self
            .suspensions
            .load_capability_set_suspension_result(query)?;
        match &status {
            EffectExecutionStatus::Completed { result } => {
                if !valid_capability_set_suspension_result(
                    query.operation,
                    &query.effect_id,
                    result,
                ) {
                    return Err(PortError::integrity_failure());
                }
                if query.operation == EffectOperation::Apply {
                    let snapshot = self
                        .suspensions
                        .load_capability_set_suspensions(&key)?
                        .ok_or_else(PortError::integrity_failure)?;
                    validate_capability_set_suspension_snapshot(&snapshot, &key)?;
                    let contribution = snapshot
                        .contributions
                        .as_slice()
                        .iter()
                        .find(|entry| {
                            entry.action_id == query.action_id && entry.effect_id == query.effect_id
                        })
                        .ok_or_else(PortError::integrity_failure)?;
                    if contribution.contribution_hash != query.contribution_hash
                        || contribution.expires_at_unix_ms != query.plan_expires_at_unix_ms
                        || capability_set_suspension_installed_version_hash(&key, contribution)?
                            != result.resulting_version_hash
                    {
                        return Err(PortError::integrity_failure());
                    }
                }
            }
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::NotExecuted => {}
        }
        Ok(status)
    }
}

pub(super) fn decode_capability_set_suspension_spec(
    body: &CanonicalBody,
) -> PortResult<CapabilitySetSuspensionSpec> {
    let spec: CapabilitySetSuspensionSpec =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::InvalidData, error.code(), error))?;
    if spec.affected_ids.as_slice().is_empty() {
        return Err(PortError::invalid_data());
    }
    let canonical =
        chio_core::canonical_json_bytes(&spec).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(spec)
}

pub(super) fn valid_capability_set_suspension_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id
        && result.applied == matches!(operation, EffectOperation::Apply)
        && result.resulting_version_hash != Digest32::new([0_u8; 32])
}
