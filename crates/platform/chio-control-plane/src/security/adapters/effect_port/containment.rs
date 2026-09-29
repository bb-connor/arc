use super::Arc;
use super::containment_installed_version_hash;
use super::containment_overlay_version_hash;
use super::containment_session_target;
use super::predict_containment_overlay_apply;
use super::predict_containment_overlay_remove;
use super::validate_containment_overlay_snapshot;
use super::CanonicalBody;
use super::ContainmentOverlayCommand;
use super::ContainmentOverlayStore;
use super::Digest32;
use super::EffectExecutionStatus;
use super::EffectOperation;
use super::EffectRequest;
use super::EffectResult;
use super::EffectResultQuery;
use super::OverlayApplyRequest;
use super::OverlayContribution;
use super::OverlayRemoveRequest;
use super::OverlaySnapshot;
use super::PortError;
use super::PortResult;
use super::SessionId;
use super::TenantId;
use super::TenantScopedId;
use super::ResponseEffectKind;
use super::ResponseTarget;
use super::SessionSuspensionContribution;
use super::ResponseEffectBackend;
use super::validate_request_binding;
use super::effect_query_from_request;
use super::verify_contribution_hash;



/// Exact `SuspendSession` backend backed by the durable containment overlay.
///
/// Contributions are effect-keyed and therefore compose safely. Removing one
/// suspension never restores or deletes another plan's contribution.
pub struct SessionSuspensionOverlayBackend {
    overlays: Arc<dyn ContainmentOverlayStore>,
}

impl SessionSuspensionOverlayBackend {
    #[must_use]
    pub fn new(overlays: Arc<dyn ContainmentOverlayStore>) -> Self {
        Self { overlays }
    }

    fn target(&self, tenant_id: &TenantId, target: &ResponseTarget) -> PortResult<TenantScopedId> {
        let ResponseTarget::Session { session_id } = target else {
            return Err(PortError::invalid_data());
        };
        session_containment_target(tenant_id, session_id)
    }

    fn load_snapshot(&self, target: &TenantScopedId) -> PortResult<OverlaySnapshot> {
        match self.overlays.load_effective(target)? {
            Some(snapshot) => {
                validate_overlay_snapshot(&snapshot, target)?;
                Ok(snapshot)
            }
            None => empty_overlay_snapshot(target.clone()),
        }
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        target: TenantScopedId,
        contribution: SessionSuspensionContribution,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&target)?;
        let desired = OverlayContribution {
            effect_id: request.effect_id.clone(),
            posture_rank: contribution.posture_rank,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: Some(request.plan_expires_at_unix_ms),
        };
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        } else if overlay_version_hash(&current)? != request.expected_version_hash {
            return Err(PortError::conflict());
        }
        let predicted =
            predict_containment_overlay_apply(&current, &desired, request.scheduler_fencing_token)?;
        let result = installed_result(request, &target, &desired, true)?;
        let applied = self.overlays.apply_contribution(&OverlayApplyRequest {
            target: target.clone(),
            action_id: request.action_id.clone(),
            contribution: desired.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: ContainmentOverlayCommand {
                request: request.clone(),
                result: result.clone(),
                resulting_snapshot: predicted.clone(),
            },
        })?;
        validate_overlay_snapshot(&applied, &target)?;
        if applied != predicted {
            return Err(PortError::integrity_failure());
        }
        let Some(stored) = applied
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        else {
            return Err(PortError::integrity_failure());
        };
        if stored != &desired {
            return Err(PortError::integrity_failure());
        }
        if installed_version_hash(request, &target, stored)? != result.resulting_version_hash {
            return Err(PortError::integrity_failure());
        }
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        target: TenantScopedId,
        contribution: SessionSuspensionContribution,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&target)?;
        let desired = OverlayContribution {
            effect_id: request.effect_id.clone(),
            posture_rank: contribution.posture_rank,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: Some(request.plan_expires_at_unix_ms),
        };
        let expected_installed = installed_version_hash(request, &target, &desired)?;
        if expected_installed != request.expected_version_hash {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        }
        let predicted = predict_containment_overlay_remove(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: overlay_version_hash(&predicted)?,
            applied: false,
        };
        let removed = self.overlays.remove_contribution(&OverlayRemoveRequest {
            target: target.clone(),
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: ContainmentOverlayCommand {
                request: request.clone(),
                result: result.clone(),
                resulting_snapshot: predicted.clone(),
            },
        })?;
        validate_overlay_snapshot(&removed, &target)?;
        if removed != predicted {
            return Err(PortError::integrity_failure());
        }
        if removed
            .active_contributions
            .as_slice()
            .iter()
            .any(|entry| entry.effect_id == request.effect_id)
        {
            return Err(PortError::integrity_failure());
        }
        if overlay_version_hash(&removed)? != result.resulting_version_hash {
            return Err(PortError::integrity_failure());
        }
        Ok(result)
    }
}

impl ResponseEffectBackend for SessionSuspensionOverlayBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::SuspendSession
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.overlays.ensure_containment_overlays_ready()
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
        if request.effect_kind != ResponseEffectKind::SuspendSession {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let contribution = decode_session_suspension(&request.canonical_contribution)?;
        let target = self.target(&request.tenant_id, &request.target)?;
        match self
            .overlays
            .load_containment_overlay_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_containment_effect_result(request.operation, &request.effect_id, &result)
                {
                    return Err(PortError::integrity_failure());
                }
                return Ok(result);
            }
            EffectExecutionStatus::NotExecuted => {}
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                return Err(PortError::integrity_failure());
            }
        }
        match request.operation {
            EffectOperation::Apply => self.execute_apply(request, target, contribution),
            EffectOperation::Remove => self.execute_remove(request, target, contribution),
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
        if query.effect_kind != ResponseEffectKind::SuspendSession {
            return Err(PortError::invalid_data());
        }
        self.target(&query.tenant_id, &query.target)?;
        let status = self.overlays.load_containment_overlay_result(query)?;
        if let EffectExecutionStatus::Completed { result } = &status {
            if !valid_containment_effect_result(query.operation, &query.effect_id, result) {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(status)
    }
}

pub(super) fn valid_containment_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}

/// Derives the exact session overlay key used by `ContainmentGuard`.
pub fn session_containment_target(
    tenant_id: &TenantId,
    session_id: &SessionId,
) -> PortResult<TenantScopedId> {
    containment_session_target(tenant_id, session_id)
}

/// Reads and commits to the exact semantic overlay version observed by a plan.
pub fn session_overlay_version_hash(
    overlays: &dyn ContainmentOverlayStore,
    target: &TenantScopedId,
) -> PortResult<Digest32> {
    let snapshot = match overlays.load_effective(target)? {
        Some(snapshot) => {
            validate_overlay_snapshot(&snapshot, target)?;
            snapshot
        }
        None => empty_overlay_snapshot(target.clone())?,
    };
    overlay_version_hash(&snapshot)
}

pub(super) fn empty_overlay_snapshot(target: TenantScopedId) -> PortResult<OverlaySnapshot> {
    Ok(OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: chio_security_types::ports::OverlayContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    })
}

pub(super) fn decode_session_suspension(body: &CanonicalBody) -> PortResult<SessionSuspensionContribution> {
    let contribution: SessionSuspensionContribution =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::InvalidData, error.code(), error))?;
    if contribution.posture_rank == 0 {
        return Err(PortError::invalid_data());
    }
    let canonical = chio_core::canonical_json_bytes(&contribution)
        .map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

pub(super) fn validate_overlay_snapshot(
    snapshot: &OverlaySnapshot,
    expected_target: &TenantScopedId,
) -> PortResult<()> {
    validate_containment_overlay_snapshot(snapshot, expected_target)
}

pub(super) fn overlay_version_hash(snapshot: &OverlaySnapshot) -> PortResult<Digest32> {
    containment_overlay_version_hash(snapshot)
}

pub(super) fn installed_result(
    request: &EffectRequest,
    target: &TenantScopedId,
    contribution: &OverlayContribution,
    applied: bool,
) -> PortResult<EffectResult> {
    Ok(EffectResult {
        effect_id: request.effect_id.clone(),
        resulting_version_hash: installed_version_hash(request, target, contribution)?,
        applied,
    })
}

pub(super) fn installed_version_hash(
    request: &EffectRequest,
    target: &TenantScopedId,
    contribution: &OverlayContribution,
) -> PortResult<Digest32> {
    if request.effect_id != contribution.effect_id {
        return Err(PortError::integrity_failure());
    }
    containment_installed_version_hash(target, contribution)
}
