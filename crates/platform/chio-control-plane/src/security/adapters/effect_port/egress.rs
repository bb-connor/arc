use super::*;


pub(super) const INSTALLED_EGRESS_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-egress-contribution.v1\0";

/// Exact destination-aware `RestrictEgress` backend.
///
/// The store owns a distinct effect-keyed contribution for every response.
/// Destination unions are recomputed from all contributions, so removing one
/// response cannot lift an overlapping destination restriction.
pub struct RestrictEgressOverlayBackend {
    restrictions: Arc<dyn EgressRestrictionStore>,
}

impl RestrictEgressOverlayBackend {
    #[must_use]
    pub fn new(restrictions: Arc<dyn EgressRestrictionStore>) -> Self {
        Self { restrictions }
    }

    fn target(
        &self,
        tenant_id: &TenantId,
        target: &ResponseTarget,
    ) -> PortResult<EgressRestrictionSessionKey> {
        let ResponseTarget::Session { session_id } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(EgressRestrictionSessionKey {
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
        })
    }

    fn load_snapshot(
        &self,
        key: &EgressRestrictionSessionKey,
    ) -> PortResult<EgressRestrictionSnapshot> {
        match self.restrictions.load_egress_restrictions(key)? {
            Some(snapshot) => {
                validate_egress_restriction_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_egress_restriction_snapshot(key.clone()),
        }
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: EgressRestrictionSessionKey,
        contribution: RestrictEgressContribution,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = EgressRestrictionContribution {
            effect_id: request.effect_id.clone(),
            destinations: contribution.destinations,
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
        } else if egress_snapshot_version_hash(&current)? != request.expected_version_hash {
            return Err(PortError::conflict());
        }
        let predicted = predict_egress_apply(&current, &desired, request.scheduler_fencing_token)?;
        let result = egress_installed_result(request, &key, &desired, true)?;
        let applied =
            self.restrictions
                .apply_egress_restriction(&EgressRestrictionApplyRequest {
                    key: key.clone(),
                    action_id: request.action_id.clone(),
                    contribution: desired.clone(),
                    expected_generation: current.generation,
                    scheduler_fencing_token: request.scheduler_fencing_token,
                    command: EgressRestrictionCommand {
                        request: request.clone(),
                        result: result.clone(),
                    },
                })?;
        validate_egress_restriction_snapshot(&applied, &key)?;
        if applied != predicted { return Err(PortError::integrity_failure()); }
        let stored = applied
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        if stored != &desired {
            return Err(PortError::integrity_failure());
        }
        if egress_installed_version_hash(request, &key, stored)? != result.resulting_version_hash {
            return Err(PortError::integrity_failure());
        }
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: EgressRestrictionSessionKey,
        contribution: RestrictEgressContribution,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = EgressRestrictionContribution {
            effect_id: request.effect_id.clone(),
            destinations: contribution.destinations,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        let expected_installed = egress_installed_version_hash(request, &key, &desired)?;
        if expected_installed != request.expected_version_hash {
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
        let predicted = predict_egress_removal(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: egress_snapshot_version_hash(&predicted)?,
            applied: false,
        };
        let removed =
            self.restrictions
                .remove_egress_restriction(&EgressRestrictionRemoveRequest {
                    key: key.clone(),
                    action_id: request.action_id.clone(),
                    effect_id: request.effect_id.clone(),
                    expected_generation: current.generation,
                    scheduler_fencing_token: request.scheduler_fencing_token,
                    command: EgressRestrictionCommand {
                        request: request.clone(),
                        result: result.clone(),
                    },
                })?;
        validate_egress_restriction_snapshot(&removed, &key)?;
        if removed
            .contributions
            .as_slice()
            .iter()
            .any(|entry| entry.effect_id == request.effect_id)
        {
            return Err(PortError::integrity_failure());
        }
        if egress_snapshot_version_hash(&removed)? != result.resulting_version_hash {
            return Err(PortError::integrity_failure());
        }
        Ok(result)
    }
}

impl ResponseEffectBackend for RestrictEgressOverlayBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::RestrictEgress
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.restrictions.ensure_egress_restrictions_ready()
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
        if request.effect_kind != ResponseEffectKind::RestrictEgress {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let contribution = decode_egress_restriction(&request.canonical_contribution)?;
        let key = self.target(&request.tenant_id, &request.target)?;
        match self
            .restrictions
            .load_egress_restriction_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_egress_effect_result(request.operation, &request.effect_id, &result) {
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
            EffectOperation::Apply => self.execute_apply(request, key, contribution),
            EffectOperation::Remove => self.execute_remove(request, key, contribution),
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
        if query.effect_kind != ResponseEffectKind::RestrictEgress {
            return Err(PortError::invalid_data());
        }
        self.target(&query.tenant_id, &query.target)?;
        let status = self.restrictions.load_egress_restriction_result(query)?;
        if let EffectExecutionStatus::Completed { result } = &status {
            if !valid_egress_effect_result(query.operation, &query.effect_id, result) {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(status)
    }
}

pub(super) fn valid_egress_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}

/// Reads and commits to the exact destination-restriction version observed by a plan.
pub fn egress_restriction_version_hash(
    restrictions: &dyn EgressRestrictionStore,
    key: &EgressRestrictionSessionKey,
) -> PortResult<Digest32> {
    let snapshot = match restrictions.load_egress_restrictions(key)? {
        Some(snapshot) => {
            validate_egress_restriction_snapshot(&snapshot, key)?;
            snapshot
        }
        None => empty_egress_restriction_snapshot(key.clone())?,
    };
    egress_snapshot_version_hash(&snapshot)
}

pub(super) fn decode_egress_restriction(body: &CanonicalBody) -> PortResult<RestrictEgressContribution> {
    let contribution: RestrictEgressContribution =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::InvalidData, error.code(), error))?;
    let canonical = chio_core::canonical_json_bytes(&contribution)
        .map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledEgressContributionCommitment<'a> {
    schema_version: u8,
    key: &'a EgressRestrictionSessionKey,
    effect_id: &'a str,
    destinations: &'a EgressDestinationSet,
    contribution_hash: Digest32,
    expires_at_unix_ms: u64,
}

pub(super) fn egress_installed_result(
    request: &EffectRequest,
    key: &EgressRestrictionSessionKey,
    contribution: &EgressRestrictionContribution,
    applied: bool,
) -> PortResult<EffectResult> {
    Ok(EffectResult {
        effect_id: request.effect_id.clone(),
        resulting_version_hash: egress_installed_version_hash(request, key, contribution)?,
        applied,
    })
}

pub(super) fn egress_installed_version_hash(
    request: &EffectRequest,
    key: &EgressRestrictionSessionKey,
    contribution: &EgressRestrictionContribution,
) -> PortResult<Digest32> {
    egress_installed_contribution_hash(
        key,
        request.effect_id.as_str(),
        &contribution.destinations,
        contribution.contribution_hash,
        contribution.expires_at_unix_ms,
    )
}

pub(super) fn egress_installed_contribution_hash(
    key: &EgressRestrictionSessionKey,
    effect_id: &str,
    destinations: &EgressDestinationSet,
    contribution_hash: Digest32,
    expires_at_unix_ms: u64,
) -> PortResult<Digest32> {
    domain_hash(
        INSTALLED_EGRESS_CONTRIBUTION_DOMAIN,
        &InstalledEgressContributionCommitment {
            schema_version: 1,
            key,
            effect_id,
            destinations,
            contribution_hash,
            expires_at_unix_ms,
        },
    )
}
