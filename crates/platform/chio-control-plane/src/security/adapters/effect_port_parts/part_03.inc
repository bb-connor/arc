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

fn effect_query_from_request(request: &EffectRequest) -> EffectResultQuery {
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

fn valid_containment_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}

fn valid_throttle_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}

fn valid_capability_set_suspension_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id
        && result.applied == matches!(operation, EffectOperation::Apply)
        && result.resulting_version_hash != Digest32::new([0_u8; 32])
}

fn valid_egress_effect_result(
    operation: EffectOperation,
    effect_id: &chio_security_types::ports::EffectId,
    result: &EffectResult,
) -> bool {
    &result.effect_id == effect_id && result.applied == matches!(operation, EffectOperation::Apply)
}

fn predict_egress_removal(
    current: &EgressRestrictionSnapshot,
    effect_id: &chio_security_types::ports::EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<EgressRestrictionSnapshot> {
    let mut contributions = current.contributions.as_slice().to_vec();
    let before = contributions.len();
    contributions.retain(|contribution| &contribution.effect_id != effect_id);
    let generation = if contributions.len() == before {
        current.generation
    } else {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let mut denied = BTreeSet::new();
    for contribution in &contributions {
        denied.extend(contribution.destinations.as_slice().iter().cloned());
    }
    Ok(EgressRestrictionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: EgressRestrictionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(denied.into_iter().collect())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    })
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

fn empty_egress_restriction_snapshot(
    key: EgressRestrictionSessionKey,
) -> PortResult<EgressRestrictionSnapshot> {
    Ok(EgressRestrictionSnapshot {
        key,
        generation: 0,
        contributions: EgressRestrictionContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    })
}

fn decode_egress_restriction(body: &CanonicalBody) -> PortResult<RestrictEgressContribution> {
    let contribution: RestrictEgressContribution =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    let canonical = chio_core::canonical_json_bytes(&contribution)
        .map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(contribution)
}

fn validate_egress_restriction_snapshot(
    snapshot: &EgressRestrictionSnapshot,
    expected_key: &EgressRestrictionSessionKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.contributions.as_slice();
    if contributions
        .windows(2)
        .any(|pair| pair[0].effect_id >= pair[1].effect_id)
        || (snapshot.highest_fencing_token == 0 && !contributions.is_empty())
        || snapshot.generation
            < u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?
    {
        return Err(PortError::integrity_failure());
    }
    let mut recomputed = BTreeSet::new();
    for contribution in contributions {
        if contribution.expires_at_unix_ms == 0 {
            return Err(PortError::integrity_failure());
        }
        recomputed.extend(contribution.destinations.as_slice().iter().cloned());
    }
    let recomputed = EgressDeniedDestinations::new(recomputed.into_iter().collect())
        .map_err(|_| PortError::integrity_failure())?;
    if recomputed != snapshot.denied_destinations {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EgressVersionCommitment<'a> {
    schema_version: u8,
    key: &'a EgressRestrictionSessionKey,
    generation: u64,
    contributions: &'a EgressRestrictionContributions,
    denied_destinations: &'a EgressDeniedDestinations,
}

fn egress_snapshot_version_hash(snapshot: &EgressRestrictionSnapshot) -> PortResult<Digest32> {
    domain_hash(
        EGRESS_VERSION_DOMAIN,
        &EgressVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
            denied_destinations: &snapshot.denied_destinations,
        },
    )
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledEgressContributionCommitment<'a> {
    schema_version: u8,
    key: &'a EgressRestrictionSessionKey,
    effect_id: &'a str,
    destinations: &'a EgressDestinationSet,
    contribution_hash: Digest32,
    expires_at_unix_ms: u64,
}

fn egress_installed_result(
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

fn egress_installed_version_hash(
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

fn egress_installed_contribution_hash(
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

fn empty_overlay_snapshot(target: TenantScopedId) -> PortResult<OverlaySnapshot> {
    Ok(OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: chio_security_types::ports::OverlayContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    })
}

fn verify_contribution_hash(body: &CanonicalBody, declared: Digest32) -> PortResult<()> {
    if Digest32::new(*chio_core::sha256(body.as_bytes()).as_bytes()) != declared {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn decode_session_suspension(body: &CanonicalBody) -> PortResult<SessionSuspensionContribution> {
    let contribution: SessionSuspensionContribution =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
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

fn validate_overlay_snapshot(
    snapshot: &OverlaySnapshot,
    expected_target: &TenantScopedId,
) -> PortResult<()> {
    validate_containment_overlay_snapshot(snapshot, expected_target)
}

fn overlay_version_hash(snapshot: &OverlaySnapshot) -> PortResult<Digest32> {
    containment_overlay_version_hash(snapshot)
}

fn installed_result(
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

fn installed_version_hash(
    request: &EffectRequest,
    target: &TenantScopedId,
    contribution: &OverlayContribution,
) -> PortResult<Digest32> {
    if request.effect_id != contribution.effect_id {
        return Err(PortError::integrity_failure());
    }
    containment_installed_version_hash(target, contribution)
}

fn domain_hash(value: &[u8], body: &impl Serialize) -> PortResult<Digest32> {
    let canonical =
        chio_core::canonical_json_bytes(body).map_err(|_| PortError::integrity_failure())?;
    let mut bytes = Vec::with_capacity(value.len().saturating_add(canonical.len()));
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(&canonical);
    Ok(Digest32::new(*chio_core::sha256(&bytes).as_bytes()))
}
