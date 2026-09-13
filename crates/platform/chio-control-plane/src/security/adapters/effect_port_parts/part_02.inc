impl IssuanceFreezeBackend {
    /// Construct a staged backend without a response-plan authority.
    ///
    /// Readiness and execution fail closed until the backend is constructed
    /// with [`Self::new_with_scheduler`].
    #[must_use]
    pub fn new(
        freezes: Arc<dyn IssuanceFreezeStore>,
        blast_radius: Arc<dyn BlastRadiusPort>,
    ) -> Self {
        Self {
            freezes,
            blast_radius,
            scheduler: None,
        }
    }

    /// Construct an executable backend bound to the authoritative response
    /// plan and scheduler lease store.
    #[must_use]
    pub fn new_with_scheduler(
        freezes: Arc<dyn IssuanceFreezeStore>,
        blast_radius: Arc<dyn BlastRadiusPort>,
        scheduler: Arc<dyn ResponseSchedulerStore>,
    ) -> Self {
        Self {
            freezes,
            blast_radius,
            scheduler: Some(scheduler),
        }
    }

    fn key(&self, tenant_id: &TenantId, target: &ResponseTarget) -> PortResult<IssuanceFreezeKey> {
        let ResponseTarget::Lineage { lineage_id } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(IssuanceFreezeKey {
            tenant_id: tenant_id.clone(),
            lineage_id: lineage_id.clone(),
        })
    }

    fn load_snapshot(&self, key: &IssuanceFreezeKey) -> PortResult<IssuanceFreezeSnapshot> {
        match self.freezes.load_issuance_freezes(key)? {
            Some(snapshot) => {
                validate_issuance_freeze_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_issuance_freeze_snapshot(key.clone()),
        }
    }

    fn validate_plan_binding(
        &self,
        request: &EffectRequest,
        spec: &IssuanceFreezeSpec,
    ) -> PortResult<ResponseSnapshot> {
        let scheduler = self.scheduler.as_ref().ok_or_else(PortError::unavailable)?;
        let record = scheduler
            .load_plan(&ResponsePlanKey {
                tenant_id: request.tenant_id.clone(),
                action_id: request.action_id.clone(),
            })?
            .ok_or_else(PortError::integrity_failure)?;
        let snapshot =
            decode_response_record(&record).map_err(|_| PortError::integrity_failure())?;
        let planned_effect = snapshot
            .plan
            .effects
            .as_slice()
            .iter()
            .find(|effect| effect.effect_id == request.effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        let BlastRadiusResult::Exact {
            sorted_affected_ids,
            affected_set_hash,
            ..
        } = &spec.acquisition.approved_result
        else {
            return Err(PortError::integrity_failure());
        };
        if snapshot.plan.tenant_id != request.tenant_id
            || snapshot.plan.action_id != request.action_id
            || snapshot.plan.plan_hash != request.plan_hash
            || snapshot.plan.expires_at_unix_ms != request.plan_expires_at_unix_ms
            || planned_effect.kind != request.effect_kind
            || planned_effect.target != request.target
            || planned_effect.canonical_contribution != request.canonical_contribution
            || planned_effect.contribution_hash != request.contribution_hash
            || (request.operation == EffectOperation::Apply
                && planned_effect.observed_base_version_hash != request.expected_version_hash)
            || sorted_affected_ids != &snapshot.plan.affected_ids
            || *affected_set_hash != snapshot.plan.affected_set_hash
        {
            return Err(PortError::integrity_failure());
        }
        Ok(snapshot)
    }

    fn expected_fence(
        request: &EffectRequest,
        spec: &IssuanceFreezeSpec,
        lease_expires_at_unix_ms: u64,
    ) -> PortResult<LineageFenceRequest> {
        let BlastRadiusResult::Exact {
            metadata,
            affected_set_hash,
            ..
        } = &spec.acquisition.approved_result
        else {
            return Err(PortError::invalid_data());
        };
        Ok(LineageFenceRequest {
            tenant_id: spec.acquisition.request.tenant_id.clone(),
            action_id: spec.acquisition.request.action_id.clone(),
            expected_commit_index: metadata.commit_index,
            expected_affected_set_hash: *affected_set_hash,
            scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: request.scheduler_fencing_token,
            expires_at_unix_ms: lease_expires_at_unix_ms,
        })
    }

    fn exact_fence(expected: &LineageFenceRequest, fence: &LineageFence) -> bool {
        fence.tenant_id == expected.tenant_id
            && fence.action_id == expected.action_id
            && fence.commit_index == expected.expected_commit_index
            && fence.affected_set_hash == expected.expected_affected_set_hash
            && fence.fencing_token != 0
            && fence.scheduler_lease_owner_id == expected.scheduler_lease_owner_id
            && fence.scheduler_fencing_token == expected.scheduler_fencing_token
            && fence.expires_at_unix_ms >= expected.expires_at_unix_ms
    }

    fn query_exact_fence(
        &self,
        expected: &LineageFenceRequest,
    ) -> PortResult<Option<LineageFence>> {
        let fence = self.blast_radius.query_fence(expected)?;
        if fence
            .as_ref()
            .is_some_and(|stored| !Self::exact_fence(expected, stored))
        {
            return Err(PortError::integrity_failure());
        }
        Ok(fence)
    }

    fn acquire_or_recover_fence(
        &self,
        request: &EffectRequest,
        spec: &IssuanceFreezeSpec,
    ) -> PortResult<LineageFence> {
        let now_unix_ms = current_unix_ms()?;
        let lease_expires_at_unix_ms = spec.acquisition.expires_at_unix_ms;
        if lease_expires_at_unix_ms <= now_unix_ms
            || lease_expires_at_unix_ms.saturating_sub(now_unix_ms) > LINEAGE_FENCE_MAX_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let expected = Self::expected_fence(request, spec, lease_expires_at_unix_ms)?;
        if let Some(fence) = self.query_exact_fence(&expected)? {
            return Ok(fence);
        }
        match self
            .blast_radius
            .acquire_fence(&spec.acquisition, &expected)
        {
            Ok(fence) if Self::exact_fence(&expected, &fence) => Ok(fence),
            Ok(fence) => {
                if fence.tenant_id == expected.tenant_id
                    && fence.action_id == expected.action_id
                    && fence.fencing_token != 0
                {
                    self.blast_radius.release_fence(&LineageFenceRelease {
                        tenant_id: fence.tenant_id,
                        action_id: fence.action_id,
                        fencing_token: fence.fencing_token,
                        scheduler_lease_owner_id: fence.scheduler_lease_owner_id,
                        scheduler_fencing_token: fence.scheduler_fencing_token,
                    })?;
                }
                Err(PortError::integrity_failure())
            }
            Err(acquire_error) => match self.query_exact_fence(&expected) {
                Ok(Some(fence)) => Ok(fence),
                Ok(None) => Err(acquire_error),
                Err(query_error) => Err(query_error),
            },
        }
    }

    fn release_or_reconcile_fence(&self, fence: &LineageFence) -> PortResult<()> {
        let expected = LineageFenceRequest {
            tenant_id: fence.tenant_id.clone(),
            action_id: fence.action_id.clone(),
            expected_commit_index: fence.commit_index,
            expected_affected_set_hash: fence.affected_set_hash,
            scheduler_lease_owner_id: fence.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: fence.scheduler_fencing_token,
            expires_at_unix_ms: fence.expires_at_unix_ms,
        };
        let Some(stored) = self.query_exact_fence(&expected)? else {
            return Ok(());
        };
        let release = LineageFenceRelease {
            tenant_id: stored.tenant_id.clone(),
            action_id: stored.action_id.clone(),
            fencing_token: stored.fencing_token,
            scheduler_lease_owner_id: stored.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: stored.scheduler_fencing_token,
        };
        match self.blast_radius.release_fence(&release) {
            Ok(()) => Ok(()),
            Err(release_error) => match self.query_exact_fence(&expected) {
                Ok(None) => Ok(()),
                Ok(Some(remaining)) if remaining == stored => Err(release_error),
                Ok(Some(_)) => Err(PortError::integrity_failure()),
                Err(query_error) => Err(query_error),
            },
        }
    }

    fn contribution(
        request: &EffectRequest,
        spec: &IssuanceFreezeSpec,
        fence: LineageFence,
    ) -> PortResult<IssuanceFreezeContribution> {
        let BlastRadiusResult::Exact {
            metadata,
            sorted_affected_ids,
            affected_set_hash,
            graph_slice_hash,
        } = &spec.acquisition.approved_result
        else {
            return Err(PortError::invalid_data());
        };
        let contribution = IssuanceFreezeContribution {
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            commit_index: metadata.commit_index,
            affected_set_hash: *affected_set_hash,
            frozen_affected_ids: sorted_affected_ids.clone(),
            graph_slice_hash: *graph_slice_hash,
            external_fence: fence,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        let key = IssuanceFreezeKey {
            tenant_id: request.tenant_id.clone(),
            lineage_id: spec.lineage_id.clone(),
        };
        validate_issuance_freeze_contribution(&key, &contribution)?;
        Ok(contribution)
    }

    fn validate_completed_result(request: &EffectRequest, result: &EffectResult) -> PortResult<()> {
        if result.effect_id != request.effect_id
            || result.applied != matches!(request.operation, EffectOperation::Apply)
            || result.resulting_version_hash == Digest32::new([0_u8; 32])
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn operation_status(
        &self,
        request: &EffectRequest,
    ) -> PortResult<IssuanceFreezeOperationStatus> {
        let status = self
            .freezes
            .load_issuance_freeze_operation(&effect_query_from_request(request))?;
        if let IssuanceFreezeOperationStatus::Completed { result } = &status {
            Self::validate_completed_result(request, result)?;
        }
        Ok(status)
    }

    fn verify_active(
        &self,
        request: &EffectRequest,
        key: &IssuanceFreezeKey,
        contribution: &IssuanceFreezeContribution,
        result: &EffectResult,
    ) -> PortResult<()> {
        let snapshot = self
            .freezes
            .load_issuance_freezes(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_issuance_freeze_snapshot(&snapshot, key)?;
        if contribution.external_fence.scheduler_lease_owner_id != request.scheduler_lease_owner_id
            || contribution.external_fence.scheduler_fencing_token
                != request.scheduler_fencing_token
        {
            return Err(PortError::conflict());
        }
        if !snapshot
            .contributions
            .as_slice()
            .iter()
            .any(|entry| entry == contribution)
            || issuance_freeze_installed_version_hash(key, contribution)?
                != result.resulting_version_hash
            || self.operation_status(request)?
                != (IssuanceFreezeOperationStatus::Completed {
                    result: result.clone(),
                })
        {
            return Err(PortError::integrity_failure());
        }
        self.verify_active_query(&effect_query_from_request(request), key, result, false)
    }

    fn verify_active_query(
        &self,
        query: &EffectResultQuery,
        key: &IssuanceFreezeKey,
        result: &EffectResult,
        allow_scheduler_takeover: bool,
    ) -> PortResult<()> {
        let scheduler = self.scheduler.as_ref().ok_or_else(PortError::unavailable)?;
        let record = scheduler
            .load_plan(&ResponsePlanKey {
                tenant_id: query.tenant_id.clone(),
                action_id: query.action_id.clone(),
            })?
            .ok_or_else(PortError::integrity_failure)?;
        let response =
            decode_response_record(&record).map_err(|_| PortError::integrity_failure())?;
        let planned_effect = response
            .plan
            .effect(&query.effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        if response.plan.tenant_id != query.tenant_id
            || response.plan.action_id != query.action_id
            || response.plan.plan_hash != query.plan_hash
            || response.plan.expires_at_unix_ms != query.plan_expires_at_unix_ms
            || planned_effect.kind != query.effect_kind
            || planned_effect.target != query.target
            || planned_effect.contribution_hash != query.contribution_hash
            || planned_effect.observed_base_version_hash != query.expected_version_hash
        {
            return Err(PortError::integrity_failure());
        }

        let snapshot = self
            .freezes
            .load_issuance_freezes(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_issuance_freeze_snapshot(&snapshot, key)?;
        let contribution = snapshot
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.action_id == query.action_id && entry.effect_id == query.effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        let live_fence = &contribution.external_fence;
        let same_command_epoch = live_fence.scheduler_fencing_token
            == query.scheduler_fencing_token
            && live_fence.scheduler_lease_owner_id == query.scheduler_lease_owner_id;
        let valid_takeover = allow_scheduler_takeover
            && live_fence.scheduler_fencing_token > query.scheduler_fencing_token;
        if contribution.contribution_hash != query.contribution_hash
            || contribution.expires_at_unix_ms != query.plan_expires_at_unix_ms
            || issuance_freeze_installed_version_hash(key, contribution)?
                != result.resulting_version_hash
            || (!same_command_epoch && !valid_takeover)
        {
            return Err(PortError::integrity_failure());
        }
        scheduler.validate_lease_identity(
            &query.tenant_id,
            &query.action_id,
            &live_fence.scheduler_lease_owner_id,
            live_fence.scheduler_fencing_token,
        )?;
        let expected = LineageFenceRequest {
            tenant_id: live_fence.tenant_id.clone(),
            action_id: live_fence.action_id.clone(),
            expected_commit_index: live_fence.commit_index,
            expected_affected_set_hash: live_fence.affected_set_hash,
            scheduler_lease_owner_id: live_fence.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: live_fence.scheduler_fencing_token,
            expires_at_unix_ms: live_fence.expires_at_unix_ms,
        };
        match self.query_exact_fence(&expected)? {
            Some(stored) if stored == *live_fence => Ok(()),
            Some(_) | None => Err(PortError::integrity_failure()),
        }
    }

    fn verify_lifted(
        &self,
        request: &EffectRequest,
        key: &IssuanceFreezeKey,
        contribution: &IssuanceFreezeContribution,
        result: &EffectResult,
    ) -> PortResult<()> {
        let snapshot = self.load_snapshot(key)?;
        if snapshot.contributions.as_slice().iter().any(|entry| {
            entry.action_id == contribution.action_id && entry.effect_id == contribution.effect_id
        }) || issuance_freeze_version_hash(&snapshot)? != result.resulting_version_hash
            || self.operation_status(request)?
                != (IssuanceFreezeOperationStatus::Completed {
                    result: result.clone(),
                })
        {
            return Err(PortError::integrity_failure());
        }
        let expected = LineageFenceRequest {
            tenant_id: contribution.external_fence.tenant_id.clone(),
            action_id: contribution.external_fence.action_id.clone(),
            expected_commit_index: contribution.external_fence.commit_index,
            expected_affected_set_hash: contribution.external_fence.affected_set_hash,
            scheduler_lease_owner_id: contribution.external_fence.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: contribution.external_fence.scheduler_fencing_token,
            expires_at_unix_ms: contribution.external_fence.expires_at_unix_ms,
        };
        if self.query_exact_fence(&expected)?.is_some() {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: IssuanceFreezeKey,
        spec: IssuanceFreezeSpec,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let existing = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .cloned();
        if existing.is_none()
            && issuance_freeze_version_hash(&current)? != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        let fence = self.acquire_or_recover_fence(request, &spec)?;
        let derived_contribution = match Self::contribution(request, &spec, fence.clone()) {
            Ok(contribution) => contribution,
            Err(error) => {
                if existing.is_none() {
                    self.release_or_reconcile_fence(&fence)?;
                }
                return Err(error);
            }
        };
        let contribution = if let Some(existing) = existing.as_ref() {
            let same_immutable_binding = existing.action_id == derived_contribution.action_id
                && existing.effect_id == derived_contribution.effect_id
                && existing.commit_index == derived_contribution.commit_index
                && existing.affected_set_hash == derived_contribution.affected_set_hash
                && existing.frozen_affected_ids == derived_contribution.frozen_affected_ids
                && existing.graph_slice_hash == derived_contribution.graph_slice_hash
                && existing.external_fence.tenant_id
                    == derived_contribution.external_fence.tenant_id
                && existing.external_fence.action_id
                    == derived_contribution.external_fence.action_id
                && existing.external_fence.commit_index
                    == derived_contribution.external_fence.commit_index
                && existing.external_fence.affected_set_hash
                    == derived_contribution.external_fence.affected_set_hash
                && existing.external_fence.fencing_token
                    == derived_contribution.external_fence.fencing_token
                && existing.external_fence.scheduler_lease_owner_id
                    == derived_contribution.external_fence.scheduler_lease_owner_id
                && existing.external_fence.scheduler_fencing_token
                    == derived_contribution.external_fence.scheduler_fencing_token
                && existing.external_fence.expires_at_unix_ms
                    <= derived_contribution.external_fence.expires_at_unix_ms
                && existing.contribution_hash == derived_contribution.contribution_hash
                && existing.expires_at_unix_ms == derived_contribution.expires_at_unix_ms;
            if !same_immutable_binding {
                return Err(PortError::conflict());
            }
            existing.clone()
        } else {
            derived_contribution
        };
        let predicted = match predict_issuance_freeze_apply(
            &current,
            &contribution,
            request.scheduler_fencing_token,
        ) {
            Ok(predicted) => predicted,
            Err(error) => {
                if existing.is_none() {
                    self.release_or_reconcile_fence(&fence)?;
                }
                return Err(error);
            }
        };
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: issuance_freeze_installed_version_hash(&key, &contribution)?,
            applied: true,
        };
        let apply = IssuanceFreezeApplyRequest {
            key: key.clone(),
            contribution: contribution.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: IssuanceFreezeCommand {
                request: request.clone(),
                result: result.clone(),
                resulting_snapshot: predicted,
            },
        };
        if let Err(apply_error) = self.freezes.apply_issuance_freeze(&apply) {
            return match self.operation_status(request) {
                Ok(IssuanceFreezeOperationStatus::Completed { result: stored })
                    if stored == result =>
                {
                    self.verify_active(request, &key, &contribution, &stored)?;
                    Ok(stored)
                }
                Ok(IssuanceFreezeOperationStatus::Completed { .. })
                | Ok(IssuanceFreezeOperationStatus::ReleasePending { .. }) => {
                    Err(PortError::integrity_failure())
                }
                Ok(IssuanceFreezeOperationStatus::NotExecuted) => {
                    self.release_or_reconcile_fence(&fence)?;
                    Err(apply_error)
                }
                Err(reconcile_error) => Err(reconcile_error),
            };
        }
        self.verify_active(request, &key, &contribution, &result)?;
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: IssuanceFreezeKey,
        spec: IssuanceFreezeSpec,
        initial_status: IssuanceFreezeOperationStatus,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let contribution = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .cloned()
            .ok_or_else(PortError::conflict)?;
        let expected_contribution =
            Self::contribution(request, &spec, contribution.external_fence.clone())?;
        if contribution != expected_contribution
            || issuance_freeze_installed_version_hash(&key, &contribution)?
                != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        let predicted = predict_issuance_freeze_remove(
            &current,
            &request.action_id,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: issuance_freeze_version_hash(&predicted)?,
            applied: false,
        };
        let remove = IssuanceFreezeRemoveRequest {
            key: key.clone(),
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: IssuanceFreezeCommand {
                request: request.clone(),
                result: result.clone(),
                resulting_snapshot: predicted,
            },
        };
        let pending_contribution = match initial_status {
            IssuanceFreezeOperationStatus::NotExecuted => {
                match self.freezes.prepare_issuance_freeze_remove(&remove) {
                    Ok(prepared) => prepared,
                    Err(prepare_error) => match self.operation_status(request) {
                        Ok(IssuanceFreezeOperationStatus::ReleasePending { contribution }) => {
                            *contribution
                        }
                        Ok(IssuanceFreezeOperationStatus::Completed { result: stored })
                            if stored == result =>
                        {
                            self.verify_lifted(request, &key, &contribution, &stored)?;
                            return Ok(stored);
                        }
                        Ok(IssuanceFreezeOperationStatus::NotExecuted) => {
                            return Err(prepare_error);
                        }
                        Ok(_) => return Err(PortError::integrity_failure()),
                        Err(reconcile_error) => return Err(reconcile_error),
                    },
                }
            }
            IssuanceFreezeOperationStatus::ReleasePending { contribution } => *contribution,
            IssuanceFreezeOperationStatus::Completed { .. } => {
                return Err(PortError::integrity_failure());
            }
        };
        if pending_contribution != contribution {
            return Err(PortError::integrity_failure());
        }
        self.release_or_reconcile_fence(&contribution.external_fence)?;
        if let Err(complete_error) = self.freezes.complete_issuance_freeze_remove(&remove) {
            return match self.operation_status(request) {
                Ok(IssuanceFreezeOperationStatus::Completed { result: stored })
                    if stored == result =>
                {
                    self.verify_lifted(request, &key, &contribution, &stored)?;
                    Ok(stored)
                }
                Ok(IssuanceFreezeOperationStatus::ReleasePending {
                    contribution: pending,
                }) if *pending == contribution => Err(complete_error),
                Ok(_) => Err(PortError::integrity_failure()),
                Err(reconcile_error) => Err(reconcile_error),
            };
        }
        self.verify_lifted(request, &key, &contribution, &result)?;
        Ok(result)
    }

    fn maintenance_effect_request(
        &self,
        effect: &chio_security_types::PlannedResponseEffect,
        maintenance: &LineageFenceMaintenanceRequest,
    ) -> PortResult<EffectRequest> {
        Ok(EffectRequest {
            tenant_id: maintenance.plan.tenant_id.clone(),
            action_id: maintenance.plan.action_id.clone(),
            plan_hash: maintenance.plan.plan_hash,
            effect_id: effect.effect_id.clone(),
            effect_kind: effect.kind,
            target: effect.target.clone(),
            plan_expires_at_unix_ms: maintenance.plan.expires_at_unix_ms,
            operation: EffectOperation::Apply,
            idempotency_key: RecordId::new(format!(
                "response_effect_command:lineage-fence-maintenance:{}:{}",
                effect.effect_id.as_str(),
                maintenance.scheduler_work.fencing_token
            ))
            .map_err(PortError::from)?,
            expected_version_hash: effect.observed_base_version_hash,
            scheduler_lease_owner_id: maintenance.scheduler_work.lease_owner_id.clone(),
            scheduler_fencing_token: maintenance.scheduler_work.fencing_token,
            canonical_contribution: effect.canonical_contribution.clone(),
            contribution_hash: effect.contribution_hash,
        })
    }

    fn exact_maintained_fence(
        before: &LineageFence,
        work: &ScheduledWork,
        renewed_expires_at_unix_ms: u64,
        maintained: &LineageFence,
    ) -> bool {
        let same_scheduler_epoch = work.lease_owner_id == before.scheduler_lease_owner_id
            && work.fencing_token == before.scheduler_fencing_token;
        let exact_fencing_transition = if same_scheduler_epoch {
            maintained.fencing_token == before.fencing_token
        } else {
            work.fencing_token > before.scheduler_fencing_token
                && maintained.fencing_token > before.fencing_token
        };
        maintained.tenant_id == before.tenant_id
            && maintained.action_id == before.action_id
            && maintained.commit_index == before.commit_index
            && maintained.affected_set_hash == before.affected_set_hash
            && exact_fencing_transition
            && maintained.scheduler_lease_owner_id == work.lease_owner_id
            && maintained.scheduler_fencing_token == work.fencing_token
            && maintained.expires_at_unix_ms == renewed_expires_at_unix_ms
    }

    fn query_maintained_fence(
        &self,
        before: &LineageFence,
        work: &ScheduledWork,
        renewed_expires_at_unix_ms: u64,
    ) -> PortResult<Option<LineageFence>> {
        self.query_exact_fence(&LineageFenceRequest {
            tenant_id: before.tenant_id.clone(),
            action_id: before.action_id.clone(),
            expected_commit_index: before.commit_index,
            expected_affected_set_hash: before.affected_set_hash,
            scheduler_lease_owner_id: work.lease_owner_id.clone(),
            scheduler_fencing_token: work.fencing_token,
            expires_at_unix_ms: renewed_expires_at_unix_ms,
        })
    }

    fn validate_pending_release_order(
        response: &ResponseSnapshot,
        effect_id: &EffectId,
    ) -> PortResult<()> {
        let effect_index = response
            .plan
            .effects
            .as_slice()
            .iter()
            .position(|effect| &effect.effect_id == effect_id)
            .ok_or_else(PortError::integrity_failure)?;
        if !matches!(
            response.state,
            ResponseState::RollingBack | ResponseState::RollbackPartial
        ) || !matches!(
            response.effect_progress(effect_id),
            Some(
                ResponseEffectProgress::RollbackRequested | ResponseEffectProgress::RollbackFailed
            )
        ) {
            return Err(PortError::conflict());
        }
        for effect in &response.plan.effects.as_slice()[effect_index.saturating_add(1)..] {
            if !effect.kind.is_reversible() {
                continue;
            }
            if matches!(
                response.effect_progress(&effect.effect_id),
                Some(
                    ResponseEffectProgress::Requested
                        | ResponseEffectProgress::Applied
                        | ResponseEffectProgress::RollbackRequested
                        | ResponseEffectProgress::RollbackFailed
                )
            ) {
                return Err(PortError::conflict());
            }
        }
        Ok(())
    }

    fn validate_release_command_binding(
        maintenance_request: &EffectRequest,
        key: &IssuanceFreezeKey,
        command: &IssuanceFreezeCommand,
    ) -> PortResult<()> {
        let command_request = &command.request;
        if command_request.tenant_id != maintenance_request.tenant_id
            || !matches!(
                &command_request.target,
                ResponseTarget::Lineage { lineage_id } if lineage_id == &key.lineage_id
            )
            || command_request.action_id != maintenance_request.action_id
            || command_request.plan_hash != maintenance_request.plan_hash
            || command_request.effect_id != maintenance_request.effect_id
            || command_request.effect_kind != maintenance_request.effect_kind
            || command_request.target != maintenance_request.target
            || command_request.plan_expires_at_unix_ms
                != maintenance_request.plan_expires_at_unix_ms
            || command_request.operation != EffectOperation::Remove
            || command_request.canonical_contribution != maintenance_request.canonical_contribution
            || command_request.contribution_hash != maintenance_request.contribution_hash
            || command.result.effect_id != maintenance_request.effect_id
            || command.result.applied
        {
            return Err(PortError::integrity_failure());
        }
        validate_issuance_freeze_snapshot(&command.resulting_snapshot, key)
            .map_err(|_| PortError::integrity_failure())?;
        if command
            .resulting_snapshot
            .contributions
            .as_slice()
            .iter()
            .any(|entry| {
                entry.action_id == maintenance_request.action_id
                    && entry.effect_id == maintenance_request.effect_id
            })
            || issuance_freeze_version_hash(&command.resulting_snapshot)?
                != command.result.resulting_version_hash
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn recover_pending_release(
        &self,
        maintenance_request: &EffectRequest,
        key: &IssuanceFreezeKey,
        response: &ResponseSnapshot,
    ) -> PortResult<bool> {
        let pending = self.freezes.load_pending_issuance_freeze_release(
            key,
            &maintenance_request.action_id,
            &maintenance_request.effect_id,
        )?;
        let Some(IssuanceFreezePendingRelease {
            request,
            contribution,
        }) = pending
        else {
            let Some(command) = self.freezes.load_completed_issuance_freeze_release(
                key,
                &maintenance_request.action_id,
                &maintenance_request.effect_id,
                maintenance_request.plan_hash,
            )?
            else {
                return Ok(false);
            };
            Self::validate_pending_release_order(response, &maintenance_request.effect_id)?;
            Self::validate_release_command_binding(maintenance_request, key, &command)?;
            if self.load_snapshot(key)? != command.resulting_snapshot {
                return Err(PortError::integrity_failure());
            }
            return Ok(true);
        };
        Self::validate_pending_release_order(response, &maintenance_request.effect_id)?;
        Self::validate_release_command_binding(maintenance_request, key, &request.command)?;
        if request.key != *key
            || request.action_id != maintenance_request.action_id
            || request.effect_id != maintenance_request.effect_id
        {
            return Err(PortError::integrity_failure());
        }
        let command_request = &request.command.request;
        if contribution.action_id != maintenance_request.action_id
            || contribution.effect_id != maintenance_request.effect_id
            || issuance_freeze_installed_version_hash(key, &contribution)?
                != command_request.expected_version_hash
        {
            return Err(PortError::integrity_failure());
        }
        let expected_result = request.command.result.clone();
        self.release_or_reconcile_fence(&contribution.external_fence)?;
        if let Err(complete_error) = self.freezes.complete_issuance_freeze_remove(&request) {
            match self.operation_status(command_request) {
                Ok(IssuanceFreezeOperationStatus::Completed { result })
                    if result == expected_result => {}
                Ok(IssuanceFreezeOperationStatus::ReleasePending {
                    contribution: pending,
                }) if *pending == contribution => return Err(complete_error),
                Ok(_) => return Err(PortError::integrity_failure()),
                Err(reconcile_error) => return Err(reconcile_error),
            }
        }
        self.verify_lifted(command_request, key, &contribution, &expected_result)?;
        Ok(true)
    }

    fn maintain_external_fence(
        &self,
        effect: &chio_security_types::PlannedResponseEffect,
        maintenance: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceResult> {
        if !maintenance
            .effect_ids
            .iter()
            .any(|id| id == &effect.effect_id)
        {
            return Err(PortError::invalid_data());
        }
        if maintenance.observed_at_unix_ms < maintenance.plan.created_at_unix_ms
            || maintenance.renewed_expires_at_unix_ms <= maintenance.observed_at_unix_ms
            || maintenance
                .renewed_expires_at_unix_ms
                .saturating_sub(maintenance.observed_at_unix_ms)
                > LINEAGE_FENCE_MAX_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let scheduler = self.scheduler.as_ref().ok_or_else(PortError::unavailable)?;
        scheduler.validate_lease(&maintenance.scheduler_work)?;
        let request = self.maintenance_effect_request(effect, maintenance)?;
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        let spec = decode_issuance_freeze_spec(&request, &key)?;
        let response = self.validate_plan_binding(&request, &spec)?;
        if response.state.is_terminal()
            || !matches!(
                response.effect_progress(&effect.effect_id),
                Some(
                    ResponseEffectProgress::Applied
                        | ResponseEffectProgress::RollbackRequested
                        | ResponseEffectProgress::RollbackFailed
                )
            )
        {
            return Err(PortError::conflict());
        }
        if self.recover_pending_release(&request, &key, &response)? {
            return Ok(LineageFenceMaintenanceResult::ReleaseCompleted);
        }
        let snapshot = self
            .freezes
            .load_issuance_freezes(&key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_issuance_freeze_snapshot(&snapshot, &key)?;
        let contribution = snapshot
            .contributions
            .as_slice()
            .iter()
            .find(|entry| {
                entry.action_id == request.action_id && entry.effect_id == request.effect_id
            })
            .ok_or_else(PortError::integrity_failure)?;
        let derived = Self::contribution(&request, &spec, contribution.external_fence.clone())?;
        if &derived != contribution
            || maintenance.renewed_expires_at_unix_ms
                < contribution.external_fence.expires_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        let before = contribution.external_fence.clone();
        if maintenance.scheduler_work.fencing_token < before.scheduler_fencing_token {
            return Err(PortError::conflict());
        }
        let same_scheduler_epoch = maintenance.scheduler_work.lease_owner_id
            == before.scheduler_lease_owner_id
            && maintenance.scheduler_work.fencing_token == before.scheduler_fencing_token;
        let maintained = if same_scheduler_epoch
            && maintenance.renewed_expires_at_unix_ms == before.expires_at_unix_ms
        {
            self.query_exact_fence(&LineageFenceRequest {
                tenant_id: before.tenant_id.clone(),
                action_id: before.action_id.clone(),
                expected_commit_index: before.commit_index,
                expected_affected_set_hash: before.affected_set_hash,
                scheduler_lease_owner_id: before.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: before.scheduler_fencing_token,
                expires_at_unix_ms: before.expires_at_unix_ms,
            })?
            .ok_or_else(PortError::integrity_failure)?
        } else if same_scheduler_epoch {
            let renewal = LineageFenceRenewal {
                tenant_id: before.tenant_id.clone(),
                action_id: before.action_id.clone(),
                fencing_token: before.fencing_token,
                scheduler_lease_owner_id: before.scheduler_lease_owner_id.clone(),
                scheduler_fencing_token: before.scheduler_fencing_token,
                expected_expires_at_unix_ms: before.expires_at_unix_ms,
                renewed_expires_at_unix_ms: maintenance.renewed_expires_at_unix_ms,
            };
            match self.blast_radius.renew_fence(&renewal) {
                Ok(renewed) => renewed,
                Err(renew_error) => match self.query_maintained_fence(
                    &before,
                    &maintenance.scheduler_work,
                    maintenance.renewed_expires_at_unix_ms,
                ) {
                    Ok(Some(renewed)) => renewed,
                    Ok(None) => return Err(renew_error),
                    Err(readback_error) => return Err(readback_error),
                },
            }
        } else {
            if maintenance.scheduler_work.fencing_token <= before.scheduler_fencing_token {
                return Err(PortError::conflict());
            }
            let takeover = LineageFenceTakeover {
                tenant_id: before.tenant_id.clone(),
                action_id: before.action_id.clone(),
                expected_fencing_token: before.fencing_token,
                expected_scheduler_lease_owner_id: before.scheduler_lease_owner_id.clone(),
                expected_scheduler_fencing_token: before.scheduler_fencing_token,
                expected_expires_at_unix_ms: before.expires_at_unix_ms,
                successor_scheduler_lease_owner_id: maintenance
                    .scheduler_work
                    .lease_owner_id
                    .clone(),
                successor_scheduler_fencing_token: maintenance.scheduler_work.fencing_token,
                successor_expires_at_unix_ms: maintenance.renewed_expires_at_unix_ms,
            };
            match self.blast_radius.takeover_fence(&takeover) {
                Ok(taken_over) => taken_over,
                Err(takeover_error) => match self.query_maintained_fence(
                    &before,
                    &maintenance.scheduler_work,
                    maintenance.renewed_expires_at_unix_ms,
                ) {
                    Ok(Some(taken_over)) => taken_over,
                    Ok(None) => return Err(takeover_error),
                    Err(readback_error) => return Err(readback_error),
                },
            }
        };
        if !Self::exact_maintained_fence(
            &before,
            &maintenance.scheduler_work,
            maintenance.renewed_expires_at_unix_ms,
            &maintained,
        ) {
            return Err(PortError::integrity_failure());
        }
        let persistence_request = IssuanceFreezeFenceMaintenanceRequest {
            key: key.clone(),
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            expected_external_fence: before,
            maintained_external_fence: maintained.clone(),
            scheduler_work: maintenance.scheduler_work.clone(),
        };
        let persisted = match self
            .freezes
            .maintain_issuance_freeze_fence(&persistence_request)
        {
            Ok(snapshot) => snapshot,
            Err(persistence_error) => {
                let readback = self
                    .freezes
                    .load_issuance_freezes(&key)?
                    .ok_or_else(PortError::integrity_failure)?;
                if readback.contributions.as_slice().iter().any(|entry| {
                    entry.action_id == request.action_id
                        && entry.effect_id == request.effect_id
                        && entry.external_fence == maintained
                }) {
                    readback
                } else {
                    return Err(persistence_error);
                }
            }
        };
        validate_issuance_freeze_snapshot(&persisted, &key)?;
        if !persisted.contributions.as_slice().iter().any(|entry| {
            entry.action_id == request.action_id
                && entry.effect_id == request.effect_id
                && entry.external_fence == maintained
        }) {
            return Err(PortError::integrity_failure());
        }
        Ok(LineageFenceMaintenanceResult::Maintained(maintained))
    }
}

impl ResponseEffectBackend for IssuanceFreezeBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::FreezeIssuance
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.scheduler.as_ref().ok_or_else(PortError::unavailable)?;
        self.freezes.ensure_issuance_freezes_ready()?;
        self.blast_radius.ensure_blast_radius_ready()
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
        if request.effect_kind != ResponseEffectKind::FreezeIssuance {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        let spec = decode_issuance_freeze_spec(request, &key)?;
        self.validate_plan_binding(request, &spec)?;
        let status = self.operation_status(request)?;
        if let IssuanceFreezeOperationStatus::Completed { result } = status {
            match request.operation {
                EffectOperation::Apply => {
                    let snapshot = self.load_snapshot(&key)?;
                    let contribution = snapshot
                        .contributions
                        .as_slice()
                        .iter()
                        .find(|entry| {
                            entry.action_id == request.action_id
                                && entry.effect_id == request.effect_id
                        })
                        .cloned()
                        .ok_or_else(PortError::integrity_failure)?;
                    self.verify_active(request, &key, &contribution, &result)?;
                }
                EffectOperation::Remove => {
                    let expected =
                        Self::expected_fence(request, &spec, request.plan_expires_at_unix_ms)?;
                    if self.query_exact_fence(&expected)?.is_some() {
                        return Err(PortError::integrity_failure());
                    }
                    let snapshot = self.load_snapshot(&key)?;
                    if snapshot.contributions.as_slice().iter().any(|entry| {
                        entry.action_id == request.action_id && entry.effect_id == request.effect_id
                    }) {
                        return Err(PortError::integrity_failure());
                    }
                }
            }
            return Ok(result);
        }
        match request.operation {
            EffectOperation::Apply => match status {
                IssuanceFreezeOperationStatus::NotExecuted => {
                    self.execute_apply(request, key, spec)
                }
                IssuanceFreezeOperationStatus::ReleasePending { .. }
                | IssuanceFreezeOperationStatus::Completed { .. } => {
                    Err(PortError::integrity_failure())
                }
            },
            EffectOperation::Remove => self.execute_remove(request, key, spec, status),
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
        if query.effect_kind != ResponseEffectKind::FreezeIssuance {
            return Err(PortError::invalid_data());
        }
        self.key(&query.tenant_id, &query.target)?;
        match self.freezes.load_issuance_freeze_operation(query)? {
            IssuanceFreezeOperationStatus::NotExecuted => Ok(EffectExecutionStatus::NotExecuted),
            IssuanceFreezeOperationStatus::ReleasePending { .. } => {
                Ok(EffectExecutionStatus::Unknown)
            }
            IssuanceFreezeOperationStatus::Completed { result } => {
                if result.effect_id != query.effect_id
                    || result.applied != matches!(query.operation, EffectOperation::Apply)
                    || result.resulting_version_hash == Digest32::new([0_u8; 32])
                {
                    return Err(PortError::integrity_failure());
                }
                if query.operation == EffectOperation::Apply {
                    let key = self.key(&query.tenant_id, &query.target)?;
                    self.verify_active_query(query, &key, &result, true)?;
                }
                Ok(EffectExecutionStatus::Completed { result })
            }
        }
    }

    fn maintain_lineage_fence(
        &self,
        effect: &chio_security_types::PlannedResponseEffect,
        request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceResult> {
        if effect.kind != ResponseEffectKind::FreezeIssuance {
            return Err(PortError::invalid_data());
        }
        self.maintain_external_fence(effect, request)
    }
}

fn decode_issuance_freeze_spec(
    request: &EffectRequest,
    key: &IssuanceFreezeKey,
) -> PortResult<IssuanceFreezeSpec> {
    let spec: IssuanceFreezeSpec =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .map_err(|_| PortError::invalid_data())?;
    let canonical =
        chio_core::canonical_json_bytes(&spec).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != request.canonical_contribution.as_bytes()
        || spec.lineage_id != key.lineage_id
        || spec.acquisition.request.tenant_id != request.tenant_id
        || spec.acquisition.request.action_id != request.action_id
        || spec.acquisition.expires_at_unix_ms == 0
        || spec.acquisition.expires_at_unix_ms > request.plan_expires_at_unix_ms
    {
        return Err(PortError::invalid_data());
    }
    let root = RecordId::new(key.lineage_id.as_str()).map_err(PortError::from)?;
    if spec.acquisition.request.seed_ids.len() != 1
        || spec.acquisition.request.seed_ids.as_slice().first() != Some(&root)
    {
        return Err(PortError::invalid_data());
    }
    let BlastRadiusResult::Exact {
        metadata,
        sorted_affected_ids,
        affected_set_hash,
        graph_slice_hash,
    } = &spec.acquisition.approved_result
    else {
        return Err(PortError::invalid_data());
    };
    let bounds = &spec.acquisition.request.query_bounds;
    if bounds.max_depth == 0
        || bounds.max_nodes == 0
        || bounds.max_edges == 0
        || metadata.query_bounds != *bounds
        || metadata.source_lineage_version == 0
        || metadata.commit_index == 0
        || metadata.commit_index != metadata.authoritative_commit_index
        || metadata
            .completeness_watermark
            .is_none_or(|watermark| watermark < metadata.commit_index)
        || sorted_affected_ids.as_slice().binary_search(&root).is_err()
        || response_affected_set_hash(&request.tenant_id, sorted_affected_ids)?
            != *affected_set_hash
        || *graph_slice_hash == Digest32::new([0_u8; 32])
    {
        return Err(PortError::invalid_data());
    }
    Ok(spec)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionSuspensionContribution {
    posture_rank: u32,
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestrictEgressContribution {
    destinations: EgressDestinationSet,
}

/// Exact destination-aware `RestrictEgress` backend.
///
/// The store owns a distinct effect-keyed contribution for every response.
/// Destination unions are recomputed from all contributions, so removing one
/// response cannot lift an overlapping destination restriction.
pub struct RestrictEgressOverlayBackend {
    restrictions: Arc<dyn EgressRestrictionStore>,
}
