impl InMemoryBudgetStoreInner {
    fn next_composite_seq(&self) -> Result<u64, BudgetStoreError> {
        self.next_seq
            .checked_add(1)
            .ok_or_else(|| BudgetStoreError::Overflow("budget sequence overflowed u64".to_string()))
    }

    fn composite_metadata(
        authority: Option<BudgetEventAuthority>,
        budget_commit_index: Option<u64>,
        event_id: String,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority,
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index,
            event_id: Some(event_id),
            partition_escrow_evidence: None,
        }
    }

    fn composite_duplicate(
        &self,
        event_id: &str,
        request: &CompositeMutationRequest,
    ) -> Result<Option<CompositeMutationDecision>, BudgetStoreError> {
        if event_id.starts_with(LOCAL_BUDGET_EVENT_PREFIX) {
            return Err(BudgetStoreError::Invariant(
                "explicit budget event_id uses the reserved local namespace".to_string(),
            ));
        }
        if self.explicit_events.contains_key(event_id) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused across mutation namespaces"
            )));
        }
        let Some(existing) = self.composite_events.get(event_id) else {
            if self
                .events
                .iter()
                .any(|existing| existing.event_id == event_id)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{event_id}` was reused across mutation namespaces"
                )));
            }
            return Ok(None);
        };
        if &existing.request != request {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{event_id}` was reused for a different composite mutation"
            )));
        }
        Ok(Some(existing.decision.clone()))
    }

    fn record_composite_mutation(
        &mut self,
        event_id: String,
        request: CompositeMutationRequest,
        decision: CompositeMutationDecision,
        record: BudgetMutationRecord,
    ) {
        self.events.push(record);
        self.composite_events
            .insert(event_id, RecordedCompositeMutation { request, decision });
    }

    fn monetary_present(request: &BudgetAuthorizeHoldRequest) -> bool {
        request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
    }

    fn usage_from_counter(
        quota: &BudgetInvocationQuota,
        counter: &InvocationQuotaCounter,
    ) -> BudgetInvocationQuotaUsage {
        BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations_after: counter.reserved_count,
            captured_invocations_after: counter.captured_count,
        }
    }

    fn compare_and_mutate_invocation_quotas<F>(
        &mut self,
        quotas: &[BudgetInvocationQuota],
        primary_key: &BudgetQuotaKey,
        primary_usage_count: u32,
        mode: InvocationQuotaMutationMode,
        action: InvocationQuotaMutationAction,
        external_gate: F,
    ) -> Result<InvocationQuotaMutationOutcome, BudgetStoreError>
    where
        F: FnOnce() -> Result<bool, BudgetStoreError>,
    {
        if mode == InvocationQuotaMutationMode::CaptureCompatibility {
            let [quota] = quotas else {
                return Err(BudgetStoreError::Invariant(
                    "compatibility capture requires exactly one primary grant quota".to_string(),
                ));
            };
            if &quota.key != primary_key
                || primary_key.profile != BudgetQuotaProfile::GrantInvocation
            {
                return Err(BudgetStoreError::Invariant(
                    "compatibility capture requires exactly one primary grant quota".to_string(),
                ));
            }
        }
        let mut staged = Vec::with_capacity(quotas.len());
        let mut quota_exhausted = false;
        for quota in quotas {
            quota.validate()?;
            let counter = if let Some(existing) = self.invocation_quotas.get(&quota.key) {
                if existing.max_invocations != quota.max_invocations {
                    return Err(BudgetStoreError::Invariant(format!(
                        "invocation quota `{}` was presented with a different maximum",
                        quota.key.owner_id
                    )));
                }
                existing.clone()
            } else {
                InvocationQuotaCounter {
                    max_invocations: quota.max_invocations,
                    reserved_count: 0,
                    captured_count: if &quota.key == primary_key {
                        primary_usage_count
                    } else {
                        0
                    },
                    compatibility_reversible_count: if mode
                        == InvocationQuotaMutationMode::CaptureCompatibility
                        && action == InvocationQuotaMutationAction::Reverse
                        && &quota.key == primary_key
                    {
                        primary_usage_count
                    } else {
                        0
                    },
                }
            };
            let current_count = counter.invocation_count()?;
            if current_count > quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key.owner_id
                )));
            }
            if mode == InvocationQuotaMutationMode::CaptureCompatibility
                && counter.reserved_count != 0
            {
                return Err(BudgetStoreError::Invariant(
                    "compatibility capture cannot mutate reserved invocation authority".to_string(),
                ));
            }
            quota_exhausted |= current_count == quota.max_invocations;
            staged.push((quota.clone(), counter));
        }
        let primary_before = staged
            .iter()
            .find(|(quota, _)| &quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .1
            .invocation_count()?;
        if primary_before != primary_usage_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from structured invocation quota".to_string(),
            ));
        }

        let allowed = match action {
            InvocationQuotaMutationAction::Attempt => {
                let external_denied = if quota_exhausted {
                    false
                } else {
                    external_gate()?
                };
                let allowed = !quota_exhausted && !external_denied;
                if allowed {
                    for (_, counter) in &mut staged {
                        match mode {
                            InvocationQuotaMutationMode::Reserve => {
                                counter.reserved_count =
                                    counter.reserved_count.checked_add(1).ok_or_else(|| {
                                        BudgetStoreError::Overflow(
                                            "reserved invocation count overflowed u32".to_string(),
                                        )
                                    })?;
                            }
                            InvocationQuotaMutationMode::CaptureCompatibility => {
                                counter.captured_count =
                                    counter.captured_count.checked_add(1).ok_or_else(|| {
                                        BudgetStoreError::Overflow(
                                            "captured invocation count overflowed u32".to_string(),
                                        )
                                    })?;
                                counter.compatibility_reversible_count = counter
                                    .compatibility_reversible_count
                                    .checked_add(1)
                                    .ok_or_else(|| {
                                        BudgetStoreError::Overflow(
                                            "compatibility reversible invocation count overflowed u32"
                                                .to_string(),
                                        )
                                    })?;
                            }
                        }
                    }
                }
                allowed
            }
            InvocationQuotaMutationAction::Reverse => {
                if mode != InvocationQuotaMutationMode::CaptureCompatibility {
                    return Err(BudgetStoreError::Invariant(
                        "only compatibility capture authority can be reversed".to_string(),
                    ));
                }
                for (_, counter) in &mut staged {
                    if counter.compatibility_reversible_count == 0 {
                        return Err(BudgetStoreError::Invariant(
                            "compatibility capture has no reversible invocation".to_string(),
                        ));
                    }
                    counter.captured_count =
                        counter.captured_count.checked_sub(1).ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "compatibility capture has no captured invocation".to_string(),
                            )
                        })?;
                    counter.compatibility_reversible_count = counter
                        .compatibility_reversible_count
                        .checked_sub(1)
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "compatibility capture has no reversible invocation".to_string(),
                            )
                        })?;
                }
                true
            }
        };

        let invocation_counts_after = staged
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        for usage in &invocation_counts_after {
            usage.validate()?;
        }
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| &usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        for (quota, counter) in staged {
            self.invocation_quotas.insert(quota.key, counter);
        }
        Ok(InvocationQuotaMutationOutcome {
            allowed,
            invocation_counts_after,
            primary_count_after,
        })
    }

    fn invocation_usages(
        &self,
        quotas: &[BudgetInvocationQuota],
    ) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        quotas
            .iter()
            .map(|quota| {
                let counter = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
                Ok(Self::usage_from_counter(quota, counter))
            })
            .collect()
    }

    fn validate_composite_hold_identity(
        hold_id: &str,
        hold: &CompositeBudgetHoldState,
        capability_id: &str,
        grant_index: usize,
        authority: Option<&BudgetEventAuthority>,
        admission_operation: Option<&super::BudgetAdmissionOperationBinding>,
    ) -> Result<(), BudgetStoreError> {
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
        if hold.admission_operation.as_ref() != admission_operation {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` belongs to a different admission operation"
            )));
        }
        Ok(())
    }

    fn authorize_composite_budget_hold(
        &mut self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.invocation_quotas().is_empty() {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold requires invocation quotas".to_string(),
            ));
        }
        if request.max_invocations.is_some() {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold must not also present legacy max_invocations".to_string(),
            ));
        }
        validate_invocation_quotas(request.invocation_quotas())?;
        let invocation_admission = request.invocation_admission.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "composite budget hold requires verified invocation admission".to_string(),
            )
        })?;
        let manages_multiple_quotas = invocation_admission.quotas().len() > 1;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget hold requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite budget hold requires event_id".to_string())
        })?;
        let revocation_set = request.revocation_set().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "composite budget hold requires a canonical revocation set".to_string(),
            )
        })?;
        revocation_set.validate().map_err(|error| {
            BudgetStoreError::Invariant(format!("invalid canonical revocation set: {error}"))
        })?;
        if revocation_set
            .ids()
            .binary_search(&request.capability_id)
            .is_err()
        {
            return Err(BudgetStoreError::Invariant(
                "canonical revocation set omits the leaf capability".to_string(),
            ));
        }

        let composite_request = CompositeMutationRequest::Authorize(Box::new(request.clone()));
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Authorize(decision) => Ok(decision),
                CompositeMutationDecision::Hold(_) => Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{event_id}` has the wrong decision kind"
                ))),
            };
        }
        if let Some(existing) = self.composite_authorizations.get(hold_id) {
            if existing.request != request {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` was reused for a different authorization"
                )));
            }
            return Ok(existing.decision.clone());
        }
        if self.legacy_authorization_hold_ids.contains(hold_id) || self.holds.contains_key(hold_id)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` collides with a legacy hold"
            )));
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut saw_primary = false;
        for quota in request.invocation_quotas() {
            if quota.key.profile == BudgetQuotaProfile::GrantInvocation {
                if quota.key != primary_key || saw_primary {
                    return Err(BudgetStoreError::Invariant(
                        "composite budget hold has an ambiguous grant invocation quota".to_string(),
                    ));
                }
                saw_primary = true;
            }
        }
        if !saw_primary {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold omits the matched grant invocation quota".to_string(),
            ));
        }
        if !manages_multiple_quotas && self.multi_quota_managed_grants.contains(&primary_key) {
            return Err(BudgetStoreError::Invariant(format!(
                "grant `{}` requires composite invocation admission",
                primary_key.owner_id
            )));
        }

        let primary_usage = match self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
        {
            Some(primary_usage) => primary_usage,
            None => Self::default_usage_record(&request.capability_id, request.grant_index)?,
        };
        let monetary_present = Self::monetary_present(&request);
        let current_committed = primary_usage.committed_cost_units()?;
        let mut new_committed = current_committed;
        let mut new_exposure = primary_usage.total_cost_exposed;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let quota_mutation = self.compare_and_mutate_invocation_quotas(
            request.invocation_quotas(),
            &primary_key,
            primary_usage.invocation_count,
            InvocationQuotaMutationMode::Reserve,
            InvocationQuotaMutationAction::Attempt,
            || {
                if request.max_cost_per_invocation.is_some_and(|maximum| {
                    request.requested_exposure_units > maximum
                }) {
                    return Ok(true);
                }
                let prospective_committed =
                    match current_committed.checked_add(request.requested_exposure_units) {
                        Some(prospective) => prospective,
                        None if request.max_total_cost_units.is_some() => return Ok(true),
                        None => {
                            return Err(BudgetStoreError::Overflow(
                                "committed cost + requested exposure overflowed u64".to_string(),
                            ));
                        }
                    };
                if request
                    .max_total_cost_units
                    .is_some_and(|maximum| prospective_committed > maximum)
                {
                    return Ok(true);
                }
                let prospective_exposure = primary_usage
                    .total_cost_exposed
                    .checked_add(request.requested_exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "total exposed cost + requested exposure overflowed u64".to_string(),
                        )
                    })?;
                new_committed = prospective_committed;
                new_exposure = prospective_exposure;
                Ok(false)
            },
        )?;
        let allowed = quota_mutation.allowed;
        let invocation_counts_after = quota_mutation.invocation_counts_after;
        let primary_count_after = quota_mutation.primary_count_after;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Authorized
        } else {
            BudgetInvocationReservationState::Denied
        };
        let monetary_state = if allowed && monetary_present {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let committed_cost_units_after = if allowed {
            new_committed
        } else {
            current_committed
        };
        let metadata =
            Self::composite_metadata(request.authority.clone(), Some(seq), event_id.to_string());
        let decision = if allowed {
            BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                hold_id: request.hold_id.clone(),
                authorized_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after: invocation_counts_after.clone(),
                invocation_state,
                monetary_state,
                revocation_set: request.revocation_set().cloned(),
                metadata: metadata.clone(),
            })
        } else {
            BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id.clone(),
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after: invocation_counts_after.clone(),
                invocation_state,
                monetary_state,
                revocation_set: request.revocation_set().cloned(),
                metadata: metadata.clone(),
            })
        };

        let record = BudgetMutationRecord {
            admission_operation: request.admission_operation.clone(),
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReserveInvocations,
            allowed: Some(allowed),
            recorded_at,
            event_seq: seq,
            usage_seq: allowed.then_some(seq),
            exposure_units: request.requested_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: request.max_cost_per_invocation,
            max_total_cost_units: request.max_total_cost_units,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state,
            monetary_state,
            revocation_set: request.revocation_set().cloned(),
            total_cost_exposed_after: if allowed {
                new_exposure
            } else {
                primary_usage.total_cost_exposed
            },
            total_cost_realized_spend_after: primary_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };

        self.next_seq = seq;
        if allowed {
            let entry = self
                .counts
                .entry((request.capability_id.clone(), request.grant_index))
                .or_insert(primary_usage.clone());
            entry.invocation_count = primary_count_after;
            entry.total_cost_exposed = new_exposure;
            entry.updated_at = recorded_at;
            entry.seq = seq;
            self.composite_holds.insert(
                hold_id.to_string(),
                CompositeBudgetHoldState {
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    invocation_admission,
                    invocation_state,
                    monetary_state,
                    authorized_exposure_units: request.requested_exposure_units,
                    remaining_exposure_units: request.requested_exposure_units,
                    authority: request.authority.clone(),
                    authorization_metadata: metadata.clone(),
                    admission_operation: request.admission_operation.clone(),
                    reserved_until: None,
                    reserved_currency: None,
                    reserved_payment_reference: None,
                    reserved_budget_total: None,
                    reserved_delegation_depth: None,
                    reserved_root_budget_holder: None,
                    expired: false,
                },
            );
        }
        self.composite_authorizations.insert(
            hold_id.to_string(),
            RecordedHoldAuthorization {
                request: request.clone(),
                decision: decision.clone(),
            },
        );
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Authorize(decision.clone()),
            record,
        );
        if manages_multiple_quotas {
            self.multi_quota_managed_grants.insert(primary_key);
        }
        Ok(decision)
    }

    fn replay_composite_budget_authorization(
        &self,
        mut request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires a snapshot-derived authorization request".to_string(),
            ));
        }
        request.authorization_policy = BudgetAuthorizationPolicy::FreshOrReplay;
        if request.invocation_quotas().is_empty() || request.invocation_admission.is_none() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires verified composite invocation admission".to_string(),
            ));
        }
        if request.admission_operation.is_none() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires admission operation ownership".to_string(),
            ));
        }
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "committed replay requires a composite budget hold_id".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "committed replay requires a composite budget event_id".to_string(),
            )
        })?;
        let mutation_request = CompositeMutationRequest::Authorize(Box::new(request.clone()));
        let Some(decision) = self.composite_duplicate(event_id, &mutation_request)? else {
            if let Some(existing) = self.composite_authorizations.get(hold_id) {
                if existing.request != request {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` was reused for a different authorization"
                    )));
                }
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` omits its committed authorization event"
                )));
            }
            if self.legacy_authorization_hold_ids.contains(hold_id)
                || self.holds.contains_key(hold_id)
                || self.composite_holds.contains_key(hold_id)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "authorization replay for hold `{hold_id}` has partial or cross-namespace state"
                )));
            }
            return Err(BudgetStoreError::MissingCommittedReplay(format!(
                "no authorization is committed for hold `{hold_id}` and event `{event_id}`"
            )));
        };
        let CompositeMutationDecision::Authorize(decision) = decision else {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` has the wrong decision kind"
            )));
        };
        let existing = self.composite_authorizations.get(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` omits its committed authorization record"
            ))
        })?;
        if existing.request != request || existing.decision != decision {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match its committed authorization replay"
            )));
        }
        Ok(decision)
    }

    fn capture_composite_invocations(
        &mut self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::CaptureInvocation(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }

        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation reservation is not authorized"
            )));
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged_counters = Vec::with_capacity(hold.invocation_quotas().len());
        for quota in hold.invocation_quotas() {
            let mut counter = self
                .invocation_quotas
                .get(&quota.key)
                .cloned()
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
            if counter.max_invocations != quota.max_invocations || counter.reserved_count == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key.owner_id
                )));
            }
            counter.reserved_count -= 1;
            counter.captured_count = counter.captured_count.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("captured invocation count overflowed u32".to_string())
            })?;
            staged_counters.push((quota.clone(), counter));
        }
        let invocation_counts_after = staged_counters
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        if current_usage.invocation_count != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let metadata =
            Self::composite_metadata(request.authority.clone(), Some(seq), event_id.to_string());
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: 0,
            realized_spend_units: 0,
            committed_cost_units_after: current_usage.committed_cost_units()?,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: hold.monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata,
        };

        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            admission_operation: request.admission_operation.clone(),
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::CaptureInvocations,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 0,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: hold.monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: current_usage.total_cost_exposed,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.invocation_state = BudgetInvocationReservationState::Captured;

        self.next_seq = seq;
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn reverse_composite_hold(
        &mut self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::Reverse(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation reservation cannot be reversed"
            )));
        }
        match hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => {
                if hold.remaining_exposure_units != request.reversed_exposure_units {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` reverse amount does not match exposure"
                    )));
                }
            }
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => {
                if request.reversed_exposure_units != 0 {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` has no reversible monetary exposure"
                    )));
                }
            }
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        }

        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged_counters = Vec::with_capacity(hold.invocation_quotas().len());
        for quota in hold.invocation_quotas() {
            let mut counter = self
                .invocation_quotas
                .get(&quota.key)
                .cloned()
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key.owner_id
                    ))
                })?;
            if counter.max_invocations != quota.max_invocations || counter.reserved_count == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key.owner_id
                )));
            }
            counter.reserved_count -= 1;
            staged_counters.push((quota.clone(), counter));
        }
        let invocation_counts_after = staged_counters
            .iter()
            .map(|(quota, counter)| Self::usage_from_counter(quota, counter))
            .collect::<Vec<_>>();
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.reversed_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot reverse more than total exposed cost".to_string(),
                )
            })?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let monetary_state = match hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldState::Reversed,
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => hold.monetary_state,
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: new_exposure
                .checked_add(current_usage.total_cost_realized_spend)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
                })?,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let record = BudgetMutationRecord {
            admission_operation: request.admission_operation.clone(),
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReverseInvocations,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.invocation_count = primary_count_after;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.invocation_state = BudgetInvocationReservationState::Reversed;
        updated_hold.monetary_state = monetary_state;
        updated_hold.remaining_exposure_units = 0;

        self.next_seq = seq;
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn release_composite_hold(
        &mut self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::Release(request.clone());
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
        )?;
        if hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || request.released_exposure_units > hold.remaining_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot release the requested exposure"
            )));
        }
        if matches!(
            hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state cannot release monetary exposure"
            )));
        }

        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot release more than total exposed cost".to_string(),
                )
            })?;
        let remaining_exposure = hold
            .remaining_exposure_units
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cannot release more than hold exposure".to_string())
            })?;
        let monetary_state = if remaining_exposure == 0 {
            BudgetMonetaryHoldState::Released
        } else {
            BudgetMonetaryHoldState::Exposed
        };
        let invocation_counts_after = self.invocation_usages(hold.invocation_quotas())?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let committed_cost_units_after = new_exposure
            .checked_add(current_usage.total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
            })?;
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let record = BudgetMutationRecord {
            admission_operation: request.admission_operation.clone(),
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: BudgetMutationKind::ReleaseExposure,
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: current_usage.total_cost_realized_spend,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.remaining_exposure_units = remaining_exposure;
        updated_hold.monetary_state = monetary_state;

        self.next_seq = seq;
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn settle_composite_hold(
        &mut self,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires event_id".to_string())
        })?;
        let composite_request = if capture {
            CompositeMutationRequest::CaptureMonetary(request.clone())
        } else {
            CompositeMutationRequest::Reconcile(request.clone())
        };
        if let Some(existing) = self.composite_duplicate(event_id, &composite_request)? {
            return match existing {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            };
        }
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "realized spend exceeds exposed cost".to_string(),
            ));
        }
        let hold = self.composite_holds.get(hold_id).cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
        Self::validate_composite_hold_identity(
            hold_id,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
        )?;
        let monetary_state_is_settleable = hold.monetary_state
            == BudgetMonetaryHoldState::Exposed
            || (request.exposed_cost_units == 0
                && request.realized_spend_units == 0
                && hold.monetary_state == BudgetMonetaryHoldState::None);
        if !monetary_state_is_settleable
            || hold.remaining_exposure_units != request.exposed_cost_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not contain the settled exposure"
            )));
        }
        if matches!(
            hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state cannot settle monetary exposure"
            )));
        }

        let current_usage = self
            .counts
            .get(&(request.capability_id.clone(), request.grant_index))
            .cloned()
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing composite budget usage row".to_string())
            })?;
        let new_exposure = current_usage
            .total_cost_exposed
            .checked_sub(request.exposed_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot settle more than total exposed cost".to_string(),
                )
            })?;
        let new_realized = current_usage
            .total_cost_realized_spend
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("realized spend overflowed u64".to_string())
            })?;
        let committed_cost_units_after =
            new_exposure.checked_add(new_realized).ok_or_else(|| {
                BudgetStoreError::Overflow("committed cost overflowed u64".to_string())
            })?;
        let invocation_counts_after = self.invocation_usages(hold.invocation_quotas())?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
        let monetary_state = if capture {
            BudgetMonetaryHoldState::Captured
        } else {
            BudgetMonetaryHoldState::Reconciled
        };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: primary_count_after,
            invocation_counts_after: invocation_counts_after.clone(),
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            metadata: Self::composite_metadata(
                request.authority.clone(),
                Some(seq),
                event_id.to_string(),
            ),
        };
        let record = BudgetMutationRecord {
            admission_operation: request.admission_operation.clone(),
            event_id: event_id.to_string(),
            hold_id: request.hold_id.clone(),
            capability_id: request.capability_id.clone(),
            grant_index,
            kind: if capture {
                BudgetMutationKind::CaptureExposure
            } else {
                BudgetMutationKind::ReconcileSpend
            },
            allowed: None,
            recorded_at,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: hold.invocation_state,
            monetary_state,
            revocation_set: Some(hold.revocation_set().clone()),
            total_cost_exposed_after: new_exposure,
            total_cost_realized_spend_after: new_realized,
            authority: request.authority.clone(),
        };
        let mut updated_usage = current_usage;
        updated_usage.total_cost_exposed = new_exposure;
        updated_usage.total_cost_realized_spend = new_realized;
        updated_usage.updated_at = recorded_at;
        updated_usage.seq = seq;
        let mut updated_hold = hold;
        updated_hold.remaining_exposure_units = 0;
        updated_hold.monetary_state = monetary_state;

        self.next_seq = seq;
        self.counts.insert(
            (request.capability_id.clone(), request.grant_index),
            updated_usage,
        );
        self.composite_holds
            .insert(hold_id.to_string(), updated_hold);
        self.record_composite_mutation(
            event_id.to_string(),
            composite_request,
            CompositeMutationDecision::Hold(decision.clone()),
            record,
        );
        Ok(decision)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        if let Some(hold) = self.holds.get(hold_id) {
            return Ok(Some(BudgetHoldSnapshot {
                hold_id: hold_id.to_string(),
                capability_id: hold.capability_id.clone(),
                grant_index: hold.grant_index,
                authorized_exposure_units: hold.authorized_exposure_units,
                remaining_exposure_units: hold.remaining_exposure_units,
                disposition: hold.disposition.view(),
                reserved_until: hold.reserved_until,
                reserved_currency: hold.reserved_currency.clone(),
                reserved_payment_reference: hold.reserved_payment_reference.clone(),
                reserved_budget_total: hold.reserved_budget_total,
                reserved_delegation_depth: hold.reserved_delegation_depth,
                reserved_root_budget_holder: hold.reserved_root_budget_holder.clone(),
                authority: hold.authority.clone(),
                authorization_metadata: hold.authorization_metadata.clone(),
            }));
        }
        let Some(hold) = self.composite_holds.get(hold_id) else {
            return Ok(None);
        };
        let disposition = if hold.expired {
            BudgetHoldDispositionView::Expired
        } else {
            match (hold.invocation_state, hold.monetary_state) {
                (_, BudgetMonetaryHoldState::Reconciled) => BudgetHoldDispositionView::Reconciled,
                (_, BudgetMonetaryHoldState::Released) => BudgetHoldDispositionView::Released,
                (_, BudgetMonetaryHoldState::Captured) => BudgetHoldDispositionView::Captured,
                (_, BudgetMonetaryHoldState::Reversed)
                | (BudgetInvocationReservationState::Reversed, BudgetMonetaryHoldState::None) => {
                    BudgetHoldDispositionView::Reversed
                }
                (
                    BudgetInvocationReservationState::Authorized
                    | BudgetInvocationReservationState::Captured,
                    BudgetMonetaryHoldState::None | BudgetMonetaryHoldState::Exposed,
                ) => BudgetHoldDispositionView::Open,
                _ => {
                    return Err(BudgetStoreError::Invariant(format!(
                        "composite budget hold `{hold_id}` has no valid disposition"
                    )))
                }
            }
        };
        Ok(Some(BudgetHoldSnapshot {
            hold_id: hold_id.to_string(),
            capability_id: hold.capability_id.clone(),
            grant_index: hold.grant_index,
            authorized_exposure_units: hold.authorized_exposure_units,
            remaining_exposure_units: hold.remaining_exposure_units,
            disposition,
            reserved_until: hold.reserved_until,
            reserved_currency: hold.reserved_currency.clone(),
            reserved_payment_reference: hold.reserved_payment_reference.clone(),
            reserved_budget_total: hold.reserved_budget_total,
            reserved_delegation_depth: hold.reserved_delegation_depth,
            reserved_root_budget_holder: hold.reserved_root_budget_holder.clone(),
            authority: hold.authority.clone(),
            authorization_metadata: hold.authorization_metadata.clone(),
        }))
    }

    fn mark_hold_reserved(
        &mut self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let hold = self.holds.get_mut(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.disposition != BudgetHoldDisposition::Open {
            return Err(BudgetStoreError::Invariant(format!(
                "cannot mark non-open budget hold `{hold_id}` reserved"
            )));
        }
        hold.reserved_until = Some(reserved_until_unix_secs);
        hold.reserved_currency = Some(currency.to_string());
        hold.reserved_payment_reference = payment_reference.map(str::to_string);
        hold.reserved_budget_total = envelope.budget_total;
        hold.reserved_delegation_depth = Some(envelope.delegation_depth);
        hold.reserved_root_budget_holder = Some(envelope.root_budget_holder.clone());
        Ok(())
    }

    fn mark_invocation_hold_reserved(
        &mut self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if envelope.budget_total.is_some() {
            return Err(BudgetStoreError::Invariant(
                "invocation-only reservation must not carry a monetary budget total".to_string(),
            ));
        }
        let hold = self.holds.get_mut(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing invocation budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Conflict(format!(
                "invocation budget hold `{hold_id}` belongs to a different capability or grant"
            )));
        }
        if hold.disposition != BudgetHoldDisposition::Open
            || !hold.invocation_count_debited
            || hold.authorized_exposure_units != 0
            || hold.remaining_exposure_units != 0
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not an open zero-exposure invocation hold"
            )));
        }
        if hold.reserved_currency.is_some()
            || hold.reserved_payment_reference.is_some()
            || hold.reserved_budget_total.is_some()
        {
            return Err(BudgetStoreError::Invariant(format!(
                "invocation budget hold `{hold_id}` carries monetary reservation metadata"
            )));
        }
        let exact_retry = hold.reserved_until == Some(reserved_until_unix_secs)
            && hold.reserved_delegation_depth == Some(envelope.delegation_depth)
            && hold.reserved_root_budget_holder.as_deref()
                == Some(envelope.root_budget_holder.as_str());
        if hold.reserved_until.is_some() {
            return if exact_retry {
                Ok(())
            } else {
                Err(BudgetStoreError::Conflict(format!(
                    "invocation budget hold `{hold_id}` was already stamped with different reservation terms"
                )))
            };
        }
        hold.reserved_until = Some(reserved_until_unix_secs);
        hold.reserved_delegation_depth = Some(envelope.delegation_depth);
        hold.reserved_root_budget_holder = Some(envelope.root_budget_holder.clone());
        Ok(())
    }

    fn mark_admission_operation_hold_reserved(
        &mut self,
        hold_id: &str,
        admission_operation: &super::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let hold = self.composite_holds.get_mut(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "missing operation-owned composite budget hold `{hold_id}`"
            ))
        })?;
        if hold.admission_operation.as_ref() != Some(admission_operation) {
            return Err(BudgetStoreError::Conflict(format!(
                "composite budget hold `{hold_id}` belongs to a different admission operation"
            )));
        }
        if hold.expired {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` is already expired"
            )));
        }
        if !matches!(
            hold.invocation_state,
            BudgetInvocationReservationState::Authorized
                | BudgetInvocationReservationState::Captured
        ) || !matches!(
            hold.monetary_state,
            BudgetMonetaryHoldState::None | BudgetMonetaryHoldState::Exposed
        ) {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` is not open for caller reservation"
            )));
        }
        if (hold.authorized_exposure_units == 0) != currency.is_none()
            || currency.is_some_and(str::is_empty)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` has an invalid reserved currency"
            )));
        }
        let exact_retry = hold.reserved_until == Some(reserved_until_unix_secs)
            && hold.reserved_currency.as_deref() == currency
            && hold.reserved_payment_reference.as_deref() == payment_reference
            && hold.reserved_budget_total == envelope.budget_total
            && hold.reserved_delegation_depth == Some(envelope.delegation_depth)
            && hold.reserved_root_budget_holder.as_deref()
                == Some(envelope.root_budget_holder.as_str());
        if hold.reserved_until.is_some() {
            return if exact_retry {
                Ok(())
            } else {
                Err(BudgetStoreError::Conflict(format!(
                    "composite budget hold `{hold_id}` was already stamped with different reservation terms"
                )))
            };
        }
        hold.reserved_until = Some(reserved_until_unix_secs);
        hold.reserved_currency = currency.map(ToOwned::to_owned);
        hold.reserved_payment_reference = payment_reference.map(ToOwned::to_owned);
        hold.reserved_budget_total = envelope.budget_total;
        hold.reserved_delegation_depth = Some(envelope.delegation_depth);
        hold.reserved_root_budget_holder = Some(envelope.root_budget_holder.clone());
        Ok(())
    }

    fn reserve_invocation_hold(
        &mut self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.holds.contains_key(hold_id)
            || self.legacy_authorization_hold_ids.contains(hold_id)
            || self.composite_holds.contains_key(hold_id)
            || self.composite_authorizations.contains_key(hold_id)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` already exists"
            )));
        }
        self.holds.insert(
            hold_id.to_string(),
            BudgetHoldState {
                capability_id: capability_id.to_string(),
                grant_index,
                authorized_exposure_units: 0,
                remaining_exposure_units: 0,
                invocation_count_debited: true,
                disposition: BudgetHoldDisposition::Open,
                authority: None,
                authorization_metadata: Self::composite_metadata(
                    None,
                    None,
                    format!("{hold_id}:authorize"),
                ),
                reserved_until: Some(reserved_until_unix_secs),
                reserved_currency: None,
                reserved_payment_reference: None,
                reserved_budget_total: envelope.budget_total,
                reserved_delegation_depth: Some(envelope.delegation_depth),
                reserved_root_budget_holder: Some(envelope.root_budget_holder.clone()),
            },
        );
        Ok(())
    }

    fn request_id_has_reserved_hold(&self, request_id: &str) -> bool {
        // A mediated hold id is `budget-hold:{request_id}:{capability}:{grant}`.
        // Matching the `budget-hold:{request_id}:` prefix reports the request_id
        // taken no matter which capability opened the hold; the trailing colon
        // keeps a request_id that is only a textual prefix of another from
        // matching.
        let prefix = format!("budget-hold:{request_id}:");
        self.holds
            .keys()
            .chain(self.composite_holds.keys())
            .any(|hold_id| hold_id.starts_with(&prefix))
    }

    fn list_open_delegated_reserved_hold_ids(&self) -> Vec<String> {
        // A delegated reserve-for-caller hold is open, was marked reserved
        // (reserved_until is set), and carries a delegation depth of at least
        // one, so it holds its child's sibling-sum share admitted against the
        // parent until it closes.
        self.holds
            .iter()
            .filter(|(_, hold)| hold.disposition == BudgetHoldDisposition::Open)
            .filter(|(_, hold)| hold.reserved_until.is_some())
            .filter(|(_, hold)| {
                hold.reserved_delegation_depth
                    .is_some_and(|depth| depth >= 1)
            })
            .map(|(hold_id, _)| hold_id.clone())
            .collect()
    }

    fn reap_expired_reserved_holds(
        &mut self,
        now_unix_secs: i64,
    ) -> Result<usize, BudgetStoreError> {
        // Snapshot the expired-and-still-open reserved holds first so the
        // settle loop can mutate the map without an aliasing borrow.
        let expired: Vec<(String, String, usize, u64, Option<BudgetEventAuthority>)> = self
            .holds
            .iter()
            .filter(|(_, hold)| hold.disposition == BudgetHoldDisposition::Open)
            .filter_map(|(hold_id, hold)| {
                hold.reserved_until
                    .filter(|until| *until <= now_unix_secs)
                    .map(|_| {
                        (
                            hold_id.clone(),
                            hold.capability_id.clone(),
                            hold.grant_index,
                            hold.remaining_exposure_units,
                            hold.authority.clone(),
                        )
                    })
            })
            .collect();

        let mut settled = 0usize;
        for (hold_id, capability_id, grant_index, remaining, authority) in expired {
            // Settle at the reserved worst-case: the abandoning caller forfeits the
            // full reserved amount to realized spend (fail-closed), rather than
            // releasing it back (which would under-count a spend that may have run).
            self.settle_charge_cost_with_ids_and_authority(
                &capability_id,
                grant_index,
                remaining,
                remaining,
                Some(&hold_id),
                Some(&format!("{hold_id}:ttl-reap-settle")),
                authority.as_ref(),
            )?;
            let hold = self.holds.get_mut(&hold_id).ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` disappeared during TTL reap"
                ))
            })?;
            hold.disposition = BudgetHoldDisposition::Expired;
            settled += 1;
        }

        // Reap captured composite reservations only; Authorized may still be capturing.
        let mut expired_composite = Vec::new();
        for (hold_id, hold) in &self.composite_holds {
            let is_expired_caller_reservation = !hold.expired
                && hold.invocation_state == BudgetInvocationReservationState::Captured
                && matches!(
                    hold.monetary_state,
                    BudgetMonetaryHoldState::None | BudgetMonetaryHoldState::Exposed
                )
                && hold
                    .reserved_until
                    .is_some_and(|until| until <= now_unix_secs);
            if !is_expired_caller_reservation {
                continue;
            }
            let binding = hold.admission_operation.clone().ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite budget hold `{hold_id}` omits admission ownership"
                ))
            })?;
            expired_composite.push((
                hold_id.clone(),
                hold.capability_id.clone(),
                hold.grant_index,
                hold.remaining_exposure_units,
                hold.authority.clone(),
                binding,
                hold.monetary_state,
            ));
        }
        for (
            hold_id,
            capability_id,
            grant_index,
            remaining,
            authority,
            admission_operation,
            monetary_state,
        ) in expired_composite
        {
            if monetary_state == BudgetMonetaryHoldState::Exposed {
                self.settle_composite_hold(
                    BudgetReconcileHoldRequest {
                        capability_id,
                        grant_index,
                        exposed_cost_units: remaining,
                        realized_spend_units: remaining,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:ttl-reap-settle")),
                        authority,
                        admission_operation: Some(admission_operation),
                    },
                    false,
                )?;
            }
            let hold = self.composite_holds.get_mut(&hold_id).ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite budget hold `{hold_id}` disappeared during TTL reap"
                ))
            })?;
            hold.expired = true;
            settled += 1;
        }
        Ok(settled)
    }
}
