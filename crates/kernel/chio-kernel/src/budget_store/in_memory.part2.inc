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
            return Err(BudgetStoreError::Invariant(format!(
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
                return Err(BudgetStoreError::Invariant(format!(
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
        let mut staged_counters = Vec::with_capacity(request.invocation_quotas().len());
        let mut quota_exhausted = false;
        for quota in request.invocation_quotas() {
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
                    captured_count: if quota.key == primary_key {
                        primary_usage.invocation_count
                    } else {
                        0
                    },
                    compatibility_reversible_count: 0,
                }
            };
            let current_count = counter.invocation_count()?;
            if current_count > quota.max_invocations {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key.owner_id
                )));
            }
            if current_count == quota.max_invocations {
                quota_exhausted = true;
            }
            staged_counters.push((quota.clone(), counter));
        }
        let staged_primary_count = staged_counters
            .iter()
            .find(|(quota, _)| quota.key == primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .1
            .invocation_count()?;
        if staged_primary_count != primary_usage.invocation_count {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite invocation quota".to_string(),
            ));
        }

        let monetary_present = Self::monetary_present(&request);
        let current_committed = primary_usage.committed_cost_units()?;
        let new_committed = current_committed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let new_exposure = primary_usage
            .total_cost_exposed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total exposed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let monetary_denied = request
            .max_cost_per_invocation
            .is_some_and(|maximum| request.requested_exposure_units > maximum)
            || request
                .max_total_cost_units
                .is_some_and(|maximum| new_committed > maximum);
        let allowed = !quota_exhausted && !monetary_denied;
        let seq = self.next_composite_seq()?;
        let recorded_at = unix_now();

        if allowed {
            for (_, counter) in &mut staged_counters {
                counter.reserved_count =
                    counter.reserved_count.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "reserved invocation count overflowed u32".to_string(),
                        )
                    })?;
            }
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
        let metadata = Self::composite_metadata(
            request.authority.clone(),
            allowed.then_some(seq),
            event_id.to_string(),
        );
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

        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("budget grant index exceeds u32".to_string())
        })?;
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
        for (quota, counter) in staged_counters {
            self.invocation_quotas.insert(quota.key, counter);
        }
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
                    admission_operation: request.admission_operation.clone(),
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
        if hold.monetary_state != BudgetMonetaryHoldState::Exposed
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
        Ok(self.holds.get(hold_id).map(|hold| BudgetHoldSnapshot {
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

    fn reserve_invocation_hold(
        &mut self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.holds.contains_key(hold_id) {
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
            settled += 1;
        }
        Ok(settled)
    }
}

impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        self.lock_inner()?.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|_| ())
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|_| ())
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map(|_| ())
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost_with_ids(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
            )
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?
            .settle_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map(|_| ())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.lock_inner()?.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        self.lock_inner()?
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        mut request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.payment_journal.is_some() {
            // The in-memory store cannot journal the money path durably, and
            // a silently dropped journal row would leave a rail movement
            // unrecoverable after a crash. Deny rather than proceed.
            return Err(BudgetStoreError::Invariant(
                "payment journal is not supported by this budget store".to_string(),
            ));
        }
        let mut inner = self.lock_inner()?;
        if request.invocation_admission.is_some() && request.admission_operation.is_none() {
            return Err(BudgetStoreError::Invariant(
                "composite budget hold requires admission operation ownership".to_string(),
            ));
        }
        if request.invocation_admission.is_none() {
            let admission = VerifiedInvocationAdmission::grant_only(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
            )?;
            request.max_invocations = None;
            request.install_verified_invocation_admission(admission)?;
        }
        inner.authorize_composite_budget_hold(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.reverse_composite_hold(request);
        }
        let record = inner.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.release_composite_hold(request);
        }
        let record = inner.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.settle_composite_hold(request, false);
        }
        let record = inner.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        self.decision_from_legacy_record(record)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        let mut inner = self.lock_inner()?;
        if request
            .hold_id
            .as_ref()
            .is_some_and(|hold_id| inner.composite_holds.contains_key(hold_id))
        {
            return inner.settle_composite_hold(request, true);
        }
        let record = inner.capture_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: record.hold_id.clone(),
            exposure_units: record.exposure_units,
            realized_spend_units: record.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                record.total_cost_exposed_after,
                record.total_cost_realized_spend_after,
            )?,
            invocation_count_after: record.invocation_count_after,
            invocation_counts_after: record.invocation_counts_after.clone(),
            invocation_state: record.invocation_state,
            monetary_state: record.monetary_state,
            revocation_set: record.revocation_set.clone(),
            metadata: budget_commit_metadata(
                self,
                record.authority.clone(),
                record.usage_seq,
                Some(record.event_id.clone()),
            ),
        })
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.lock_inner()?.capture_composite_invocations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture query requires event_id".to_string())
        })?;
        let composite_request = CompositeMutationRequest::CaptureInvocation(request.clone());
        self.lock_inner()?
            .composite_duplicate(event_id, &composite_request)?
            .map(|decision| match decision {
                CompositeMutationDecision::Hold(decision) => Ok(decision),
                CompositeMutationDecision::Authorize(_) => Err(BudgetStoreError::Invariant(
                    format!("budget event_id `{event_id}` has the wrong decision kind"),
                )),
            })
            .transpose()
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        self.lock_inner()?.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.reserve_invocation_hold(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.lock_inner()?
            .reap_expired_reserved_holds(now_unix_secs)
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(Some(
            self.lock_inner()?.list_open_delegated_reserved_hold_ids(),
        ))
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        Ok(Some(
            self.lock_inner()?.request_id_has_reserved_hold(request_id),
        ))
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
