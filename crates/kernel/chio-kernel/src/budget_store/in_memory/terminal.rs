impl InMemoryBudgetStoreInner {
    fn reverse_hold(&mut self, request: &BudgetReverseHoldRequest) -> Result<(), BudgetStoreError> {
        self.reverse_hold_with_mutation(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            &request.hold_id,
            &request.event_id,
            request.authority.as_ref(),
            request.expected_cumulative_approval_state,
            BudgetMutationRequest::Reverse {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                hold_id: request.hold_id.clone(),
                cost_units: request.reversed_exposure_units,
                expected_cumulative_approval_state: request.expected_cumulative_approval_state,
                authority: request.authority.clone(),
            },
            BudgetMutationKind::ReverseExposure,
            false,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules.")]
    fn reverse_hold_with_mutation(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: &str,
        event_id: &str,
        authority: Option<&BudgetEventAuthority>,
        expected_cumulative_approval_state: Option<BudgetCumulativeApprovalState>,
        request: BudgetMutationRequest,
        kind: BudgetMutationKind,
        cancels_captured_before_dispatch: bool,
    ) -> Result<(bool, u64, BudgetUsageRecord), BudgetStoreError> {
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "reversal")?;
            return Ok((
                false,
                existing.record.event_seq,
                BudgetUsageRecord {
                    capability_id: existing.record.capability_id,
                    grant_index: existing.record.grant_index,
                    invocation_count: existing.record.invocation_count_after,
                    updated_at: existing.record.recorded_at,
                    seq: existing.record.usage_seq.unwrap_or(0),
                    total_cost_exposed: existing.record.total_cost_exposed_after,
                    total_cost_realized_spend: existing.record.total_cost_realized_spend_after,
                },
            ));
        }
        let hold = self
            .validate_hold(hold_id, capability_id, grant_index)?
            .clone();
        if hold.remaining_exposure_units != cost_units {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match reverse amount"
            )));
        }
        let expected_state = if cancels_captured_before_dispatch {
            BudgetInvocationState::Captured
        } else {
            BudgetInvocationState::Authorized
        };
        if hold.invocation_state != expected_state {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state cannot be reversed"
            )));
        }
        if cancels_captured_before_dispatch && !hold.captured_cancellation_allowed {
            return Err(BudgetStoreError::Invariant(
                "captured composite invocation reservations are terminal".to_string(),
            ));
        }
        if cost_units > 0 && hold.monetary_state != BudgetMonetaryState::Exposed {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary exposure is not reversible"
            )));
        }
        for quota in &hold.invocation_quotas {
            let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing reserved invocation quota".to_string())
            })?;
            let reversible_invocations = if cancels_captured_before_dispatch {
                state.captured_invocations
            } else {
                state.reserved_invocations
            };
            if state.max_invocations != quota.max_invocations || reversible_invocations == 0 {
                return Err(BudgetStoreError::Invariant(
                    "invocation quota reservation does not match its hold".to_string(),
                ));
            }
        }
        if let Some(participant) = &hold.cumulative_approval {
            if expected_cumulative_approval_state
                .is_some_and(|expected| participant.state != expected)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cumulative approval state changed"
                )));
            }
            if !(matches!(
                participant.state,
                BudgetCumulativeApprovalState::PendingApproval
                    | BudgetCumulativeApprovalState::Authorized
            ) || cancels_captured_before_dispatch
                && participant.state == BudgetCumulativeApprovalState::Captured)
            {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval participant is terminal".to_string(),
                ));
            }
            let account = self
                .cumulative_approval_accounts
                .get(&participant.request.account_key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "missing cumulative approval account".to_string(),
                    )
                })?;
            let reversible_authorized_units =
                if participant.state == BudgetCumulativeApprovalState::Captured {
                    account.captured_authorized_units
                } else {
                    account.reserved_authorized_units
                };
            if reversible_authorized_units < participant.request.requested_authorized.units {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval reservation is incomplete".to_string(),
                ));
            }
            account.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "cumulative approval account version overflowed u64".to_string(),
                )
            })?;
        } else if expected_cumulative_approval_state.is_some() {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` has no cumulative approval participant"
            )));
        }
        Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;

        let affected_quotas = hold.invocation_quotas.clone();
        let invocation_quota_usages_before = self.invocation_quota_usages(&affected_quotas)?;
        let cumulative_before = hold
            .cumulative_approval
            .as_ref()
            .map(|participant| {
                self.cumulative_approval_accounts
                    .get(&participant.request.account_key)
                    .map(|account| {
                        (
                            account.reserved_authorized_units,
                            account.captured_authorized_units,
                            account.version,
                            participant.clone(),
                        )
                    })
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "cumulative approval account disappeared".to_string(),
                        )
                    })
            })
            .transpose()?;

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        let accounting = self.prepare_reversal_accounting(&hold, cancels_captured_before_dispatch)?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reverse charge larger than total_cost_exposed".to_string(),
                ));
            }
            let next_count =
                InvocationCount::new(entry.invocation_count).try_sub(InvocationCount::ONE)?;
            let next_balance =
                ExposureBalance::new(entry.total_cost_exposed, entry.total_cost_realized_spend)?
                    .release(ExposureUnits::new(cost_units))?;
            self.next_seq = next_seq;
            entry.invocation_count = next_count.get();
            entry.total_cost_exposed = next_balance.exposed();
            entry.updated_at = self.now;
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        accounting.apply(self);
        let invocation_quota_usages = self.invocation_quota_usages(&affected_quotas)?;
        let invocation_quota_mutations = Self::invocation_quota_mutations(
            &invocation_quota_usages_before,
            &invocation_quota_usages,
        )?;
        let cumulative_approval = hold
            .cumulative_approval
            .as_ref()
            .map(|participant| {
                self.cumulative_approval_usage(
                    &participant.request,
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                )
            })
            .transpose()?;
        let cumulative_approval_mutation = cumulative_before
            .as_ref()
            .map(|(reserved, captured, version, participant)| {
                self.cumulative_approval_mutation(
                    &participant.request,
                    Some(participant.state),
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    (*reserved, *captured, *version),
                )
            })
            .transpose()?;
        let Some(stored_hold) = self.holds.get_mut(hold_id) else {
            return Err(BudgetStoreError::Invariant(
                "validated hold missing during reversal".to_string(),
            ));
        };
        stored_hold.remaining_exposure_units = 0;
        stored_hold.invocation_state = BudgetInvocationState::Reversed;
        if cost_units > 0 {
            stored_hold.monetary_state = BudgetMonetaryState::Reversed;
        }
        if let Some(participant) = stored_hold.cumulative_approval.as_mut() {
            participant.state = BudgetCumulativeApprovalState::ReversedBeforeDispatch;
        }
        stored_hold.authority = authority.cloned().or_else(|| stored_hold.authority.clone());
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: Some(hold_id.to_string()),
                admission_binding: hold.admission_binding.clone(),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: if cancels_captured_before_dispatch || invocation_quota_usages.is_empty() {
                    kind
                } else {
                    BudgetMutationKind::ReverseInvocation
                },
                allowed: cancels_captured_before_dispatch.then_some(true),
                authorization_outcome: None,
                invocation_state_before: hold.invocation_state,
                invocation_state_after: BudgetInvocationState::Reversed,
                monetary_state_before: hold.monetary_state,
                monetary_state_after: if cost_units == 0 {
                    hold.monetary_state
                } else {
                    BudgetMonetaryState::Reversed
                },
                recorded_at: self.now,
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages,
                invocation_quota_mutations,
                cumulative_approval,
                cumulative_approval_mutation,
                cumulative_approval_set_digest: hold
                    .cumulative_approval
                    .as_ref()
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok((
            true,
            seq,
            BudgetUsageRecord {
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                invocation_count: invocation_count_after,
                updated_at: self.now,
                seq,
                total_cost_exposed: total_cost_exposed_after,
                total_cost_realized_spend: total_cost_realized_spend_after,
            },
        ))
    }

    fn cancel_captured_before_dispatch(
        &mut self,
        request: &BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<(bool, u64, BudgetUsageRecord), BudgetStoreError> {
        let cost_units = self
            .holds
            .get(&request.hold_id)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!("unknown budget hold `{}`", request.hold_id))
            })?
            .remaining_exposure_units;
        self.reverse_hold_with_mutation(
            &request.capability_id,
            request.grant_index,
            cost_units,
            &request.hold_id,
            &request.event_id,
            request.authority.as_ref(),
            None,
            BudgetMutationRequest::CancelCapturedBeforeDispatch {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                hold_id: request.hold_id.clone(),
                authority: request.authority.clone(),
            },
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            true,
        )
    }

    fn release_hold(&mut self, request: &BudgetReleaseHoldRequest) -> Result<(), BudgetStoreError> {
        let capability_id = request.capability_id.as_str();
        let grant_index = request.grant_index;
        let cost_units = request.released_exposure_units;
        let hold_id = request.hold_id.as_str();
        let event_id = request.event_id.as_str();
        let authority = request.authority.as_ref();
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if cost_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary release is not a state transition".to_string(),
            ));
        }
        let mutation = BudgetMutationRequest::Release {
            capability_id: capability_id.to_string(),
            grant_index,
            hold_id: hold_id.to_string(),
            cost_units,
            authority: authority.cloned(),
        };
        if let Some(existing) = self.duplicate_mutation(event_id, &mutation)? {
            let hold = self.validate_hold(hold_id, capability_id, grant_index)?;
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
            self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "release")?;
            return Ok(());
        }
        let hold = self
            .validate_hold(hold_id, capability_id, grant_index)?
            .clone();
        if hold.remaining_exposure_units < cost_units {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot release more than remaining exposure"
            )));
        }
        if hold.monetary_state != BudgetMonetaryState::Exposed {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary exposure is not releasable"
            )));
        }
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` crossed the dispatch commitment fence"
            )));
        }
        Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.total_cost_exposed < cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot reduce charge larger than total_cost_exposed".to_string(),
                ));
            }

            let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
            })?;
            let next_balance =
                ExposureBalance::new(entry.total_cost_exposed, entry.total_cost_realized_spend)?
                    .release(ExposureUnits::new(cost_units))?;
            self.next_seq = next_seq;
            entry.total_cost_exposed = next_balance.exposed();
            entry.updated_at = self.now;
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        let Some(stored_hold) = self.holds.get_mut(hold_id) else {
            return Err(BudgetStoreError::Invariant(
                "validated hold missing during release".to_string(),
            ));
        };
        stored_hold.remaining_exposure_units =
            ExposureUnits::new(stored_hold.remaining_exposure_units)
                .try_sub(ExposureUnits::new(cost_units))?
                .get();
        if stored_hold.remaining_exposure_units == 0 {
            stored_hold.monetary_state = BudgetMonetaryState::Released;
        }
        stored_hold.authority = authority.cloned().or_else(|| stored_hold.authority.clone());
        self.append_mutation(
            event_id,
            mutation,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: Some(hold_id.to_string()),
                admission_binding: hold.admission_binding.clone(),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                authorization_outcome: None,
                invocation_state_before: hold.invocation_state,
                invocation_state_after: hold.invocation_state,
                monetary_state_before: hold.monetary_state,
                monetary_state_after: if hold.remaining_exposure_units == cost_units {
                    BudgetMonetaryState::Released
                } else {
                    BudgetMonetaryState::Exposed
                },
                recorded_at: self.now,
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: cost_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages: self.invocation_quota_usages(&hold.invocation_quotas)?,
                invocation_quota_mutations: Vec::new(),
                cumulative_approval: hold
                    .cumulative_approval
                    .as_ref()
                    .map(|participant| {
                        self.cumulative_approval_usage(&participant.request, participant.state)
                    })
                    .transpose()?,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: hold
                    .cumulative_approval
                    .as_ref()
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
    }

    fn reconcile_hold(
        &mut self,
        request: &BudgetReconcileHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        self.settle_hold_with_mutation(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            &request.hold_id,
            &request.event_id,
            request.authority.as_ref(),
            BudgetMutationRequest::Reconcile {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                hold_id: request.hold_id.clone(),
                exposed_cost_units: request.exposed_cost_units,
                realized_cost_units: request.realized_spend_units,
                authority: request.authority.clone(),
            },
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryState::Reconciled,
        )
    }

    #[allow(clippy::too_many_arguments, reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules.")]
    fn settle_hold_with_mutation(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: &str,
        event_id: &str,
        authority: Option<&BudgetEventAuthority>,
        request: BudgetMutationRequest,
        mutation_kind: BudgetMutationKind,
        terminal_state: BudgetMonetaryState,
    ) -> Result<(), BudgetStoreError> {
        let grant_index_u32 = u32::try_from(grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        if exposed_cost_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary settlement is not a state transition".to_string(),
            ));
        }
        if let Some(existing) = self.duplicate_mutation(event_id, &request)? {
            let hold = self.validate_hold(hold_id, capability_id, grant_index)?;
            Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;
            self.ensure_latest_hold_event(hold_id, existing.record.event_seq, "settlement")?;
            return Ok(());
        }
        let hold = self
            .validate_hold(hold_id, capability_id, grant_index)?
            .clone();
        if hold.invocation_state != BudgetInvocationState::Captured {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation is not dispatch-captured"
            )));
        }
        if hold.remaining_exposure_units != exposed_cost_units {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match reconciled exposure"
            )));
        }
        if hold.monetary_state != BudgetMonetaryState::Exposed {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary exposure is not reconcilable"
            )));
        }
        Self::validate_hold_authority(hold_id, hold.authority.as_ref(), authority)?;

        let key = (capability_id.to_string(), grant_index);
        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            seq,
        );
        let next_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        {
            let entry = self.counts.get_mut(&key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;

            if entry.invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle charge with zero invocation_count".to_string(),
                ));
            }
            if entry.total_cost_exposed < exposed_cost_units {
                return Err(BudgetStoreError::Invariant(
                    "cannot settle more exposure than total_cost_exposed".to_string(),
                ));
            }

            let next_balance =
                ExposureBalance::new(entry.total_cost_exposed, entry.total_cost_realized_spend)?
                    .settle(
                        ExposureUnits::new(exposed_cost_units),
                        ExposureUnits::new(realized_cost_units),
                    )?;
            entry.total_cost_realized_spend = next_balance.spent();
            entry.total_cost_exposed = next_balance.exposed();
            self.next_seq = next_seq;
            entry.updated_at = self.now;
            entry.seq = next_seq;
            invocation_count_after = entry.invocation_count;
            total_cost_exposed_after = entry.total_cost_exposed;
            total_cost_realized_spend_after = entry.total_cost_realized_spend;
            seq = entry.seq;
        }
        let Some(stored_hold) = self.holds.get_mut(hold_id) else {
            return Err(BudgetStoreError::Invariant(
                "validated hold missing during settlement".to_string(),
            ));
        };
        stored_hold.remaining_exposure_units = 0;
        stored_hold.monetary_state = terminal_state;
        stored_hold.authority = authority.cloned().or_else(|| stored_hold.authority.clone());
        self.append_mutation(
            event_id,
            request,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: Some(hold_id.to_string()),
                admission_binding: hold.admission_binding.clone(),
                capability_id: capability_id.to_string(),
                grant_index: grant_index_u32,
                kind: mutation_kind,
                allowed: None,
                authorization_outcome: None,
                invocation_state_before: hold.invocation_state,
                invocation_state_after: hold.invocation_state,
                monetary_state_before: hold.monetary_state,
                monetary_state_after: terminal_state,
                recorded_at: self.now,
                event_seq: seq,
                usage_seq: Some(seq),
                exposure_units: exposed_cost_units,
                realized_spend_units: realized_cost_units,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after,
                invocation_quota_usages: self.invocation_quota_usages(&hold.invocation_quotas)?,
                invocation_quota_mutations: Vec::new(),
                cumulative_approval: hold
                    .cumulative_approval
                    .as_ref()
                    .map(|participant| {
                        self.cumulative_approval_usage(&participant.request, participant.state)
                    })
                    .transpose()?,
                cumulative_approval_mutation: None,
                cumulative_approval_set_digest: hold
                    .cumulative_approval
                    .as_ref()
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority: authority.cloned(),
            },
        );
        Ok(())
    }

    fn capture_budget_hold(
        &mut self,
        request: &BudgetCaptureHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        self.settle_hold_with_mutation(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            &request.hold_id,
            &request.event_id,
            request.authority.as_ref(),
            BudgetMutationRequest::CaptureMonetary(request.clone()),
            BudgetMutationKind::CaptureSpend,
            BudgetMonetaryState::Captured,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut records = self
            .counts
            .values()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.capability_id.cmp(&right.capability_id))
                .then_with(|| left.grant_index.cmp(&right.grant_index))
        });
        records.truncate(limit);
        Ok(records)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(self
            .counts
            .get(&(capability_id.to_string(), grant_index))
            .cloned())
    }

    fn get_invocation_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Option<BudgetInvocationQuotaUsage> {
        self.invocation_quotas
            .get(key)
            .map(|state| BudgetInvocationQuotaUsage {
                quota: BudgetInvocationQuota {
                    key: key.clone(),
                    max_invocations: state.max_invocations,
                },
                reserved_invocations: state.reserved_invocations,
                captured_invocations: state.captured_invocations,
            })
    }

    fn get_cumulative_approval_account_usage(
        &self,
        key: &BudgetCumulativeApprovalAccountKey,
    ) -> Option<BudgetCumulativeApprovalAccountUsage> {
        self.cumulative_approval_accounts.get(key).map(|account| {
            let amount = |units| chio_core::capability::scope::MonetaryAmount {
                units,
                currency: key.currency.clone(),
            };
            BudgetCumulativeApprovalAccountUsage {
                account_key: key.clone(),
                authority_threshold: amount(account.authority_threshold_units),
                reserved_authorized: amount(account.reserved_authorized_units),
                captured_authorized: amount(account.captured_authorized_units),
                version: account.version,
            }
        })
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let grant_index = grant_index
            .map(u32::try_from)
            .transpose()
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let mut events = self
            .events
            .iter()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .filter(|record| grant_index.is_none_or(|value| record.grant_index == value))
            .cloned()
            .collect::<Vec<_>>();
        events.truncate(limit);
        Ok(events)
    }
}
