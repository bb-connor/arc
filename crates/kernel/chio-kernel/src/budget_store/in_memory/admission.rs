impl InMemoryBudgetStoreInner {
    fn capture_invocation_reservations(
        &mut self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<(bool, u64, String, BudgetUsageRecord), BudgetStoreError> {
        let grant_index = u32::try_from(request.grant_index)
            .map_err(|_| BudgetStoreError::Invariant("grant_index does not fit u32".to_string()))?;
        let mutation = BudgetMutationRequest::CaptureInvocation {
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: request.hold_id.clone(),
            trusted_time: request.trusted_time,
            authority: request.authority.clone(),
        };
        if let Some(existing) = self.duplicate_mutation(&request.event_id, &mutation)? {
            let hold = self.validate_hold(
                &request.hold_id,
                &request.capability_id,
                request.grant_index,
            )?;
            Self::validate_hold_authority(
                &request.hold_id,
                hold.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            if hold.invocation_state != BudgetInvocationState::Captured {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` capture event was superseded by a terminal transition",
                    request.hold_id
                )));
            }
            return Ok((
                false,
                existing.record.event_seq,
                existing.record.event_id,
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
            .validate_hold(
                &request.hold_id,
                &request.capability_id,
                request.grant_index,
            )?
            .clone();
        Self::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if hold.authorized_exposure_units > 0
            && (hold.monetary_state != BudgetMonetaryState::Exposed
                || hold.remaining_exposure_units == 0)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no live monetary exposure for invocation capture",
                request.hold_id
            )));
        }
        if let Some(expires_at) = hold
            .admission_binding
            .as_ref()
            .and_then(|binding| binding.supplemental_authorization_expires_at)
        {
            let trusted_time = request.trusted_time.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "supplemental invocation capture requires trusted time".to_string(),
                )
            })?;
            if trusted_time >= expires_at {
                return Err(BudgetStoreError::Invariant(
                    "supplemental authorization expired before invocation capture".to_string(),
                ));
            }
        }
        if hold.invocation_state == BudgetInvocationState::Captured {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation reservations were already captured by another event",
                request.hold_id
            )));
        }
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation reservations are terminal",
                request.hold_id
            )));
        }
        if hold
            .cumulative_approval
            .as_ref()
            .is_some_and(|participant| {
                participant.state == BudgetCumulativeApprovalState::PendingApproval
            })
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` still requires cumulative approval",
                request.hold_id
            )));
        }

        let quota_usages_before = self.invocation_quota_usages(&hold.invocation_quotas)?;
        for quota in &hold.invocation_quotas {
            let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                BudgetStoreError::Invariant("missing reserved invocation quota".to_string())
            })?;
            if state.max_invocations != quota.max_invocations || state.reserved_invocations == 0 {
                return Err(BudgetStoreError::Invariant(
                    "invocation quota reservation does not match its hold".to_string(),
                ));
            }
            InvocationCount::new(state.captured_invocations)
                .try_add(InvocationCount::new(1))
                .map(InvocationCount::get)
                .map_err(|_| {
                    BudgetStoreError::Overflow(
                        "captured invocation quota overflowed u32".to_string(),
                    )
                })?;
        }
        let cumulative_before = if let Some(participant) = &hold.cumulative_approval {
            if participant.state != BudgetCumulativeApprovalState::Authorized {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval participant is not authorized".to_string(),
                ));
            }
            let account = self
                .cumulative_approval_accounts
                .get(&participant.request.account_key)
                .ok_or_else(|| {
                    BudgetStoreError::Invariant("missing cumulative approval account".to_string())
                })?;
            if account.reserved_authorized_units < participant.request.requested_authorized.units {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval reservation is incomplete".to_string(),
                ));
            }
            ExposureUnits::new(account.captured_authorized_units)
                .try_add(ExposureUnits::new(
                    participant.request.requested_authorized.units,
                ))
                .map(ExposureUnits::get)
                .map_err(|_| {
                    BudgetStoreError::Overflow(
                        "captured cumulative authorized units overflowed u64".to_string(),
                    )
                })?;
            account.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "cumulative approval account version overflowed u64".to_string(),
                )
            })?;
            Some((
                account.reserved_authorized_units,
                account.captured_authorized_units,
                account.version,
                participant.clone(),
            ))
        } else {
            None
        };

        let key = (request.capability_id.clone(), request.grant_index);
        let usage =
            self.counts.get(&key).cloned().ok_or_else(|| {
                BudgetStoreError::Invariant("missing charged budget row".to_string())
            })?;
        let event_seq = self.next_seq.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget event sequence overflowed u64".to_string())
        })?;
        let accounting = self.prepare_capture_accounting(&hold)?;
        self.next_seq = event_seq;
        accounting.apply(self);
        let quota_usages = self.invocation_quota_usages(&hold.invocation_quotas)?;
        let quota_mutations =
            Self::invocation_quota_mutations(&quota_usages_before, &quota_usages)?;
        let cumulative_approval = hold
            .cumulative_approval
            .as_ref()
            .map(|participant| {
                self.cumulative_approval_usage(
                    &participant.request,
                    BudgetCumulativeApprovalState::Captured,
                )
            })
            .transpose()?;
        let cumulative_approval_mutation = cumulative_before
            .as_ref()
            .map(
                |(reserved_before, captured_before, version_before, participant)| {
                    let account = self
                        .cumulative_approval_accounts
                        .get(&participant.request.account_key)
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "cumulative approval account disappeared".to_string(),
                            )
                        })?;
                    let amount = |units| chio_core::capability::scope::MonetaryAmount {
                        units,
                        currency: participant.request.account_key.currency.clone(),
                    };
                    Ok::<_, BudgetStoreError>(BudgetCumulativeApprovalMutation {
                        operation_id: participant.request.operation_id.clone(),
                        account_key: participant.request.account_key.clone(),
                        state_before: Some(BudgetCumulativeApprovalState::Authorized),
                        state_after: BudgetCumulativeApprovalState::Captured,
                        reserved_authorized_before: amount(*reserved_before),
                        captured_authorized_before: amount(*captured_before),
                        reserved_authorized_after: amount(account.reserved_authorized_units),
                        captured_authorized_after: amount(account.captured_authorized_units),
                        version_before: *version_before,
                        version_after: account.version,
                    })
                },
            )
            .transpose()?;
        let stored_hold = self.holds.get_mut(&request.hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant("validated budget hold missing".to_string())
        })?;
        stored_hold.invocation_state = BudgetInvocationState::Captured;
        if let Some(participant) = stored_hold.cumulative_approval.as_mut() {
            participant.state = BudgetCumulativeApprovalState::Captured;
        }
        self.append_mutation(
            &request.event_id,
            mutation,
            BudgetMutationRecord {
                event_id: String::new(),
                hold_id: Some(request.hold_id.clone()),
                admission_binding: hold.admission_binding.clone(),
                capability_id: request.capability_id.clone(),
                grant_index,
                kind: BudgetMutationKind::CaptureInvocation,
                allowed: Some(true),
                authorization_outcome: None,
                invocation_state_before: BudgetInvocationState::Authorized,
                invocation_state_after: BudgetInvocationState::Captured,
                monetary_state_before: hold.monetary_state,
                monetary_state_after: hold.monetary_state,
                recorded_at: self.now,
                event_seq,
                usage_seq: Some(usage.seq),
                exposure_units: hold.remaining_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: usage.invocation_count,
                invocation_quota_usages: quota_usages,
                invocation_quota_mutations: quota_mutations,
                cumulative_approval,
                cumulative_approval_mutation,
                cumulative_approval_set_digest: hold
                    .cumulative_approval
                    .as_ref()
                    .and_then(|participant| participant.approval_set_digest.clone()),
                total_cost_exposed_after: usage.total_cost_exposed,
                total_cost_realized_spend_after: usage.total_cost_realized_spend,
                authority: request.authority.clone(),
            },
        );
        Ok((true, event_seq, request.event_id.clone(), usage))
    }
}
