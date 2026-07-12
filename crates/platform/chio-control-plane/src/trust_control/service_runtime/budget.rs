use super::client::build_client;
use super::errors::into_budget_store_error;
use super::*;

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        cached_usage: Mutex::new(HashMap::new()),
    }))
}

impl BudgetStore for RemoteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let response = self
            .client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map_err(into_budget_store_error)?;
        let evidence =
            validate_remote_budget_evidence(response.budget_authority.as_ref(), None, None)?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            None,
            None,
        );
        Ok(response.allowed)
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
        let response = self
            .client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(response.allowed)
    }

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
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
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
        _authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let response = self
            .client
            .try_charge_cost_with_ids(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(response.allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let response = self
            .client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
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
        let response = self
            .client
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let response = self
            .client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
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
        let response = self
            .client
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let response = self
            .client
            .reconcile_budget_spend(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
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
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
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
        let response = self
            .client
            .reconcile_budget_spend_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            return Err(BudgetStoreError::Invariant(
                "remote composite budget holds are not installed".to_string(),
            ));
        }
        let response = self
            .client
            .try_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        let metadata = self.remote_budget_commit_metadata(&evidence, request.event_id.clone());
        let authorized_monetary_state = if request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        if response.allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: invocation_count,
                    invocation_counts_after: Vec::new(),
                    invocation_state: BudgetInvocationReservationState::Absent,
                    monetary_state: authorized_monetary_state,
                    revocation_set: None,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: invocation_count,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationState::Denied,
                monetary_state: BudgetMonetaryHoldState::None,
                revocation_set: None,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reverse_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.reversed_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                request.authority.as_ref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
        )?;
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reversed,
            revocation_set: None,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reduce_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.released_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                request.authority.as_ref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
        )?;
        if response.released_exposure_units != Some(request.released_exposure_units) {
            return Err(BudgetStoreError::Invariant(
                "remote budget release response does not match released exposure".to_string(),
            ));
        }
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Released,
            revocation_set: None,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reconcile_budget_spend_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.exposed_cost_units,
                request.realized_spend_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                request.authority.as_ref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
        )?;
        let expected_released_exposure = request
            .exposed_cost_units
            .checked_sub(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed reconciled exposure".to_string(),
                )
            })?;
        if response.released_exposure_units != Some(expected_released_exposure) {
            return Err(BudgetStoreError::Invariant(
                "remote budget reconcile response does not match released exposure".to_string(),
            ));
        }
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reconciled,
            revocation_set: None,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        })
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .capture_budget_spend_with_ids(
                &request.capability_id,
                request.grant_index,
                request.exposed_cost_units,
                request.realized_spend_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                request.authority.as_ref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
        )?;
        if response.capability_id != request.capability_id
            || response.grant_index != request.grant_index
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget capture response does not match capability/grant".to_string(),
            ));
        }
        let expected_released_exposure = request
            .exposed_cost_units
            .checked_sub(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed captured exposure".to_string(),
                )
            })?;
        if response.released_exposure_units != Some(expected_released_exposure) {
            return Err(BudgetStoreError::Invariant(
                "remote budget capture response does not match released exposure".to_string(),
            ));
        }
        let invocation_count = response.invocation_count.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted invocation_count".to_string(),
            )
        })?;
        let total_cost_exposed = response.total_cost_exposed.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted total exposed cost".to_string(),
            )
        })?;
        let total_cost_realized_spend = response.total_cost_realized_spend.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted total realized spend".to_string(),
            )
        })?;
        let committed_cost_units_after = total_cost_exposed
            .checked_add(total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "remote captured committed cost overflowed u64".to_string(),
                )
            })?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Captured,
            revocation_set: None,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        })
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map(|response| {
                let usages: Vec<_> = response
                    .usages
                    .into_iter()
                    .map(|usage| BudgetUsageRecord {
                        capability_id: usage.capability_id,
                        grant_index: usage.grant_index,
                        invocation_count: usage.invocation_count,
                        updated_at: usage.updated_at,
                        seq: usage.seq.unwrap_or(0),
                        total_cost_exposed: usage.total_cost_exposed,
                        total_cost_realized_spend: usage.total_cost_realized_spend,
                    })
                    .collect();
                self.replace_cached_usages(capability_id, &usages);
                usages
            })
            .map_err(into_budget_store_error)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        if let Some(cached) = self.cached_usage(capability_id, grant_index) {
            return Ok(Some(cached));
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index as u32)
            })
    }
}

impl RemoteBudgetStore {
    fn cache_terminal_response(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) {
        if seq.is_some() {
            self.cache_usage(
                capability_id,
                grant_index,
                seq,
                invocation_count,
                total_cost_exposed,
                total_cost_realized_spend,
            );
        } else {
            self.cache_usage(capability_id, grant_index, None, None, None, None);
        }
    }

    fn cache_terminal_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: u32,
        total_cost_exposed: u64,
        total_cost_realized_spend: u64,
    ) {
        self.cache_terminal_response(
            capability_id,
            grant_index,
            seq,
            Some(invocation_count),
            Some(total_cost_exposed),
            Some(total_cost_realized_spend),
        );
    }

    fn cache_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (capability_id.to_string(), grant_index as u32);
        if seq.is_some_and(|incoming_seq| {
            cached_usage
                .get(&key)
                .is_some_and(|existing| existing.seq > incoming_seq)
        }) {
            return;
        }
        let updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        match (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        ) {
            (None, None, None) => {
                cached_usage.remove(&key);
            }
            _ => {
                let entry = cached_usage
                    .entry(key)
                    .or_insert_with(|| BudgetUsageRecord {
                        capability_id: capability_id.to_string(),
                        grant_index: grant_index as u32,
                        invocation_count: 0,
                        updated_at,
                        seq: seq.unwrap_or(0),
                        total_cost_exposed: 0,
                        total_cost_realized_spend: 0,
                    });
                if let Some(seq) = seq {
                    entry.seq = seq;
                }
                if let Some(invocation_count) = invocation_count {
                    entry.invocation_count = invocation_count;
                }
                if let Some(total_cost_exposed) = total_cost_exposed {
                    entry.total_cost_exposed = total_cost_exposed;
                }
                if let Some(total_cost_realized_spend) = total_cost_realized_spend {
                    entry.total_cost_realized_spend = total_cost_realized_spend;
                }
                entry.updated_at = updated_at;
            }
        }
    }

    fn cached_usage(&self, capability_id: &str, grant_index: usize) -> Option<BudgetUsageRecord> {
        match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
        .get(&(capability_id.to_string(), grant_index as u32))
        .cloned()
    }

    fn replace_cached_usages(&self, capability_id: Option<&str>, usages: &[BudgetUsageRecord]) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(capability_id) = capability_id {
            cached_usage
                .retain(|(cached_capability_id, _), _| cached_capability_id != capability_id);
        } else {
            cached_usage.clear();
        }

        for usage in usages {
            cached_usage.insert(
                (usage.capability_id.clone(), usage.grant_index),
                usage.clone(),
            );
        }
    }

    fn remote_budget_commit_metadata(
        &self,
        evidence: &ValidatedRemoteBudgetEvidence,
        event_id: Option<String>,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: evidence.authority.clone(),
            guarantee_level: evidence.guarantee_level,
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: evidence.commit_index,
            event_id,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedRemoteBudgetEvidence {
    authority: Option<BudgetEventAuthority>,
    guarantee_level: BudgetGuaranteeLevel,
    commit_index: Option<u64>,
}

fn required_remote_transition_snapshot(
    expected_capability_id: &str,
    expected_grant_index: usize,
    response_capability_id: &str,
    response_grant_index: usize,
    invocation_count: Option<u32>,
    total_cost_exposed: Option<u64>,
    total_cost_realized_spend: Option<u64>,
) -> Result<(u32, u64, u64, u64), BudgetStoreError> {
    if response_capability_id != expected_capability_id
        || response_grant_index != expected_grant_index
    {
        return Err(BudgetStoreError::Invariant(
            "remote budget transition response does not match capability/grant".to_string(),
        ));
    }
    let invocation_count = invocation_count.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted invocation_count".to_string(),
        )
    })?;
    let total_cost_exposed = total_cost_exposed.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted total exposed cost".to_string(),
        )
    })?;
    let total_cost_realized_spend = total_cost_realized_spend.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "remote budget transition response omitted total realized spend".to_string(),
        )
    })?;
    let committed_cost_units_after = total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "remote budget transition committed cost overflowed u64".to_string(),
            )
        })?;
    Ok((
        invocation_count,
        total_cost_exposed,
        total_cost_realized_spend,
        committed_cost_units_after,
    ))
}

fn validate_remote_budget_evidence(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
    requested_terminal_authority: Option<&BudgetEventAuthority>,
) -> Result<ValidatedRemoteBudgetEvidence, BudgetStoreError> {
    let metadata_authority = authority
        .map(|authority| {
            if authority.budget_term != authority.lease_epoch {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority term does not match its lease epoch".to_string(),
                ));
            }
            if authority.authority_id.is_empty() || authority.lease_id.is_empty() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority identity is incomplete".to_string(),
                ));
            }
            Ok(BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            })
        })
        .transpose()?;

    let commit_authority = commit
        .map(|commit| {
            if commit.budget_term != commit.lease_epoch {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit term does not match its lease epoch".to_string(),
                ));
            }
            if commit.authority_id.is_empty() || commit.lease_id.is_empty() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit authority identity is incomplete".to_string(),
                ));
            }
            if commit.budget_seq != commit.commit_index {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit index does not match its budget sequence".to_string(),
                ));
            }
            if !commit.quorum_committed {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit is not quorum committed".to_string(),
                ));
            }
            if commit.quorum_size == 0 || commit.committed_nodes < commit.quorum_size {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit does not contain a quorum of witnesses".to_string(),
                ));
            }
            let unique_witnesses = commit.witness_urls.iter().collect::<BTreeSet<_>>();
            if unique_witnesses.len() != commit.witness_urls.len() {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit contains duplicate witness URLs".to_string(),
                ));
            }
            if commit.witness_urls.len() != commit.committed_nodes {
                return Err(BudgetStoreError::Invariant(
                    "remote budget commit witness count does not match committed nodes".to_string(),
                ));
            }
            Ok(BudgetEventAuthority {
                authority_id: commit.authority_id.clone(),
                lease_id: commit.lease_id.clone(),
                lease_epoch: commit.lease_epoch,
            })
        })
        .transpose()?;

    if let (Some(metadata_authority), Some(commit_authority)) =
        (metadata_authority.as_ref(), commit_authority.as_ref())
    {
        if metadata_authority != commit_authority
            || authority.is_some_and(|authority| {
                authority.budget_term != commit.map_or(0, |commit| commit.budget_term)
            })
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget authority does not match budget commit authority".to_string(),
            ));
        }
    }

    if let Some(commit) = commit {
        if let Some(authority) = authority {
            if authority.budget_commit_index != Some(commit.commit_index) {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authority commit index does not match budget commit".to_string(),
                ));
            }
        }
    }

    if let Some(requested) = requested_terminal_authority {
        let Some(response_authority) = metadata_authority.as_ref() else {
            return Err(BudgetStoreError::Invariant(
                "remote budget transition response omitted the requested budget authority"
                    .to_string(),
            ));
        };
        if response_authority != requested {
            return Err(BudgetStoreError::Invariant(
                "remote budget transition response authority does not match the requested budget authority"
                    .to_string(),
            ));
        }
    }

    let guarantee_level = match authority.map(|authority| authority.guarantee_level.as_str()) {
        Some("single_node_atomic") if commit.is_none() => BudgetGuaranteeLevel::SingleNodeAtomic,
        Some("ha_quorum_commit") | Some("ha_linearizable") if commit.is_some() => {
            BudgetGuaranteeLevel::HaLinearizable
        }
        Some("partition_escrowed") if commit.is_none() => BudgetGuaranteeLevel::PartitionEscrowed,
        Some("ha_leader_visible") | Some("advisory_posthoc") if commit.is_none() => {
            BudgetGuaranteeLevel::AdvisoryPosthoc
        }
        Some("ha_quorum_commit") | Some("ha_linearizable") => {
            return Err(BudgetStoreError::Invariant(
                "remote HA budget authority omitted its quorum commit".to_string(),
            ));
        }
        Some(
            "single_node_atomic" | "partition_escrowed" | "ha_leader_visible" | "advisory_posthoc",
        ) => {
            return Err(BudgetStoreError::Invariant(
                "remote budget guarantee contradicts the supplied quorum commit".to_string(),
            ));
        }
        Some(unknown) => {
            return Err(BudgetStoreError::Invariant(format!(
                "remote budget response has unknown guarantee level `{unknown}`"
            )));
        }
        None if commit.is_some() => BudgetGuaranteeLevel::HaLinearizable,
        None => BudgetGuaranteeLevel::SingleNodeAtomic,
    };

    let response_authority = metadata_authority.or(commit_authority);
    let commit_index = commit
        .map(|commit| commit.commit_index)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index));
    if commit.is_none()
        && authority.is_some_and(|authority| authority.budget_commit_index.is_some())
    {
        return Err(BudgetStoreError::Invariant(
            "remote budget authority supplied a commit index without quorum commit evidence"
                .to_string(),
        ));
    }

    Ok(ValidatedRemoteBudgetEvidence {
        authority: response_authority,
        guarantee_level,
        commit_index,
    })
}
