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
        // Preserve the legacy single-grant path for callers that did not present
        // verified composite admission. It atomically debits the primary
        // invocation and monetary exposure and records a legacy hold, matching
        // the SQLite backend and the BudgetStore default implementation. Turning
        // this request into an ownerless composite hold strands its reserved
        // invocation because composite capture and recovery require an admission
        // operation binding.
        if request.invocation_admission.is_none() && request.admission_operation.is_none() {
            let monetary_state = if request.requested_exposure_units > 0
                || request.max_cost_per_invocation.is_some()
                || request.max_total_cost_units.is_some()
            {
                BudgetMonetaryHoldState::Exposed
            } else {
                BudgetMonetaryHoldState::None
            };
            let allowed = self.try_charge_cost_with_ids_and_authority(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
                request.authority.as_ref(),
            )?;
            let usage = self.get_usage(&request.capability_id, request.grant_index)?;
            let committed_cost_units_after = usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0);
            let invocation_count_after =
                usage.as_ref().map_or(0, |usage| usage.invocation_count);
            let metadata = budget_commit_metadata(
                self,
                request.authority,
                allowed
                    .then(|| usage.as_ref().map(|usage| usage.seq))
                    .flatten(),
                request.event_id,
            );
            return if allowed {
                Ok(BudgetAuthorizeHoldDecision::Authorized(
                    AuthorizedBudgetHold {
                        hold_id: request.hold_id,
                        authorized_exposure_units: request.requested_exposure_units,
                        committed_cost_units_after,
                        invocation_count_after,
                        invocation_counts_after: Vec::new(),
                        invocation_state: BudgetInvocationReservationState::Absent,
                        monetary_state,
                        revocation_set: None,
                        metadata,
                    },
                ))
            } else {
                Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                    hold_id: request.hold_id,
                    attempted_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    invocation_counts_after: Vec::new(),
                    invocation_state: BudgetInvocationReservationState::Denied,
                    monetary_state: BudgetMonetaryHoldState::None,
                    revocation_set: None,
                    metadata,
                }))
            };
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

    fn mark_invocation_hold_reserved(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.mark_invocation_hold_reserved(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &super::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.lock_inner()?.mark_admission_operation_hold_reserved(
            hold_id,
            admission_operation,
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
