impl RemoteBudgetStore {
    fn reject_legacy_partition_escrow_path(&self, operation: &str) -> Result<(), BudgetStoreError> {
        if self.partition_escrow_authority.is_some() {
            return Err(BudgetStoreError::Invariant(format!(
                "sealed partition escrow remote authority rejects legacy budget operation `{operation}`"
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn composite_hold_for_terminal(
        &self,
        capability_id: &str,
        grant_index: usize,
        hold_id: Option<&str>,
        requested_authority: Option<&BudgetEventAuthority>,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        operation: &str,
    ) -> Result<Option<RemoteCompositeHoldEvidence>, BudgetStoreError> {
        let cached = hold_id.and_then(|hold_id| self.cached_composite_hold(hold_id));
        let Some(cached) = cached else {
            if self.partition_escrow_authority.is_some() || admission_operation.is_some() {
                return Err(BudgetStoreError::Invariant(format!(
                    "remote {operation} has no exact cached composite authorization"
                )));
            }
            return Ok(None);
        };
        if cached.capability_id != capability_id
            || cached.grant_index != grant_index
            || requested_authority != Some(&cached.authority)
            || admission_operation != Some(&cached.admission_operation)
        {
            return Err(BudgetStoreError::Conflict(format!(
                "remote {operation} changed its cached composite authorization binding"
            )));
        }
        validate_remote_composite_hold_cache(self.partition_escrow_authority.as_deref(), &cached)?;
        Ok(Some(cached))
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_remote_terminal_if_committed(
        &self,
        event_id: Option<&str>,
        hold_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        requested_authority: Option<&BudgetEventAuthority>,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        expected_kind: BudgetMutationKind,
        exposure_units: u64,
        realized_spend_units: u64,
        composite: Option<&RemoteCompositeHoldEvidence>,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let Some(exact) = self.query_exact_remote_mutation_event_evidence(event_id)? else {
            return Ok(None);
        };
        let record = exact.record;
        let record_grant_index = usize::try_from(record.grant_index).map_err(|_| {
            BudgetStoreError::Invariant(
                "remote terminal event grant index does not fit usize".to_string(),
            )
        })?;
        if record.hold_id.as_deref() != hold_id
            || record.capability_id != capability_id
            || record_grant_index != grant_index
            || record.admission_operation.as_ref() != admission_operation
            || record.kind != expected_kind
            || record.exposure_units != exposure_units
            || record.realized_spend_units != realized_spend_units
            || (requested_authority.is_some() && record.authority.as_ref() != requested_authority)
            || composite
                .is_some_and(|expected| record.authority.as_ref() != Some(&expected.authority))
        {
            return Err(BudgetStoreError::Conflict(
                "remote terminal event_id belongs to a different mutation request".to_string(),
            ));
        }
        let committed_cost_units_after = record
            .total_cost_exposed_after
            .checked_add(record.total_cost_realized_spend_after)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "remote terminal event committed cost overflowed u64".to_string(),
                )
            })?;
        let decision = BudgetHoldMutationDecision {
            hold_id: record.hold_id.clone(),
            exposure_units: record.exposure_units,
            realized_spend_units: record.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: record.invocation_count_after,
            invocation_counts_after: record.invocation_counts_after.clone(),
            invocation_state: record.invocation_state,
            monetary_state: record.monetary_state,
            revocation_set: record.revocation_set.clone(),
            metadata: BudgetCommitMetadata {
                authority: record.authority.clone(),
                guarantee_level: self.budget_guarantee_level(),
                budget_profile: self.budget_authority_profile(),
                metering_profile: self.budget_metering_profile(),
                budget_commit_index: Some(record.event_seq),
                event_id: Some(record.event_id.clone()),
                partition_escrow_evidence: exact.partition_escrow_evidence,
            },
        };
        validate_exact_remote_mutation_decision(
            &record,
            &decision,
            expected_kind,
            admission_operation,
        )?;
        if composite.is_some() {
            self.apply_exact_remote_composite_mutation(&decision, expected_kind)?;
            if matches!(
                expected_kind,
                BudgetMutationKind::ReverseInvocations
                    | BudgetMutationKind::ReconcileSpend
                    | BudgetMutationKind::CaptureExposure
            ) || (expected_kind == BudgetMutationKind::ReleaseExposure
                && decision.monetary_state == BudgetMonetaryHoldState::Released)
            {
                if let Some(hold_id) = decision.hold_id.as_deref() {
                    self.forget_composite_hold(hold_id);
                }
            }
        }
        self.cache_terminal_usage(
            capability_id,
            grant_index,
            Some(record.event_seq),
            record.invocation_count_after,
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        );
        Ok(Some(decision))
    }

    fn query_exact_remote_mutation_event(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        self.query_exact_remote_mutation_event_evidence(event_id)
            .map(|exact| exact.map(|exact| exact.record))
    }

    fn query_exact_remote_mutation_event_evidence(
        &self,
        event_id: &str,
    ) -> Result<Option<RemoteExactMutationEvent>, BudgetStoreError> {
        Self::query_exact_remote_mutation_event_evidence_with_context(
            &self.client,
            self.partition_escrow_authority.as_deref(),
            &self.composite_holds,
            event_id,
        )
    }

    fn query_exact_remote_mutation_event_with_context(
        client: &TrustControlClient,
        authority: Option<&SealedPartitionEscrowRemoteAuthority>,
        composite_holds: &Arc<Mutex<HashMap<String, RemoteCompositeHoldEvidence>>>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        Self::query_exact_remote_mutation_event_evidence_with_context(
            client,
            authority,
            composite_holds,
            event_id,
        )
        .map(|exact| exact.map(|exact| exact.record))
    }

    fn query_exact_remote_mutation_event_evidence_with_context(
        client: &TrustControlClient,
        authority: Option<&SealedPartitionEscrowRemoteAuthority>,
        composite_holds: &Arc<Mutex<HashMap<String, RemoteCompositeHoldEvidence>>>,
        event_id: &str,
    ) -> Result<Option<RemoteExactMutationEvent>, BudgetStoreError> {
        if event_id.is_empty() || event_id.len() > 512 || event_id.bytes().any(|byte| byte == 0) {
            return Err(BudgetStoreError::Invariant(
                "remote exact mutation event identity is invalid".to_string(),
            ));
        }
        if let Some(authority) = authority {
            authority.verify_persisted_configuration()?;
        }
        let request = BudgetMutationEventQueryRequest {
            request_nonce: uuid::Uuid::new_v4().to_string(),
            event_id: event_id.to_string(),
        };
        let endpoints = authority
            .map(|authority| authority.service_endpoints())
            .unwrap_or(client.endpoints.as_slice());
        if endpoints.iter().collect::<BTreeSet<_>>().len() != endpoints.len() {
            return Err(BudgetStoreError::Invariant(
                "remote mutation event membership contains duplicate endpoints".to_string(),
            ));
        }
        let quorum_size = endpoints.len() / 2 + 1;
        let mut groups = BTreeMap::<Vec<u8>, (BudgetMutationEventQueryView, usize)>::new();
        let mut valid_present_response = false;

        for endpoint in endpoints {
            let response = match client.query_budget_mutation_event_at(endpoint, &request) {
                Ok(response) => response,
                Err(_) => continue,
            };
            match validate_remote_mutation_event_replica_response(
                authority, endpoints, endpoint, &request, response,
            ) {
                Ok((membership_digest, query)) => {
                    let canonical =
                        canonical_json_bytes(&(membership_digest, &query)).map_err(|error| {
                            BudgetStoreError::Invariant(format!(
                                "remote mutation event quorum view cannot be canonicalized: {error}"
                            ))
                        })?;
                    valid_present_response |=
                        query.mutation_event.is_some() || query.rejection.is_some();
                    let entry = groups.entry(canonical).or_insert((query, 0));
                    entry.1 = entry.1.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "remote mutation event quorum count overflowed usize".to_string(),
                        )
                    })?;
                }
                Err(_) => continue,
            }
        }

        let mut quorum_views = groups
            .into_values()
            .filter(|(_, count)| *count >= quorum_size)
            .collect::<Vec<_>>();
        if quorum_views.len() != 1 {
            let message = if valid_present_response {
                "remote mutation event replicas did not produce one quorum-identical committed event"
            } else {
                "remote mutation event replicas did not produce one quorum-identical absence view"
            };
            return Err(BudgetStoreError::Conflict(message.to_string()));
        }
        let (view, _) = quorum_views.pop().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote mutation event quorum selection lost its selected view".to_string(),
            )
        })?;
        if view.mutation_event.is_none() && view.rejection.is_none() && valid_present_response {
            return Err(BudgetStoreError::Conflict(
                "remote mutation event absence quorum conflicts with a signed present response"
                    .to_string(),
            ));
        }
        let query_partition_escrow_evidence = partition_escrow_evidence_from_mutation_query(&view)?;
        if let Some(rejection) = view.rejection.as_ref() {
            return Err(BudgetStoreError::Conflict(format!(
                "remote mutation was durably rejected with status {} and code `{}`: {}",
                rejection.status_code, rejection.code, rejection.message
            )));
        }
        let Some(event) = view.mutation_event else {
            return Ok(None);
        };
        let record = super::super::cluster::budget_mutation_record_from_view(&event)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        validate_remote_mutation_record_shape(&record)?;
        if let Some(hold_id) = record.hold_id.as_deref() {
            let cached = cached_remote_composite_hold(composite_holds, hold_id);
            if let Some(cached) = cached {
                if query_partition_escrow_evidence.as_ref()
                    != cached.partition_escrow_evidence.as_ref()
                {
                    return Err(BudgetStoreError::Conflict(
                        "remote exact mutation event changed the persisted partition escrow proof"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(Some(RemoteExactMutationEvent {
            record,
            partition_escrow_evidence: query_partition_escrow_evidence,
        }))
    }

    fn authorize_remote_composite_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
        existing_only: bool,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.max_invocations.is_some() {
            return Err(BudgetStoreError::Invariant(
                "remote composite budget hold must not include legacy max_invocations".to_string(),
            ));
        }
        let hold_id = request.hold_id.clone().ok_or_else(|| {
            BudgetStoreError::Invariant("remote composite budget hold requires hold_id".to_string())
        })?;
        let event_id = request.event_id.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote composite budget hold requires event_id".to_string(),
            )
        })?;
        let admission = request.invocation_admission_evidence().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote composite budget hold requires verified admission evidence".to_string(),
            )
        })?;
        let expected_partition_escrow_evidence = admission
            .partition_escrow_evidence()
            .map(PartitionEscrowCommitEvidence::from_admission_evidence)
            .transpose()?;
        match (
            self.partition_escrow_authority.as_deref(),
            expected_partition_escrow_evidence.as_ref(),
        ) {
            (Some(authority), Some(evidence)) if existing_only => {
                authority.validate_persisted_commit_evidence(evidence)?;
            }
            (Some(authority), Some(evidence)) => {
                authority.validate_fresh_authorization_evidence_now(evidence)?;
            }
            (None, None) => {}
            (Some(_), None) => {
                return Err(BudgetStoreError::Invariant(
                    "sealed remote composite authorization omitted partition escrow evidence"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(BudgetStoreError::Invariant(
                    "ordinary remote composite authorization carried partition escrow evidence"
                        .to_string(),
                ));
            }
        }
        let admission_operation = request.admission_operation.clone().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote composite budget hold requires admission operation ownership".to_string(),
            )
        })?;
        let invocation_quotas = request.invocation_quotas().to_vec();
        let revocation_set = request.revocation_set().cloned().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote composite budget hold requires a canonical revocation set".to_string(),
            )
        })?;
        let wire_request = CompositeBudgetAuthorizeRequest {
            existing_only,
            operation_id: admission_operation.operation_id().to_string(),
            request_binding_hash: admission_operation.request_binding_hash().to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            requested_exposure_units: request.requested_exposure_units,
            max_exposure_per_invocation: request.max_cost_per_invocation,
            max_total_exposure_units: request.max_total_cost_units,
            hold_id: hold_id.clone(),
            event_id: event_id.clone(),
            admission_evidence: admission_evidence_view(admission)?,
        };
        let response = if existing_only {
            self.client
                .query_committed_composite_budget_authorization(&wire_request)
                .map_err(into_replay_budget_store_error)?
        } else {
            self.client
                .authorize_composite_budget_hold(&wire_request)
                .map_err(into_budget_store_error)?
        };
        let decision = validate_composite_authorize_response_for_authority(
            &wire_request,
            response,
            self.partition_escrow_authority.as_deref(),
        )?;

        match &decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                let event_seq = authorized.metadata.budget_commit_index.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote composite authorization omitted its durable event sequence"
                            .to_string(),
                    )
                })?;
                let authority = authorized.metadata.authority.clone().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote composite authorization omitted its persisted authority"
                            .to_string(),
                    )
                })?;
                self.remember_composite_hold(
                    hold_id.clone(),
                    RemoteCompositeHoldEvidence {
                        authorization_event_id: event_id.clone(),
                        last_event_id: event_id.clone(),
                        last_event_seq: event_seq,
                        admission_operation,
                        capability_id: request.capability_id.clone(),
                        grant_index: request.grant_index,
                        invocation_quotas,
                        invocation_counts_after: authorized.invocation_counts_after.clone(),
                        invocation_state: authorized.invocation_state,
                        revocation_set,
                        authorized_exposure_units: authorized.authorized_exposure_units,
                        remaining_exposure_units: authorized.authorized_exposure_units,
                        monetary_state: authorized.monetary_state,
                        authority,
                        partition_escrow_evidence: authorized
                            .metadata
                            .partition_escrow_evidence
                            .clone(),
                    },
                )?;
            }
            BudgetAuthorizeHoldDecision::Denied(denied) => {
                let event_seq = denied.metadata.budget_commit_index.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote composite denial omitted its durable event sequence".to_string(),
                    )
                })?;
                let authority = denied.metadata.authority.clone().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote composite denial omitted its persisted authority".to_string(),
                    )
                })?;
                self.remember_composite_hold(
                    hold_id.clone(),
                    RemoteCompositeHoldEvidence {
                        authorization_event_id: event_id.clone(),
                        last_event_id: event_id.clone(),
                        last_event_seq: event_seq,
                        admission_operation,
                        capability_id: request.capability_id.clone(),
                        grant_index: request.grant_index,
                        invocation_quotas,
                        invocation_counts_after: denied.invocation_counts_after.clone(),
                        invocation_state: denied.invocation_state,
                        revocation_set,
                        authorized_exposure_units: 0,
                        remaining_exposure_units: 0,
                        monetary_state: denied.monetary_state,
                        authority,
                        partition_escrow_evidence: denied
                            .metadata
                            .partition_escrow_evidence
                            .clone(),
                    },
                )?;
            }
        }
        let record = self
            .query_exact_remote_mutation_event(&event_id)?
            .ok_or_else(|| {
                BudgetStoreError::Conflict(
                    "remote composite authorization has no quorum-attested durable event"
                        .to_string(),
                )
            })?;
        validate_exact_remote_authorization_decision(&record, &decision, &wire_request)?;
        if matches!(&decision, BudgetAuthorizeHoldDecision::Denied(_)) {
            self.forget_composite_hold(&hold_id);
        }
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            None,
            None,
            None,
            None,
        );
        Ok(decision)
    }

    fn capture_remote_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("remote invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("remote invocation capture requires event_id".to_string())
        })?;
        let replay_composite = self.cached_composite_hold(hold_id);
        if let Some(decision) = self.replay_remote_terminal_if_committed(
            Some(event_id),
            Some(hold_id),
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            BudgetMutationKind::CaptureInvocations,
            0,
            0,
            replay_composite.as_ref(),
        )? {
            return Ok(decision);
        }
        let expected = replay_composite.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "remote invocation capture has no exact cached evidence for hold `{hold_id}`"
            ))
        })?;
        if expected.capability_id != request.capability_id
            || expected.grant_index != request.grant_index
        {
            return Err(BudgetStoreError::Invariant(
                "remote invocation capture does not match the cached capability/grant".to_string(),
            ));
        }
        if request.authority.as_ref() != Some(&expected.authority) {
            return Err(BudgetStoreError::Invariant(
                "remote invocation capture must carry the exact persisted authorization authority"
                    .to_string(),
            ));
        }
        if request.admission_operation.as_ref() != Some(&expected.admission_operation) {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture does not match the cached admission operation ownership"
                    .to_string(),
            ));
        }
        let wire_request = CaptureInvocationReservationsRequest {
            operation_id: expected.admission_operation.operation_id().to_string(),
            request_binding_hash: expected
                .admission_operation
                .request_binding_hash()
                .to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            budget_authority: request.authority.as_ref().map(|authority| {
                BudgetMutationAuthorityView {
                    authority_id: authority.authority_id.clone(),
                    lease_id: authority.lease_id.clone(),
                    lease_epoch: authority.lease_epoch,
                }
            }),
        };
        let response = self
            .client
            .capture_invocation_reservations(&wire_request)
            .map_err(into_budget_store_error)?;
        let decision = validate_invocation_capture_response_for_authority(
            &request,
            &expected.invocation_quotas,
            &expected.revocation_set,
            expected.monetary_state,
            response,
            self.partition_escrow_authority.as_deref(),
            expected.partition_escrow_evidence.as_ref(),
        )?;
        self.validate_and_remember_invocation_capture(&request, &decision)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            None,
            None,
            None,
            None,
        );
        Ok(decision)
    }

    fn validate_and_remember_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
        decision: &BudgetHoldMutationDecision,
    ) -> Result<(), BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("remote invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("remote invocation capture requires event_id".to_string())
        })?;
        let record = self
            .query_exact_remote_mutation_event(event_id)?
            .ok_or_else(|| {
                BudgetStoreError::Conflict(
                    "remote invocation capture has no quorum-attested durable event".to_string(),
                )
            })?;
        validate_exact_remote_mutation_decision(
            &record,
            decision,
            BudgetMutationKind::CaptureInvocations,
            request.admission_operation.as_ref(),
        )?;
        update_remote_composite_hold(&self.composite_holds, hold_id, |expected| {
            let Some(event) = next_remote_composite_event(expected, decision)? else {
                return Ok(());
            };
            if expected.capability_id != request.capability_id
                || expected.grant_index != request.grant_index
                || request.authority.as_ref() != Some(&expected.authority)
                || request.admission_operation.as_ref() != Some(&expected.admission_operation)
                || decision.invocation_state != BudgetInvocationReservationState::Captured
                || decision.monetary_state != expected.monetary_state
                || decision.revocation_set.as_ref() != Some(&expected.revocation_set)
                || decision.metadata.partition_escrow_evidence != expected.partition_escrow_evidence
            {
                return Err(BudgetStoreError::Conflict(
                    "remote invocation capture changed its cached composite evidence".to_string(),
                ));
            }
            if expected.invocation_state != BudgetInvocationReservationState::Authorized {
                return Err(BudgetStoreError::Conflict(
                    "remote invocation capture cached an ineligible invocation state".to_string(),
                ));
            }
            validate_exact_invocation_capture_transition(
                &expected.invocation_counts_after,
                &decision.invocation_counts_after,
            )?;
            expected.invocation_counts_after = decision.invocation_counts_after.clone();
            expected.invocation_state = decision.invocation_state;
            finish_remote_composite_event(expected, event);
            Ok(())
        })
    }

    fn validate_remote_terminal_decision(
        &self,
        decision: &BudgetHoldMutationDecision,
        expected_kind: BudgetMutationKind,
        expected_admission_operation: Option<&BudgetAdmissionOperationBinding>,
    ) -> Result<(), BudgetStoreError> {
        let event_id = decision.metadata.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote terminal decision omitted its durable event_id".to_string(),
            )
        })?;
        let record = self
            .query_exact_remote_mutation_event(event_id)?
            .ok_or_else(|| {
                BudgetStoreError::Conflict(
                    "remote terminal decision has no quorum-attested durable event".to_string(),
                )
            })?;
        validate_exact_remote_mutation_decision(
            &record,
            decision,
            expected_kind,
            expected_admission_operation,
        )
    }

    fn apply_exact_remote_composite_mutation(
        &self,
        decision: &BudgetHoldMutationDecision,
        kind: BudgetMutationKind,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = decision.hold_id.as_deref() else {
            return Ok(());
        };
        if self.cached_composite_hold(hold_id).is_none() {
            return Ok(());
        }
        update_remote_composite_hold(&self.composite_holds, hold_id, |cached| {
            let Some(event) = next_remote_composite_event(cached, decision)? else {
                return Ok(());
            };
            match kind {
                BudgetMutationKind::CaptureInvocations => {
                    if cached.invocation_state != BudgetInvocationReservationState::Authorized
                        || decision.invocation_state != BudgetInvocationReservationState::Captured
                        || decision.monetary_state != cached.monetary_state
                    {
                        return Err(BudgetStoreError::Conflict(
                            "remote invocation capture is not eligible from cached state"
                                .to_string(),
                        ));
                    }
                    validate_exact_invocation_capture_transition(
                        &cached.invocation_counts_after,
                        &decision.invocation_counts_after,
                    )?;
                    cached.invocation_counts_after = decision.invocation_counts_after.clone();
                    cached.invocation_state = decision.invocation_state;
                }
                BudgetMutationKind::ReverseInvocations => {
                    if cached.invocation_state != BudgetInvocationReservationState::Authorized
                        || decision.invocation_state != BudgetInvocationReservationState::Reversed
                    {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite reverse is not eligible from cached invocation state"
                                .to_string(),
                        ));
                    }
                    validate_exact_invocation_reverse_transition(
                        &cached.invocation_counts_after,
                        &decision.invocation_counts_after,
                    )?;
                    match cached.monetary_state {
                        BudgetMonetaryHoldState::Exposed => {
                            if decision.exposure_units != cached.remaining_exposure_units
                                || decision.monetary_state != BudgetMonetaryHoldState::Reversed
                            {
                                return Err(BudgetStoreError::Conflict(
                                    "remote composite reverse changed its remaining exposure"
                                        .to_string(),
                                ));
                            }
                            cached.remaining_exposure_units = 0;
                        }
                        BudgetMonetaryHoldState::None
                        | BudgetMonetaryHoldState::Released
                        | BudgetMonetaryHoldState::Reversed => {
                            if decision.exposure_units != 0
                                || decision.monetary_state != cached.monetary_state
                            {
                                return Err(BudgetStoreError::Conflict(
                                    "remote composite reverse created monetary exposure"
                                        .to_string(),
                                ));
                            }
                        }
                        BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                            return Err(BudgetStoreError::Conflict(
                                "remote composite reverse followed a terminal monetary state"
                                    .to_string(),
                            ));
                        }
                    }
                    cached.invocation_counts_after = decision.invocation_counts_after.clone();
                    cached.invocation_state = decision.invocation_state;
                    cached.monetary_state = decision.monetary_state;
                }
                BudgetMutationKind::ReleaseExposure => {
                    if cached.monetary_state != BudgetMonetaryHoldState::Exposed
                        || !matches!(
                            cached.invocation_state,
                            BudgetInvocationReservationState::Authorized
                                | BudgetInvocationReservationState::Captured
                        )
                        || decision.invocation_counts_after != cached.invocation_counts_after
                        || decision.invocation_state != cached.invocation_state
                    {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite release is not eligible from cached state"
                                .to_string(),
                        ));
                    }
                    let remaining = cached
                        .remaining_exposure_units
                        .checked_sub(decision.exposure_units)
                        .ok_or_else(|| {
                            BudgetStoreError::Conflict(
                                "remote composite release exceeded remaining exposure".to_string(),
                            )
                        })?;
                    let expected_state = if remaining == 0 {
                        BudgetMonetaryHoldState::Released
                    } else {
                        BudgetMonetaryHoldState::Exposed
                    };
                    if decision.monetary_state != expected_state {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite release changed its resulting monetary state"
                                .to_string(),
                        ));
                    }
                    cached.remaining_exposure_units = remaining;
                    cached.monetary_state = decision.monetary_state;
                }
                BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureExposure => {
                    let expected_state = if kind == BudgetMutationKind::ReconcileSpend {
                        BudgetMonetaryHoldState::Reconciled
                    } else {
                        BudgetMonetaryHoldState::Captured
                    };
                    if cached.monetary_state != BudgetMonetaryHoldState::Exposed
                        || !matches!(
                            cached.invocation_state,
                            BudgetInvocationReservationState::Authorized
                                | BudgetInvocationReservationState::Captured
                        )
                        || decision.exposure_units != cached.remaining_exposure_units
                        || decision.realized_spend_units > decision.exposure_units
                        || decision.invocation_counts_after != cached.invocation_counts_after
                        || decision.invocation_state != cached.invocation_state
                        || decision.monetary_state != expected_state
                    {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite settlement is not eligible from cached state"
                                .to_string(),
                        ));
                    }
                    cached.remaining_exposure_units = 0;
                    cached.monetary_state = decision.monetary_state;
                }
                _ => {
                    return Err(BudgetStoreError::Invariant(
                        "remote composite cache received an unsupported mutation kind".to_string(),
                    ));
                }
            }
            finish_remote_composite_event(cached, event);
            Ok(())
        })
    }

    fn remember_composite_hold(
        &self,
        hold_id: String,
        evidence: RemoteCompositeHoldEvidence,
    ) -> Result<(), BudgetStoreError> {
        if evidence.authorization_event_id.is_empty()
            || evidence.last_event_id != evidence.authorization_event_id
            || evidence.last_event_seq == 0
            || !matches!(
                evidence.invocation_state,
                BudgetInvocationReservationState::Authorized
                    | BudgetInvocationReservationState::Denied
            )
        {
            return Err(BudgetStoreError::Invariant(
                "remote composite authorization cache input is incomplete".to_string(),
            ));
        }
        let mut holds = match self.composite_holds.lock() {
            Ok(holds) => holds,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(existing) = holds.get(&hold_id) else {
            if holds.len() >= MAX_REMOTE_COMPOSITE_HOLDS {
                return Err(BudgetStoreError::Conflict(
                    "remote composite hold cache reached its fail-closed capacity".to_string(),
                ));
            }
            holds.insert(hold_id, evidence);
            return Ok(());
        };
        if !remote_composite_hold_immutable_evidence_matches(existing, &evidence) {
            return Err(BudgetStoreError::Conflict(format!(
                "remote composite hold `{hold_id}` collided with different authorization evidence"
            )));
        }
        if existing.last_event_seq < evidence.last_event_seq {
            return Err(BudgetStoreError::Conflict(format!(
                "remote composite hold `{hold_id}` regressed behind its authorization event"
            )));
        }
        if existing.last_event_seq == evidence.last_event_seq
            && (existing.last_event_id != evidence.last_event_id
                || !remote_composite_hold_mutable_state_matches(existing, &evidence))
        {
            return Err(BudgetStoreError::Conflict(format!(
                "remote composite hold `{hold_id}` replay changed its frozen authorization state"
            )));
        }
        Ok(())
    }

    fn forget_composite_hold(&self, hold_id: &str) {
        match self.composite_holds.lock() {
            Ok(mut holds) => {
                holds.remove(hold_id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(hold_id);
            }
        }
    }

    fn cached_composite_hold(&self, hold_id: &str) -> Option<RemoteCompositeHoldEvidence> {
        match self.composite_holds.lock() {
            Ok(holds) => holds.get(hold_id).cloned(),
            Err(poisoned) => poisoned.into_inner().get(hold_id).cloned(),
        }
    }

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
            partition_escrow_evidence: evidence.partition_escrow_evidence.clone(),
        }
    }
}

include!("part_01_validation.inc");
