use super::client::{
    build_client, BudgetCostMutationRequest, BudgetMutationParts, BudgetSpendMutationRequest,
};
use super::errors::into_budget_store_error;
use super::*;

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Mutex::new(HashMap::new()),
    }))
}

pub fn build_remote_admission_capture_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn AdmissionCaptureAuthority>, CliError> {
    Ok(Box::new(RemoteAdmissionCaptureAuthority {
        client: build_client(control_url, control_token)?,
    }))
}

impl AdmissionCaptureAuthority for RemoteAdmissionCaptureAuthority {
    fn query_admission_capture(
        &self,
        request: &AdmissionCaptureRequest,
    ) -> Result<Option<AdmissionCaptureDecision>, AdmissionCaptureError> {
        let capture_request = remote_admission_capture_wire_request(request)?;
        let response = self
            .client
            .query_admission_capture(&AdmissionCapturePointQueryRequest { capture_request })
            .map_err(|error| AdmissionCaptureError::Unavailable(error.to_string()))?;
        let admission_operation =
            request
                .budget()
                .admission_operation
                .as_ref()
                .ok_or_else(|| {
                    AdmissionCaptureError::InvalidRequest(
                        "remote admission capture query requires admission operation ownership"
                            .to_string(),
                    )
                })?;
        if response.operation_id != request.operation_id()
            || response.request_binding_hash != admission_operation.request_binding_hash()
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "remote admission capture query response changed its operation binding".to_string(),
            ));
        }
        response
            .capture
            .map(|capture| validate_remote_admission_capture_response(request, capture))
            .transpose()
    }

    fn capture_admission(
        &self,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        let wire_request = remote_admission_capture_wire_request(&request)?;
        let response = self
            .client
            .capture_admission(&wire_request)
            .map_err(|error| AdmissionCaptureError::Unavailable(error.to_string()))?;
        validate_remote_admission_capture_response(&request, response)
    }
}

fn remote_admission_capture_wire_request(
    request: &AdmissionCaptureRequest,
) -> Result<CombinedAdmissionCaptureRequest, AdmissionCaptureError> {
    let budget = request.budget();
    let hold_id = budget.hold_id.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires hold_id".to_string(),
        )
    })?;
    let event_id = budget.event_id.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires event_id".to_string(),
        )
    })?;
    let authority = budget.authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires persisted authority".to_string(),
        )
    })?;
    let admission_operation = budget.admission_operation.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires admission operation ownership".to_string(),
        )
    })?;
    Ok(CombinedAdmissionCaptureRequest {
        operation_id: request.operation_id().to_string(),
        request_binding_hash: admission_operation.request_binding_hash().to_string(),
        capability_id: budget.capability_id.clone(),
        grant_index: budget.grant_index,
        hold_id: hold_id.clone(),
        event_id: event_id.clone(),
        budget_authority: Some(BudgetMutationAuthorityView {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        }),
        revocation_set: canonical_revocation_set_view(request.revocation_set()),
        bound_revocation_set_digest: request.bound_revocation_set_digest().to_string(),
        authorization_artifact_digests: request.authorization_artifact_digests().to_vec(),
        aggregate_root_capability_id: request
            .aggregate_root_capability_id()
            .map(ToOwned::to_owned),
        aggregate_root_binding_digest: request
            .aggregate_root_binding_digest()
            .map(ToOwned::to_owned),
        last_observed_revocation_index: request.last_observed_revocation_index(),
    })
}

impl BudgetStore for RemoteBudgetStore {
    fn authority_profile(&self) -> BudgetStoreProfile {
        BudgetStoreProfile::SharedLinearizable
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::HaLinearizable
    }

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
            .reconcile_budget_spend_with_ids_and_authority(BudgetSpendMutationRequest::new(
                BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, authority),
                exposed_cost_units,
                realized_cost_units,
            ))
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
        if request.invocation_admission_evidence().is_some() {
            return self.authorize_remote_composite_budget_hold(request);
        }
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            return Err(BudgetStoreError::Invariant(
                "remote composite budget request contains incomplete admission evidence"
                    .to_string(),
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

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_remote_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote invocation capture query requires hold_id".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote invocation capture query requires event_id".to_string(),
            )
        })?;
        let expected = self.cached_composite_hold(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "remote invocation capture query has no exact cached evidence for hold `{hold_id}`"
            ))
        })?;
        if expected.capability_id != request.capability_id
            || expected.grant_index != request.grant_index
            || request.authority.as_ref() != Some(&expected.authority)
            || request.admission_operation.as_ref() != Some(&expected.admission_operation)
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture query changed the persisted operation binding"
                    .to_string(),
            ));
        }
        let capture_request = CaptureInvocationReservationsRequest {
            operation_id: expected.admission_operation.operation_id().to_string(),
            request_binding_hash: expected
                .admission_operation
                .request_binding_hash()
                .to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: expected.authority.authority_id.clone(),
                lease_id: expected.authority.lease_id.clone(),
                lease_epoch: expected.authority.lease_epoch,
            }),
        };
        let response = self
            .client
            .query_invocation_capture(&CaptureInvocationPointQueryRequest { capture_request })
            .map_err(into_budget_store_error)?;
        if response.operation_id != expected.admission_operation.operation_id()
            || response.request_binding_hash != expected.admission_operation.request_binding_hash()
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture query response changed its operation binding"
                    .to_string(),
            ));
        }
        let decision = response
            .capture
            .map(|capture| {
                validate_invocation_capture_response(
                    request,
                    &expected.invocation_quotas,
                    &expected.revocation_set,
                    expected.monetary_state,
                    capture,
                )
            })
            .transpose()?;
        if decision.is_some() {
            self.cache_usage(
                &request.capability_id,
                request.grant_index,
                None,
                None,
                None,
                None,
            );
        }
        Ok(decision)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let composite = request
            .hold_id
            .as_deref()
            .and_then(|hold_id| self.cached_composite_hold(hold_id));
        if let Some(expected) = composite.as_ref() {
            if expected.capability_id != request.capability_id
                || expected.grant_index != request.grant_index
                || request.authority.as_ref() != Some(&expected.authority)
                || request.admission_operation.as_ref() != Some(&expected.admission_operation)
            {
                return Err(BudgetStoreError::Conflict(
                    "remote composite reverse does not match the cached operation ownership"
                        .to_string(),
                ));
            }
            let exposure_matches = match expected.monetary_state {
                BudgetMonetaryHoldState::Exposed => {
                    request.reversed_exposure_units == expected.authorized_exposure_units
                }
                BudgetMonetaryHoldState::None => request.reversed_exposure_units == 0,
                BudgetMonetaryHoldState::Released
                | BudgetMonetaryHoldState::Reconciled
                | BudgetMonetaryHoldState::Captured
                | BudgetMonetaryHoldState::Reversed => false,
            };
            if !exposure_matches {
                return Err(BudgetStoreError::Conflict(
                    "remote composite reverse does not match the cached monetary hold".to_string(),
                ));
            }
        }
        let response = self
            .client
            .reverse_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.reversed_exposure_units,
            ))
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
        let (invocation_counts_after, invocation_state, monetary_state, revocation_set) =
            if let Some(expected) = composite {
                let mut invocation_counts_after = expected.invocation_counts_after;
                for usage in &mut invocation_counts_after {
                    usage.reserved_invocations_after = usage
                        .reserved_invocations_after
                        .checked_sub(1)
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "remote composite reverse has no reserved invocation to release"
                                    .to_string(),
                            )
                        })?;
                    usage.validate()?;
                }
                validate_primary_invocation_count(
                    &request.capability_id,
                    request.grant_index,
                    invocation_count,
                    &invocation_counts_after,
                )?;
                let monetary_state = match expected.monetary_state {
                    BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldState::Reversed,
                    BudgetMonetaryHoldState::None => BudgetMonetaryHoldState::None,
                    BudgetMonetaryHoldState::Released
                    | BudgetMonetaryHoldState::Reconciled
                    | BudgetMonetaryHoldState::Captured
                    | BudgetMonetaryHoldState::Reversed => {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite reverse cached an ineligible monetary state"
                                .to_string(),
                        ));
                    }
                };
                (
                    invocation_counts_after,
                    BudgetInvocationReservationState::Reversed,
                    monetary_state,
                    Some(expected.revocation_set),
                )
            } else {
                (
                    Vec::new(),
                    BudgetInvocationReservationState::Absent,
                    BudgetMonetaryHoldState::Reversed,
                    None,
                )
            };
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after,
            invocation_state,
            monetary_state,
            revocation_set,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reduce_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.released_exposure_units,
            ))
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
            .reconcile_budget_spend_with_ids_authority_and_operation(
                BudgetSpendMutationRequest::new(
                    BudgetMutationParts::new(
                        &request.capability_id,
                        request.grant_index,
                        request.hold_id.as_deref(),
                        request.event_id.as_deref(),
                        request.authority.as_ref(),
                    )
                    .with_admission_operation(request.admission_operation.as_ref()),
                    request.exposed_cost_units,
                    request.realized_spend_units,
                ),
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
            .capture_budget_spend_with_ids_and_operation(BudgetSpendMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.exposed_cost_units,
                request.realized_spend_units,
            ))
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
    fn authorize_remote_composite_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
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
            operation_id: admission_operation.operation_id().to_string(),
            request_binding_hash: admission_operation.request_binding_hash().to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            requested_exposure_units: request.requested_exposure_units,
            max_exposure_per_invocation: request.max_cost_per_invocation,
            max_total_exposure_units: request.max_total_cost_units,
            hold_id: hold_id.clone(),
            event_id,
            admission_evidence: admission_evidence_view(admission)?,
        };
        let response = self
            .client
            .authorize_composite_budget_hold(&wire_request)
            .map_err(into_budget_store_error)?;
        let decision = validate_composite_authorize_response(&wire_request, response)?;

        match &decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                let authority = authorized.metadata.authority.clone().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "remote composite authorization omitted its persisted authority"
                            .to_string(),
                    )
                })?;
                self.remember_composite_hold(
                    hold_id,
                    RemoteCompositeHoldEvidence {
                        admission_operation,
                        capability_id: request.capability_id.clone(),
                        grant_index: request.grant_index,
                        invocation_quotas,
                        invocation_counts_after: authorized.invocation_counts_after.clone(),
                        revocation_set,
                        authorized_exposure_units: authorized.authorized_exposure_units,
                        monetary_state: authorized.monetary_state,
                        authority,
                    },
                );
            }
            BudgetAuthorizeHoldDecision::Denied(_) => {
                self.forget_composite_hold(&hold_id);
            }
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
        let expected = self.cached_composite_hold(hold_id).ok_or_else(|| {
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
        let decision = validate_invocation_capture_response(
            &request,
            &expected.invocation_quotas,
            &expected.revocation_set,
            expected.monetary_state,
            response,
        )?;
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

    fn remember_composite_hold(&self, hold_id: String, evidence: RemoteCompositeHoldEvidence) {
        match self.composite_holds.lock() {
            Ok(mut holds) => {
                holds.insert(hold_id, evidence);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(hold_id, evidence);
            }
        }
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
        }
    }
}

fn admission_evidence_view(
    evidence: BudgetInvocationAdmissionEvidence<'_>,
) -> Result<BudgetInvocationAdmissionEvidenceView, BudgetStoreError> {
    let supplemental_binding = match (
        evidence.supplemental_artifact_digest(),
        evidence.supplemental_verifier_id(),
        evidence.supplemental_request_binding_hash(),
        evidence.supplemental_negotiated_features_digest(),
    ) {
        (None, None, None, None) => None,
        (
            Some(artifact_digest),
            Some(verifier_id),
            Some(request_binding_hash),
            Some(negotiated_features_digest),
        ) => Some(BudgetSupplementalQuotaBindingView {
            artifact_digest: artifact_digest.to_string(),
            verifier_id: verifier_id.to_string(),
            request_binding_hash: request_binding_hash.to_string(),
            negotiated_features_digest: negotiated_features_digest.to_string(),
        }),
        _ => {
            return Err(BudgetStoreError::Invariant(
                "kernel supplemental admission evidence is incomplete".to_string(),
            ));
        }
    };
    Ok(BudgetInvocationAdmissionEvidenceView {
        invocation_quotas: evidence
            .quotas()
            .iter()
            .map(invocation_quota_view)
            .collect(),
        revocation_set: canonical_revocation_set_view(evidence.revocation_set()),
        aggregate_root_capability_id: evidence
            .aggregate_root_capability_id()
            .map(ToOwned::to_owned),
        aggregate_binding_digest: evidence.aggregate_binding_digest().map(ToOwned::to_owned),
        supplemental_binding,
    })
}

fn quota_profile_view(profile: BudgetQuotaProfile) -> BudgetQuotaProfileView {
    match profile {
        BudgetQuotaProfile::GrantInvocation => BudgetQuotaProfileView::GrantInvocation,
        BudgetQuotaProfile::AggregateCapabilityInvocation => {
            BudgetQuotaProfileView::AggregateCapabilityInvocation
        }
        BudgetQuotaProfile::AggregateFamilyInvocation => {
            BudgetQuotaProfileView::AggregateFamilyInvocation
        }
        BudgetQuotaProfile::SupplementalBrokerExecution => {
            BudgetQuotaProfileView::SupplementalBrokerExecution
        }
    }
}

fn quota_profile_from_view(profile: BudgetQuotaProfileView) -> BudgetQuotaProfile {
    match profile {
        BudgetQuotaProfileView::GrantInvocation => BudgetQuotaProfile::GrantInvocation,
        BudgetQuotaProfileView::AggregateCapabilityInvocation => {
            BudgetQuotaProfile::AggregateCapabilityInvocation
        }
        BudgetQuotaProfileView::AggregateFamilyInvocation => {
            BudgetQuotaProfile::AggregateFamilyInvocation
        }
        BudgetQuotaProfileView::SupplementalBrokerExecution => {
            BudgetQuotaProfile::SupplementalBrokerExecution
        }
    }
}

pub(crate) fn invocation_quota_view(quota: &BudgetInvocationQuota) -> BudgetInvocationQuotaView {
    BudgetInvocationQuotaView {
        key: BudgetQuotaKeyView {
            profile: quota_profile_view(quota.key().profile()),
            owner_id: quota.key().owner_id().to_string(),
            grant_index: quota.key().grant_index(),
        },
        max_invocations: quota.max_invocations(),
    }
}

pub(crate) fn invocation_quota_from_view(
    quota: &BudgetInvocationQuotaView,
) -> Result<BudgetInvocationQuota, BudgetStoreError> {
    let key = BudgetQuotaKey::from_persisted_parts(
        quota_profile_from_view(quota.key.profile),
        quota.key.owner_id.clone(),
        quota.key.grant_index,
    )?;
    BudgetInvocationQuota::from_persisted_parts(key, quota.max_invocations)
}

pub(crate) fn canonical_revocation_set_view(
    set: &CanonicalRevocationSet,
) -> CanonicalRevocationSetView {
    CanonicalRevocationSetView {
        ids: set.ids().to_vec(),
        digest: set.digest().to_string(),
    }
}

pub(crate) fn canonical_revocation_set_from_view(
    set: &CanonicalRevocationSetView,
) -> Result<CanonicalRevocationSet, BudgetStoreError> {
    CanonicalRevocationSet::from_persisted_parts(set.ids.clone(), set.digest.clone()).map_err(
        |error| {
            BudgetStoreError::Invariant(format!(
                "remote response contains an invalid canonical revocation set: {error}"
            ))
        },
    )
}

pub(crate) fn admission_capture_request_from_view(
    request: &CombinedAdmissionCaptureRequest,
) -> Result<AdmissionCaptureRequest, AdmissionCaptureError> {
    let authority = request.budget_authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture request omitted persisted authority".to_string(),
        )
    })?;
    if authority.authority_id.is_empty()
        || authority.lease_id.is_empty()
        || authority.lease_epoch == 0
    {
        return Err(AdmissionCaptureError::InvalidRequest(
            "remote admission capture request contains incomplete persisted authority".to_string(),
        ));
    }
    let revocation_set = canonical_revocation_set_from_view(&request.revocation_set)?;
    AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: request.operation_id.clone(),
        budget: BudgetCaptureInvocationRequest {
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                request.operation_id.clone(),
                request.request_binding_hash.clone(),
            )?),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
        },
        revocation_set,
        bound_revocation_set_digest: request.bound_revocation_set_digest.clone(),
        authorization_artifact_digests: request.authorization_artifact_digests.clone(),
        aggregate_root_capability_id: request.aggregate_root_capability_id.clone(),
        aggregate_root_binding_digest: request.aggregate_root_binding_digest.clone(),
        last_observed_revocation_index: request.last_observed_revocation_index,
    })
}
