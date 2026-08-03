use super::super::*;

pub(crate) struct BudgetMutationParts<'a> {
    capability_id: &'a str,
    grant_index: usize,
    hold_id: Option<&'a str>,
    event_id: Option<&'a str>,
    authority: Option<&'a BudgetEventAuthority>,
    admission_operation: Option<&'a BudgetAdmissionOperationBinding>,
}

impl<'a> BudgetMutationParts<'a> {
    pub(crate) fn new(
        capability_id: &'a str,
        grant_index: usize,
        hold_id: Option<&'a str>,
        event_id: Option<&'a str>,
        authority: Option<&'a BudgetEventAuthority>,
    ) -> Self {
        Self {
            capability_id,
            grant_index,
            hold_id,
            event_id,
            authority,
            admission_operation: None,
        }
    }

    pub(crate) fn with_admission_operation(
        mut self,
        admission_operation: Option<&'a BudgetAdmissionOperationBinding>,
    ) -> Self {
        self.admission_operation = admission_operation;
        self
    }
}

pub(crate) struct BudgetCostMutationRequest<'a> {
    parts: BudgetMutationParts<'a>,
    cost_units: u64,
}

impl<'a> BudgetCostMutationRequest<'a> {
    pub(crate) fn new(parts: BudgetMutationParts<'a>, cost_units: u64) -> Self {
        Self { parts, cost_units }
    }
}

pub(crate) struct BudgetSpendMutationRequest<'a> {
    parts: BudgetMutationParts<'a>,
    authorized_exposure_units: u64,
    realized_spend_units: u64,
}

impl<'a> BudgetSpendMutationRequest<'a> {
    pub(crate) fn new(
        parts: BudgetMutationParts<'a>,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
    ) -> Self {
        Self {
            parts,
            authorized_exposure_units,
            realized_spend_units,
        }
    }
}

impl TrustControlClient {
    pub(crate) fn authorize_structured_budget_hold(
        &self,
        request: &StructuredBudgetAuthorizeRequest,
    ) -> Result<StructuredBudgetAuthorizeResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_AUTHORIZE_PATH, request)
    }

    pub(crate) fn get_structured_cumulative_operation(
        &self,
        request: &StructuredBudgetCumulativeOperationRequest,
    ) -> Result<StructuredBudgetCumulativeOperationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH, request)
    }

    pub(crate) fn cancel_structured_captured_invocation(
        &self,
        request: &StructuredBudgetCancelCapturedRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH, request)
    }

    pub(crate) fn capture_structured_invocation(
        &self,
        request: &StructuredBudgetCaptureInvocationRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH, request)
    }

    pub(crate) fn reverse_structured_budget_hold(
        &self,
        request: &StructuredBudgetFencedReverseRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_FENCED_REVERSE_PATH, request)
    }

    pub(crate) fn release_structured_budget_hold(
        &self,
        request: &StructuredBudgetReleaseRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_RELEASE_PATH, request)
    }

    pub(crate) fn reconcile_structured_budget_hold(
        &self,
        request: &StructuredBudgetReconcileRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_RECONCILE_PATH, request)
    }

    pub(crate) fn capture_structured_budget_spend(
        &self,
        request: &StructuredBudgetCaptureSpendRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CAPTURE_SPEND_PATH, request)
    }

    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    pub(crate) fn try_increment_budget(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<TryIncrementBudgetResponse, CliError> {
        self.post_json(
            BUDGET_INCREMENT_PATH,
            &TryIncrementBudgetRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
            },
        )
    }

    pub(crate) fn authorize_composite_budget_hold(
        &self,
        request: &CompositeBudgetAuthorizeRequest,
    ) -> Result<CompositeBudgetAuthorizeResponse, CliError> {
        self.post_json(BUDGET_AUTHORIZE_HOLD_PATH, request)
    }

    pub(crate) fn query_committed_composite_budget_authorization(
        &self,
        request: &CompositeBudgetAuthorizeRequest,
    ) -> Result<CompositeBudgetAuthorizeResponse, CliError> {
        self.post_json(BUDGET_AUTHORIZE_HOLD_QUERY_PATH, request)
    }

    pub(crate) fn capture_invocation_reservations(
        &self,
        request: &CaptureInvocationReservationsRequest,
    ) -> Result<CaptureInvocationReservationsResponse, CliError> {
        self.post_json(BUDGET_CAPTURE_INVOCATIONS_PATH, request)
    }

    pub(crate) fn query_invocation_capture(
        &self,
        request: &CaptureInvocationPointQueryRequest,
    ) -> Result<CaptureInvocationPointQueryResponse, CliError> {
        self.post_json(BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH, request)
    }

    pub(crate) fn query_budget_mutation_event_at(
        &self,
        endpoint: &str,
        request: &BudgetMutationEventQueryRequest,
    ) -> Result<BudgetMutationEventReplicaResponse, CliError> {
        self.post_json_to_endpoint(endpoint, BUDGET_MUTATION_EVENT_QUERY_PATH, request)
    }

    pub(crate) fn capture_admission(
        &self,
        request: &CombinedAdmissionCaptureRequest,
    ) -> Result<CombinedAdmissionCaptureResponse, CliError> {
        self.post_json(ADMISSION_CAPTURE_PATH, request)
    }

    pub(crate) fn query_admission_capture(
        &self,
        request: &AdmissionCapturePointQueryRequest,
    ) -> Result<AdmissionCapturePointQueryResponse, CliError> {
        self.post_json(ADMISSION_CAPTURE_QUERY_PATH, request)
    }

    pub(crate) fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    pub(crate) fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &TryChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    pub(crate) fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    pub(crate) fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
            BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, authority),
            cost_units,
        ))
    }

    pub(crate) fn reverse_charge_cost_with_ids_authority_and_operation(
        &self,
        request: BudgetCostMutationRequest<'_>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        let BudgetCostMutationRequest { parts, cost_units } = request;
        self.post_json(
            BUDGET_RELEASE_EXPOSURE_PATH,
            &ReverseChargeCostRequest {
                operation_id: parts
                    .admission_operation
                    .map(|binding| binding.operation_id().to_string()),
                request_binding_hash: parts
                    .admission_operation
                    .map(|binding| binding.request_binding_hash().to_string()),
                capability_id: parts.capability_id.to_string(),
                grant_index: parts.grant_index,
                cost_units,
                hold_id: parts.hold_id.map(ToOwned::to_owned),
                event_id: parts.event_id.map(ToOwned::to_owned),
                budget_authority: parts.authority.map(budget_mutation_authority_view),
            },
        )
    }

    pub(crate) fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    pub(crate) fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    pub(crate) fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
            BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, authority),
            cost_units,
        ))
    }

    pub(crate) fn reduce_charge_cost_with_ids_authority_and_operation(
        &self,
        request: BudgetCostMutationRequest<'_>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let BudgetCostMutationRequest { parts, cost_units } = request;
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                operation_id: parts
                    .admission_operation
                    .map(|binding| binding.operation_id().to_string()),
                request_binding_hash: parts
                    .admission_operation
                    .map(|binding| binding.request_binding_hash().to_string()),
                capability_id: parts.capability_id.to_string(),
                grant_index: parts.grant_index,
                cost_units,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: parts.hold_id.map(ToOwned::to_owned),
                event_id: parts.event_id.map(ToOwned::to_owned),
                budget_authority: parts.authority.map(budget_mutation_authority_view),
            },
        )
    }

    pub(crate) fn reconcile_budget_spend(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids(
            capability_id,
            grant_index,
            authorized_exposure_units,
            realized_spend_units,
            None,
            None,
        )
    }

    pub(crate) fn reconcile_budget_spend_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids_and_authority(BudgetSpendMutationRequest::new(
            BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, None),
            authorized_exposure_units,
            realized_spend_units,
        ))
    }

    pub(crate) fn reconcile_budget_spend_with_ids_and_authority(
        &self,
        request: BudgetSpendMutationRequest<'_>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids_authority_and_operation(request)
    }

    pub(crate) fn reconcile_budget_spend_with_ids_authority_and_operation(
        &self,
        request: BudgetSpendMutationRequest<'_>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let BudgetSpendMutationRequest {
            parts,
            authorized_exposure_units,
            realized_spend_units,
        } = request;
        let released_exposure_units = authorized_exposure_units
            .checked_sub(realized_spend_units)
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "realized spend cannot exceed authorized exposure during reconciliation"
                        .to_string(),
                )
            })?;
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                operation_id: parts
                    .admission_operation
                    .map(|binding| binding.operation_id().to_string()),
                request_binding_hash: parts
                    .admission_operation
                    .map(|binding| binding.request_binding_hash().to_string()),
                capability_id: parts.capability_id.to_string(),
                grant_index: parts.grant_index,
                cost_units: released_exposure_units,
                exposure_units: Some(authorized_exposure_units),
                realized_spend_units: Some(realized_spend_units),
                hold_id: parts.hold_id.map(ToOwned::to_owned),
                event_id: parts.event_id.map(ToOwned::to_owned),
                budget_authority: parts.authority.map(budget_mutation_authority_view),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn capture_budget_spend_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.capture_budget_spend_with_ids_and_operation(BudgetSpendMutationRequest::new(
            BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, authority),
            authorized_exposure_units,
            realized_spend_units,
        ))
    }

    pub(crate) fn capture_budget_spend_with_ids_and_operation(
        &self,
        request: BudgetSpendMutationRequest<'_>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let BudgetSpendMutationRequest {
            parts,
            authorized_exposure_units,
            realized_spend_units,
        } = request;
        let released_exposure_units = authorized_exposure_units
            .checked_sub(realized_spend_units)
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "realized spend cannot exceed authorized exposure during capture".to_string(),
                )
            })?;
        self.post_json(
            BUDGET_CAPTURE_EXPOSURE_PATH,
            &ReduceChargeCostRequest {
                operation_id: parts
                    .admission_operation
                    .map(|binding| binding.operation_id().to_string()),
                request_binding_hash: parts
                    .admission_operation
                    .map(|binding| binding.request_binding_hash().to_string()),
                capability_id: parts.capability_id.to_string(),
                grant_index: parts.grant_index,
                cost_units: released_exposure_units,
                exposure_units: Some(authorized_exposure_units),
                realized_spend_units: Some(realized_spend_units),
                hold_id: parts.hold_id.map(ToOwned::to_owned),
                event_id: parts.event_id.map(ToOwned::to_owned),
                budget_authority: parts.authority.map(budget_mutation_authority_view),
            },
        )
    }
}

fn budget_mutation_authority_view(authority: &BudgetEventAuthority) -> BudgetMutationAuthorityView {
    BudgetMutationAuthorityView {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    }
}
