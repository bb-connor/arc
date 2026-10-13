use super::super::*;

impl TrustControlClient {
    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    pub(crate) fn authorize_budget_exposure(
        &self,
        request: &TryChargeCostRequest,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(BUDGET_AUTHORIZE_EXPOSURE_PATH, request)
    }

    #[cfg(test)]
    pub(crate) fn capture_invocation_reservations(
        &self,
        capability_id: &str,
        grant_index: usize,
        hold_id: &str,
        event_id: &str,
    ) -> Result<CaptureInvocationResponse, CliError> {
        self.post_json(
            BUDGET_CAPTURE_INVOCATION_PATH,
            &CaptureInvocationRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                hold_id: hold_id.to_string(),
                event_id: event_id.to_string(),
            },
        )
    }

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
}
