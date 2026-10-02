//! Authenticate terminal records before granting outcome or zero-charge authority.
use super::*;

impl DurableAdmissionRuntime {
    fn qualified_terminal_records(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(ToolOutcomeRecordV1, PostReturnEvaluationRecordV1), ToolOutcomeError> {
        let unavailable =
            || ToolOutcomeError::ReleaseAuthorityUnavailable("durable terminal outcome store");
        let outcome = self
            .outcome_store
            .lookup_by_operation(operation.binding().operation_id())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let evaluation = self
            .outcome_store
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        Ok((outcome, evaluation))
    }
}

impl QualifiedDurableOutcomeAuthority for DurableAdmissionRuntime {
    fn verify_terminal_outcome(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<ToolOutcomeTerminalEvidenceV1, ToolOutcomeError> {
        let (outcome, evaluation) = self.qualified_terminal_records(operation)?;
        ToolOutcomeTerminalEvidenceV1::from_records(operation, context, &outcome, &evaluation)
    }

    fn verify_contractual_zero_charge(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedContractualZeroCharge, ToolOutcomeError> {
        let (outcome, evaluation) = self.qualified_terminal_records(operation)?;
        VerifiedContractualZeroCharge::from_records(operation, context, &outcome, &evaluation)
    }
}
