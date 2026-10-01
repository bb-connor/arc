//! Private delivery signatures survive raw-return persistence without entering
//! public receipts. Structural validation is separate from independently pinned
//! authentication of the original capture at the kernel's release boundary.
use super::*;
use crate::caller_delivery::CallerDeliveryEvidenceV1;

impl RawInvocationOutcomeV1 {
    pub(crate) fn with_caller_delivery_evidence(
        mut self,
        evidence: Option<Box<CallerDeliveryEvidenceV1>>,
    ) -> Result<Self, ToolOutcomeError> {
        if let Some(evidence) = evidence {
            if self
                .caller_delivery_evidence
                .as_ref()
                .is_some_and(|original| original != &evidence)
            {
                return Err(invalid());
            }
            self.caller_delivery_evidence = Some(evidence);
            self.schema = RAW_INVOCATION_OUTCOME_WITH_CALLER_DELIVERY_SCHEMA;
            self.canonical_blob()?;
        }
        Ok(self)
    }

    pub(crate) fn caller_delivery_evidence(&self) -> Option<&CallerDeliveryEvidenceV1> {
        self.caller_delivery_evidence.as_deref()
    }

    pub(super) fn validate_caller_delivery_evidence(&self) -> Result<(), ToolOutcomeError> {
        if (self.schema == RAW_INVOCATION_OUTCOME_WITH_CALLER_DELIVERY_SCHEMA)
            != self.caller_delivery_evidence.is_some()
        {
            return Err(invalid());
        }
        let Some(evidence) = self.caller_delivery_evidence() else {
            return Ok(());
        };
        let authorization = &evidence.authorization.authorization;
        let report = &evidence.report.report;
        evidence
            .report
            .verify(
                &evidence.authorization,
                &authorization.kernel_public_key,
                &authorization.executor,
                &authorization.invocation,
            )
            .map_err(|_| invalid())?;
        // These internally consistent keys are still untrusted here. The
        // release path must compare them with the original physical admission.
        let invocation = &authorization.invocation;
        if !self.provider_attempt.is_caller_report()
            || invocation.operation_id != self.operation_id
            || invocation.request_id != self.request_id
            || invocation.server_id != self.tool_server
            || invocation.tool_name != self.tool_name
            || authorization
                .committed
                .dispatch_commit
                .provider_attempt
                .as_ref()
                != Some(&self.provider_attempt)
            || authorization.committed.dispatch_commit.committed_version
                != self.dispatch_operation_version
            || authorization
                .committed
                .dispatch_commit
                .store_fence
                .owner_epoch
                != self.dispatch_fence
            || self.reported_cost != report.realized_cost
            || self.elapsed_millis
                != report.completed_at_unix_ms - report.execution_started_at_unix_ms
            || !matches!(&self.output, InvocationOutputV1::Value { value } if value == &report.output)
        {
            return Err(invalid());
        }
        let request = self.recovery_request()?.ok_or_else(invalid)?;
        let action =
            crate::ToolCallAction::from_parameters(request.arguments).map_err(|_| invalid())?;
        if invocation.capability_id.as_str() != request.capability.id.as_str()
            || invocation.capability_digest.as_str()
                != sha256_hex(&canonical_json_bytes(&request.capability).map_err(|_| invalid())?)
            || invocation.parameters_digest.as_str() != action.parameter_hash
        {
            return Err(invalid());
        }
        let report_digest = sha256_hex(&evidence.report.canonical_bytes().map_err(|_| invalid())?);
        if self
            .receipt_metadata_snapshot
            .as_ref()
            .and_then(|metadata| metadata.pointer("/caller_delivery/report_digest"))
            .and_then(Value::as_str)
            != Some(report_digest.as_str())
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> ToolOutcomeError {
    ToolOutcomeError::Binding("raw.caller_delivery_evidence")
}
