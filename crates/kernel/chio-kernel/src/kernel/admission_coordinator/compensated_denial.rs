//! Public denial metadata comes from the actual confirmed compensation.
use super::*;
use crate::admission_operation::AdmissionTerminal;

pub(in crate::kernel) struct ConfirmedPreDispatchCompensation {
    pub(super) context: AdmissionProjectionContext,
    pub(super) terminal: AdmissionTerminal,
}

impl ConfirmedPreDispatchCompensation {
    pub(in crate::kernel) fn trusted_time_unix_ms(&self) -> u64 {
        self.context.trusted_time_unix_ms
    }
}

impl ChioKernel {
    pub(in crate::kernel) fn compensated_native_denial_metadata(
        &self,
        request: &ToolCallRequest,
        original_operation: Option<&AdmissionOperationV1>,
        compensation: Option<&ConfirmedPreDispatchCompensation>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let (Some(original_operation), Some(compensation)) = (original_operation, compensation)
        else {
            return Ok(None);
        };
        // Existing generic stores keep their established cleanup path. Native
        // originals require the selected fenced retained-request readback.
        let Some(selected) = self.native_security_authority_binding()? else {
            return Ok(None);
        };
        let runtime = self.durable_runtime()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let (operation, original) = native_acquisition::store_call(|| {
            runtime.store.load_retained_tool_request(
                original_operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| {
            KernelError::DurableAdmission("native compensation readback is absent".into())
        })?;
        let Some(native) = original.native_security_authority_binding() else {
            return Ok(None);
        };
        original
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        original
            .validate_native_security_authority(&selected)
            .map_err(durable_store_error)?;
        let context = &compensation.context;
        let terminal_version = context
            .expected_operation_version
            .checked_add(1)
            .ok_or_else(|| {
                KernelError::DurableAdmission("native compensation version overflow".into())
            })?;
        if native != &selected
            || operation.binding() != original_operation.binding()
            || operation.binding().request_id().as_str() != request.request_id
            || operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
            || operation.dispatch_state() != AdmissionDispatchState::Terminal
            || operation.dispatch_commit().is_some()
            || operation.version() != terminal_version
            || operation.coordinator_lease_epoch() != context.coordinator_lease_epoch
            || context.operation_id != *operation.binding().operation_id()
            || context.request_id != *operation.binding().request_id()
            || context.store_fence != runtime.fence
            || compensation.terminal.operation_id != context.operation_id
            || compensation.terminal.state != operation.state()
            || operation.terminal_replay() != Some(&compensation.terminal.replay)
            || !matches!(
                operation.terminal_replay(),
                Some(AdmissionTerminalReplay::Incident { .. })
            )
        {
            return Err(KernelError::DurableAdmission(
                "native compensation readback differs from committed original custody".into(),
            ));
        }
        let metadata = AdmissionReceiptMetadataV1 {
            schema: AdmissionReceiptSchema::V1,
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.binding().request_id().clone(),
            request_namespace_digest: operation.binding().request_namespace_digest().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            projected_operation_version: operation.version(),
            projected_state: operation.state(),
            projected_dispatch_state: operation.dispatch_state(),
            trusted_time_unix_ms: context.trusted_time_unix_ms,
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            store_fence: context.store_fence.clone(),
            retained_dispatch_commit: None,
            compensation_status: AdmissionCompensationStatus::CompensatedBeforeDispatch,
            tool_outcome_id: None,
            tool_outcome_version: None,
        };
        Ok(Some(
            serde_json::json!({ ADMISSION_RECEIPT_METADATA_KEY: metadata }),
        ))
    }
}
