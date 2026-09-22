//! Kernel-owned delivery over the independently configured broker control port.
use super::original::OriginalBrokerRequest;
use super::{canonical, rejected, unavailable, BrokerNativeCaptureReader};
use crate::budget::CaptureExecutionHoldRequest;
use crate::kernel_admission::BrokerAdmissionParticipant;
use crate::{BrokerError, Result};
use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionOperationState};
use chio_kernel::budget_store::BudgetInvocationState;
use chio_kernel::{
    BlockingToolServerConnection, KernelError, ToolDispatchContext, ToolInvocationContext,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Install through `BlockingToolServerAdapter`. Registration and preparation
/// use the selected privileged broker port; execution additionally requires a
/// kernel-created caller context and the original native capture. A transport
/// failure returns to durable kernel recovery without a retry or refund here.
pub struct BrokerKernelConnection {
    reader: BrokerNativeCaptureReader,
    participant: Arc<BrokerAdmissionParticipant>,
}

impl BrokerKernelConnection {
    pub fn new(
        reader: BrokerNativeCaptureReader,
        participant: Arc<BrokerAdmissionParticipant>,
    ) -> Result<Self> {
        if participant.binding() != &reader.participant {
            return Err(rejected());
        }
        Ok(Self {
            reader,
            participant,
        })
    }

    fn original_delivery(
        &self,
        context: &ToolDispatchContext,
        now: u64,
    ) -> Result<OriginalBrokerRequest> {
        let operation_id =
            AdmissionOperationId::from_persisted(context.operation_id()).map_err(|_| rejected())?;
        let original = self
            .reader
            .read_original(&operation_id, now)?
            .ok_or_else(rejected)?;
        let request = original.retained.request_for_revalidation();
        if context.request_id() != original.operation.binding().request_id().as_str()
            || original.operation.provider_attempt() != Some(context.attempt())
            || request.server_id != self.participant.server_id
            || request.tool_name != self.participant.tool_name
        {
            return Err(rejected());
        }
        Ok(original)
    }

    fn prepare(&self, context: &ToolDispatchContext) -> Result<()> {
        let now = trusted_now_ms()?;
        let original = self.original_delivery(context, now)?;
        if !matches!(
            original.operation.state(),
            AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch
        ) {
            return Err(rejected());
        }
        let operation_id = original.operation.binding().operation_id();
        let (registration, execute) = self
            .reader
            .read_registration(self.participant.as_ref(), operation_id, now)?
            .ok_or_else(rejected)?;
        let custody = self
            .reader
            .store
            .load_admission_budget_custody(operation_id, &self.reader.fence, now)
            .map_err(unavailable)?
            .ok_or_else(rejected)?;
        if custody.invocation_state != BudgetInvocationState::Authorized
            || execute != original.execute
        {
            return Err(rejected());
        }
        self.participant
            .client
            .prepare_dispatch(&registration, &execute)?;
        Ok(())
    }

    fn execute(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let now = trusted_now_ms()?;
        let dispatch = context.dispatch().ok_or_else(rejected)?;
        let original = self.original_delivery(dispatch, now)?;
        let request = original.retained.request_for_revalidation();
        if original.operation.state() != AdmissionOperationState::DispatchCommitted
            || context.request_id() != request.request_id
            || context.server_id() != self.participant.server_id
            || context.tool_name() != self.participant.tool_name
            || context.capability_id() != request.capability.id
            || context.subject_key() != request.capability.subject.to_hex()
            || context.capability_hash()
                != chio_core_types::crypto::sha256_hex(&canonical(&request.capability)?)
            || dispatch.caller_capability_sha256() != Some(context.capability_hash())
            || canonical(&arguments)? != canonical(&original.execute)?
        {
            return Err(rejected());
        }
        let operation_id = original.operation.binding().operation_id();
        let (registration, execute) = self
            .reader
            .read_registration(self.participant.as_ref(), operation_id, now)?
            .ok_or_else(rejected)?;
        let custody = self
            .reader
            .store
            .load_admission_budget_custody(operation_id, &self.reader.fence, now)
            .map_err(unavailable)?
            .ok_or_else(rejected)?;
        if custody.invocation_state != BudgetInvocationState::Captured
            || execute != original.execute
        {
            return Err(rejected());
        }
        let revocation_ids = custody.admission.revocation_set.ids().to_vec();
        let capture = CaptureExecutionHoldRequest {
            operation_id: registration.ids.operation_id,
            invocation_id: registration.invocation_id,
            parent_capability_id: registration.parent_capability_id,
            broker_capability_id: registration.broker_capability_id,
            hold_id: registration.ids.hold_id,
            capture_event_id: registration.ids.capture_event_id,
            revocation_set_digest: crate::revocation::digest_canonical_revocation_ids(
                &revocation_ids,
            )?,
            revocation_ids,
            authority_metadata_digest: registration.authority_metadata_digest,
            authorization_artifact_digest: crate::capability::capability_digest(
                &execute.capability,
            )?,
        };
        self.reader
            .read_capture(&capture, now)?
            .ok_or_else(rejected)?;
        // The broker rechecks live parent/revocation authority and its original
        // prepared state, and owns durable provider deduplication. Historical
        // capture readback alone never reaches this kernel-context entry point.
        let response = self.participant.client.execute(&execute)?;
        serde_json::to_value(response).map_err(|_| rejected())
    }
}

impl BlockingToolServerConnection for BrokerKernelConnection {
    fn server_id(&self) -> &str {
        &self.participant.server_id
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.participant.tool_name.clone()]
    }

    fn invoke_blocking(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        Err(KernelError::GuardDenied(
            "broker execution requires kernel caller context".into(),
        ))
    }

    fn prepare_delivery_blocking(
        &self,
        context: &ToolDispatchContext,
    ) -> std::result::Result<(), KernelError> {
        self.prepare(context).map_err(kernel_error)
    }

    fn invoke_blocking_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        self.execute(context, arguments).map_err(kernel_error)
    }
}

fn kernel_error(error: BrokerError) -> KernelError {
    KernelError::ToolServerError(error.diagnostic_code().into())
}

pub(super) fn trusted_now_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rejected())?;
    u64::try_from(elapsed.as_millis()).map_err(|_| rejected())
}
