//! Kernel-owned delivery over the independently configured broker control port.
use super::delivery::CapturedBrokerDelivery;
use super::original::OriginalBrokerRequest;
use super::{canonical, rejected, trusted_now_ms, BrokerNativeCaptureReader};
use crate::kernel_admission::BrokerAdmissionParticipant;
use crate::{BrokerError, Result};
use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionOperationState};
use chio_kernel::budget_store::BudgetInvocationState;
use chio_kernel::{
    BlockingToolServerConnection, KernelError, ToolDispatchContext, ToolInvocationContext,
};
use std::sync::Arc;

#[cfg(unix)]
mod mcp;
#[cfg(unix)]
pub use mcp::{BrokerMcpConnection, BrokerMcpToolConnection};

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
        let (registration, execute) = self.prepared_registration(context)?;
        self.participant
            .client
            .prepare_dispatch(&registration, &execute)?;
        Ok(())
    }

    #[cfg(unix)]
    fn prepare_connection(
        &self,
        context: &ToolDispatchContext,
    ) -> Result<std::os::unix::net::UnixStream> {
        let (registration, execute) = self.prepared_registration(context)?;
        self.participant
            .client
            .prepare_dispatch_connection(&registration, &execute)
    }

    fn prepared_registration(
        &self,
        context: &ToolDispatchContext,
    ) -> Result<(
        crate::store::AttemptRegistration,
        crate::protocol::BrokerExecuteRequest,
    )> {
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
        let registration = self
            .reader
            .registration_for_original(self.participant.as_ref(), &original)?
            .ok_or_else(rejected)?;
        let custody = original.custody.as_ref().ok_or_else(rejected)?;
        if custody.invocation_state != BudgetInvocationState::Authorized {
            return Err(rejected());
        }
        Ok((registration, original.execute))
    }

    fn execute(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let delivery = self.validate_delivery(context, &arguments)?;
        // The daemon still checks current parent/revocation authority and owns
        // provider deduplication. This connector never retries a lost reply.
        let response = self.participant.client.execute(&delivery.execute)?;
        delivery.verify_response(self.participant.as_ref(), &response, trusted_now_ms()?)?;
        serde_json::to_value(response).map_err(|_| rejected())
    }

    fn validate_delivery(
        &self,
        context: &ToolInvocationContext,
        arguments: &serde_json::Value,
    ) -> Result<CapturedBrokerDelivery> {
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
            || canonical(arguments)? != canonical(&original.execute)?
        {
            return Err(rejected());
        }
        self.reader
            .captured_delivery(self.participant.as_ref(), &original, now)
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
