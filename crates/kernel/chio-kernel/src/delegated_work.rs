//! Opt-in binding of dynamic work allocations to native receiver authority.
//!
//! Install after durable stores and before serving. The owner must bind this
//! profile and its protected allocator into deployment policy. Qualified tool
//! confinement and complete observer declarations remain host assumptions.
//! This guard checks allocation and output; ordinary native capabilities,
//! admission custody, receipts and payment rails retain their authority.

use crate::{ChioKernel, Guard, GuardContext, GuardDecision, KernelError, ToolServerOutput};
use chio_core::{capability::scope::Operation, crypto::PublicKey};
use chio_workflow::delegation::{
    binding_digest, verify_dispatch_permit, work_input_digest, Admission, DispatchBinding,
    DispatchPermit, Effect, Signed,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Install a fail-closed work profile. An ephemeral kernel cannot safely replay
/// a durable allocation claim, so it is rejected at configuration time.
pub fn install_delegated_work(
    kernel: &mut ChioKernel,
    accepted_allocators: Vec<PublicKey>,
) -> Result<(), KernelError> {
    if !kernel.has_durable_admission_store() {
        return Err(denied(
            "durable native admission must be configured before installation",
        ));
    }
    kernel.require_durable_request_retention();
    kernel.add_guard(Box::new(DelegatedWorkGuard {
        accepted_allocators,
        receiver: kernel.public_key(),
    }));
    Ok(())
}

struct DelegatedWorkGuard {
    accepted_allocators: Vec<PublicKey>,
    receiver: PublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    slot_id: String,
    payload: Value,
    allocation: Signed<DispatchPermit>,
}

fn denied(message: impl std::fmt::Display) -> KernelError {
    KernelError::GuardDenied(format!("delegated work: {message}"))
}

impl DelegatedWorkGuard {
    fn admit(&self, ctx: &GuardContext<'_>) -> Result<Admission, KernelError> {
        let request = ctx.request;
        let args: Arguments = serde_json::from_value(request.arguments.clone()).map_err(denied)?;
        let [grant] = ctx.scope.grants.as_slice() else {
            return Err(denied("one exact invocation grant required"));
        };
        if grant.server_id != request.server_id
            || grant.tool_name != request.tool_name
            || grant.operations.as_slice() != [Operation::Invoke]
            || grant.max_invocations != Some(1)
            || request.capability.issuer != self.receiver
        {
            return Err(denied("receiver-local exact invocation authority required"));
        }
        let per_call = grant
            .max_cost_per_invocation
            .as_ref()
            .ok_or_else(|| denied("per-call ceiling absent"))?;
        let total = grant
            .max_total_cost
            .as_ref()
            .ok_or_else(|| denied("total ceiling absent"))?;
        if per_call.currency != total.currency {
            return Err(denied("currency mismatch"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(denied)?
            .as_secs();
        verify_dispatch_permit(
            &args.allocation,
            &DispatchBinding {
                slot_id: args.slot_id.clone(),
                receiver: self.receiver.clone(),
                subject: request.capability.subject.clone(),
                request_id: request.request_id.clone(),
                capability_hash: binding_digest(&request.capability).map_err(denied)?,
                arguments_hash: work_input_digest(&args.slot_id, &args.payload).map_err(denied)?,
                effect: Effect {
                    server: request.server_id.clone(),
                    tool: request.tool_name.clone(),
                },
                max_units: per_call.units.max(total.units),
                currency: total.currency.clone(),
            },
            now,
            &self.accepted_allocators,
        )
        .map_err(denied)
    }
}

impl Guard for DelegatedWorkGuard {
    fn name(&self) -> &str {
        "dynamic-work-delegation-v1"
    }
    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.admit(ctx)?;
        Ok(GuardDecision::allow())
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn revalidate_before_dispatch(&self, ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.admit(ctx)?;
        Ok(())
    }
    fn validate_output_before_release(
        &self,
        ctx: &GuardContext<'_>,
        output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        let admission = self.admit(ctx)?;
        let ToolServerOutput::Value(value) = output else {
            return Err(denied("JSON return required"));
        };
        admission
            .slot
            .contract
            .acceptance
            .check(value)
            .map_err(denied)
    }
    fn requires_exact_released_output(&self, _: &GuardContext<'_>) -> bool {
        true
    }
    fn output_rejection_is_zero_charge(&self, ctx: &GuardContext<'_>) -> bool {
        // This installed profile prices the receiver-signed offer on acceptance.
        // Invalid evidence cannot opt a request into this pricing authority.
        self.admit(ctx).is_ok()
    }
}
