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
use std::sync::Arc;

/// Install a fail-closed work profile. An ephemeral kernel cannot safely replay
/// a durable allocation claim, so it is rejected at configuration time.
pub fn install_delegated_work(
    kernel: &mut ChioKernel,
    accepted_allocators: Vec<PublicKey>,
) -> Result<(), KernelError> {
    install_delegated_work_with_layout(kernel, accepted_allocators, DelegatedWorkLayout::Arguments)
}

/// The receiver chooses the permit location when installing the guard. Requests
/// cannot switch layouts or fall back to an unguarded input format.
#[derive(Clone, Copy, Debug)]
pub enum DelegatedWorkLayout {
    /// Existing `{slot_id, payload, allocation}` tool argument envelope.
    Arguments,
    /// `{slot_id, allocation}` in `governed_intent.context.chioDelegation`.
    /// The input commitment covers the complete, unchanged tool arguments.
    GovernedContext,
}

pub fn install_delegated_work_with_layout(
    kernel: &mut ChioKernel,
    accepted_allocators: Vec<PublicKey>,
    layout: DelegatedWorkLayout,
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
        clock: kernel.authority_clock(),
        layout,
    }));
    Ok(())
}

struct DelegatedWorkGuard {
    accepted_allocators: Vec<PublicKey>,
    receiver: PublicKey,
    clock: Arc<dyn crate::Clock>,
    layout: DelegatedWorkLayout,
}

#[derive(Clone, Copy)]
enum PermitUse {
    LiveDispatch,
    OutputContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    slot_id: String,
    payload: Value,
    allocation: Signed<DispatchPermit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPermit {
    slot_id: String,
    allocation: Signed<DispatchPermit>,
}

fn denied(message: impl std::fmt::Display) -> KernelError {
    KernelError::GuardDenied(format!("delegated work: {message}"))
}

impl DelegatedWorkGuard {
    fn admit(&self, ctx: &GuardContext<'_>, usage: PermitUse) -> Result<Admission, KernelError> {
        let request = ctx.request;
        let args: Arguments = match self.layout {
            DelegatedWorkLayout::Arguments => {
                serde_json::from_value(request.arguments.clone()).map_err(denied)?
            }
            DelegatedWorkLayout::GovernedContext => {
                let value = request
                    .governed_intent
                    .as_ref()
                    .and_then(|intent| intent.context.as_ref())
                    .and_then(|context| context.get("chioDelegation"))
                    .ok_or_else(|| denied("governed delegation permit absent"))?;
                let permit: ContextPermit =
                    serde_json::from_value(value.clone()).map_err(denied)?;
                Arguments {
                    slot_id: permit.slot_id,
                    allocation: permit.allocation,
                    payload: request.arguments.clone(),
                }
            }
        };
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
        let now = match usage {
            PermitUse::LiveDispatch => self.clock.unix_millis().map_err(denied)?.get() / 1000,
            // Dispatch already required a live permit. Its signed output
            // contract survives execution and replay; checking it at issuance
            // preserves all signature and binding checks without minting fresh
            // invocation authority after expiry.
            PermitUse::OutputContract => args.allocation.body.issued_at,
        };
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
        "dynamic-work-delegation-v2"
    }
    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.admit(ctx, PermitUse::LiveDispatch)?;
        Ok(GuardDecision::allow())
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn revalidate_before_dispatch(&self, ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.admit(ctx, PermitUse::LiveDispatch)?;
        Ok(())
    }
    fn validate_output_before_release(
        &self,
        ctx: &GuardContext<'_>,
        output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        let admission = self.admit(ctx, PermitUse::OutputContract)?;
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
        self.admit(ctx, PermitUse::OutputContract).is_ok()
    }
}
