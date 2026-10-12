use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::admission_operation::AdmissionOperationV1;
use crate::{CapabilityToken, PaymentAuthorization, ToolCallRequest};

use super::{
    merge_metadata_objects, scope_pre_invocation_guard_evidence, ChioKernel,
    PreExecutionBudgetMutation, VerifiedGovernedPayeeBinding,
};

const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
    pub(crate) verified_payee_binding: Option<VerifiedGovernedPayeeBinding>,
}

/// A single pre-dispatch cleanup step that failed. Collected so a signed fault
/// receipt can name the failing step, its redacted reason, and the hold /
/// reservation ids that step was unwinding, letting an operator locate a hold
/// or reservation that may be stuck without cross-referencing the top-level
/// admission metadata.
struct PreDispatchCleanupFault {
    step: &'static str,
    reason: String,
    /// Ids of the holds / reservations this step was releasing (budget hold id,
    /// payment authorization id, delegated child / parent capability id, or the
    /// reserved runtime lease / continuation ids). Empty when the failing step
    /// carries no locatable id.
    hold_ids: Vec<String>,
}

/// Extract the reserved runtime-admission lease / continuation ids carried in
/// the admission metadata so a runtime-admission release fault can name the
/// possibly-stuck reservations directly in its fault entry.
pub(crate) fn reserved_runtime_admission_ids(metadata: Option<&serde_json::Value>) -> Vec<String> {
    let Some(runtime) = metadata
        .and_then(|value| value.get("chio_runtime"))
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for key in [
        "reserved_destructive_lease_id",
        "reserved_treaty_continuation_id",
        "reserved_swarm_continuation_id",
    ] {
        if let Some(id) = runtime.get(key).and_then(serde_json::Value::as_str) {
            ids.push(id.to_string());
        }
    }
    ids
}

/// Owns cleanup while an admitted request remains before dispatch.
/// PostEffectObligation takes custody when execution can begin.
pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    budget_mutation: &'a PreExecutionBudgetMutation,
    payment_authorization: Option<&'a PaymentAuthorization>,
    receipt_context: PostAdmissionReceiptContext,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `Ok(true)` from `admit_capability_budget`). `false` means the
    /// capability had no parent to admit against, so there is no lease to drop.
    /// When `true`, a pre-dispatch drop releases exactly this evaluation's one
    /// lease; the shared edge is freed only when the last holder releases, so an
    /// overlapping evaluation that still holds it keeps its share protected.
    /// Gates the step-4 child-budget release in `handle_pre_dispatch_drop`.
    budget_lease_acquired: bool,
    durable_operation: Option<&'a AdmissionOperationV1>,
    armed: bool,
}

impl<'a> PostAdmissionDropGuard<'a> {
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    pub(crate) fn new(
        kernel: &'a ChioKernel,
        request: &'a ToolCallRequest,
        cap: &'a CapabilityToken,
        matched_grant_index: Option<usize>,
        budget_mutation: &'a PreExecutionBudgetMutation,
        payment_authorization: Option<&'a PaymentAuthorization>,
        receipt_context: PostAdmissionReceiptContext,
        budget_lease_acquired: bool,
    ) -> Self {
        Self {
            kernel,
            request,
            cap,
            matched_grant_index,
            budget_mutation,
            payment_authorization,
            receipt_context,
            budget_lease_acquired,
            durable_operation: None,
            armed: true,
        }
    }

    pub(crate) fn with_durable_operation(
        mut self,
        operation: Option<&'a AdmissionOperationV1>,
    ) -> Self {
        self.durable_operation = operation;
        self
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Fully unwind a future dropped BEFORE tool-server dispatch. No side
    /// effect is possible, so every pre-execution mutation is reversed: the
    /// monetary hold, an invocation-only budget increment,
    /// runtime-admission reservations, and an admitted child/delegated
    /// capability budget share. A clean unwind records NO receipt
    /// (the intended receipt-free exit). If any step fails, a signed fault
    /// receipt is attempted to identify the stuck hold/reservation. Cleanup and
    /// receipt publication are best-effort from Drop: each cleanup step is
    /// attempted independently, and clock, construction or append failure is
    /// reported through an audit fault without claiming signed evidence.
    fn handle_pre_dispatch_drop(&self) {
        let mut faults: Vec<PreDispatchCleanupFault> = Vec::new();

        // 1. Monetary hold reversal (budget charge + payment release/refund).
        if self.budget_mutation.charge_result().is_some() {
            match self.kernel.unwind_pre_dispatch_monetary_invocation(
                self.request,
                self.cap,
                self.budget_mutation.charge_result(),
                self.payment_authorization,
                self.durable_operation,
            ) {
                Ok(_) => {}
                Err(error) => {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to unwind dropped pre-dispatch monetary invocation"
                    );
                    let mut hold_ids = Vec::new();
                    if let Some(charge) = self.budget_mutation.charge_result() {
                        hold_ids.push(charge.budget_hold_id.clone());
                    }
                    if let Some(authorization) = self.payment_authorization {
                        hold_ids.push(authorization.authorization_id.clone());
                    }
                    faults.push(PreDispatchCleanupFault {
                        step: "monetary_unwind",
                        reason,
                        hold_ids,
                    });
                }
            }
        }

        // 2. Invocation-only budget reversal. A non-monetary grant
        //    with `max_invocations` incremented the invocation counter at
        //    admission; reverse it so a never-dispatched call does not
        //    permanently consume a slot. Reuse the same primitive the
        //    pre-dispatch denial path uses, gated on the Invocation variant so
        //    a Charge (handled above) is not reversed twice.
        if matches!(
            self.budget_mutation,
            PreExecutionBudgetMutation::Invocation { .. }
                | PreExecutionBudgetMutation::InvocationHold(_)
        ) {
            match self
                .kernel
                .reverse_pre_execution_budget_mutation(self.cap, self.budget_mutation)
            {
                Ok(_) => {}
                Err(error) => {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to reverse dropped pre-dispatch invocation budget"
                    );
                    faults.push(PreDispatchCleanupFault {
                        step: "invocation_reversal",
                        reason,
                        hold_ids: self.budget_mutation.durable_hold_result().map_or_else(
                            || vec![self.cap.id.clone()],
                            |hold| vec![hold.budget_hold_id.clone()],
                        ),
                    });
                }
            }
        }

        // 3. Runtime-admission reservation release.
        if let Err(error) = self.kernel.release_runtime_admission_reservations(
            self.durable_operation,
            self.receipt_context.extra_metadata.as_ref(),
        ) {
            let reason = redacted!(&error).to_string();
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                "failed to release runtime-admission reservations on pre-dispatch drop"
            );
            faults.push(PreDispatchCleanupFault {
                step: "runtime_admission_release",
                reason,
                // Name the reserved lease / continuation ids so an operator can
                // locate the possibly-stuck reservation from the fault entry.
                hold_ids: reserved_runtime_admission_ids(
                    self.receipt_context.extra_metadata.as_ref(),
                ),
            });
        }

        // 4. Admitted child/delegated capability budget lease release (Finding
        //    B), gated on this evaluation having acquired a lease. A delegated
        //    capability took a holder lease on its share of the parent budget at
        //    admission; drop it or the lease stays permanently recorded. Release
        //    ONLY when THIS evaluation acquired a lease (`budget_lease_acquired`).
        //    The release is reference-counted: it decrements the holder count
        //    and frees the edge (returning the share to the parent) only when
        //    this was the LAST holder. An overlapping evaluation that still holds
        //    the edge keeps its share, so an oversubscribing sibling stays
        //    denied. Fail-closed: an evaluation that never acquired a lease
        //    (`budget_lease_acquired == false`) releases nothing, because
        //    over-releasing (dropping a holder this evaluation never took) would
        //    free another evaluation's live share (a budget bypass), the worse
        //    failure. Mirrors the pre-dispatch denial path.
        if self.budget_lease_acquired {
            if let Err(error) = self.kernel.release_admitted_capability_budget(self.cap) {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to release admitted capability budget on pre-dispatch drop"
                );
                // Name the delegated child capability id and its parent so the
                // stuck sibling-sum share is locatable from the fault entry.
                let mut hold_ids = vec![self.cap.id.clone()];
                if let Some(parent_link) = self.cap.delegation_chain.last() {
                    hold_ids.push(parent_link.capability_id.clone());
                }
                faults.push(PreDispatchCleanupFault {
                    step: "child_budget_release",
                    reason,
                    hold_ids,
                });
            }
        }

        if faults.is_empty() {
            if let Some(operation) = self.durable_operation {
                if let Err(error) = self
                    .kernel
                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                        Some(operation),
                        None,
                        self.payment_authorization,
                    )
                {
                    let reason = redacted!(&error).to_string();
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        "failed to terminalize dropped pre-dispatch admission"
                    );
                    faults.push(PreDispatchCleanupFault {
                        step: "durable_admission_compensation",
                        reason,
                        hold_ids: vec![operation.binding().operation_id().as_str().to_owned()],
                    });
                }
            }
        }

        // 5. Fault receipt. Clean cleanup is receipt-free (the
        //    intended design); any fault attempts a signed receipt.
        if !faults.is_empty() {
            self.record_pre_dispatch_cleanup_fault_receipt(&faults);
        }
    }

    /// Record a signed cancellation receipt documenting a pre-dispatch cleanup
    /// fault. Best-effort from Drop: clock, construction or append failure is
    /// logged with the `audit_fault` field. The failing steps and the reserved
    /// lease/continuation ids (carried in the admission metadata) are folded
    /// into the receipt so an operator can locate the stuck hold.
    fn record_pre_dispatch_cleanup_fault_receipt(&self, faults: &[PreDispatchCleanupFault]) {
        let fault_entries: Vec<serde_json::Value> = faults
            .iter()
            .map(|fault| {
                serde_json::json!({
                    "step": fault.step,
                    "reason": fault.reason,
                    "hold_ids": fault.hold_ids,
                })
            })
            .collect();
        let metadata = merge_metadata_objects(
            self.receipt_context.extra_metadata.clone(),
            Some(serde_json::json!({
                "chio_runtime": {
                    "pre_dispatch_cleanup_failed": true,
                    "pre_dispatch_cleanup_faults": fault_entries,
                }
            })),
        );

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.trusted_now_millis().and_then(|now| {
            self.kernel
                .build_cancelled_response_with_metadata_and_payee_binding(
                    self.request,
                    PRE_DISPATCH_CLEANUP_FAULT_REASON,
                    now.as_secs(),
                    self.matched_grant_index,
                    metadata,
                    self.receipt_context.verified_payee_binding.as_ref(),
                )
        }) {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "pre_dispatch_cleanup_fault_receipt_unrecorded",
                "failed to record pre-dispatch cleanup fault receipt"
            );
        }
    }
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.handle_pre_dispatch_drop();
        }
    }
}
