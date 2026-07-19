use chio_core::receipt::metadata::GuardEvidence;
use chio_log_redact::redacted;
use tracing::warn;

use crate::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationState, CapabilityToken,
    ChildRequestReceipt, PaymentAuthorization, SecurityDispatchOutcomeHandle, ToolCallRequest,
};

use super::{
    current_unix_timestamp, merge_metadata_objects, scope_pre_invocation_guard_evidence,
    ChioKernel, PreExecutionBudgetMutation,
};

/// Builds a pending-reversal marker for a budget hold that could not be
/// reversed on the spot. The returned value is recorded under the `budget_authority`
/// key in receipt metadata as a durable audit breadcrumb of the failed on-the-spot
/// reverse; the reaper locates open holds by scanning `disposition='open'` in the
/// budget store, not by keying off this marker.
///
/// The `terminal.disposition` field is nested consistently with every other
/// terminal disposition in this codebase ("reversed", "reconciled").
pub(crate) fn pending_reversal_marker(hold_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "hold_id": hold_id,
        "terminal": {
            "disposition": "pending_reversal",
            "reason": reason,
        }
    })
}

const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";
const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: Vec<GuardEvidence>,
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

pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    budget_mutation: &'a PreExecutionBudgetMutation,
    payment_authorization: Option<&'a PaymentAuthorization>,
    receipt_context: PostAdmissionReceiptContext,
    /// Signed child-request receipts buffered by the nested-flow bridge during
    /// dispatch. Owned by the guard (rather than the evaluation stack frame) so
    /// a post-dispatch drop can still flush them onto the append-only log,
    /// preserving receipt-completeness for nested child operations.
    child_receipts: Vec<ChildRequestReceipt>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `Ok(true)` from `admit_capability_budget`). `false` means the
    /// capability had no parent to admit against, so there is no lease to drop.
    /// When `true`, a pre-dispatch drop releases exactly this evaluation's one
    /// lease; the shared edge is freed only when the last holder releases, so an
    /// overlapping evaluation that still holds it keeps its share protected.
    /// Gates the step-4 child-budget release in `handle_pre_dispatch_drop`.
    budget_lease_acquired: bool,
    threshold_operation: Option<AdmissionOperation>,
    security_dispatch_outcome: Option<SecurityDispatchOutcomeHandle>,
    armed: bool,
    dispatch_started: bool,
}

impl<'a> PostAdmissionDropGuard<'a> {
    #[allow(clippy::too_many_arguments)]
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
            child_receipts: Vec::new(),
            budget_lease_acquired,
            threshold_operation: None,
            security_dispatch_outcome: None,
            armed: true,
            dispatch_started: false,
        }
    }

    /// Borrow the buffered child-receipt sink so the nested-flow bridge can push
    /// signed child receipts into it while dispatch is in flight. The guard owns
    /// the buffer so a post-dispatch drop can still flush it (see
    /// `flush_buffered_child_receipts_from_drop`).
    pub(crate) fn child_receipts_mut(&mut self) -> &mut Vec<ChildRequestReceipt> {
        &mut self.child_receipts
    }

    /// Record the buffered child receipts on the normal (non-drop) path,
    /// removing each from the buffer only once it is durably persisted. If a
    /// bounded append fails, the not-yet-persisted receipts stay buffered so the
    /// still-armed drop path flushes them onto the append-only log instead of
    /// discarding them with the dropped future. The guard must stay armed until
    /// this returns `Ok`; the caller disarms only on success, so the disarmed
    /// drop then flushes an empty buffer and never double-records.
    pub(crate) fn record_buffered_child_receipts(&mut self) -> Result<(), KernelError> {
        while !self.child_receipts.is_empty() {
            self.kernel.record_child_receipt(&self.child_receipts[0])?;
            self.child_receipts.remove(0);
        }
        Ok(())
    }

    /// Mark that the tool-server dispatch await has been entered. After this
    /// point a dropped future may correspond to an executed side effect, so
    /// the drop path must record a cancellation receipt and fail closed on
    /// reservations.
    pub(crate) fn mark_dispatch_started(&mut self) {
        self.dispatch_started = true;
        if let Some(outcome) = self.security_dispatch_outcome.as_mut() {
            outcome.mark_dispatch_started();
        }
    }

    pub(crate) fn bind_threshold_operation(&mut self, operation: AdmissionOperation) {
        self.threshold_operation = Some(operation);
    }

    pub(crate) fn bind_security_dispatch_outcome(
        &mut self,
        outcome: Option<SecurityDispatchOutcomeHandle>,
    ) {
        self.security_dispatch_outcome = outcome;
    }

    pub(crate) fn take_security_dispatch_outcome(
        &mut self,
    ) -> Option<SecurityDispatchOutcomeHandle> {
        self.security_dispatch_outcome.take()
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Release the pre-execution monetary exposure, if any, and fold the
    /// release into the receipt metadata. Charge-gated: a `None`
    /// charge_result (every non-monetary grant) returns the base metadata
    /// unchanged. Errors are logged; a Drop impl cannot surface them.
    fn release_charge_from_post_dispatch_drop(&self) -> Option<serde_json::Value> {
        let base = self.receipt_context.extra_metadata.clone();
        let charge = self.budget_mutation.charge_result();
        // A no-ceiling MustPrepay hold carries a payment authorization with
        // charge_result == None and must still be released so the prepaid funds
        // are not left frozen; return the base metadata only when there is
        // neither a charge to reverse nor a payment authorization to release.
        if charge.is_none() && self.payment_authorization.is_none() {
            return base;
        }
        let cleanup = self.kernel.release_post_dispatch_monetary_invocation(
            self.request,
            self.cap,
            self.budget_mutation.charge_result(),
            self.payment_authorization,
            self.threshold_operation.is_some(),
        );
        if let Err(failure) = &cleanup {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(failure.reason()),
                "failed to release dropped post-admission monetary invocation"
            );
        }
        self.kernel
            .post_dispatch_cleanup_receipt_metadata(base, charge, &cleanup)
    }

    /// Fully unwind a future dropped BEFORE tool-server dispatch. No side
    /// effect is possible, so every pre-execution mutation is reversed: the
    /// monetary hold, an invocation-only budget increment,
    /// runtime-admission reservations, and an admitted child/delegated
    /// capability budget share. A clean unwind records NO receipt
    /// (the intended receipt-free exit). If ANY step fails, a signed fault
    /// receipt is recorded so a stuck hold/reservation is on the
    /// append-only log rather than silently burned. Best-effort from Drop:
    /// each step is attempted independently and failures are collected.
    fn handle_pre_dispatch_drop(&self) {
        let mut faults: Vec<PreDispatchCleanupFault> = Vec::new();

        // Operation-owned cleanup has one durable winner. Claim compensation
        // before releasing any participant. If another coordinator already
        // committed dispatch, this stale drop guard must release nothing.
        if let Some(admission) = self.budget_mutation.ordinary_admission() {
            match self.kernel.claim_pre_dispatch_compensation(
                admission.operation_id(),
                "tool evaluation future dropped before dispatch",
            ) {
                Ok(Some(_)) => {}
                Ok(None) => return,
                Err(error) => {
                    faults.push(PreDispatchCleanupFault {
                        step: "compensation_claim",
                        reason: redacted!(&error).to_string(),
                        hold_ids: vec![admission.operation_id().to_string()],
                    });
                    self.record_pre_dispatch_cleanup_fault_receipt(&faults);
                    return;
                }
            }
        }

        // 1. Monetary hold reversal (budget charge + payment release/refund). A
        //    no-ceiling MustPrepay hold carries a payment authorization with no
        //    charge_result, so fire this step on either signal to release the
        //    prepaid funds and avoid a frozen facilitator hold.
        if self.budget_mutation.charge_result().is_some()
            || self.budget_mutation.ordinary_admission().is_some()
            || self.payment_authorization.is_some()
        {
            if let Err(error) = self.kernel.unwind_aborted_monetary_invocation(
                self.request,
                self.cap,
                self.budget_mutation,
                self.payment_authorization,
            ) {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to unwind dropped pre-dispatch monetary invocation"
                );
                // Name the budget hold (and payment authorization, if any) the
                // failed reversal was unwinding so an operator can locate the
                // possibly-stuck monetary hold from the fault entry alone.
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

        // 2. Invocation-only budget reversal. A non-monetary grant
        //    with `max_invocations` incremented the invocation counter at
        //    admission; reverse it so a never-dispatched call does not
        //    permanently consume a slot. Reuse the same primitive the
        //    pre-dispatch denial path uses, gated on the Invocation variant so
        //    a Charge (handled above) is not reversed twice.
        if matches!(
            self.budget_mutation,
            PreExecutionBudgetMutation::Invocation { .. }
        ) {
            if let Err(error) = self
                .kernel
                .reverse_pre_execution_budget_mutation(self.cap, self.budget_mutation)
            {
                let reason = redacted!(&error).to_string();
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to reverse dropped pre-dispatch invocation budget"
                );
                faults.push(PreDispatchCleanupFault {
                    step: "invocation_reversal",
                    reason,
                    // The invocation slot is keyed by the capability id; name it
                    // so the stuck slot is locatable from the fault entry.
                    hold_ids: vec![self.cap.id.clone()],
                });
            }
        }

        // 3. Runtime-admission reservation release.
        if let Err(error) = self
            .kernel
            .release_runtime_admission_reservations(self.receipt_context.extra_metadata.as_ref())
        {
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
            let release = match self.threshold_operation.as_ref() {
                Some(operation) => self
                    .kernel
                    .release_threshold_delegated_budget(self.cap, operation),
                None => self
                    .kernel
                    .release_admitted_capability_budget(self.cap)
                    .map_err(super::KernelError::DelegationInvalid),
            };
            if let Err(error) = release {
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

        // 5. Fault receipt. Clean cleanup is receipt-free (the
        //    intended design); any fault records a signed receipt.
        if !faults.is_empty() {
            self.record_pre_dispatch_cleanup_fault_receipt(&faults);
        }
    }

    /// Flush the child receipts the nested-flow bridge buffered during dispatch
    /// onto the append-only log. The receipts are ALREADY SIGNED, so this
    /// persists each through the same synchronous per-receipt record path the
    /// normal exit uses. Called only from the post-dispatch drop branch (a child
    /// operation can only have run once dispatch started); a pre-dispatch drop
    /// leaves the buffer empty. Each receipt is recorded independently and a
    /// failure does NOT abandon the receipts queued behind it: a saturated or
    /// wedged writer that fails one bounded append must not discard the rest,
    /// which a stop-at-first-failure batch record would. Best-effort from Drop:
    /// a per-receipt failure logs an `audit_fault` and never panics, and the
    /// buffer is drained unconditionally so the guard cannot re-record on a
    /// later drop.
    fn flush_buffered_child_receipts_from_drop(&mut self) {
        for receipt in std::mem::take(&mut self.child_receipts) {
            if let Err(error) = self.kernel.record_child_receipt(&receipt) {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    audit_fault = "post_admission_drop_child_receipts_unrecorded",
                    "failed to flush a buffered nested child receipt on post-admission drop"
                );
            }
        }
    }

    /// Record a signed cancellation receipt documenting a pre-dispatch cleanup
    /// fault. Best-effort from Drop: if even the receipt cannot be recorded,
    /// log with the `audit_fault` field. The failing steps and the reserved
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
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            PRE_DISPATCH_CLEANUP_FAULT_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            metadata,
        ) {
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
        if !self.armed {
            return;
        }

        drop(self.security_dispatch_outcome.take());

        if !self.dispatch_started {
            // Pre-dispatch drop (or a panic unwinding before dispatch).
            // Nothing was written to the tool server, so no side effect is
            // possible: fully reverse every pre-execution mutation. A clean
            // unwind records NO cancellation receipt; a cleanup fault records
            // a signed fault receipt (see `handle_pre_dispatch_drop`).
            self.handle_pre_dispatch_drop();
            return;
        }

        let terminal_operation = self.threshold_operation.clone().or_else(|| {
            self.budget_mutation
                .ordinary_admission()
                .and_then(|admission| {
                    match self.kernel.load_ordinary_admission(admission.operation_id()) {
                        Ok(operation) => Some(operation),
                        Err(error) => {
                            warn!(
                                request_id = %self.request.request_id,
                                reason = %redacted!(&error),
                                audit_fault = "ordinary_drop_terminal_receipt_load_failed",
                                "failed to load dropped ordinary admission for signed terminal staging"
                            );
                            None
                        }
                    }
                })
        });
        let mut terminal_receipt_scope = None;
        let terminal_metadata = terminal_operation.as_ref().and_then(|operation| {
            match self.kernel.scope_threshold_terminal_receipt_outbox(
                self.request,
                operation,
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown,
                Some(POST_ADMISSION_DROP_REASON.to_string()),
            ) {
                Ok((metadata, scope)) => {
                    terminal_receipt_scope = Some(scope);
                    Some(metadata)
                }
                Err(error) => {
                    warn!(
                        request_id = %self.request.request_id,
                        reason = %redacted!(&error),
                        audit_fault = "admission_drop_terminal_receipt_staging_failed",
                        "failed to stage unknown outcome and signed receipt for dropped governed dispatch"
                    );
                    None
                }
            }
        });

        // Flush the buffered nested child receipts FIRST. The child operations
        // completed and were signed before the parent evaluation was cancelled,
        // so on the append-only log they precede the parent cancellation
        // receipt recorded below. Without this flush the already-signed child
        // receipts would be discarded with the dropped future, leaving the
        // completed child requests off the log and breaking receipt-completeness.
        self.flush_buffered_child_receipts_from_drop();

        // Charge-gated section: release the pre-execution monetary exposure,
        // if any, folding the release into the post-dispatch receipt metadata.
        // The invocation count remains consumed because dispatch started and a
        // tool-side effect may already have occurred.
        // Best-effort from a Drop context; a non-monetary grant returns the
        // base metadata unchanged.
        let released_metadata = merge_metadata_objects(
            self.release_charge_from_post_dispatch_drop(),
            terminal_metadata,
        );

        // Post-dispatch drop. The tool-server invoke was in flight; a side
        // effect MAY have executed. Fail closed: retain the runtime-
        // admission reservations (releasing a single-use destructive lease
        // here would license a replay) and ALWAYS record a cancellation
        // receipt so the executed-or-not side effect is on the append-only
        // log. The retained reservations are marked in the receipt metadata
        // so the burned lease is auditable and operator-recoverable.
        let receipt_metadata = self
            .kernel
            .mark_runtime_admission_reservations_retained_fail_closed(released_metadata);

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            POST_ADMISSION_DROP_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            receipt_metadata,
        ) {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "post_admission_drop_receipt_unrecorded",
                "failed to record cancellation receipt for dropped post-admission invocation"
            );
        }
        drop(terminal_receipt_scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_reversal_marker_nests_disposition_under_terminal() {
        let marker = pending_reversal_marker("budget-hold:req-x:cap-x:0", "store unavailable");
        assert_eq!(marker["terminal"]["disposition"], "pending_reversal");
        assert_eq!(marker["hold_id"], "budget-hold:req-x:cap-x:0");
        assert_eq!(marker["terminal"]["reason"], "store unavailable");
    }
}
