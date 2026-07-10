use super::*;

use crate::kernel::responses::ReservedHoldStamp;

/// Incomplete-decision reason for a strict-nonce preflight whose hold was
/// reversed. The caller retries the same endpoint presenting the minted nonce,
/// at which point the hold is re-taken and the tool dispatched.
const EXECUTION_NONCE_PREFLIGHT_RETRY_REASON: &str =
    "execution nonce preflight requires retry with presented nonce";

/// Incomplete-decision reason for a pre-execution authorization whose hold was
/// reserved (kept open) for a caller that executes the tool downstream. The
/// caller does not retry this endpoint: it presents the minted nonce to the
/// real tool server, which consumes it and reconciles the reserved hold.
const EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON: &str =
    "pre-execution authorization reserved; present the minted execution nonce to the tool server";

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
}

impl ChioKernel {
    pub(super) fn with_pre_invocation_guard_evidence<T>(
        &self,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
        build: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(evidence.to_vec());
        build()
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        self.release_admitted_capability_budget(denial.cap)
            .map_err(KernelError::DelegationInvalid)?;
        let reverse = match denial.payment_authorization {
            Some(payment_authorization) => self.unwind_aborted_monetary_invocation(
                denial.request,
                denial.cap,
                denial.budget_mutation.charge_result(),
                Some(payment_authorization),
            )?,
            None => {
                self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?
            }
        };

        if let (Some(charge), Some(reverse)) =
            (denial.budget_mutation.charge_result(), reverse.as_ref())
        {
            return self.build_pre_execution_monetary_deny_response_with_metadata(
                denial.request,
                denial.reason,
                denial.timestamp,
                charge,
                reverse.committed_cost_units_after,
                denial.cap,
                self.merge_budget_receipt_metadata(
                    runtime_admission_metadata,
                    self.budget_execution_receipt_metadata(
                        charge,
                        Some(("reversed", reverse)),
                        None,
                    ),
                ),
            );
        }

        self.build_deny_response_with_metadata(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
        )
    }

    pub(super) fn build_execution_nonce_preflight_allow_response_after_cleanup(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: usize,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_admission_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        self.release_admitted_capability_budget(cap)
            .map_err(KernelError::DelegationInvalid)?;
        let reverse = self.reverse_pre_execution_budget_mutation(cap, budget_mutation)?;
        let budget_metadata = match (budget_mutation.charge_result(), reverse.as_ref()) {
            (Some(charge), Some(reverse)) => Some(self.budget_execution_receipt_metadata(
                charge,
                Some(("reversed", reverse)),
                None,
            )),
            _ => None,
        };
        let preflight_metadata = Some(serde_json::json!({
            "execution_nonce": {
                "stage": "preflight",
                "tool_dispatched": false
            }
        }));
        let metadata = merge_metadata_objects(
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            preflight_metadata,
        );

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
            EXECUTION_NONCE_PREFLIGHT_RETRY_REASON,
            None,
        )
    }

    /// Build the pre-execution authorization response for a caller that executes
    /// the tool itself (the sidecar mediated `/v1/evaluate` route).
    ///
    /// Unlike [`Self::build_execution_nonce_preflight_allow_response_after_cleanup`],
    /// a monetary reservation KEEPS the pre-execution budget hold reserved
    /// (open): it does not call `reverse_pre_execution_budget_mutation`. Only the
    /// in-memory per-dispatch runtime-admission slot is released, because the tool
    /// never dispatches on this kernel. The delegated child's sibling-sum share
    /// stays admitted in `budget_registry` and is recorded against the reserved
    /// hold (see `build_execution_nonce_preflight_allow_response_with_metadata`),
    /// so an outstanding reservation still counts against the parent; it is
    /// released only when the hold closes (reconciled by nonce or reaped). The
    /// durable hold stays open so it also enforces `max_total_cost` against
    /// concurrent authorizations; it is reconciled at the execution site when
    /// the caller presents the minted nonce, or reclaimed by the crash reaper
    /// if the caller never executes (fail-closed, never over-subscribed).
    ///
    /// A non-monetary grant authorizes no reserved hold, so there is nothing to
    /// record the sibling-sum share against or ever close; the share is released
    /// immediately (as the reverse-for-retry preflight does) rather than leaked
    /// for the parent's lifetime.
    ///
    /// The receipt records the reserved hold's authorize block with no terminal
    /// disposition, so it is truthfully non-authoritative: the hold is reserved,
    /// not reconciled, and `is_authoritative_spend_receipt` rejects it.
    pub(super) fn build_execution_nonce_authorization_reserving_response(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: usize,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_admission_metadata: Option<serde_json::Value>,
        reserved_payment_reference: Option<String>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );

        // A non-monetary grant (max_invocations-only or unlimited) authorizes no
        // reserved monetary hold, so nothing durable exists to record the
        // delegated child's admitted sibling-sum share against and later release
        // it (reconcile-by-nonce and the TTL reaper both key off a hold). Release
        // the share now, matching the reverse-for-retry preflight; otherwise it
        // would stay admitted for the parent's whole lifetime, permanently
        // shrinking its sibling-sum headroom. Only a monetary reserved hold below
        // retains the share, recorded against the hold and released when it closes.
        if budget_mutation.charge_result().is_none() {
            self.release_admitted_capability_budget(&request.capability)
                .map_err(KernelError::DelegationInvalid)?;
        }

        // Record the reserved hold's authorize block with NO terminal event:
        // the hold is open, neither reversed nor reconciled. This is what keeps
        // the receipt non-authoritative and keeps the budget reserved.
        let budget_metadata = budget_mutation
            .charge_result()
            .map(|charge| self.budget_execution_receipt_metadata(charge, None, None));
        let authorization_metadata = Some(serde_json::json!({
            "execution_nonce": {
                "stage": "authorization",
                "tool_dispatched": false,
                "hold_disposition": "reserved"
            }
        }));
        let metadata = merge_metadata_objects(
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            authorization_metadata,
        );

        // The reserved hold is kept open and bound into the signed nonce so
        // reconcile-by-nonce (and reverse-by-nonce) can name the exact hold to
        // settle at the execution site. The response builder stamps the hold's TTL
        // deadline from the minted nonce's exact expiry, keeping the reaper
        // deadline and the nonce validity window consistent. A monetary grant
        // keeps its already-authorized charge; an invocation-only grant adopts its
        // already-debited invocation into a durable zero-exposure reserved hold so
        // the reaper and reconcile/reverse paths handle it uniformly.
        let reserved_hold = match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => Some(ReservedHoldStamp::Monetary {
                charge,
                payment_reference: reserved_payment_reference,
            }),
            PreExecutionBudgetMutation::Invocation { grant_index } => {
                let hold_id = format!(
                    "budget-hold:{}:{}:{}",
                    request.request_id, request.capability.id, grant_index
                );
                Some(ReservedHoldStamp::Invocation {
                    hold_id,
                    grant_index: *grant_index,
                })
            }
            PreExecutionBudgetMutation::None => None,
        };

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
            EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON,
            reserved_hold,
        )
    }
}
