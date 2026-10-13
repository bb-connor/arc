//! Strict-nonce preparation without execution authority.

use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;

/// Admitted state before nonce issuance and reversal of the preflight hold.
pub(super) struct StrictNoncePreflight<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) now: u64,
    pub(super) cap: &'a CapabilityToken,
    pub(super) matching_grants: &'a [MatchingGrant<'a>],
    pub(super) matched_grant_index: usize,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) durable_admission: &'a mut Option<DurableToolAdmission>,
    pub(super) extra_metadata: Option<serde_json::Value>,
    pub(super) pre_invocation_guard_evidence: &'a [GuardEvidence],
    pub(super) verified_governed_payee_binding: &'a Option<VerifiedGovernedPayeeBinding>,
    pub(super) budget_lease_acquired: bool,
}

impl ChioKernel {
    pub(super) fn run_strict_nonce_preflight(
        &self,
        preflight: StrictNoncePreflight<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let StrictNoncePreflight {
            request,
            now,
            cap,
            matching_grants,
            matched_grant_index,
            budget_mutation,
            durable_admission,
            extra_metadata,
            pre_invocation_guard_evidence,
            verified_governed_payee_binding,
            budget_lease_acquired,
        } = preflight;
        if matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .is_some_and(|selected| {
                selected
                    .grant
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, Constraint::OutputDigestSha256(_)))
            })
        {
            let reason =
                "output-digest delivery cannot be enforced on a no-output authorization path";
            warn!(request_id = %request.request_id, reason, "delivery contract denied");
            return self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: extra_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }
        self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
            self.build_execution_nonce_preflight_allow_response_after_cleanup(
                request,
                now,
                matched_grant_index,
                cap,
                budget_mutation,
                durable_admission.as_mut(),
                extra_metadata,
                budget_lease_acquired,
            )
        })
    }
}
