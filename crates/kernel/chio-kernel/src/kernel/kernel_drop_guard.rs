use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use chio_core::receipt::{
    body::ChioReceiptBody,
    decision::ToolCallAction,
    kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    },
    signing::ReceiptSigningHandle,
};
use chio_log_redact::redacted;
use tracing::warn;

use crate::admission_operation::{AdmissionOperationV1, LOCAL_SYSTEM_TENANT_ID};
use crate::kernel::admission_coordinator::DurableRefusalResponse;
use crate::receipt_support::{
    next_receipt_id, receipt_attribution_metadata, request_receipt_metadata_with_payee_binding,
};
use crate::{CapabilityToken, PaymentAuthorization, ToolCallRequest};

use super::{
    current_scoped_receipt_tenant_id, merge_metadata_objects, ChioKernel,
    PreExecutionBudgetMutation, VerifiedGovernedPayeeBinding,
};

const PRE_DISPATCH_CLEANUP_FAULT_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";

pub(crate) struct PostAdmissionReceiptContext {
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_output: crate::kernel::PreInvocationGuardOutput,
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

    /// Release participants held before dispatch and persist the durable cancellation.
    /// Cleanup faults produce signed observations when signing and persistence succeed.
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
                if let Err(error) = self.kernel.with_pre_invocation_guard_output(
                    &self.receipt_context.pre_invocation_guard_output,
                    || {
                        self.kernel
                            .compensate_durable_admission_after_pre_dispatch_cleanup(
                                Some(operation),
                                None,
                                self.payment_authorization,
                                None,
                                DurableRefusalResponse {
                                    reason: "evaluation cancelled before dispatch",
                                    cancelled: true,
                                    matched_grant_index: self.matched_grant_index,
                                    metadata: self.receipt_context.extra_metadata.clone(),
                                    verified_payee_binding: self
                                        .receipt_context
                                        .verified_payee_binding
                                        .as_ref(),
                                },
                            )
                    },
                ) {
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

        if !faults.is_empty() {
            self.record_pre_dispatch_cleanup_fault_receipt(&faults);
        }
    }

    /// Record a signed observation documenting a pre-dispatch cleanup
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
        if let Err(error) = self.kernel.trusted_now_millis().and_then(|now| {
            self.kernel.ensure_receipt_persistence_ready()?;
            let authority = self.kernel.signing_authority.backend.as_ref();
            let authority_key = self.kernel.receipt_signing_public_key()?;
            if !self
                .kernel
                .signing_authority
                .floor
                .allowed_signing_algorithms()
                .contains(&authority_key.algorithm())
            {
                return Err(super::KernelError::ReceiptSigningFailed(
                    "cleanup observation authority does not satisfy the boot signing floor".into(),
                ));
            }
            let namespace = match self.durable_operation {
                Some(operation) => operation.binding().request_namespace_digest().clone(),
                None => self
                    .kernel
                    .authenticated_receipt_namespace(&self.request.request_id)?
                    .digest()
                    .clone(),
            };
            let tenant_id = match self.durable_operation {
                Some(operation) => {
                    let binding = operation.binding().to_persisted();
                    let tenant = binding.authenticated_tenant_id.as_str();
                    (tenant != LOCAL_SYSTEM_TENANT_ID).then(|| tenant.to_owned())
                }
                None => self
                    .kernel
                    .receipt_tenant_id_for_request(Some(&self.request.request_id))
                    .or_else(current_scoped_receipt_tenant_id),
            };
            let mut metadata = self
                .receipt_context
                .extra_metadata
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut runtime = metadata
                .remove("chio_runtime")
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            // A fault observes unfinished cleanup. The original operation still
            // owns any terminal decision, regardless of its current custody.
            runtime.remove(crate::kernel::runtime_field::IDENTITY_DISPOSITION);
            runtime.insert(
                crate::kernel::runtime_field::PRE_DISPATCH_CLEANUP_FAILED.into(),
                serde_json::json!(true),
            );
            runtime.insert(
                crate::kernel::runtime_field::PRE_DISPATCH_CLEANUP_FAULTS.into(),
                serde_json::json!(fault_entries),
            );
            runtime.insert(
                crate::kernel::runtime_field::PRE_DISPATCH_CLEANUP_REASON.into(),
                serde_json::json!(PRE_DISPATCH_CLEANUP_FAULT_REASON),
            );
            metadata.insert("chio_runtime".into(), serde_json::Value::Object(runtime));
            metadata.insert(
                "receipt_context".into(),
                serde_json::json!({
                    "request_id": self.request.request_id,
                    "request_namespace_digest": namespace.as_str(),
                }),
            );
            let metadata = Some(serde_json::Value::Object(metadata));
            let request_metadata = request_receipt_metadata_with_payee_binding(
                self.request,
                self.kernel.attestation_trust_policy.as_ref(),
                now.as_secs(),
                metadata.as_ref(),
                self.receipt_context.verified_payee_binding.as_ref(),
            )?;
            let metadata = merge_metadata_objects(
                merge_metadata_objects(metadata, request_metadata),
                receipt_attribution_metadata(self.cap, self.matched_grant_index)?,
            );
            let encode_error = |error: chio_core::error::Error| {
                super::KernelError::ReceiptSigningFailed(error.to_string())
            };
            let content = canonical_json_bytes(&metadata).map_err(encode_error)?;
            let action = ToolCallAction::from_parameters(self.request.arguments.clone())
                .map_err(encode_error)?;
            let body = ChioReceiptBody {
                id: next_receipt_id("rcpt-cleanup-observation")?,
                timestamp: now.as_secs(),
                capability_id: self.cap.id.clone(),
                tool_server: self.request.server_id.clone(),
                tool_name: self.request.tool_name.clone(),
                action,
                decision: None,
                receipt_kind: ReceiptKind::TraceObservation,
                boundary_class: BoundaryClass::DetectOnly,
                observation_outcome: Some(ObservationOutcome::Observed),
                tool_origin: ToolOrigin::ChioInternal,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: sha256_hex(&content),
                policy_hash: self.kernel.config.policy_hash.clone(),
                evidence: self
                    .receipt_context
                    .pre_invocation_guard_output
                    .evidence
                    .clone(),
                metadata,
                trust_level: TrustLevel::Verified,
                tenant_id,
                kernel_key: authority_key,
                bbs_projection_version: None,
            };
            let receipt = chio_kernel_core::sign_receipt_with_handle(
                body,
                authority,
                ReceiptSigningHandle::from_content_preimage(content),
            )
            .map_err(|error| {
                super::KernelError::ReceiptSigningFailed(format!(
                    "cleanup observation signing failed: {error:?}"
                ))
            })?;
            self.kernel.record_chio_receipt_without_settlement(&receipt)
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
