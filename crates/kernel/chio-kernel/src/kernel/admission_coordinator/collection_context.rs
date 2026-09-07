//! Current collection authority from the original kernel admission, not a proposal.

use super::*;
use crate::approval::{
    ApprovalStoreError, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters,
};
use crate::threshold_approval::{
    ThresholdApprovalCollectionPolicy, ThresholdApprovalCollector, ThresholdApprovalCollectorStore,
    ThresholdApprovalContextResolver, ThresholdApprovalRequest,
};

struct KernelCollectionContextResolver {
    kernel: Arc<ChioKernel>,
    policy: ThresholdApprovalCollectionPolicy,
}

impl ThresholdApprovalContextResolver for KernelCollectionContextResolver {
    fn resolve_context(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalProposalCreationContext, ApprovalStoreError> {
        self.kernel
            .resolve_current_collection_context(&self.policy, request_id, now)
    }
}

impl ChioKernel {
    /// Compose a collector with this kernel's original-request resolver. The
    /// operator must complete durable startup reconciliation first. Collection
    /// never reserves a budget, consumes approval evidence or dispatches a tool.
    ///
    /// The authenticated submitter is the original capability-bound agent, with
    /// DPoP enforced at original admission when required by its matching grants.
    /// This does not assert a separate human submitter or physical-person identity.
    pub fn create_threshold_approval_collector(
        self: &Arc<Self>,
        store: Arc<dyn ThresholdApprovalCollectorStore>,
        policy: ThresholdApprovalCollectionPolicy,
    ) -> Result<ThresholdApprovalCollector, ApprovalStoreError> {
        self.validate_collection_configuration(&policy)?;
        let resolver = KernelCollectionContextResolver {
            kernel: Arc::clone(self),
            policy,
        };
        Ok(ThresholdApprovalCollector::new(
            store,
            self.config.policy_hash.clone(),
            self.trusted_threshold_proposal_authorities(),
            Arc::new(resolver),
        ))
    }

    fn validate_collection_configuration(
        &self,
        policy: &ThresholdApprovalCollectionPolicy,
    ) -> Result<&DurableAdmissionRuntime, ApprovalStoreError> {
        if policy.policy_hash() != self.config.policy_hash {
            return Err(denied(
                "collection rules do not match the active kernel policy",
            ));
        }
        if self.is_emergency_stopped() || self.is_rss_shedding() {
            return Err(denied("kernel is unavailable for approval collection"));
        }
        let runtime = self.durable_runtime().map_err(denied)?;
        if !*runtime
            .startup_reconciled
            .lock()
            .map_err(|_| denied("startup reconciliation state is unavailable"))?
        {
            return Err(denied(
                "approval collection requires completed startup reconciliation",
            ));
        }
        Ok(runtime)
    }

    fn resolve_current_collection_context(
        &self,
        policy: &ThresholdApprovalCollectionPolicy,
        request_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalProposalCreationContext, ApprovalStoreError> {
        let runtime = self.validate_collection_configuration(policy)?;
        let selector = AdmissionIdentifier::try_new("request_id", request_id).map_err(denied)?;
        let now_ms = runtime.refresh_trusted_time(
            now.checked_mul(1000)
                .ok_or_else(|| denied("collection time overflow"))?,
        );
        let (operation, retained) = runtime
            .store
            .load_unambiguous_retained_tool_request(&selector, &runtime.fence, now_ms)
            .map_err(denied)?
            .ok_or_else(|| denied("original request material is unavailable"))?;
        let binding = operation.binding();
        if operation.state() != AdmissionOperationState::ApprovalRequired
            || binding.request_id() != &selector
            || binding.coordinator_authority_id().as_str() != runtime.fence.store_uuid
            || binding.policy_hash().as_str() != self.config.policy_hash
        {
            return Err(denied(
                "original admission is not eligible for approval collection",
            ));
        }
        retained.validate_binding(binding).map_err(denied)?;
        let request = retained.request_for_revalidation();
        let now = now_ms / 1000;
        self.verify_capability_full_pre_admit(
            &request.capability,
            request.federated_origin_kernel_id.as_deref(),
            now,
        )
        .map_err(denied)?;
        self.check_revocation(&request.capability).map_err(denied)?;
        self.validate_delegation_admission(&request.capability)
            .map_err(denied)?;
        check_subject_binding(&request.capability, &request.agent_id).map_err(denied)?;
        let submitter = chio_core::PublicKey::from_hex(&request.agent_id).map_err(denied)?;
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(denied)?;
        let current_plan = self.durable_post_return_plan().map_err(denied)?;
        if immutable_tool_admission_request_hash(request, &matching, &current_plan)
            .map_err(denied)?
            != *binding.immutable_request_hash()
        {
            return Err(denied(
                "current request routing or post-return policy changed",
            ));
        }
        let requirement = self
            .threshold_approval_requirement(request, now)
            .map_err(denied)?;
        let proposal = operation
            .threshold_proposal()
            .ok_or_else(|| denied("pending admission has no signed proposal"))?;
        if proposal.body.proposal_id != binding.operation_id().as_str() {
            return Err(denied("pending proposal belongs to another operation"));
        }
        self.validate_cumulative_threshold_proposal(request, proposal, &requirement, now)
            .map_err(denied)?;
        let intent = request
            .governed_intent
            .as_ref()
            .ok_or_else(|| denied("original governed intent is unavailable"))?;
        let refreshed_ms = runtime.refresh_trusted_time(now_ms);
        let current_requirement = self
            .threshold_approval_requirement(request, refreshed_ms / 1000)
            .map_err(denied)?;
        if current_requirement != requirement {
            return Err(denied(
                "threshold policy changed during collection validation",
            ));
        }
        self.verify_capability_full_pre_admit(
            &request.capability,
            request.federated_origin_kernel_id.as_deref(),
            runtime.refresh_trusted_time(refreshed_ms) / 1000,
        )
        .map_err(denied)?;
        self.check_revocation(&request.capability).map_err(denied)?;
        self.validate_delegation_admission(&request.capability)
            .map_err(denied)?;
        // Preserve the same alternative-grant semantics as tool admission,
        // using refreshed time after current-authority lookups. The pending
        // operation proves prior guard admission, not execution authority.
        // Execution re-evaluates guards and one-shot proofs independently.
        let current_now = runtime.refresh_trusted_time(refreshed_ms) / 1000;
        if !matching.iter().any(|candidate| {
            self.validate_governed_transaction_pure(
                request,
                &request.capability,
                candidate.grant,
                GovernedValidationContext {
                    parent_context: None,
                    now: current_now,
                },
            )
            .is_ok()
        }) {
            return Err(denied("original governed intent is no longer admissible"));
        }
        self.validate_cumulative_threshold_proposal(
            request,
            proposal,
            &requirement,
            runtime.refresh_trusted_time(refreshed_ms) / 1000,
        )
        .map_err(denied)?;
        // Re-read through the qualified store after potentially slow authority
        // checks. A changed operation, new ambiguity or fenced owner cannot be
        // hidden by the earlier snapshot. Collection remains separate from the
        // independent execution admission and its durable replay reservation.
        self.validate_collection_configuration(policy)?;
        let (current, original) = runtime
            .store
            .load_unambiguous_retained_tool_request(
                &selector,
                &runtime.fence,
                runtime.refresh_trusted_time(refreshed_ms),
            )
            .map_err(denied)?
            .ok_or_else(|| denied("original request disappeared during validation"))?;
        if current != operation || original.canonical_bytes() != retained.canonical_bytes() {
            return Err(denied(
                "original admission changed during collection validation",
            ));
        }
        ThresholdApprovalProposalCreationContext::new(ThresholdApprovalProposalCreationParameters {
            matched_request: ThresholdApprovalRequest::new(
                &request.request_id,
                &request.server_id,
                &request.tool_name,
            )
            .map_err(denied)?,
            requirement,
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash().map_err(denied)?,
            authorization_capability_hash:
                crate::threshold_approval::authorization_capability_hash(&request.capability)
                    .map_err(denied)?,
            authorizing_capability_expires_at: request.capability.expires_at,
            governed_operation_expires_at: intent
                .governed_operation_expires_at()
                .unwrap_or(u64::MAX),
            submitter: Some(submitter),
            separation_of_duties: policy.require_submitter_separation(),
        })
    }
}

fn denied(error: impl std::fmt::Display) -> ApprovalStoreError {
    ApprovalStoreError::Invalid(error.to_string())
}
