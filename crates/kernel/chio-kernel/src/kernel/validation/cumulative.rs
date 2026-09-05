//! Cumulative approval holds, proposal issuance, and budget authorization.

use super::*;

impl ChioKernel {
    pub(super) fn cumulative_approval_request_for_grant(
        &self,
        request: &ToolCallRequest,
        matching: &MatchingGrant<'_>,
        admission: Option<&DurableToolAdmission>,
        now: u64,
    ) -> Result<Option<BudgetCumulativeApprovalRequest>, KernelError> {
        let cumulative_constraint_count = matching
            .grant
            .constraints
            .iter()
            .filter(|constraint| {
                matches!(
                    constraint,
                    Constraint::RequireCumulativeApprovalAbove { .. }
                )
            })
            .count();
        if cumulative_constraint_count == 0 {
            return Ok(None);
        }
        if cumulative_constraint_count != 1 {
            return Err(KernelError::GovernedTransactionDenied(
                "a matching grant must contain exactly one cumulative approval constraint"
                    .to_owned(),
            ));
        }
        // A configured cumulative profile must be able to issue an admissible
        // proposal before reserving an allowance that could require approval.
        self.ensure_threshold_proposal_signer_ready()?;
        let admission = admission.ok_or_else(|| {
            KernelError::DurableAdmission(
                "cumulative approval requires a durable admission operation".to_owned(),
            )
        })?;
        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        if !peer.supports(chio_core::capability::features::CUMULATIVE_APPROVAL_BUDGET) {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval budgets were not negotiated".to_owned(),
            ));
        }
        let direct_root = self
            .negotiated_capability_root(&request.capability, &peer)
            .map_err(KernelError::GovernedTransactionDenied)?;
        let verified =
            chio_core::capability::cumulative_approval::verify_cumulative_approval_constraints(
                &request.capability,
                &self.trusted_issuer_keys(),
                direct_root.as_ref(),
            )
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let mut matching_constraints = verified
            .into_iter()
            .filter(|constraint| constraint.grant_index == matching.index);
        let constraint = matching_constraints.next().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval verification omitted the matching grant".to_owned(),
            )
        })?;
        if matching_constraints.next().is_some() {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval verification produced an ambiguous grant".to_owned(),
            ));
        }
        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".to_owned(),
            )
        })?;
        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent target does not match the request".to_owned(),
            ));
        }
        let requested_authorized = intent.max_amount.clone().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval intent requires a maximum amount".to_owned(),
            )
        })?;
        if requested_authorized.currency != constraint.threshold.currency {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent currency does not match the capability".to_owned(),
            ));
        }
        Ok(Some(BudgetCumulativeApprovalRequest {
            operation_id: admission.operation_id().to_owned(),
            account_key: BudgetCumulativeApprovalAccountKey {
                authority_id: constraint.authority_id.to_hex(),
                owner_id: constraint.owner_id,
                approval_budget_id: constraint.approval_budget_id,
                approval_budget_epoch: constraint.approval_budget_epoch,
                root_grant_hash: constraint.root_grant_hash,
                delegation_root_id: constraint.delegation_root_id,
                root_binding_digest: constraint.root_binding_digest,
                currency: constraint.threshold.currency.clone(),
            },
            authority_threshold: constraint.authority_threshold,
            effective_threshold: constraint.threshold,
            requested_authorized,
        }))
    }

    pub(super) fn ensure_cumulative_approval_proposal(
        &self,
        request: &ToolCallRequest,
        required: &ApprovalRequiredBudgetHold,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<chio_core::capability::governance::ThresholdApprovalProposal, KernelError> {
        let trusted_now_unix_ms = self.refresh_admission_trusted_time(trusted_now_unix_ms)?;
        let now = trusted_now_unix_ms / 1_000;
        let requirement = self.threshold_approval_requirement(request, now)?;
        if admission.operation.state() == AdmissionOperationState::ApprovalRequired {
            if admission
                .operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != required.hold_id)
            {
                return Err(KernelError::DurableAdmission(
                    "retained approval proposal changed its budget hold".to_owned(),
                ));
            }
            let proposal = admission
                .operation
                .threshold_proposal()
                .cloned()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "approval-required operation omitted its stored proposal".to_owned(),
                    )
                })?;
            if proposal.body.proposal_id != admission.operation_id() {
                return Err(KernelError::DurableAdmission(
                    "retained threshold proposal changed its admission operation".into(),
                ));
            }
            self.validate_cumulative_threshold_proposal(request, &proposal, &requirement, now)?;
            return Ok(proposal);
        }
        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".to_owned(),
            )
        })?;
        let intent_hash = intent
            .binding_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let capability_digest = sha256_hex(
            &canonical_json_bytes(&request.capability)
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?,
        );
        let proposal_created_at = required.metadata.recorded_at_unix_seconds.ok_or_else(|| {
            KernelError::DurableAdmission(
                "cumulative approval authorization omitted its durable timestamp".to_owned(),
            )
        })?;
        let proposal_deadline =
            chio_core::capability::governance::ThresholdApprovalProposalBody::proposal_deadline(
                proposal_created_at,
                requirement.timeout_seconds,
                request.capability.expires_at,
                intent.governed_operation_expires_at(),
            )
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let proposal = self.sign_threshold_proposal(
            chio_core::capability::governance::ThresholdApprovalProposalBody {
                schema: chio_core::capability::governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA
                    .to_owned(),
                proposal_id: admission.operation_id().to_owned(),
                request_id: request.request_id.clone(),
                governed_intent_hash: intent_hash,
                subject: request.capability.subject.clone(),
                authorizing_capability_digest: capability_digest,
                policy_hash: requirement.policy_hash.clone(),
                threshold: requirement.threshold,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at,
                proposal_deadline,
                policy_authority: self.threshold_proposal_signing_key(),
            },
        )?;
        self.validate_cumulative_threshold_proposal(request, &proposal, &requirement, now)?;
        let proposal_hash = AdmissionDigest::try_new(
            "threshold_proposal_hash",
            proposal
                .artifact_digest()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?,
        )?;
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            vec![
                AdmissionAttachment::ThresholdProposalHash(proposal_hash),
                AdmissionAttachment::BudgetHoldId(AdmissionIdentifier::try_new(
                    "budget_hold_id",
                    required.hold_id.clone(),
                )?),
                AdmissionAttachment::ThresholdProposal(Box::new(proposal.clone())),
            ],
            AdmissionOperationState::ApprovalRequired,
            trusted_now_unix_ms,
        )?;
        Ok(proposal)
    }

    pub(in crate::kernel) fn validate_cumulative_threshold_proposal(
        &self,
        request: &ToolCallRequest,
        proposal: &chio_core::capability::governance::ThresholdApprovalProposal,
        requirement: &chio_core::capability::threshold_approval::ThresholdApprovalRequirement,
        now: u64,
    ) -> Result<(), KernelError> {
        use crate::threshold_approval::{
            authorization_capability_hash, verify_threshold_approval_proposal,
            ThresholdApprovalProposalVerificationInput,
        };
        // Budget persistence and policy lookup may cross a clock boundary.
        // Refresh from the trusted runtime, never from the proposal's timestamps.
        let now = self.refresh_admission_trusted_time(now.saturating_mul(1_000))? / 1_000;
        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".into(),
            )
        })?;
        let intent_hash = intent
            .binding_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let capability_hash = authorization_capability_hash(&request.capability)
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        verify_threshold_approval_proposal(
            &ThresholdApprovalProposalVerificationInput {
                request_id: &request.request_id,
                governed_intent_hash: &intent_hash,
                subject: &request.capability.subject,
                authorization_capability_hash: &capability_hash,
                authorizing_capability_expires_at: request.capability.expires_at,
                governed_operation_expires_at: intent
                    .governed_operation_expires_at()
                    .unwrap_or(u64::MAX),
                policy_hash: &self.config.policy_hash,
                proposal,
                trusted_policy_authorities: &self.trusted_threshold_proposal_authorities(),
                allowed_signing_algorithms: self
                    .capability_crypto_floor
                    .allowed_signing_algorithms(),
                now,
            },
            requirement,
        )
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        Ok(())
    }

    pub(super) fn authorize_cumulative_approval(
        &self,
        request: &ToolCallRequest,
        grant_index: usize,
        required: &ApprovalRequiredBudgetHold,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, KernelError> {
        let proposal = self.ensure_cumulative_approval_proposal(
            request,
            required,
            admission,
            trusted_now_unix_ms,
        )?;
        let trusted_now_unix_ms = self.refresh_admission_trusted_time(trusted_now_unix_ms)?;
        if request.threshold_approval_proposal.as_ref() != Some(&proposal) {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold approval request does not carry the stored proposal".to_owned(),
            ));
        }
        let intent_hash = request
            .governed_intent
            .as_ref()
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "cumulative approval requires a governed transaction intent".to_owned(),
                )
            })?
            .binding_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let verified = self.validate_threshold_approval_set(
            request,
            &request.capability,
            &intent_hash,
            trusted_now_unix_ms / 1_000,
        )?;
        let approval_set_digest = verified
            .body
            .approval_set_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        // A retained hold records its original owner for audit, not authority
        // to mutate after restart. The store verifies that historical owner
        // separately from this runtime's current fenced mutation authority.
        let (_, authority) = self.durable_budget_binding(admission, &request.capability)?;
        let decision = self.with_budget_store(|store| {
            Ok(
                store.authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
                    capability_id: request.capability.id.clone(),
                    grant_index,
                    operation_id: admission.operation_id().to_owned(),
                    hold_id: required.hold_id.clone(),
                    admission_binding: required.admission_binding.clone(),
                    approval_set_digest,
                    event_id: format!("{}:authorize-cumulative", required.hold_id),
                    authority: Some(authority),
                })?,
            )
        })?;
        let mutation = match decision {
            BudgetCumulativeApprovalAuthorizationDecision::Authorized(mutation)
            | BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(mutation) => {
                mutation
            }
        };
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            Vec::new(),
            AdmissionOperationState::BudgetAuthorized,
            trusted_now_unix_ms,
        )?;
        Ok(mutation)
    }
}
