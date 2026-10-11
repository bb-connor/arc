//! Exact original preparation authentication before definitive cleanup.
use super::*;

impl ChioKernel {
    /// Authenticate the exact prepared request before using a live denial to
    /// mutate its durable operation or dispatch fence. Historical verification
    /// authenticates evidence only and cannot authorize execution.
    pub(in crate::kernel) fn verify_active_response_prepared_request_binding_at(
        &self,
        request: &ActiveResponseAdmissionRequest,
        binding: &PreparedActiveResponseDispatchBinding,
        now_unix_ms: u64,
    ) -> Result<u64, KernelError> {
        validate_executable_response_plan(request)?;
        let expected_fingerprint =
            binding
                .admission_artifact_fingerprint
                .ok_or(KernelError::ResponseDispatchRejected(
                    chio_security_types::DispatchRejection::UnboundArtifactPreparation,
                ))?;
        if super::active_response_artifact::active_response_admission_artifact_fingerprint(request)?
            != expected_fingerprint
        {
            return Err(active_response_denied(
                "current admission artifact does not match the original preparation",
            ));
        }
        let authorization_capability_hash =
            crate::threshold_approval::authorization_capability_hash(
                request.authorization().operator_capability(),
            )
            .map_err(|error| active_response_denied(error.to_string()))?;
        let governed_intent_hash = request
            .authorization()
            .governed_intent()
            .binding_hash()
            .map_err(|error| active_response_denied(error.to_string()))?;
        if request.response_plan().plan_hash != binding.plan_hash
            || request.response_plan().tenant_id != binding.tenant_id
            || request.response_plan().action_id != binding.action_id
            || authorization_capability_hash != digest_hex(&binding.authorization_capability_hash)
            || governed_intent_hash != digest_hex(&binding.governed_intent_hash)
            || binding.authorized_at_unix_ms > now_unix_ms
        {
            return Err(active_response_denied(
                "current admission request does not match the prepared dispatch binding",
            ));
        }

        let bindings = self.verify_active_response_immutable_authorization_at(
            request.authorization(),
            binding.authorized_at_unix_ms,
        )?;
        self.verify_active_response_artifact_authority_attestation(
            request,
            &bindings,
            binding.authorized_at_unix_ms,
        )?;
        let requirement = self.resolve_active_response_requirement(&bindings)?;
        if bindings.plan_body_hash() != digest_hex(&binding.plan_hash)
            || requirement.executor_authority().authority_id()
                != binding.executor_authority_id.as_str()
            || requirement.executor_authority().generation()
                != binding.executor_authority_generation
        {
            return Err(active_response_denied(
                "current admission request does not match the prepared dispatch binding",
            ));
        }
        let mut expires_at_unix_ms = request
            .response_plan()
            .expires_at_unix_ms
            .min(
                request
                    .response_plan()
                    .operator_capability
                    .expires_at_unix_ms,
            )
            .min(
                request
                    .authorization()
                    .submission_proof()
                    .body
                    .expires_at_unix_ms,
            )
            .min(
                request
                    .artifact_authority_attestation()
                    .body
                    .expires_at_unix_ms,
            );
        match (&binding.approval, requirement.approval_requirement()) {
            (ResponseDispatchApproval::Automatic, ResponseApprovalRequirement::Automatic) => {
                if request.threshold_proposal().is_some() || !request.approval_tokens().is_empty() {
                    return Err(active_response_denied(
                        "automatic prepared admission cannot carry threshold artifacts",
                    ));
                }
            }
            (
                ResponseDispatchApproval::Governed {
                    approval_set_hash, ..
                },
                ResponseApprovalRequirement::Governed { .. },
            ) => {
                let verified = self.verify_active_response_threshold(
                    request,
                    &bindings,
                    &requirement,
                    binding.authorized_at_unix_ms / 1_000,
                )?;
                if verified
                    .approval_set_hash()
                    .map_err(|error| active_response_denied(error.to_string()))?
                    != digest_hex(approval_set_hash)
                {
                    return Err(active_response_denied(
                        "current approval set does not match the prepared dispatch binding",
                    ));
                }
                let deadline_unix_ms = verified
                    .body()
                    .proposal_deadline
                    .checked_mul(1_000)
                    .ok_or_else(|| {
                        active_response_internal(
                            "verified active-response proposal deadline overflowed milliseconds",
                        )
                    })?;
                expires_at_unix_ms = expires_at_unix_ms.min(deadline_unix_ms);
                // Every token was verified above and its digest belongs to the
                // exact prepared set. Unsigned or unrelated expiry claims never
                // participate in this immutable window.
                for token in request.approval_tokens() {
                    let token_expires_at_unix_ms =
                        token.expires_at.checked_mul(1_000).ok_or_else(|| {
                            active_response_internal(
                                "verified active-response approval expiry overflowed milliseconds",
                            )
                        })?;
                    expires_at_unix_ms = expires_at_unix_ms.min(token_expires_at_unix_ms);
                }
            }
            _ => {
                return Err(active_response_denied(
                    "current approval requirement does not match the prepared dispatch binding",
                ))
            }
        }
        Ok(expires_at_unix_ms)
    }

    pub(in crate::kernel) fn require_definitive_active_response_denial(
        &self,
        request: &ActiveResponseAdmissionRequest,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<(), KernelError> {
        let now_unix_ms = self.read_authority_time()?.get();
        let authenticated_expires_at_unix_ms =
            self.verify_active_response_prepared_request_binding_at(request, binding, now_unix_ms)?;
        let denial = match self.verify_active_response_admission_at(request, now_unix_ms) {
            Ok(_) => {
                return Err(active_response_denied(
                    "current live admission remains valid and cannot be terminated",
                ))
            }
            Err(error) => error,
        };
        if matches!(
            &denial,
            KernelError::CapabilityRevoked(_) | KernelError::DelegationChainRevoked(_)
        ) || (now_unix_ms >= authenticated_expires_at_unix_ms
            && matches!(&denial, KernelError::GovernedTransactionDenied(_)))
        {
            return Ok(());
        }
        Err(denial)
    }
}
