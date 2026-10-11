//! Non-consuming permission preview selects only the independently configured
//! replay profile. Test helpers cannot bypass operation-owned custody.
use super::*;

impl ChioKernel {
    /// Require the request's proof for a non-consuming preview. Credential
    /// reservation remains a separate operation-owned dispatch step.
    pub(crate) fn verify_required_dpop_preview(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let proof = request
            .dpop_proof
            .as_ref()
            .ok_or(KernelError::Dpop(crate::dpop::DpopError::MissingProof))?;
        self.verify_dpop_for_permission_preview(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &request.arguments,
        )
    }

    /// Verify a DPoP proof carried on the request against the capability.
    ///
    /// Fails closed: if no proof is present, or if the nonce store / config is
    /// absent (misconfigured kernel), or if verification fails, the call is denied.
    #[cfg(test)]
    pub(crate) fn verify_dpop_for_request(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        if self.dpop_authority.is_some() {
            return Err(KernelError::DurableAdmission(
                "operation-owned DPoP requires admitted credential custody".into(),
            ));
        }
        let proof = request
            .dpop_proof
            .as_ref()
            .ok_or(KernelError::Dpop(crate::dpop::DpopError::MissingProof))?;

        let nonce_store = self
            .dpop_nonce_store
            .as_ref()
            .ok_or(KernelError::Dpop(crate::dpop::DpopError::MissingStore))?;

        let config = self.dpop_config.as_ref().ok_or(KernelError::Dpop(
            crate::dpop::DpopError::MissingConfiguration,
        ))?;

        let args_bytes = canonical_json_bytes(&request.arguments)
            .map_err(|e| crate::dpop::DpopError::Encoding(Box::new(e)))?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &action_hash,
            nonce_store,
            config,
        )
    }

    /// Verify a DPoP proof for non-mutating permission preview.
    ///
    /// Check the explicitly configured durable domain, or the live process-local
    /// cache and policy when no durable domain is selected. This does not
    /// claim a nonce; authoritative invocation still requires replay custody.
    pub fn verify_dpop_for_permission_preview(
        &self,
        proof: &dpop::DpopProof,
        cap: &CapabilityToken,
        expected_tool_server: &str,
        expected_tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(), KernelError> {
        if self.dpop_authority.is_some() {
            return self
                .verify_operation_owned_dpop(
                    proof,
                    cap,
                    expected_tool_server,
                    expected_tool_name,
                    arguments,
                )
                .map(|_| ());
        }
        self.dpop_nonce_store
            .as_ref()
            .ok_or(KernelError::Dpop(crate::dpop::DpopError::MissingStore))?
            .ensure_accepting_proofs()?;

        let config = self.dpop_config.as_ref().ok_or(KernelError::Dpop(
            crate::dpop::DpopError::MissingConfiguration,
        ))?;

        let args_bytes = canonical_json_bytes(arguments)
            .map_err(|e| crate::dpop::DpopError::Encoding(Box::new(e)))?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof_stateless(
            proof,
            cap,
            expected_tool_server,
            expected_tool_name,
            &action_hash,
            config,
            self.dpop_nonce_store
                .as_ref()
                .ok_or(crate::dpop::DpopError::MissingStore)?
                .trusted_now()?,
        )
    }
}
