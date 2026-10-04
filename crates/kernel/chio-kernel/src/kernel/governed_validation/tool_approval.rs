//! Host construction and current authority checks for ordinary tool approvals.

use super::*;
use crate::approval::ToolApprovalContext;

impl ChioKernel {
    /// Hash of the currently installed admission policy.
    pub fn policy_hash(&self) -> &str {
        &self.config.policy_hash
    }

    /// Install an explicit approval roster for a tenant. Replacing the roster
    /// retires removed approvers immediately, including on retained requests.
    /// An empty roster disables ordinary approvals.
    pub fn set_governed_approval_policy(
        &mut self,
        tenant_id: String,
        approvers: Vec<chio_core::PublicKey>,
    ) -> Result<(), KernelError> {
        if tenant_id.is_empty()
            || tenant_id.len() > 512
            || tenant_id.trim() != tenant_id
            || tenant_id.chars().any(char::is_control)
        {
            return Err(denied("approval tenant identity is invalid"));
        }
        let unique: std::collections::BTreeSet<_> =
            approvers.iter().map(|key| key.to_hex()).collect();
        if unique.len() != approvers.len() {
            return Err(denied("approval roster contains duplicate principals"));
        }
        if approvers.iter().any(chio_core::PublicKey::is_weak_ed25519) {
            return Err(denied("approval roster contains a weak signing key"));
        }
        self.governed_approval_tenant = Some(tenant_id);
        self.governed_approvers = approvers;
        Ok(())
    }

    /// Validate a proposed call without reserving budget or credentials, then
    /// construct its exact approval intent using current server authority.
    pub fn bind_tool_approval_intent(
        &self,
        request: &ToolCallRequest,
    ) -> Result<chio_core::capability::governance::GovernedTransactionIntent, KernelError> {
        use chio_core::capability::governance::{
            GovernedTransactionIntent, GovernedTransactionIntentBody,
        };
        let tenant = self
            .governed_approval_tenant
            .as_deref()
            .ok_or_else(|| denied("approval policy is not configured"))?;
        if self.governed_approvers.is_empty() {
            return Err(denied("approval roster is empty"));
        }
        let now = self.read_authority_time()?.get() / 1000;
        self.verify_capability_full_pre_admit(&request.capability, None, now)
            .map_err(|error| denied(&error))?;
        check_subject_binding(&request.capability, &request.agent_id)?;
        if self.is_capability_revoked(&request.capability.id)? {
            return Err(denied("approval capability is revoked"));
        }
        for ancestor in &request.capability.delegation_chain {
            if self.is_capability_revoked(&ancestor.capability_id)? {
                return Err(denied("approval capability ancestor is revoked"));
            }
        }
        resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        let mut intent =
            request
                .governed_intent
                .clone()
                .unwrap_or_else(|| GovernedTransactionIntent {
                    id: request.request_id.clone(),
                    server_id: request.server_id.clone(),
                    tool_name: request.tool_name.clone(),
                    purpose: "approve exact tool invocation".into(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    runtime_attestation: None,
                    call_chain: None,
                    autonomy: None,
                    context: None,
                    body: GovernedTransactionIntentBody::ToolInvocation,
                });
        if intent.server_id != request.server_id
            || intent.tool_name != request.tool_name
            || matches!(
                intent.body,
                GovernedTransactionIntentBody::ActiveResponsePlan(_)
            )
        {
            return Err(denied("approval intent does not name this tool invocation"));
        }
        ToolApprovalContext::bind(
            &mut intent,
            &request.capability,
            &request.arguments,
            &request.request_id,
            &self.config.policy_hash,
            tenant,
        )?;
        Ok(intent)
    }

    pub(super) fn validate_tool_approval_context(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let tenant = self
            .governed_approval_tenant
            .as_deref()
            .ok_or_else(|| denied("approval policy is not configured"))?;
        let intent = request
            .governed_intent
            .as_ref()
            .ok_or_else(|| denied("approval requires a governed tool intent"))?;
        ToolApprovalContext::verify(
            intent,
            cap,
            &request.arguments,
            &request.request_id,
            &self.config.policy_hash,
            tenant,
        )
    }
}

fn denied(message: &str) -> KernelError {
    KernelError::GovernedTransactionDenied(message.to_owned())
}
