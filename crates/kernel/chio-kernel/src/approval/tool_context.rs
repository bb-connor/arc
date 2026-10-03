//! Current policy and tenant binding for ordinary tool approvals.

use chio_core::capability::governance::{GovernedTransactionIntent, GovernedTransactionIntentBody};
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, sha256, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::KernelError;

const CONTEXT_KEY: &str = "chio_tool_approval";
const SCHEMA: &str = "chio.tool-approval-context.v1";

/// Server-built authority context covered by `GovernedTransactionIntent::binding_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolApprovalContext {
    schema: String,
    tenant_id: String,
    policy_hash: String,
    capability_hash: String,
    request_id: String,
    arguments: serde_json::Value,
}

impl ToolApprovalContext {
    /// Bind an intent after the host has admitted the capability and resolved
    /// its current policy and tenant. Arguments are canonicalized with RFC 8785.
    pub fn bind(
        intent: &mut GovernedTransactionIntent,
        capability: &CapabilityToken,
        arguments: &serde_json::Value,
        request_id: &str,
        policy_hash: &str,
        tenant_id: &str,
    ) -> Result<(), KernelError> {
        let context = Self::new(capability, arguments, request_id, policy_hash, tenant_id)?;
        let arguments = canonical_json_bytes(arguments).map_err(rejected)?;
        let value = intent.context.get_or_insert_with(|| serde_json::json!({}));
        let object = value
            .as_object_mut()
            .ok_or_else(|| rejected("tool approval context must be an object"))?;
        object.insert(
            CONTEXT_KEY.into(),
            serde_json::to_value(context).map_err(rejected)?,
        );
        intent.body = GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: capability.id.clone(),
            parameters_hash: sha256(&arguments),
        };
        Ok(())
    }

    pub(crate) fn verify(
        intent: &GovernedTransactionIntent,
        capability: &CapabilityToken,
        arguments: &serde_json::Value,
        request_id: &str,
        policy_hash: &str,
        tenant_id: &str,
    ) -> Result<(), KernelError> {
        let value = intent
            .context
            .as_ref()
            .and_then(|value| value.get(CONTEXT_KEY))
            .ok_or_else(|| rejected("tool approval is missing current authority context"))?;
        let actual: Self = serde_json::from_value(value.clone()).map_err(rejected)?;
        if actual != Self::new(capability, arguments, request_id, policy_hash, tenant_id)? {
            return Err(rejected(
                "tool approval policy, tenant, capability or request binding changed",
            ));
        }
        Ok(())
    }

    fn new(
        capability: &CapabilityToken,
        arguments: &serde_json::Value,
        request_id: &str,
        policy_hash: &str,
        tenant_id: &str,
    ) -> Result<Self, KernelError> {
        for (name, value) in [
            ("request", request_id),
            ("policy", policy_hash),
            ("tenant", tenant_id),
        ] {
            if value.is_empty()
                || value.len() > 512
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(rejected(format!(
                    "tool approval {name} identity is invalid"
                )));
            }
        }
        Ok(Self {
            schema: SCHEMA.into(),
            tenant_id: tenant_id.into(),
            policy_hash: policy_hash.into(),
            capability_hash: sha256_hex(&canonical_json_bytes(capability).map_err(rejected)?),
            request_id: request_id.into(),
            arguments: arguments.clone(),
        })
    }
}

fn rejected(error: impl std::fmt::Display) -> KernelError {
    KernelError::GovernedTransactionDenied(error.to_string())
}
