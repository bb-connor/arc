//! Security context binding and the pre-dispatch commitment hook.

use super::*;

const SECURITY_PRE_DISPATCH_GUARD_NAME: &str = "chio-security-pre-dispatch";
const SECURITY_PRE_DISPATCH_MISSING_CONTEXT_REASON: &str =
    "authoritative security context is missing at dispatch";
const SECURITY_PRE_DISPATCH_MISSING_HOOK_REASON: &str =
    "security pre-dispatch hook is not installed";
const SECURITY_PRE_DISPATCH_BINDING_REASON: &str =
    "security pre-dispatch commitment could not be derived";
const SECURITY_PRE_DISPATCH_REJECTION_REASON: &str = "security pre-dispatch hook rejected dispatch";
const SECURITY_DISPATCH_COMMITMENT_DOMAIN: &[u8] =
    b"chio.kernel.security-pre-dispatch.commitment.v2\0";

#[derive(serde::Serialize)]
struct SecurityDispatchContextBinding<'a> {
    schema: &'static str,
    context_version: u16,
    tenant_id: &'a str,
    session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    lineage_root_id: &'a str,
    context_generation: u64,
    flow_state_generation: Option<u64>,
}

fn security_pre_dispatch_denial(reason: &'static str) -> SecurityPreDispatchDenial {
    SecurityPreDispatchDenial {
        reason,
        evidence: GuardEvidence {
            guard_name: SECURITY_PRE_DISPATCH_GUARD_NAME.to_string(),
            verdict: false,
            details: Some(reason.to_string()),
        },
    }
}

pub(crate) fn derive_security_dispatch_commitment_id(
    canonical_request: &[u8],
    security_context: &SecurityInvocationContext,
) -> Result<chio_security_types::ports::RecordId, KernelError> {
    let context = security_context.as_v1();
    let binding = SecurityDispatchContextBinding {
        schema: "chio.kernel.security-dispatch-context.v2",
        context_version: security_context.version(),
        tenant_id: context.tenant_id().as_str(),
        session_id: context.session_id().as_str(),
        principal_id: context.principal_id().as_str(),
        isolation_epoch_id: context.isolation_epoch_id().as_str(),
        lineage_root_id: context.lineage_root_id().as_str(),
        context_generation: context.context_generation(),
        flow_state_generation: context.flow_state_generation(),
    };
    let canonical_context = canonical_json_bytes(&binding).map_err(|error| {
        KernelError::Internal(format!(
            "failed to canonicalize security dispatch context: {error}"
        ))
    })?;
    let request_len = u64::try_from(canonical_request.len()).map_err(|_| {
        KernelError::Internal("canonical security dispatch request is too large".to_string())
    })?;
    let context_len = u64::try_from(canonical_context.len()).map_err(|_| {
        KernelError::Internal("canonical security dispatch context is too large".to_string())
    })?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SECURITY_DISPATCH_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&request_len.to_be_bytes());
    preimage.extend_from_slice(canonical_request);
    preimage.extend_from_slice(&context_len.to_be_bytes());
    preimage.extend_from_slice(&canonical_context);
    chio_security_types::ports::RecordId::new(format!(
        "dispatch-commitment:{}",
        sha256_hex(&preimage)
    ))
    .map_err(|error| {
        KernelError::Internal(format!(
            "failed to construct security dispatch commitment identifier: {error}"
        ))
    })
}

impl ChioKernel {
    /// Bind trusted-host security state to the request before any admission
    /// mutation or connector side effect.
    pub(crate) fn validate_security_invocation_context_binding(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
        authenticated_session_id: Option<&SessionId>,
    ) -> Result<(), KernelError> {
        let capability_binding = request.capability.security_binding().map_err(|error| {
            KernelError::GuardDenied(format!("capability security binding is invalid: {error}"))
        })?;
        let expected_workload = self.capability_authority.workload_binding();
        let Some(security_context) = security_context else {
            if capability_binding.is_some() || expected_workload.is_some() {
                return Err(KernelError::GuardDenied(
                    "security-bound capability requires an authoritative invocation context"
                        .to_string(),
                ));
            }
            return Ok(());
        };
        let context = security_context.as_v1();
        if context.context_generation() == 0 {
            return Err(KernelError::GuardDenied(
                "authoritative security context generation must be positive".to_string(),
            ));
        }
        if context.principal_id().as_str() != request.agent_id.as_str() {
            return Err(KernelError::GuardDenied(
                "authoritative security context principal does not match the request agent"
                    .to_string(),
            ));
        }
        let expected_lineage_root = capability_binding.as_ref().map_or_else(
            || {
                request
                    .capability
                    .delegation_chain
                    .first()
                    .map_or(request.capability.id.as_str(), |link| {
                        link.capability_id.as_str()
                    })
            },
            |binding| binding.lineage_id.as_str(),
        );
        if context.lineage_root_id().as_str() != expected_lineage_root {
            return Err(KernelError::GuardDenied(
                "authoritative security context lineage root does not match the request capability"
                    .to_string(),
            ));
        }
        if authenticated_session_id
            .is_some_and(|session_id| context.session_id().as_str() != session_id.as_str())
        {
            return Err(KernelError::GuardDenied(
                "authoritative security context does not match the authenticated session"
                    .to_string(),
            ));
        }
        match (capability_binding.as_ref(), expected_workload.as_ref()) {
            (Some(binding), Some(workload)) => {
                if binding.tenant_id != context.tenant_id().as_str()
                    || binding.lineage_id != context.lineage_root_id().as_str()
                    || binding.session_id != context.session_id().as_str()
                    || binding.principal_id != context.principal_id().as_str()
                    || binding.isolation_epoch_id != context.isolation_epoch_id().as_str()
                    || binding.context_generation != context.context_generation()
                    || binding.tenant_id != workload.tenant_id
                    || binding.workload_id != workload.workload_id
                    || binding.server_id != workload.server_id
                    || binding.workload_signer_public_key != workload.signer_public_key.to_hex()
                {
                    return Err(KernelError::GuardDenied(
                        "capability security binding does not match the live invocation and pinned workload identity"
                            .to_string(),
                    ));
                }
                if !request.capability.delegation_chain.is_empty() {
                    return Err(KernelError::GuardDenied(
                        "security-bound remote capabilities cannot be delegated".to_string(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(KernelError::GuardDenied(
                    "capability carries a workload binding but no workload authority is pinned"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(KernelError::GuardDenied(
                    "pinned workload authority returned an unbound capability".to_string(),
                ));
            }
            (None, None) => {}
        }
        Ok(())
    }

    pub(crate) fn run_security_pre_dispatch_hook(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<SecurityPreDispatchCommit, SecurityPreDispatchDenial> {
        let Some(security_context) = security_context else {
            return if self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce {
                Err(security_pre_dispatch_denial(
                    SECURITY_PRE_DISPATCH_MISSING_CONTEXT_REASON,
                ))
            } else {
                Ok(SecurityPreDispatchCommit {
                    dispatch_outcome: None,
                    request_lifecycle: None,
                })
            };
        };
        let Some(hook) = self.security_pre_dispatch_hook.as_ref() else {
            return if self.security_pre_dispatch_policy == SecurityPreDispatchPolicy::Enforce {
                Err(security_pre_dispatch_denial(
                    SECURITY_PRE_DISPATCH_MISSING_HOOK_REASON,
                ))
            } else {
                Ok(SecurityPreDispatchCommit {
                    dispatch_outcome: None,
                    request_lifecycle: None,
                })
            };
        };
        let canonical_request = canonical_json_bytes(request).map_err(|error| {
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&error.to_string()),
                "security pre-dispatch request canonicalization failed"
            );
            security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_BINDING_REASON)
        })?;
        let dispatch_commitment_id =
            derive_security_dispatch_commitment_id(&canonical_request, security_context).map_err(
                |error| {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error.to_string()),
                        "security pre-dispatch commitment derivation failed"
                    );
                    security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_BINDING_REASON)
                },
            )?;
        let context = SecurityPreDispatchContext {
            request,
            canonical_request: &canonical_request,
            security_context,
            dispatch_commitment_id: &dispatch_commitment_id,
        };
        let map_rejection = |error: KernelError| {
            warn!(
                request_id = %request.request_id,
                hook = hook.name(),
                reason = %redacted!(&error.to_string()),
                "security pre-dispatch hook rejected dispatch"
            );
            security_pre_dispatch_denial(SECURITY_PRE_DISPATCH_REJECTION_REASON)
        };
        let request_lifecycle = hook
            .acquire_request_lifecycle(&context)
            .map_err(&map_rejection)?;
        let dispatch_outcome = hook.commit(&context).map_err(map_rejection)?;
        Ok(SecurityPreDispatchCommit {
            dispatch_outcome,
            request_lifecycle,
        })
    }
}
