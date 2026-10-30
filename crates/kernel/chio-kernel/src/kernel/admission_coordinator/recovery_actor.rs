//! Recovery operator authentication against the installed deployment, the
//! live native binding, the configured policy and the effect contract of the
//! currently registered recovery server. Authentication does not dispatch,
//! charge recovery budget or mutate recovery records.

use super::*;
use crate::kernel::validation::CapabilityPreAdmissionError;
use crate::recovery::{
    recovery_digest, AuthenticatedRecoveryActor, RecoveryDeploymentV1, RecoveryPermission,
    RecoveryToolServerConnection,
};
use chio_core_types::capability::scope::Operation;
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::recovery::RecoveryDigestDomain;
use chio_security_types::recovery::{DeploymentDigest, PolicyDigest, RecoveryScopeV1};

const RECOVERY_SERVER_ID: &str = "chio.recovery";

fn unsupported() -> KernelError {
    KernelError::DurableAdmission("native recovery profile is unsupported".into())
}

/// Closed issuer, scope and cryptographic policy refusals deny the actor.
/// Backend and internal failures remain operational.
fn capability_refusal(error: CapabilityPreAdmissionError) -> KernelError {
    use chio_kernel_core::{BudgetSplitError, CapabilityError};
    match error {
        CapabilityPreAdmissionError::IssuerLifecycle(KernelError::UntrustedIssuer)
        | CapabilityPreAdmissionError::Issuance(KernelError::InvalidConstraint(_)) => {
            KernelError::RecoveryAuthorityDenied
        }
        CapabilityPreAdmissionError::Verification(
            CapabilityError::UntrustedIssuer
            | CapabilityError::InvalidSignature
            | CapabilityError::CryptoFloorRejected(_)
            | CapabilityError::NotYetValid
            | CapabilityError::Expired
            | CapabilityError::AttenuationViolation(_)
            | CapabilityError::DelegationRootMismatch
            | CapabilityError::BudgetSplitRejected(
                BudgetSplitError::ChildShareExceedsCap { .. }
                | BudgetSplitError::OversubscribedSiblings { .. },
            ),
        ) => KernelError::RecoveryAuthorityDenied,
        CapabilityPreAdmissionError::Verification(_)
        | CapabilityPreAdmissionError::IssuerLifecycle(_)
        | CapabilityPreAdmissionError::Issuance(_)
        | CapabilityPreAdmissionError::Preparation(_) => {
            KernelError::Internal("recovery capability authentication unavailable".into())
        }
    }
}

fn policy_hex(digest: &PolicyDigest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Every grant naming the permission, directly or by wildcard, must be the
/// exact unconstrained `chio.recovery` invocation grant of that permission.
fn recovery_grant_permits(capability: &CapabilityToken, permission: RecoveryPermission) -> bool {
    let wire = permission.wire_name();
    let mut matching = capability
        .scope
        .grants
        .iter()
        .filter(|grant| {
            (grant.server_id == RECOVERY_SERVER_ID || grant.server_id == "*")
                && (grant.tool_name == wire || grant.tool_name == "*")
        })
        .peekable();
    matching.peek().is_some()
        && matching.all(|grant| {
            grant.server_id == RECOVERY_SERVER_ID
                && grant.tool_name == wire
                && grant.constraints.is_empty()
                && grant.max_invocations.is_none()
                && grant.max_cost_per_invocation.is_none()
                && grant.max_total_cost.is_none()
                && grant.dpop_required != Some(true)
                && grant.operations.contains(&Operation::Invoke)
        })
}

impl ChioKernel {
    /// Authenticate one recovery permission of `capability` against the
    /// installed deployment of `scope`. Full capability verification,
    /// revocation, the current assignment and the deployment bindings are
    /// checked on every call.
    pub fn authenticate_recovery_actor(
        &self,
        scope: &RecoveryScopeV1,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, KernelError> {
        let now = self.read_authority_time()?.as_secs();
        // Recovery control has its own durable quotas and no native invocation
        // or sender-proof admission, so it refuses tokens that require those
        // stateful enforcement paths.
        if capability.aggregate_invocation_budget.is_some()
            || capability.budget_share_bps.is_some()
            || !capability.delegation_chain.is_empty()
            || !capability.caveats.is_empty()
            || capability.scope_attenuations.is_some()
            || capability.attenuation_proof.is_some()
        {
            return Err(KernelError::RecoveryAuthorityDenied);
        }
        self.verify_capability_full_pre_admit_typed(capability, None, now)
            .map_err(capability_refusal)?;
        if self.is_capability_revoked(&capability.id)? {
            return Err(KernelError::RecoveryAuthorityDenied);
        }
        let (deployment, server) = self.current_recovery_deployment(scope)?;
        let assignment = deployment
            .actors
            .as_slice()
            .iter()
            .find(|actor| {
                actor.subject == capability.subject
                    && actor.permissions.as_slice().contains(&permission)
            })
            .ok_or(KernelError::RecoveryAuthorityDenied)?;
        if !recovery_grant_permits(capability, permission) {
            return Err(KernelError::RecoveryAuthorityDenied);
        }
        let digest = recovery_digest(RecoveryDigestDomain::Deployment, &deployment)
            .map_err(KernelError::RecoveryEncoding)?;
        Ok(AuthenticatedRecoveryActor {
            scope: scope.clone(),
            principal: assignment.principal.clone(),
            capability: capability.clone(),
            permission,
            deployment: DeploymentDigest::from_bytes(digest),
            server,
        })
    }

    /// Repeat full authentication and require the same principal, the same
    /// installed deployment and the same registered recovery connection.
    pub fn revalidate_recovery_actor(
        &self,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<(), KernelError> {
        let current =
            self.authenticate_recovery_actor(&actor.scope, &actor.capability, actor.permission)?;
        if current.principal != actor.principal
            || current.deployment != actor.deployment
            || !std::ptr::addr_eq(Arc::as_ptr(&current.server), Arc::as_ptr(&actor.server))
        {
            return Err(KernelError::RecoveryAuthorityDenied);
        }
        Ok(())
    }

    /// The installed deployment of `scope`, read through this kernel's serving
    /// fence and trusted time, with the recovery connection that currently
    /// serves its effect.
    fn current_recovery_deployment(
        &self,
        scope: &RecoveryScopeV1,
    ) -> Result<(RecoveryDeploymentV1, Arc<dyn RecoveryToolServerConnection>), KernelError> {
        let runtime = self.durable_runtime()?;
        let port = runtime
            .store
            .recovery_deployment_port()
            .ok_or_else(unsupported)?;
        if scope.authority_domain.as_str() != runtime.fence.store_uuid {
            return Err(unsupported());
        }
        let now = runtime.refresh_trusted_time(0)?;
        let deployment = port
            .deployment(scope, &runtime.fence, now)
            .map_err(durable_store_error)?;
        let server = self
            .registered_recovery_tool_server(deployment.server_id.as_str())
            .ok_or_else(unsupported)?;
        if self.native_security_authority_binding()?.as_ref() != Some(&deployment.native_authority)
            || self.config.policy_hash != policy_hex(&deployment.policy_digest)
            || server.recovery_effect_contract() != deployment.effect_contract
        {
            return Err(unsupported());
        }
        Ok((deployment, server))
    }
}
