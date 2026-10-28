//! Host-selected semantic roots, exposure and native bindings.
use chio_core::recovery::{
    semantic_content_digest, SignedSemanticDeploymentV1, SignedSemanticPackageV1,
};
use chio_core::PublicKey;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::recovery::recovery_flow_key;
use chio_kernel::SecurityInvocationContext;
use chio_security_types::recovery::{
    AuthorityDomainId, NonEmptyBoundedList, RecoveryScopeV1, MAX_RECOVERY_VERIFICATION_WORK,
};
use chio_security_types::work::VerificationBudget;
use chio_semantic_contracts::{
    compile_semantic_registry, CompiledSemanticRegistryV1, ExposedSemanticToolV1,
};
use serde::{Deserialize, Serialize};

use super::{invariant, AdmissionOperationStoreError};

/// Trusted operator input binds signed contracts to the host's actual exposure.
/// Publisher signatures cannot select the native authority or operator roots.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSemanticInstallation {
    pub deployment: SignedSemanticDeploymentV1,
    pub packages: NonEmptyBoundedList<SignedSemanticPackageV1, 16>,
    pub operator_root: PublicKey,
    pub publisher_roots: NonEmptyBoundedList<PublicKey, 16>,
    pub exposed: NonEmptyBoundedList<ExposedSemanticToolV1, 16>,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub security_context: SecurityInvocationContext,
}

impl std::fmt::Debug for NativeSemanticInstallation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeSemanticInstallation([redacted])")
    }
}

impl NativeSemanticInstallation {
    pub(super) fn validate_binding(
        &self,
        domain: &AuthorityDomainId,
    ) -> Result<(), AdmissionOperationStoreError> {
        let body = self.deployment.body();
        if body.scope.authority_domain != *domain
            || self.native_authority.store_uuid().as_str() != domain.as_str()
            || body.scope.tenant_id.as_str() != self.security_context.as_v1().tenant_id().as_str()
        {
            return Err(invariant("semantic deployment scope differs"));
        }
        let native = semantic_content_digest(&self.native_authority)
            .map_err(|_| invariant("semantic native binding digest refused"))?;
        if body.native_binding != native {
            return Err(invariant("semantic deployment native binding differs"));
        }
        let context = semantic_content_digest(&(
            recovery_flow_key(&self.security_context),
            self.security_context.as_v1().context_generation(),
        ))
        .map_err(|_| invariant("semantic context binding digest refused"))?;
        if body.context_binding != context {
            return Err(invariant("semantic deployment context binding differs"));
        }
        Ok(())
    }

    pub(super) fn compile(
        &self,
        expected_scope: &RecoveryScopeV1,
    ) -> Result<CompiledSemanticRegistryV1, AdmissionOperationStoreError> {
        let mut budget = VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)
            .map_err(|_| invariant("semantic verification budget refused"))?;
        compile_semantic_registry(
            &self.deployment,
            expected_scope,
            self.packages.as_slice(),
            &self.operator_root,
            self.publisher_roots.as_slice(),
            self.exposed.as_slice(),
            &mut budget,
        )
        .map_err(|_| invariant("semantic deployment registry refused"))
    }
}
