//! Capability issuance and response validation share kernel authority time.

use super::{CapabilityToken, ChioKernel, ChioScope, KernelError, SecurityInvocationContext};
use tracing::info;

impl ChioKernel {
    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        if self.capability_issuance_admission_authority.is_some() {
            return Err(KernelError::CapabilityIssuanceDenied(
                "authoritative tenant and lineage context is required for capability issuance"
                    .to_string(),
            ));
        }
        crate::ensure_capability_issuance_supported(&scope)?;
        self.capability_issuance_now()?;
        let capability =
            self.capability_authority
                .issue_capability(subject, scope.clone(), ttl_seconds)?;
        crate::validate_issued_capability_response_at(
            &capability,
            subject,
            &scope,
            ttl_seconds,
            &self.capability_authority.authority_public_key()?,
            self.capability_issuance_now()?,
            crate::authority::DEFAULT_CAPABILITY_ISSUANCE_CLOCK_SKEW_SECONDS,
        )?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            "issuing capability"
        );

        self.record_observed_capability_snapshot(&capability)?;

        Ok(capability)
    }

    /// Issue a capability through the installed tenant and lineage admission authority.
    pub fn issue_capability_with_security_context(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        security_context: &SecurityInvocationContext,
    ) -> Result<CapabilityToken, KernelError> {
        let authority = self
            .capability_issuance_admission_authority
            .as_ref()
            .ok_or_else(|| {
                KernelError::CapabilityIssuanceDenied(
                    "capability issuance admission authority is unavailable".to_string(),
                )
            })?;
        let context = security_context.as_v1();
        if context.context_generation() == 0 || context.principal_id().as_str() != subject.to_hex()
        {
            return Err(KernelError::CapabilityIssuanceDenied(
                "capability issuance context does not bind the requested subject".to_string(),
            ));
        }
        let query = chio_security_types::ports::IssuanceFreezeAdmissionQuery {
            tenant_id: context.tenant_id().clone(),
            lineage_id: context.lineage_root_id().clone(),
            operation: chio_security_types::ports::CapabilityIssuanceOperation::Issue,
            parent_capability_id: None,
        };
        authority.authorize(&query).map_err(|error| {
            KernelError::CapabilityIssuanceDenied(format!(
                "active issuance freeze rejected capability admission: {error}"
            ))
        })?;

        crate::ensure_capability_issuance_supported(&scope)?;
        self.capability_issuance_now()?;
        let issuance_context = crate::CapabilityIssuanceContext::authoritative_session(
            query.tenant_id,
            query.lineage_id,
            context.session_id().clone(),
            context.principal_id().clone(),
            context.isolation_epoch_id().clone(),
            context.context_generation(),
        );
        let workload_binding = self.capability_authority.workload_binding();
        let expected_binding = workload_binding
            .as_ref()
            .map(|workload| crate::capability_security_binding(&issuance_context, workload))
            .transpose()?;
        let capability = self
            .capability_authority
            .issue_capability_with_security_context(
                subject,
                scope.clone(),
                ttl_seconds,
                None,
                &issuance_context,
            )?;
        crate::validate_issued_capability_response_with_binding_at(
            &capability,
            subject,
            &scope,
            ttl_seconds,
            &self.capability_authority.authority_public_key()?,
            self.capability_issuance_now()?,
            crate::authority::DEFAULT_CAPABILITY_ISSUANCE_CLOCK_SKEW_SECONDS,
            expected_binding.as_ref(),
        )?;
        authority
            .authorize(&chio_security_types::ports::IssuanceFreezeAdmissionQuery {
                tenant_id: context.tenant_id().clone(),
                lineage_id: context.lineage_root_id().clone(),
                operation: chio_security_types::ports::CapabilityIssuanceOperation::Issue,
                parent_capability_id: None,
            })
            .map_err(|error| {
                KernelError::CapabilityIssuanceDenied(format!(
                    "active issuance freeze changed before capability publication: {error}"
                ))
            })?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            tenant = %context.tenant_id().as_str(),
            lineage = %context.lineage_root_id().as_str(),
            "issuing security-bound capability"
        );
        self.record_observed_capability_snapshot(&capability)?;
        Ok(capability)
    }

    pub(super) fn validate_delegation_issuance_freeze(
        &self,
        capability: &CapabilityToken,
        parent_capability_id: &str,
        ancestors: &[crate::capability_lineage::CapabilitySnapshot],
    ) -> Result<(), KernelError> {
        use chio_security_types::ports::{
            CapabilityIssuanceOperation, IssuanceFreezeAdmissionQuery, LineageId, RecordId,
            TenantId,
        };
        let denied = |error| {
            KernelError::CapabilityIssuanceDenied(format!(
                "invalid delegated capability security binding: {error}"
            ))
        };
        let binding = capability
            .security_binding()
            .map_err(|error| KernelError::CapabilityIssuanceDenied(error.to_string()))?;
        self.validate_delegation_ancestor_binding(binding.as_ref(), ancestors)?;
        let Some(binding) = binding else {
            if self.capability_issuance_admission_authority.is_some() {
                return Err(KernelError::CapabilityIssuanceDenied(
                    "signed tenant and lineage binding is required for delegation admission".into(),
                ));
            }
            return Ok(());
        };
        let authority = self
            .capability_issuance_admission_authority
            .as_ref()
            .ok_or_else(|| {
                KernelError::CapabilityIssuanceDenied(
                    "delegated capability issuance admission authority is unavailable".into(),
                )
            })?;
        let query = IssuanceFreezeAdmissionQuery {
            tenant_id: TenantId::new(binding.tenant_id).map_err(denied)?,
            lineage_id: LineageId::new(binding.lineage_id).map_err(denied)?,
            operation: CapabilityIssuanceOperation::Delegate,
            parent_capability_id: Some(RecordId::new(parent_capability_id).map_err(denied)?),
        };
        authority.authorize(&query).map_err(|error| {
            KernelError::CapabilityIssuanceDenied(format!(
                "active issuance freeze rejected delegated capability admission: {error}"
            ))
        })
    }

    fn validate_delegation_ancestor_binding(
        &self,
        binding: Option<&chio_core::capability::caveat::CapabilitySecurityBinding>,
        ancestors: &[crate::capability_lineage::CapabilitySnapshot],
    ) -> Result<(), KernelError> {
        let evidence_required =
            binding.is_some() || self.capability_issuance_admission_authority.is_some();
        for ancestor in ancestors.iter().rev() {
            let Some(token) = ancestor.signed_capability.as_ref() else {
                if evidence_required {
                    return Err(KernelError::CapabilityIssuanceDenied(format!(
                        "delegation ancestor {} has no signed tenant and lineage evidence",
                        ancestor.capability_id
                    )));
                }
                continue;
            };
            let Some(ancestor_binding) = token
                .security_binding()
                .map_err(|error| KernelError::CapabilityIssuanceDenied(error.to_string()))?
            else {
                continue;
            };
            match binding {
                Some(binding)
                    if binding.tenant_id == ancestor_binding.tenant_id
                        && binding.lineage_id == ancestor_binding.lineage_id => {}
                Some(_) => {
                    return Err(KernelError::CapabilityIssuanceDenied(format!(
                        "delegated capability tenant and lineage binding differs from ancestor {}",
                        ancestor.capability_id
                    )));
                }
                None => {
                    return Err(KernelError::CapabilityIssuanceDenied(format!(
                        "delegated capability omits the tenant and lineage binding of ancestor {}",
                        ancestor.capability_id
                    )));
                }
            }
        }
        Ok(())
    }

    fn capability_issuance_now(&self) -> Result<u64, KernelError> {
        self.read_authority_time()
            .map(|time| time.as_secs())
            .map_err(Into::into)
    }
}
