//! Explicit shared-family issuance through the installed authority.

use super::*;

impl ChioKernel {
    /// Issue a root whose descendants share one authoritative invocation limit.
    /// This requires the durable admission coordinator for every tool call.
    /// Tenant-bound issuance remains unavailable through this context-free API.
    pub fn issue_aggregate_family_root(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        max_invocations: u32,
    ) -> Result<CapabilityToken, KernelError> {
        if self.capability_issuance_admission_authority.is_some() {
            return Err(KernelError::CapabilityIssuanceDenied(
                "authoritative tenant and lineage context is required for capability issuance"
                    .into(),
            ));
        }
        if self.durable_admission_mode() != crate::admission_operation::DurableAdmissionMode::All
            || self.durable_admission_store_uuid().is_none()
        {
            return Err(KernelError::CapabilityIssuanceDenied(
                "aggregate family-root issuance requires qualified durable admission for all calls"
                    .into(),
            ));
        }
        crate::ensure_capability_issuance_supported(&scope)?;
        let capability = self.capability_authority.issue_aggregate_family_root(
            subject,
            scope.clone(),
            ttl_seconds,
            max_invocations,
        )?;
        crate::authority::validate_issued_aggregate_family_root_response(
            &capability,
            subject,
            &scope,
            ttl_seconds,
            &self.capability_authority.authority_public_key(),
            max_invocations,
        )?;
        self.record_observed_capability_snapshot(&capability)?;
        Ok(capability)
    }
}
