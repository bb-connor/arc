//! Stable admission identity, not a dispatch permit or a flow-state snapshot.

use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use serde::{Deserialize, Serialize};

use super::invalid;
use crate::admission_operation::{
    AdmissionOperationStoreError, NativeSecurityAuthorityBindingV1, I_JSON_MAX_SAFE_INTEGER,
};
use crate::SecurityInvocationContext;

const SCHEMA: &str = "chio.admission-security-binding.v1";
const NATIVE_SCHEMA: &str = "chio.admission-security-binding.v2";

/// Historical data derived only from trusted invocation context and kernel
/// configuration at begin. Decoding this record does not authenticate it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionSecurityBindingV1 {
    schema: String,
    context: Option<StableSecurityContextV1>,
    pre_dispatch_required: bool,
    pre_dispatch_hook_installed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_authority: Option<NativeSecurityAuthorityBindingV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableSecurityContextV1 {
    tenant_id: TenantId,
    session_id: SessionId,
    principal_id: PrincipalId,
    isolation_epoch_id: IsolationEpochId,
    lineage_root_id: LineageId,
    context_generation: u64,
}

impl AdmissionSecurityBindingV1 {
    pub(crate) fn matches_requirements(
        &self,
        required: bool,
        hook_installed: bool,
        native_authority: Option<&NativeSecurityAuthorityBindingV1>,
    ) -> bool {
        self.pre_dispatch_required == required
            && self.pre_dispatch_hook_installed == hook_installed
            && self.native_authority.as_ref() == native_authority
    }

    pub(crate) fn native_authority(&self) -> Option<&NativeSecurityAuthorityBindingV1> {
        self.native_authority.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn from_trusted_context(
        context: Option<&SecurityInvocationContext>,
        pre_dispatch_required: bool,
        pre_dispatch_hook_installed: bool,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::from_trusted_selection(
            context,
            pre_dispatch_required,
            pre_dispatch_hook_installed,
            None,
        )
    }

    pub(crate) fn from_trusted_selection(
        context: Option<&SecurityInvocationContext>,
        pre_dispatch_required: bool,
        pre_dispatch_hook_installed: bool,
        native_authority: Option<NativeSecurityAuthorityBindingV1>,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        if context.is_none()
            && !pre_dispatch_required
            && !pre_dispatch_hook_installed
            && native_authority.is_none()
        {
            // Preserve the exact established v1 hash for unbound operations.
            return Ok(None);
        }
        let binding = Self {
            schema: if native_authority.is_some() {
                NATIVE_SCHEMA
            } else {
                SCHEMA
            }
            .into(),
            context: context.map(|context| {
                let context = context.as_v1();
                StableSecurityContextV1 {
                    tenant_id: context.tenant_id().clone(),
                    session_id: context.session_id().clone(),
                    principal_id: context.principal_id().clone(),
                    isolation_epoch_id: context.isolation_epoch_id().clone(),
                    lineage_root_id: context.lineage_root_id().clone(),
                    context_generation: context.context_generation(),
                    // Flow generation is a mutable observation, deliberately
                    // not a stable identity. Dispatch must check it live.
                }
            }),
            pre_dispatch_required,
            pre_dispatch_hook_installed,
            native_authority,
        };
        binding.validate()?;
        Ok(Some(binding))
    }

    pub(super) fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        let expected_schema = if self.native_authority.is_some() {
            NATIVE_SCHEMA
        } else {
            SCHEMA
        };
        if self.schema != expected_schema
            || (self.native_authority.is_some()
                && (self.context.is_none()
                    || !self.pre_dispatch_required
                    || !self.pre_dispatch_hook_installed))
            || (self.context.is_none()
                && !self.pre_dispatch_required
                && !self.pre_dispatch_hook_installed)
            || self.context.as_ref().is_some_and(|context| {
                context.context_generation == 0
                    || context.context_generation > I_JSON_MAX_SAFE_INTEGER
            })
        {
            return Err(invalid("invalid stable admission security binding"));
        }
        Ok(())
    }
}
