//! Receipt identity uses the same authenticated namespace as replay admission.

use super::*;

impl ChioKernel {
    pub(in crate::kernel) fn require_stopped_request_has_no_output(
        &self,
        request_id: &str,
    ) -> Result<(), KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(());
        };
        let namespace = self.authenticated_receipt_namespace(request_id)?;
        let key = crate::admission_operation::AdmissionReplayKey {
            request_namespace_digest: namespace.digest().clone(),
            request_id: AdmissionIdentifier::try_new("request_id", request_id)?,
        };
        let _mutation_guard = runtime.lock_mutations()?;
        if runtime
            .store
            .load_by_replay_key(&key)
            .map_err(durable_store_error)?
            .is_some_and(|operation| {
                matches!(
                    operation.state(),
                    AdmissionOperationState::Finalizing | AdmissionOperationState::Completed
                )
            })
        {
            return Err(KernelError::OutputWithheld);
        }
        Ok(())
    }

    pub(in crate::kernel) fn require_unoccupied_receipt_identity(
        &self,
        request_id: &str,
        namespace: &AuthenticatedRequestNamespace,
    ) -> Result<(), KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(());
        };
        let key = crate::admission_operation::AdmissionReplayKey {
            request_namespace_digest: namespace.digest().clone(),
            request_id: AdmissionIdentifier::try_new("request_id", request_id)?,
        };
        let _mutation_guard = runtime.lock_mutations()?;
        if runtime
            .store
            .load_by_replay_key(&key)
            .map_err(durable_store_error)?
            .is_some()
        {
            return Err(KernelError::DurableAdmission(
                "request identity is already owned by a durable operation".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::kernel) fn authenticated_receipt_namespace(
        &self,
        request_id: &str,
    ) -> Result<AuthenticatedRequestNamespace, KernelError> {
        let authority = self.durable_admission_runtime.as_ref().map_or_else(
            || format!("kernel:{}", self.config.keypair.public_key().to_hex()),
            |runtime| runtime.fence.store_uuid.clone(),
        );
        let authority = AdmissionIdentifier::try_new("coordinator_authority_id", authority)?;
        match self.receipt_tenant_id_for_request(Some(request_id)) {
            Some(tenant) => {
                AuthenticatedRequestNamespace::from_authentication_context(authority, tenant)
            }
            None => AuthenticatedRequestNamespace::for_local_system(authority),
        }
        .map_err(Into::into)
    }

    pub(in crate::kernel) fn receipt_request_namespace_digest(
        &self,
        request_id: &str,
    ) -> Result<String, KernelError> {
        Ok(self
            .authenticated_receipt_namespace(request_id)?
            .digest()
            .as_str()
            .to_owned())
    }
}
