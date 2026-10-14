//! Current signing attests private settlement of an authenticated captured return.
//! The original identity remains immutable evidence and never grants new access.
use super::*;
use crate::tool_outcome::{
    FrozenReceiptSigningIdentityV1, PrivateRecoverySettlementReceiptV1,
    PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY,
};

impl ChioKernel {
    pub(super) fn select_captured_settlement_signer(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        returned: &DurableToolReturn,
        live_release_owner: bool,
    ) -> Result<
        (
            FrozenReceiptSigningIdentityV1,
            Option<PrivateRecoverySettlementReceiptV1>,
        ),
        KernelError,
    > {
        let original_signer = self.durable_return_signing_identity(&returned.raw)?;
        let current_signer = self.freeze_receipt_signing_identity()?;
        let historical = self.captured_recovery_deployment(&admission.operation)?;
        let Some(RecoveryCapturedDeploymentV1::Verified(profile)) = historical else {
            self.require_original_receipt_signer(&original_signer)?;
            return Ok((original_signer, None));
        };
        let runtime = self.durable_runtime()?;
        let port = runtime.store.recovery_authority().ok_or_else(|| {
            KernelError::DurableAdmission("captured settlement authority disappeared".into())
        })?;
        let record = port
            .historical_release(
                admission.operation.binding().operation_id(),
                &runtime.fence,
                runtime.refresh_trusted_time(current_unix_timestamp_ms()),
            )
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("captured settlement original absent".into())
            })?;
        if original_signer.public_key() == current_signer.public_key()
            && record.historical_hold.is_none()
        {
            self.require_original_receipt_signer(&original_signer)?;
            return Ok((original_signer, None));
        }
        if live_release_owner {
            return Err(KernelError::DurableAdmission(
                "private historical settlement cannot replace a live release owner".into(),
            ));
        }
        // Validate the retained return before selecting current signing. The
        // physical store port independently authenticated capture, grant roots
        // and any exact historical signing hold under this serving fence.
        self.frozen_recovery_signer_unavailable(admission)?;
        let original = admission.original_retained_request().ok_or_else(|| {
            KernelError::DurableAdmission("captured settlement original request absent".into())
        })?;
        original
            .validate_binding(admission.operation.binding())
            .and_then(|()| original.validate_request_material(request))
            .and_then(|()| original.validate_native_security_authority(&profile.native_authority))
            .and_then(|()| original.validate_native_security_context(&profile.security_context))
            .map_err(durable_store_error)?;
        let captured_digest = chio_security_types::recovery::DeploymentDigest::from_bytes(
            crate::recovery::recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::Deployment,
                profile.as_ref(),
            )?,
        );
        if captured_digest != record.deployment_digest {
            return Err(KernelError::DurableAdmission(
                "captured settlement deployment differs from original custody".into(),
            ));
        }
        self.require_original_receipt_signer(&current_signer)?;
        let settlement = PrivateRecoverySettlementReceiptV1::prepare(
            &admission.operation,
            &returned.raw,
            current_signer.clone(),
            captured_digest,
            runtime.fence.clone(),
            record.historical_hold,
        )
        .map_err(tool_outcome_error)?;
        Ok((current_signer, Some(settlement)))
    }

    pub(super) fn attach_private_settlement_metadata(
        &self,
        metadata: Option<serde_json::Value>,
        settlement: Option<&PrivateRecoverySettlementReceiptV1>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        if metadata.as_ref().is_some_and(|metadata| {
            metadata
                .get(PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY)
                .is_some()
        }) {
            return Err(KernelError::DurableAdmission(
                "caller or hook metadata carries a reserved private settlement block".into(),
            ));
        }
        Ok(match settlement {
            Some(settlement) => merge_metadata_objects(
                metadata,
                Some(serde_json::json!({PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY: settlement})),
            ),
            None => metadata,
        })
    }

    /// This signed disposition is permanent, even if an old signer is restored.
    pub(in crate::kernel::admission_coordinator) fn require_no_historical_settlement_delivery(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), KernelError> {
        if PrivateRecoverySettlementReceiptV1::from_receipt(receipt)
            .map_err(tool_outcome_error)?
            .is_some()
        {
            return Err(KernelError::RecoveryAuthorityDenied);
        }
        Ok(())
    }
}
