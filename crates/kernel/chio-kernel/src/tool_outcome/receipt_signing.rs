//! Retained public signing selection, never a signing permit or private key.

use super::*;
use chio_core::crypto::SigningAlgorithm;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReceiptSigningIdentityV1 {
    public_key: PublicKey,
    crypto_floor: ReceiptCryptoFloor,
}

impl FrozenReceiptSigningIdentityV1 {
    pub(crate) fn new(
        public_key: PublicKey,
        crypto_floor: ReceiptCryptoFloor,
    ) -> Result<Self, ToolOutcomeError> {
        let identity = Self {
            public_key,
            crypto_floor,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn validate(&self) -> Result<(), ToolOutcomeError> {
        let permitted = match self.public_key.algorithm() {
            SigningAlgorithm::Hybrid => self.crypto_floor.allows_hybrid(),
            SigningAlgorithm::Ed25519 | SigningAlgorithm::P256 | SigningAlgorithm::P384 => {
                self.crypto_floor.allows_classical_only()
            }
        };
        if !permitted {
            return Err(ToolOutcomeError::Binding("raw.receipt_signing_floor"));
        }
        Ok(())
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn crypto_floor(&self) -> ReceiptCryptoFloor {
        self.crypto_floor
    }
}

impl RawInvocationOutcomeV1 {
    pub(crate) fn with_receipt_signing_identity(
        mut self,
        identity: FrozenReceiptSigningIdentityV1,
    ) -> Result<Self, ToolOutcomeError> {
        identity.validate()?;
        if self.request_canonical_json.is_none() {
            return Err(ToolOutcomeError::Binding("raw.receipt_signing_request"));
        }
        self.requires_security_release()?;
        self.receipt_signing_identity = Some(identity);
        self.schema = if self.caller_delivery_evidence.is_some() {
            RAW_INVOCATION_OUTCOME_WITH_CALLER_DELIVERY_SCHEMA
        } else {
            RAW_INVOCATION_OUTCOME_WITH_SIGNING_IDENTITY_SCHEMA
        };
        self.canonical_blob()?;
        Ok(self)
    }

    pub(crate) fn receipt_signing_identity(&self) -> Option<&FrozenReceiptSigningIdentityV1> {
        self.receipt_signing_identity.as_ref()
    }
}

/// Reserved for the kernel's private captured-effect settlement attestation.
/// A caller or hook cannot supply this receipt metadata block.
pub const PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY: &str = "chio_recovery_private_settlement";

/// Signed historical facts, never dispatch, result delivery or signing authority.
/// The kernel constructs this only after authenticating the original capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRecoverySettlementReceiptV1 {
    schema: PrivateSettlementSchema,
    disposition: PrivateSettlementDisposition,
    original_signing_identity: FrozenReceiptSigningIdentityV1,
    settlement_signing_identity: FrozenReceiptSigningIdentityV1,
    operation_id: AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    source_operation_version: u64,
    raw_output_digest: AdmissionDigest,
    captured_deployment_digest: chio_security_types::recovery::DeploymentDigest,
    store_fence: StoreMutationFence,
    historical_signing_hold: Option<crate::recovery::RecoveryHistoricalHoldV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum PrivateSettlementSchema {
    #[serde(rename = "chio.recovery.private-settlement-receipt.v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum PrivateSettlementDisposition {
    #[serde(rename = "permanently_withheld")]
    PermanentlyWithheld,
}

impl PrivateRecoverySettlementReceiptV1 {
    pub(crate) fn prepare(
        operation: &AdmissionOperationV1,
        raw: &RawInvocationOutcomeV1,
        settlement_signing_identity: FrozenReceiptSigningIdentityV1,
        captured_deployment_digest: chio_security_types::recovery::DeploymentDigest,
        store_fence: StoreMutationFence,
        historical_signing_hold: Option<crate::recovery::RecoveryHistoricalHoldV1>,
    ) -> Result<Self, ToolOutcomeError> {
        if operation.state() != AdmissionOperationState::Finalizing {
            return Err(ToolOutcomeError::Binding("private_settlement.state"));
        }
        let value = Self {
            schema: PrivateSettlementSchema::V1,
            disposition: PrivateSettlementDisposition::PermanentlyWithheld,
            original_signing_identity: raw.receipt_signing_identity().cloned().ok_or(
                ToolOutcomeError::Binding("private_settlement.original_signer"),
            )?,
            settlement_signing_identity,
            operation_id: operation.binding().operation_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            source_operation_version: operation.version(),
            raw_output_digest: raw.canonical_blob()?.blob_ref().digest().clone(),
            captured_deployment_digest,
            store_fence,
            historical_signing_hold,
        };
        value.validate_identities()?;
        Ok(value)
    }

    /// Decode only signed data. Physical ownership must be verified by the caller.
    pub fn from_receipt(
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<Option<Self>, ToolOutcomeError> {
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(PRIVATE_RECOVERY_SETTLEMENT_METADATA_KEY))
            .map(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|_| ToolOutcomeError::Binding("private_settlement.metadata"))
            })
            .transpose()
    }

    fn validate_identities(&self) -> Result<(), ToolOutcomeError> {
        self.original_signing_identity.validate()?;
        self.settlement_signing_identity.validate()?;
        if self.historical_signing_hold.as_ref().is_some_and(|hold| {
            hold.reason != crate::recovery::RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
        }) || (self.original_signing_identity.public_key()
            == self.settlement_signing_identity.public_key()
            && self.historical_signing_hold.is_none())
        {
            return Err(ToolOutcomeError::Binding("private_settlement.signing_reason"));
        }
        Ok(())
    }

    /// Check the marker against independently authenticated physical originals
    /// and the actual terminal projection fence, not current deployment bytes.
    pub fn validate_receipt(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
        operation: &AdmissionOperationV1,
        outcome: &ToolOutcomeRecordV1,
        captured_deployment_digest: chio_security_types::recovery::DeploymentDigest,
        current_fence: &StoreMutationFence,
        historical_signing_hold: Option<&crate::recovery::RecoveryHistoricalHoldV1>,
    ) -> Result<(), ToolOutcomeError> {
        self.validate_identities()?;
        let source_version = match operation.state() {
            AdmissionOperationState::Finalizing => Some(operation.version()),
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery => {
                operation.version().checked_sub(1)
            }
            _ => None,
        };
        let admission: crate::admission_operation::AdmissionReceiptMetadataV1 = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.get(crate::admission_operation::ADMISSION_RECEIPT_METADATA_KEY)
            })
            .cloned()
            .ok_or(ToolOutcomeError::Binding("private_settlement.admission"))
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|_| ToolOutcomeError::Binding("private_settlement.admission"))
            })?;
        if Self::from_receipt(receipt)?.as_ref() != Some(self)
            || self.operation_id != *operation.binding().operation_id()
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || source_version != Some(self.source_operation_version)
            || self.raw_output_digest != *outcome.raw_output_digest()
            || self.captured_deployment_digest != captured_deployment_digest
            || self.historical_signing_hold.as_ref() != historical_signing_hold
            || self.store_fence != admission.store_fence
            || self.store_fence.store_uuid != current_fence.store_uuid
            || self.store_fence.owner_epoch > current_fence.owner_epoch
            || operation.dispatch_commit().is_none_or(|capture| {
                capture.store_fence.store_uuid != self.store_fence.store_uuid
                    || capture.store_fence.owner_epoch > self.store_fence.owner_epoch
            })
            || receipt.kernel_key != *self.settlement_signing_identity.public_key()
            || !receipt
                .verify_signature_with_floor(self.settlement_signing_identity.crypto_floor())
                .map_err(|_| ToolOutcomeError::Binding("private_settlement.signature"))?
        {
            return Err(ToolOutcomeError::Binding(
                "private_settlement.original_custody",
            ));
        }
        outcome.validate_against(operation)
    }

    pub fn validate_raw(&self, raw: &RawInvocationOutcomeV1) -> Result<(), ToolOutcomeError> {
        if raw.receipt_signing_identity() != Some(&self.original_signing_identity)
            || raw.canonical_blob()?.blob_ref().digest() != &self.raw_output_digest
        {
            return Err(ToolOutcomeError::Binding(
                "private_settlement.original_return",
            ));
        }
        Ok(())
    }

    /// Validate a known completed provider return bound to this exact marker.
    /// This authenticates signed data and does not grant settlement authority.
    pub fn validate_completed_raw_return(
        &self,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<(), ToolOutcomeError> {
        self.validate_raw(raw)?;
        if !matches!(
            raw.output(),
            InvocationOutputV1::Value { .. } | InvocationOutputV1::CompleteStream { .. }
        ) {
            return Err(ToolOutcomeError::Binding(
                "private_settlement.completed_return",
            ));
        }
        Ok(())
    }
}
