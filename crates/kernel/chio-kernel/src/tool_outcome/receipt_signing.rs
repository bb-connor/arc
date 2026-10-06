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
    /// Original basic-profile equality with the authenticated admission and
    /// evaluation. No profile or retained-request row is invented. The caller
    /// must require an actually NULL begin participant digest for this path.
    pub fn matches_unprofiled_compacted_admission(
        &self,
        operation: &AdmissionOperationV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> bool {
        let Ok(Some(request)) = self.recovery_request() else {
            return false;
        };
        let Ok(matching) = crate::request_matching::resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) else {
            return false;
        };
        crate::admission_operation::RetainedToolAdmissionRequestV1::validate_request_binding(
            operation.binding(),
            &request,
            &matching,
            evaluation.retained_frozen_steps(),
            None,
            None,
        )
        .is_ok()
    }

    /// Historical request equality only. A false result holds raw custody;
    /// the enclosing store must separately verify the retained begin commit.
    pub fn matches_compacted_original_request(
        &self,
        retained: &crate::admission_operation::RetainedToolAdmissionRequestV1,
    ) -> bool {
        self.recovery_request().is_ok_and(|request| {
            request.is_some_and(|request| retained.validate_request_material(&request).is_ok())
        })
    }

    /// Data-only retention qualification. The fenced store must separately
    /// authenticate the Completed record, original request and sealed evidence.
    /// Missing or richer signing selections keep their raw identity material.
    pub fn supports_compacted_value_replay(&self) -> bool {
        let Some(identity) = &self.receipt_signing_identity else {
            return false;
        };
        let Ok(Some(request)) = self.recovery_request() else {
            return false;
        };
        identity.crypto_floor == ReceiptCryptoFloor::AllowClassical
            && identity.public_key.algorithm() == SigningAlgorithm::Ed25519
            && identity.public_key == request.capability.issuer
            && request.federated_origin_kernel_id.is_none()
            && matches!(self.output, InvocationOutputV1::Value { .. })
            && self.security_invocation_context.is_none()
            && self.requires_security_release() == Ok(false)
            && self.federation_context_json.is_none()
            && self.caller_delivery_evidence.is_none()
            && self
                .receipt_metadata_snapshot
                .as_ref()
                .is_none_or(compactable_receipt_metadata)
    }

    /// A false result holds bytes, including unverifiable receipt evidence.
    /// This predicate supplies no execution, signer or mutation authority.
    pub fn supports_compacted_value_receipt(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> bool {
        self.supports_compacted_value_replay()
            && self
                .receipt_signing_identity
                .as_ref()
                .is_some_and(|identity| identity.public_key == receipt.kernel_key)
            && receipt
                .metadata
                .as_ref()
                .is_none_or(compactable_receipt_metadata)
            && receipt
                .verify_signature_with_floor(ReceiptCryptoFloor::AllowClassical)
                .is_ok_and(|valid| valid)
    }

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
        self.schema = if self.original_security_dispatch_binding.is_some() {
            RAW_INVOCATION_OUTCOME_WITH_ORIGINAL_SECURITY_DISPATCH_SCHEMA
        } else if self.caller_delivery_evidence.is_some() {
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

fn compactable_receipt_metadata(metadata: &Value) -> bool {
    metadata.get("stream").is_none()
        && metadata.get("caller_delivery").is_none()
        && metadata
            .get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
            .is_none()
        && metadata
            .get(crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY)
            .is_none()
}
