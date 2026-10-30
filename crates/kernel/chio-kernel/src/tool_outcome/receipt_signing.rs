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
    /// Request equality only. A false result holds raw custody;
    /// the enclosing store must separately verify the retained begin commit.
    pub fn matches_compacted_original_request(
        &self,
        retained: &crate::admission_operation::RetainedToolAdmissionRequestV1,
    ) -> bool {
        self.recovery_request()
            .is_ok_and(|request| retained.validate_request_material(&request).is_ok())
    }

    /// Data-only retention qualification. The fenced store must separately
    /// authenticate the Completed record, original request and sealed evidence.
    /// Signing selections outside the basic profile retain their raw identity material.
    pub fn supports_compacted_value_replay(&self) -> bool {
        let identity = &self.receipt_signing_identity;
        let Ok(request) = self.recovery_request() else {
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
            && self.receipt_signing_identity.public_key == receipt.kernel_key
            && receipt
                .metadata
                .as_ref()
                .is_none_or(compactable_receipt_metadata)
            && receipt
                .verify_signature_with_floor(
                    &self.receipt_signing_identity.public_key,
                    ReceiptCryptoFloor::AllowClassical,
                )
                .is_ok_and(|valid| valid)
    }

    pub(crate) fn receipt_signing_identity(&self) -> &FrozenReceiptSigningIdentityV1 {
        &self.receipt_signing_identity
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
