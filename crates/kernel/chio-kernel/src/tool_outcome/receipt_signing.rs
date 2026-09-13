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
