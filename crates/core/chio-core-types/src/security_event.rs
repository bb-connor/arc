use alloc::string::ToString;
use alloc::vec::Vec;

use chio_security_types::ports::{ProducerId, RecordId};
use chio_security_types::SecurityEventBody;
use serde::{Deserialize, Serialize};

use crate::{
    canonical_json_bytes, Error, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};

/// Domain separator for independently signed detector provenance.
pub const SECURITY_EVENT_SIGNATURE_DOMAIN: &str = "chio:security-event:v1";

/// Detector-signed security event provenance envelope.
///
/// Deserialization establishes only the wire shape. Callers must invoke
/// [`Self::verify_trusted_producer`] with independently trusted producer
/// identity and key material before treating the body as verified evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSecurityEvent {
    body: SecurityEventBody,
    producer_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

impl SignedSecurityEvent {
    pub fn sign_with_backend(
        body: SecurityEventBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        body.validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        let producer_key = backend.public_key();
        let algorithm = backend.algorithm();
        if producer_key.algorithm() != algorithm {
            return Err(Error::InvalidSignature(
                "security event signing backend algorithm mismatch".into(),
            ));
        }
        let signing_bytes = signing_bytes(&body)?;
        let signature = backend.sign_bytes(&signing_bytes)?;
        if signature.algorithm() != algorithm {
            return Err(Error::InvalidSignature(
                "security event signature algorithm mismatch".into(),
            ));
        }
        Ok(Self {
            body,
            producer_key,
            algorithm,
            signature,
        })
    }

    pub fn verify_trusted_producer(
        &self,
        expected_producer_id: &ProducerId,
        expected_producer_key_id: &RecordId,
        trusted_producer_key: &PublicKey,
    ) -> Result<bool> {
        self.body
            .validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        if &self.body.producer_id != expected_producer_id
            || &self.body.producer_key_id != expected_producer_key_id
            || &self.producer_key != trusted_producer_key
            || self.producer_key.algorithm() != self.algorithm
            || self.signature.algorithm() != self.algorithm
        {
            return Ok(false);
        }
        Ok(self
            .producer_key
            .verify(&signing_bytes(&self.body)?, &self.signature))
    }

    #[must_use]
    pub const fn body(&self) -> &SecurityEventBody {
        &self.body
    }

    #[must_use]
    pub const fn producer_key(&self) -> &PublicKey {
        &self.producer_key
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(&self.body)
    }
}

fn signing_bytes(body: &SecurityEventBody) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(body)?;
    let mut bytes = Vec::with_capacity(SECURITY_EVENT_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(SECURITY_EVENT_SIGNATURE_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
