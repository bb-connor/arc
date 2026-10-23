pub const EVENT_EVIDENCE_HASH_DOMAIN: &[u8] = b"chio.verified-security-event-evidence.v1\0";
pub const EVENT_RECEIPT_EVIDENCE_HASH_DOMAIN: &[u8] =
    b"chio.verified-security-event-receipt-evidence.v1\0";
use alloc::string::ToString;

use chio_security_types::ports::{ProducerId, RecordId};
use chio_security_types::SecurityEventBody;
use serde::{Deserialize, Serialize};

use crate::crypto::{verify_wrapped, wrapped_verdict};
use crate::{CanonicalBytes, Error, PublicKey, Result, Signature, SigningBackend};

/// Signing-wrapper schema id of detector-signed security event provenance.
pub const CHIO_SIGNED_SECURITY_EVENT_SCHEMA: &str = "chio.signed-security-event.v1";

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
    signature: Signature,
}

impl SignedSecurityEvent {
    pub fn sign_with_backend(
        body: SecurityEventBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        body.validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        let outcome = backend.sign_wrapped(
            CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
            &CanonicalBytes::from_serializable(&body)?,
        )?;
        Ok(Self {
            body,
            producer_key: outcome.public_key,
            signature: outcome.signature,
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
        {
            return Ok(false);
        }
        wrapped_verdict(verify_wrapped(
            trusted_producer_key,
            CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
            &self.body,
            &self.signature,
        ))
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
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}
