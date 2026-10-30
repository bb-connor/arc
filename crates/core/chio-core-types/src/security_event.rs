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

#[cfg(feature = "tenant-index")]
pub use projection::SecurityEventProjection;

#[cfg(feature = "tenant-index")]
mod projection {
    use chio_security_types::ports::{OpaqueReceiptRef, ProducerId};
    use chio_security_types::SecurityEventBody;
    use serde::{Deserialize, Serialize};

    use crate::receipt::metadata::{
        metadata_salt_ref, MetadataCommitment, MetadataOpenings, MetadataProjector, ProjectionError,
    };
    use crate::rng::Rng;
    use crate::tenant_index::{TenantBinding, TenantIndexKeySet};

    /// Signed metadata block `security_event`: the tenant as a keyed binding, the subject
    /// as a commitment (`metadata.security_event.subject`), and the Chio receipt and
    /// producer ids. The full body stays the receipt's content preimage.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SecurityEventProjection {
        pub tenant_binding: TenantBinding,
        pub subject: MetadataCommitment,
        pub source_receipt_id: OpaqueReceiptRef,
        pub producer_id: ProducerId,
    }

    impl SecurityEventProjection {
        /// Projects `body` under the active generation of `keys`, drawing the subject salt
        /// from `rng`; returns the projection and its openings.
        pub fn project(
            body: &SecurityEventBody,
            keys: &TenantIndexKeySet,
            rng: &dyn Rng,
        ) -> Result<(Self, MetadataOpenings), ProjectionError> {
            let mut projector = MetadataProjector::project(keys, rng);
            let projection = Self::build(body, &mut projector)?;
            Ok((projection, projector.into_openings()))
        }

        /// True when this projection is the projection of `body` under `openings` and the
        /// generation its tenant binding names; false on any mismatch, missing or unused
        /// opening or unknown generation.
        #[must_use]
        pub fn matches(
            &self,
            body: &SecurityEventBody,
            openings: &MetadataOpenings,
            keys: &TenantIndexKeySet,
        ) -> bool {
            MetadataProjector::verify(keys, &self.tenant_binding.key_id, openings)
                .and_then(|mut projector| {
                    let rebuilt = Self::build(body, &mut projector)?;
                    projector.finish()?;
                    Ok(rebuilt)
                })
                .is_ok_and(|rebuilt| rebuilt == *self)
        }

        fn build(
            body: &SecurityEventBody,
            projector: &mut MetadataProjector<'_>,
        ) -> Result<Self, ProjectionError> {
            Ok(Self {
                tenant_binding: projector.tenant_binding(body.tenant_id.as_str())?,
                subject: projector.commit(
                    metadata_salt_ref("security_event", "subject")?,
                    &body.subject,
                )?,
                source_receipt_id: body.source_receipt_id.clone(),
                producer_id: body.producer_id.clone(),
            })
        }
    }
}
