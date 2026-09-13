//! Original native authority selection, never a mutation or dispatch permit.

use super::{AdmissionDigest, AdmissionIdentifier};
use serde::{Deserialize, Deserializer, Serialize};

const SCHEMA: &str = "chio.native-security-authority-binding.v1";

/// Data selected by trusted host configuration at original admission. The
/// initialization digest commits to the original source and destination
/// history. Current ownership and mutable flow observations are intentionally
/// excluded, so recovering under a new serving owner cannot retarget authority.
///
/// Constructing or decoding this value authenticates nothing. A native store
/// must compare it with its independently verified initialization and validate
/// the actual operation and current recovery lease before every new mutation.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct NativeSecurityAuthorityBindingV1 {
    schema: String,
    store_uuid: AdmissionIdentifier,
    security_authority_id: AdmissionIdentifier,
    initialization_digest: AdmissionDigest,
}

impl NativeSecurityAuthorityBindingV1 {
    pub fn store_uuid(&self) -> &AdmissionIdentifier {
        &self.store_uuid
    }

    pub fn security_authority_id(&self) -> &AdmissionIdentifier {
        &self.security_authority_id
    }

    pub fn initialization_digest(&self) -> &AdmissionDigest {
        &self.initialization_digest
    }

    #[must_use]
    pub fn new(
        store_uuid: AdmissionIdentifier,
        security_authority_id: AdmissionIdentifier,
        initialization_digest: AdmissionDigest,
    ) -> Self {
        Self {
            schema: SCHEMA.into(),
            store_uuid,
            security_authority_id,
            initialization_digest,
        }
    }
}

impl std::fmt::Debug for NativeSecurityAuthorityBindingV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityAuthorityBindingV1")
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for NativeSecurityAuthorityBindingV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: String,
            store_uuid: AdmissionIdentifier,
            security_authority_id: AdmissionIdentifier,
            initialization_digest: AdmissionDigest,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.schema != SCHEMA {
            return Err(serde::de::Error::custom(
                "unsupported native security authority binding schema",
            ));
        }
        Ok(Self::new(
            wire.store_uuid,
            wire.security_authority_id,
            wire.initialization_digest,
        ))
    }
}
