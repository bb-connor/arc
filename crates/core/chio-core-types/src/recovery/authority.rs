//! Signed recovery authority: grants, coverage attestations and provider finality.
use alloc::vec::Vec;
use chio_security_types::recovery::{
    AuthorityCoverageAttestationV1, RecoveryGrantBindingV1, SafeInteger, VersionV1,
};
use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Serialize};

use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, Error, Keypair, PublicKey, Result, Signature, SigningAlgorithm,
    SigningBackend,
};

pub const RECOVERY_GRANT_SIGNATURE_DOMAIN: &str = "chio:recovery-grant:v1";
pub const RECOVERY_COVERAGE_SIGNATURE_DOMAIN: &str = "chio:recovery-authority-coverage:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryGrantSchema {
    #[serde(rename = "chio.recovery.grant.v1")]
    V1,
}

/// Declassification claims bound to one exact recovery action. The claims keep
/// their declassification field meanings and are signed only inside this body.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGrantBody {
    pub schema: RecoveryGrantSchema,
    pub version: VersionV1,
    pub claims: DeclassificationGrantBody,
    pub recovery: RecoveryGrantBindingV1,
}
impl RecoveryGrantBody {
    pub fn validate(&self) -> Result<()> {
        self.claims.validate().map_err(|_| invalid())?;
        let issued = self.claims.issued_at_unix_seconds();
        let expires = self.claims.expires_at_unix_seconds();
        if expires > SafeInteger::MAX / 1000
            || expires.saturating_sub(issued) > 60
            || self.recovery.isolation_epoch.get() == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(super) fn invalid() -> Error {
    Error::InvalidSignature("invalid recovery authority".into())
}

macro_rules! signed_authority {
    ($name:ident, $body:ty, $domain:ident, $validate:expr) => {
        #[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            body: $body,
            authority_key: PublicKey,
            algorithm: SigningAlgorithm,
            signature: Signature,
        }
        impl $name {
            pub fn sign(body: $body, key: &Keypair) -> Result<Self> {
                Self::sign_with_backend(body, &Ed25519Backend::new(key.clone()))
            }
            pub fn sign_with_backend(body: $body, backend: &dyn SigningBackend) -> Result<Self> {
                ($validate)(&body)?;
                let signed = backend.sign_bytes_with_identity(&Self::body_signing_bytes(&body)?)?;
                if signed.public_key.algorithm() != signed.algorithm
                    || signed.signature.algorithm() != signed.algorithm
                {
                    return Err(invalid());
                }
                Ok(Self {
                    body,
                    authority_key: signed.public_key,
                    algorithm: signed.algorithm,
                    signature: signed.signature,
                })
            }
            fn body_signing_bytes(body: &$body) -> Result<Vec<u8>> {
                let canonical = canonical_json_bytes(body)?;
                let mut bytes = Vec::with_capacity($domain.len() + 1 + canonical.len());
                bytes.extend_from_slice($domain.as_bytes());
                bytes.push(0);
                bytes.extend_from_slice(&canonical);
                Ok(bytes)
            }
            pub fn signing_bytes(&self) -> Result<Vec<u8>> {
                Self::body_signing_bytes(&self.body)
            }
            pub fn verify_signature(&self) -> Result<bool> {
                ($validate)(&self.body)?;
                if self.authority_key.algorithm() != self.algorithm
                    || self.signature.algorithm() != self.algorithm
                {
                    return Ok(false);
                }
                Ok(self
                    .authority_key
                    .verify(&self.signing_bytes()?, &self.signature))
            }
            pub const fn body(&self) -> &$body {
                &self.body
            }
            pub const fn authority_key(&self) -> &PublicKey {
                &self.authority_key
            }
            pub const fn algorithm(&self) -> SigningAlgorithm {
                self.algorithm
            }
            pub const fn signature(&self) -> &Signature {
                &self.signature
            }
        }
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}
pub(super) use signed_authority;
signed_authority!(
    SignedRecoveryGrant,
    RecoveryGrantBody,
    RECOVERY_GRANT_SIGNATURE_DOMAIN,
    RecoveryGrantBody::validate
);
signed_authority!(
    SignedAuthorityCoverageAttestationV1,
    AuthorityCoverageAttestationV1,
    RECOVERY_COVERAGE_SIGNATURE_DOMAIN,
    |body: &AuthorityCoverageAttestationV1| {
        if body.issued_at_unix_ms >= body.expires_at_unix_ms
            || body.expires_at_unix_ms.get() - body.issued_at_unix_ms.get() > 900_000
        {
            return Err(invalid());
        }
        Ok(())
    }
);
impl core::fmt::Debug for RecoveryGrantBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryGrantBody([redacted])")
    }
}

pub const RECOVERY_PROVIDER_SIGNATURE_DOMAIN: &str = "chio:recovery-provider-finality:v1";
signed_authority!(
    SignedRecoveryProviderFinalityV1,
    chio_security_types::recovery::RecoveryProviderFinalityV1,
    RECOVERY_PROVIDER_SIGNATURE_DOMAIN,
    |body: &chio_security_types::recovery::RecoveryProviderFinalityV1| {
        if body.observed_at_unix_ms >= body.expires_at_unix_ms
            || body.expires_at_unix_ms.get() - body.observed_at_unix_ms.get() > 60_000
            || body.applied_effects.get() != 1
        {
            return Err(invalid());
        }
        Ok(())
    }
);
