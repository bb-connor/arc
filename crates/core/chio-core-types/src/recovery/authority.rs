//! Signed recovery authority: grants, coverage attestations and provider finality.
use chio_security_types::recovery::{
    AuthorityCoverageAttestationV1, RecoveryGrantBindingV1, SafeInteger, VersionV1,
};
use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Serialize};

use crate::{Error, Keypair, PublicKey, Result, Signature, SigningBackend};

/// Signing-wrapper schema id of a recovery grant.
pub const CHIO_RECOVERY_GRANT_SCHEMA: &str = "chio.recovery.grant.v1";
/// Signing-wrapper schema id of an authority coverage attestation.
pub const CHIO_RECOVERY_AUTHORITY_COVERAGE_SCHEMA: &str =
    "chio.recovery.signed-authority-coverage.v1";
/// Signing-wrapper schema id of a recovery provider finality statement.
pub const CHIO_RECOVERY_PROVIDER_FINALITY_SCHEMA: &str =
    "chio.recovery.signed-provider-finality.v1";

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
    ($name:ident, $body:ty, $schema:ident, $validate:expr) => {
        #[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            body: $body,
            authority_key: PublicKey,
            signature: Signature,
        }
        impl $name {
            pub fn sign(body: $body, key: &Keypair) -> Result<Self> {
                Self::sign_with_backend(body, &$crate::crypto::Ed25519Backend::new(key.clone()))
            }
            pub fn sign_with_backend(body: $body, backend: &dyn SigningBackend) -> Result<Self> {
                ($validate)(&body)?;
                let signed = backend
                    .sign_wrapped($schema, &$crate::CanonicalBytes::from_serializable(&body)?)?;
                Ok(Self {
                    body,
                    authority_key: signed.public_key,
                    signature: signed.signature,
                })
            }
            /// Verifies integrity under the embedded key; the caller must bind that key
            /// to a trusted source before acting on the result.
            pub fn verify_integrity_embedded_key(&self) -> Result<bool> {
                ($validate)(&self.body)?;
                $crate::crypto::wrapped_verdict($crate::crypto::verify_wrapped(
                    &self.authority_key,
                    $schema,
                    &self.body,
                    &self.signature,
                ))
            }
            pub const fn body(&self) -> &$body {
                &self.body
            }
            pub const fn authority_key(&self) -> &PublicKey {
                &self.authority_key
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
    CHIO_RECOVERY_GRANT_SCHEMA,
    RecoveryGrantBody::validate
);
signed_authority!(
    SignedAuthorityCoverageAttestationV1,
    AuthorityCoverageAttestationV1,
    CHIO_RECOVERY_AUTHORITY_COVERAGE_SCHEMA,
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

signed_authority!(
    SignedRecoveryProviderFinalityV1,
    chio_security_types::recovery::RecoveryProviderFinalityV1,
    CHIO_RECOVERY_PROVIDER_FINALITY_SCHEMA,
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
