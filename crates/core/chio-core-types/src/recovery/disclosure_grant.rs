//! Explicit recovery variant; historical v1 serialization remains byte-stable.
use super::SignedRecoveryGrantV2;
use crate::{PublicKey, Signature, SignedDeclassificationGrant, SigningAlgorithm};
use alloc::boxed::Box;
use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Eq, PartialEq)]
pub enum SignedDisclosureGrant {
    LegacyV1(Box<SignedDeclassificationGrant>),
    RecoveryV2(Box<SignedRecoveryGrantV2>),
}
impl From<SignedDeclassificationGrant> for SignedDisclosureGrant {
    fn from(grant: SignedDeclassificationGrant) -> Self {
        Self::LegacyV1(Box::new(grant))
    }
}
impl From<SignedRecoveryGrantV2> for SignedDisclosureGrant {
    fn from(grant: SignedRecoveryGrantV2) -> Self {
        Self::RecoveryV2(Box::new(grant))
    }
}
impl SignedDisclosureGrant {
    pub fn verify_signature(&self) -> crate::Result<bool> {
        match self {
            Self::LegacyV1(grant) => grant.verify_signature(),
            Self::RecoveryV2(grant) => grant.verify_signature(),
        }
    }
    pub fn authority_key(&self) -> &PublicKey {
        match self {
            Self::LegacyV1(grant) => grant.authority_key(),
            Self::RecoveryV2(grant) => grant.authority_key(),
        }
    }
    pub fn legacy_v1(&self) -> Option<&SignedDeclassificationGrant> {
        match self {
            Self::LegacyV1(grant) => Some(grant),
            Self::RecoveryV2(_) => None,
        }
    }
    pub fn recovery_v2(&self) -> Option<&SignedRecoveryGrantV2> {
        match self {
            Self::RecoveryV2(grant) => Some(grant),
            Self::LegacyV1(_) => None,
        }
    }
    /// Common claims keep their v1 meaning. This accessor proves no authority.
    pub fn body(&self) -> &DeclassificationGrantBody {
        match self {
            Self::LegacyV1(grant) => grant.body(),
            Self::RecoveryV2(grant) => &grant.body().claims,
        }
    }
}
impl core::fmt::Debug for SignedDisclosureGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SignedDisclosureGrant([redacted])")
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    RecoveryV2,
}
impl Serialize for SignedDisclosureGrant {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::LegacyV1(grant) => grant.serialize(s),
            Self::RecoveryV2(grant) => {
                #[derive(Serialize)]
                struct Wire<'a> {
                    kind: Kind,
                    grant: &'a SignedRecoveryGrantV2,
                }
                Wire {
                    kind: Kind::RecoveryV2,
                    grant,
                }
                .serialize(s)
            }
        }
    }
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
impl<'de> Deserialize<'de> for SignedDisclosureGrant {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // There is no try-v2/then-v1 fallback. A present recovery selector
        // requires its complete v2 object and prohibits every legacy field.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default, deserialize_with = "present")]
            kind: Option<Kind>,
            #[serde(default, deserialize_with = "present")]
            grant: Option<SignedRecoveryGrantV2>,
            #[serde(default, deserialize_with = "present")]
            body: Option<DeclassificationGrantBody>,
            #[serde(default, deserialize_with = "present")]
            authority_key: Option<PublicKey>,
            #[serde(default, deserialize_with = "present")]
            algorithm: Option<SigningAlgorithm>,
            #[serde(default, deserialize_with = "present")]
            signature: Option<Signature>,
        }
        let wire = Wire::deserialize(d)?;
        match (
            wire.kind,
            wire.grant,
            wire.body,
            wire.authority_key,
            wire.algorithm,
            wire.signature,
        ) {
            (Some(Kind::RecoveryV2), Some(grant), None, None, None, None) => {
                Ok(Self::RecoveryV2(Box::new(grant)))
            }
            (None, None, Some(body), Some(authority_key), Some(algorithm), Some(signature)) => Ok(
                Self::LegacyV1(Box::new(SignedDeclassificationGrant::from_untrusted_parts(
                    body,
                    authority_key,
                    algorithm,
                    signature,
                ))),
            ),
            _ => Err(serde::de::Error::custom(
                "invalid version-selected disclosure grant",
            )),
        }
    }
}
