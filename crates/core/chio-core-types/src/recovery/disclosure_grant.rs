//! A disclosure grant is a plain declassification grant or a recovery grant.
//! A declassification grant serializes exactly as `SignedDeclassificationGrant`;
//! a recovery grant is wrapped as `{"kind":"recovery","grant":...}`.
use super::SignedRecoveryGrant;
use crate::{PublicKey, Signature, SignedDeclassificationGrant};
use alloc::boxed::Box;
use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Eq, PartialEq)]
pub enum SignedDisclosureGrant {
    Declassification(Box<SignedDeclassificationGrant>),
    Recovery(Box<SignedRecoveryGrant>),
}
impl From<SignedDeclassificationGrant> for SignedDisclosureGrant {
    fn from(grant: SignedDeclassificationGrant) -> Self {
        Self::Declassification(Box::new(grant))
    }
}
impl From<SignedRecoveryGrant> for SignedDisclosureGrant {
    fn from(grant: SignedRecoveryGrant) -> Self {
        Self::Recovery(Box::new(grant))
    }
}
impl SignedDisclosureGrant {
    /// Verify the grant under `pinned`, an authority key the caller trusts.
    pub fn verify_signature(&self, pinned: &PublicKey) -> crate::Result<bool> {
        match self {
            Self::Declassification(grant) => grant.verify_signature(pinned),
            Self::Recovery(grant) => grant.verify_signature(pinned),
        }
    }
    /// Verifies integrity under the embedded key; the caller must bind that key
    /// to a trusted source before acting on the result.
    pub fn verify_integrity_embedded_key(&self) -> crate::Result<bool> {
        match self {
            Self::Declassification(grant) => grant.verify_integrity_embedded_key(),
            Self::Recovery(grant) => grant.verify_integrity_embedded_key(),
        }
    }
    pub fn authority_key(&self) -> &PublicKey {
        match self {
            Self::Declassification(grant) => grant.authority_key(),
            Self::Recovery(grant) => grant.authority_key(),
        }
    }
    pub fn declassification(&self) -> Option<&SignedDeclassificationGrant> {
        match self {
            Self::Declassification(grant) => Some(grant),
            Self::Recovery(_) => None,
        }
    }
    pub fn recovery(&self) -> Option<&SignedRecoveryGrant> {
        match self {
            Self::Recovery(grant) => Some(grant),
            Self::Declassification(_) => None,
        }
    }
    /// Declassification claims shared by both kinds. This accessor proves no authority.
    pub fn body(&self) -> &DeclassificationGrantBody {
        match self {
            Self::Declassification(grant) => grant.body(),
            Self::Recovery(grant) => &grant.body().claims,
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
    Recovery,
}
impl Serialize for SignedDisclosureGrant {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Declassification(grant) => grant.serialize(s),
            Self::Recovery(grant) => {
                #[derive(Serialize)]
                struct Wire<'a> {
                    kind: Kind,
                    grant: &'a SignedRecoveryGrant,
                }
                Wire {
                    kind: Kind::Recovery,
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
        // The `kind` selector decides the shape. A recovery selector requires
        // the complete recovery grant and refuses every declassification field.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default, deserialize_with = "present")]
            kind: Option<Kind>,
            #[serde(default, deserialize_with = "present")]
            grant: Option<SignedRecoveryGrant>,
            #[serde(default, deserialize_with = "present")]
            body: Option<DeclassificationGrantBody>,
            #[serde(default, deserialize_with = "present")]
            authority_key: Option<PublicKey>,
            #[serde(default, deserialize_with = "present")]
            signature: Option<Signature>,
        }
        let wire = Wire::deserialize(d)?;
        match (
            wire.kind,
            wire.grant,
            wire.body,
            wire.authority_key,
            wire.signature,
        ) {
            (Some(Kind::Recovery), Some(grant), None, None, None) => {
                Ok(Self::Recovery(Box::new(grant)))
            }
            (None, None, Some(body), Some(authority_key), Some(signature)) => {
                Ok(Self::Declassification(Box::new(
                    SignedDeclassificationGrant::from_untrusted_parts(
                        body,
                        authority_key,
                        signature,
                    ),
                )))
            }
            _ => Err(serde::de::Error::custom("invalid disclosure grant")),
        }
    }
}
