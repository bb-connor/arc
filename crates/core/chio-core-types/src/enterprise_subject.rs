//! Keyed enterprise subject identifiers under the `enterprise-subject` purpose of the tenant
//! index key set.
//!
//! An enterprise subject is the keyed value of
//! `"chio.enterprise-subject.v1\0" || field(provider scope) || field(canonical principal)`,
//! where `field(x) = be32(len(x)) || x`, carried as `esk1.<hex key_id>.<hex value>`. The SCIM
//! capability id suffix and the SCIM deprovision policy hash are keyed values under the same
//! purpose subkey in their own domains. Every value names its generation; two values are
//! equal only as `(key_id, value)` pairs, so values of different generations never compare
//! equal by value.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::root_authority::Sha256Digest;
use crate::tenant_index::{
    IndexDomain, IndexPurpose, KeyedIndexValue, TenantBindingError, TenantIndexKeySet,
};

/// The prefix of a SCIM capability id; an enterprise-subject string form follows it.
pub const SCIM_CAPABILITY_ID_PREFIX: &str = "scim-user:";

const FIELD_LENGTH_BYTES: usize = 4;
const DIGEST_HEX_LEN: usize = 64;

/// Why an enterprise subject value is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterpriseSubjectError {
    /// The key set refused the value: its generation is not loaded, it does not verify, or
    /// its string form is malformed.
    Index(TenantBindingError),
    /// A preimage field does not fit its 32-bit length prefix.
    FieldTooLong { field: &'static str },
    /// A SCIM policy hash is not 64 lowercase hex characters.
    MalformedPolicyHash,
}

impl fmt::Display for EnterpriseSubjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Index(error) => fmt::Display::fmt(error, formatter),
            Self::FieldTooLong { field } => {
                write!(formatter, "enterprise subject {field} exceeds 4 GiB")
            }
            Self::MalformedPolicyHash => {
                formatter.write_str("scim policy hash is not 64 lowercase hex characters")
            }
        }
    }
}

impl core::error::Error for EnterpriseSubjectError {}

impl From<TenantBindingError> for EnterpriseSubjectError {
    fn from(error: TenantBindingError) -> Self {
        Self::Index(error)
    }
}

/// `field(first) || field(second)`, so no two pairs share a preimage.
fn length_prefixed(
    first: (&'static str, &str),
    second: (&'static str, &str),
) -> Result<Vec<u8>, EnterpriseSubjectError> {
    let capacity = first
        .1
        .len()
        .saturating_add(second.1.len())
        .saturating_add(2 * FIELD_LENGTH_BYTES);
    let mut preimage = Vec::with_capacity(capacity);
    for (field, text) in [first, second] {
        let length = u32::try_from(text.len())
            .map_err(|_| EnterpriseSubjectError::FieldTooLong { field })?;
        preimage.extend_from_slice(&length.to_be_bytes());
        preimage.extend_from_slice(text.as_bytes());
    }
    Ok(preimage)
}

fn subject_preimage(
    provider_scope: &str,
    canonical_principal: &str,
) -> Result<Vec<u8>, EnterpriseSubjectError> {
    length_prefixed(
        ("provider scope", provider_scope),
        ("canonical principal", canonical_principal),
    )
}

/// A keyed enterprise subject: one `(key_id, value)` pair under the `enterprise-subject`
/// purpose. Equality, ordering and hashing cover both members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnterpriseSubjectKey(KeyedIndexValue);

impl EnterpriseSubjectKey {
    /// The subject of `canonical_principal` in `provider_scope` under the active generation.
    pub fn derive(
        keys: &TenantIndexKeySet,
        provider_scope: &str,
        canonical_principal: &str,
    ) -> Result<Self, EnterpriseSubjectError> {
        let preimage = subject_preimage(provider_scope, canonical_principal)?;
        Ok(Self(keys.derive(IndexDomain::EnterpriseSubject, &preimage)))
    }

    /// Verifies the subject under the generation its `key_id` names. An unknown generation
    /// refuses; there is no fallback generation and no unkeyed form.
    pub fn verify(
        &self,
        keys: &TenantIndexKeySet,
        provider_scope: &str,
        canonical_principal: &str,
    ) -> Result<(), EnterpriseSubjectError> {
        let preimage = subject_preimage(provider_scope, canonical_principal)?;
        Ok(keys.verify_value(IndexDomain::EnterpriseSubject, &preimage, &self.0)?)
    }

    /// Parses `esk1.<64 lowercase hex>.<64 lowercase hex>` exactly.
    pub fn parse(text: &str) -> Result<Self, EnterpriseSubjectError> {
        Ok(Self(KeyedIndexValue::parse_string_form(
            IndexPurpose::EnterpriseSubject,
            text,
        )?))
    }

    #[must_use]
    pub const fn keyed_value(&self) -> &KeyedIndexValue {
        &self.0
    }

    #[must_use]
    pub const fn key_id(&self) -> &Sha256Digest {
        &self.0.key_id
    }
}

impl fmt::Display for EnterpriseSubjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.to_string_form(IndexPurpose::EnterpriseSubject))
    }
}

impl Serialize for EnterpriseSubjectKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string_form(IndexPurpose::EnterpriseSubject))
    }
}

impl<'de> Deserialize<'de> for EnterpriseSubjectKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// The SCIM capability id of one provisioned user: [`SCIM_CAPABILITY_ID_PREFIX`] followed by
/// the string form of the keyed value over the provider id and the SCIM user id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScimCapabilityId(KeyedIndexValue);

impl ScimCapabilityId {
    /// The capability id under the active generation.
    pub fn derive(
        keys: &TenantIndexKeySet,
        provider_id: &str,
        user_id: &str,
    ) -> Result<Self, EnterpriseSubjectError> {
        let preimage = length_prefixed(("provider id", provider_id), ("user id", user_id))?;
        Ok(Self(keys.derive(IndexDomain::ScimCapability, &preimage)))
    }

    #[must_use]
    pub const fn keyed_value(&self) -> &KeyedIndexValue {
        &self.0
    }
}

impl fmt::Display for ScimCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCIM_CAPABILITY_ID_PREFIX)?;
        formatter.write_str(&self.0.to_string_form(IndexPurpose::EnterpriseSubject))
    }
}

/// The SCIM deprovision policy hash: the keyed value over the provider id and the string form
/// of the enterprise subject. A receipt carries [`Self::to_hex`]; the SCIM lifecycle row
/// records [`Self::key_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScimPolicyHash(KeyedIndexValue);

impl ScimPolicyHash {
    fn preimage(
        provider_id: &str,
        subject: &EnterpriseSubjectKey,
    ) -> Result<Vec<u8>, EnterpriseSubjectError> {
        let subject = subject.0.to_string_form(IndexPurpose::EnterpriseSubject);
        length_prefixed(("provider id", provider_id), ("subject", &subject))
    }

    /// The policy hash under the active generation.
    pub fn derive(
        keys: &TenantIndexKeySet,
        provider_id: &str,
        subject: &EnterpriseSubjectKey,
    ) -> Result<Self, EnterpriseSubjectError> {
        let preimage = Self::preimage(provider_id, subject)?;
        Ok(Self(keys.derive(IndexDomain::ScimPolicy, &preimage)))
    }

    /// Verifies a carried policy hash under the generation recorded beside it. An unknown
    /// generation refuses.
    pub fn verify(
        keys: &TenantIndexKeySet,
        key_id: &Sha256Digest,
        policy_hash_hex: &str,
        provider_id: &str,
        subject: &EnterpriseSubjectKey,
    ) -> Result<(), EnterpriseSubjectError> {
        let value = parse_policy_hash(policy_hash_hex)?;
        let preimage = Self::preimage(provider_id, subject)?;
        Ok(keys.verify_value(
            IndexDomain::ScimPolicy,
            &preimage,
            &KeyedIndexValue {
                key_id: *key_id,
                value,
            },
        )?)
    }

    #[must_use]
    pub const fn key_id(&self) -> &Sha256Digest {
        &self.0.key_id
    }

    /// The value as 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.value.to_bare_hex()
    }
}

fn parse_policy_hash(text: &str) -> Result<Sha256Digest, EnterpriseSubjectError> {
    if text.len() != DIGEST_HEX_LEN
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EnterpriseSubjectError::MalformedPolicyHash);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| EnterpriseSubjectError::MalformedPolicyHash)?;
    Ok(Sha256Digest::from_bytes(bytes))
}
