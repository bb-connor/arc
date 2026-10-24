//! Keyed index values under a deployment's tenant index key set.
//!
//! Each generation of the set holds one 32-byte set key. Every purpose uses its own subkey,
//! never the set key: `K[purpose] = HKDF-SHA256(IKM = set key, salt = TENANT_INDEX_HKDF_SALT,
//! info = TENANT_INDEX_HKDF_SALT || "/" || label, L = 32)`. A value is
//! `HMAC-SHA256(K[purpose], domain || preimage)`, where `domain` is one [`IndexDomain`]: a
//! NUL-terminated `chio.<area>.v<N>` constant that fixes its purpose. A generation is named by
//! `key_id = SHA-256(TENANT_INDEX_KEY_ID_DOMAIN || set key)`; every derived value carries it.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::root_authority::Sha256Digest;

#[cfg(feature = "std")]
mod load;
#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
pub use load::TenantIndexKeyLoadError;

pub const TENANT_INDEX_KEY_LEN: usize = 32;
pub const TENANT_INDEX_KEY_ID_DOMAIN: &[u8] = b"chio.tenant-index-key-id.v1\0";
pub const TENANT_INDEX_HKDF_SALT: &[u8] = b"chio.tenant-index.v1";
pub const TENANT_BINDING_DOMAIN: &[u8] = b"chio.receipt.tenant-binding.v1\0";
pub const TENANT_TAG_DOMAIN: &[u8] = b"chio.tenant-tag.v1\0";
pub const SUBJECT_TAG_DOMAIN: &[u8] = b"chio.subject-tag.v1\0";
pub const ENTERPRISE_SUBJECT_DOMAIN: &[u8] = b"chio.enterprise-subject.v1\0";
pub const SCIM_CAPABILITY_DOMAIN: &[u8] = b"chio.scim-capability.v1\0";
pub const SCIM_POLICY_DOMAIN: &[u8] = b"chio.scim-policy.v1\0";
pub const ACTIVE_DEFENSE_KEYED_DIGEST_DOMAIN: &[u8] = b"chio.active-defense.keyed-digest.v1\0";

const HKDF_INFO_SEPARATOR: &[u8] = b"/";
const DIGEST_HEX_LEN: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// The closed set of index purposes. The purpose of a value is fixed by the field that
/// carries it, never read from the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexPurpose {
    TenantBinding,
    TenantTag,
    SubjectTag,
    EnterpriseSubject,
    ActiveDefenseDigest,
}

impl IndexPurpose {
    pub const ALL: [Self; 5] = [
        Self::TenantBinding,
        Self::TenantTag,
        Self::SubjectTag,
        Self::EnterpriseSubject,
        Self::ActiveDefenseDigest,
    ];

    /// The HKDF label. Labels are distinct, so no two purposes share a subkey.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TenantBinding => "tenant-binding",
            Self::TenantTag => "tenant-tag",
            Self::SubjectTag => "subject-tag",
            Self::EnterpriseSubject => "enterprise-subject",
            Self::ActiveDefenseDigest => "active-defense-digest",
        }
    }

    /// The prefix of the string form `<prefix>1.<hex key_id>.<hex value>`.
    #[must_use]
    pub const fn string_prefix(self) -> &'static str {
        match self {
            Self::TenantBinding => "tb1",
            Self::TenantTag => "tt1",
            Self::SubjectTag => "st1",
            Self::EnterpriseSubject => "esk1",
            Self::ActiveDefenseDigest => "ad1",
        }
    }
}

/// The closed set of keyed index value domains. Each domain belongs to exactly one purpose,
/// so a value can only be derived under the subkey of its own domain's purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexDomain {
    TenantBinding,
    TenantTag,
    SubjectTag,
    EnterpriseSubject,
    ScimCapability,
    ScimPolicy,
    ActiveDefenseKeyedDigest,
}

impl IndexDomain {
    pub const ALL: [Self; 7] = [
        Self::TenantBinding,
        Self::TenantTag,
        Self::SubjectTag,
        Self::EnterpriseSubject,
        Self::ScimCapability,
        Self::ScimPolicy,
        Self::ActiveDefenseKeyedDigest,
    ];

    #[must_use]
    pub const fn purpose(self) -> IndexPurpose {
        match self {
            Self::TenantBinding => IndexPurpose::TenantBinding,
            Self::TenantTag => IndexPurpose::TenantTag,
            Self::SubjectTag => IndexPurpose::SubjectTag,
            Self::EnterpriseSubject | Self::ScimCapability | Self::ScimPolicy => {
                IndexPurpose::EnterpriseSubject
            }
            Self::ActiveDefenseKeyedDigest => IndexPurpose::ActiveDefenseDigest,
        }
    }

    /// `chio.<area>.v<N>` followed by exactly one NUL, which is the only NUL.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::TenantBinding => TENANT_BINDING_DOMAIN,
            Self::TenantTag => TENANT_TAG_DOMAIN,
            Self::SubjectTag => SUBJECT_TAG_DOMAIN,
            Self::EnterpriseSubject => ENTERPRISE_SUBJECT_DOMAIN,
            Self::ScimCapability => SCIM_CAPABILITY_DOMAIN,
            Self::ScimPolicy => SCIM_POLICY_DOMAIN,
            Self::ActiveDefenseKeyedDigest => ACTIVE_DEFENSE_KEYED_DIGEST_DOMAIN,
        }
    }
}

const fn nul_count(bytes: &[u8]) -> usize {
    match bytes {
        [] => 0,
        [first, rest @ ..] => {
            if *first == 0 {
                1 + nul_count(rest)
            } else {
                nul_count(rest)
            }
        }
    }
}

const fn every_domain_nul_terminated_once(domains: &[IndexDomain]) -> bool {
    match domains {
        [] => true,
        [first, rest @ ..] => {
            let bytes = first.as_bytes();
            matches!(bytes.last(), Some(&0))
                && nul_count(bytes) == 1
                && every_domain_nul_terminated_once(rest)
        }
    }
}

// Domains are prefix-free, so `domain || preimage` is unambiguous across domains.
const _: () = assert!(every_domain_nul_terminated_once(&IndexDomain::ALL));

/// One keyed value and the key generation it was derived under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyedIndexValue {
    /// `SHA-256("chio.tenant-index-key-id.v1\0" || set key)` of the generation.
    pub key_id: Sha256Digest,
    pub value: Sha256Digest,
}

impl KeyedIndexValue {
    /// `<prefix>1.<hex key_id>.<hex value>` with lowercase hex.
    #[must_use]
    pub fn to_string_form(&self, purpose: IndexPurpose) -> String {
        let prefix = purpose.string_prefix();
        let mut text = String::with_capacity(prefix.len() + 2 + 2 * DIGEST_HEX_LEN);
        text.push_str(prefix);
        text.push('.');
        text.push_str(&self.key_id.to_bare_hex());
        text.push('.');
        text.push_str(&self.value.to_bare_hex());
        text
    }

    /// Parses the string form of `purpose` exactly: its own prefix, two dots and two
    /// 64-character lowercase hex fields. Anything else refuses.
    pub fn parse_string_form(
        purpose: IndexPurpose,
        text: &str,
    ) -> Result<Self, TenantBindingError> {
        let malformed = TenantBindingError::MalformedStringForm { purpose };
        let mut parts = text.split('.');
        let (Some(prefix), Some(key_id), Some(value), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed);
        };
        if prefix != purpose.string_prefix() {
            return Err(malformed);
        }
        Ok(Self {
            key_id: parse_bare_hex(key_id).ok_or(malformed)?,
            value: parse_bare_hex(value).ok_or(malformed)?,
        })
    }
}

fn parse_bare_hex(text: &str) -> Option<Sha256Digest> {
    if text.len() != DIGEST_HEX_LEN
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(text, &mut bytes).ok()?;
    Some(Sha256Digest::from_bytes(bytes))
}

/// Closed tenant binding algorithm set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TenantBindingAlg {
    #[serde(rename = "hkdf-hmac-sha256")]
    HkdfHmacSha256,
}

/// `value = HMAC-SHA256(K[tenant-binding], "chio.receipt.tenant-binding.v1\0" || tenant_id)`
/// under the generation named by `key_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantBinding {
    pub alg: TenantBindingAlg,
    pub key_id: Sha256Digest,
    pub value: Sha256Digest,
}

impl TenantBinding {
    #[must_use]
    pub const fn keyed_value(&self) -> KeyedIndexValue {
        KeyedIndexValue {
            key_id: self.key_id,
            value: self.value,
        }
    }
}

/// Why a keyed index value or tenant binding is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantBindingError {
    /// The value names a generation the key set does not hold.
    TenantIndexKeyUnknown { key_id: Sha256Digest },
    /// The value does not verify under its generation's purpose subkey.
    Mismatch,
    /// The string form is not exactly `<prefix>1.<hex key_id>.<hex value>`.
    MalformedStringForm { purpose: IndexPurpose },
    /// Two generations of one key set share a `key_id`.
    DuplicateKeyId { key_id: Sha256Digest },
    /// HKDF refused to expand a subkey.
    SubkeyDerivation,
}

impl fmt::Display for TenantBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TenantIndexKeyUnknown { key_id } => {
                write!(formatter, "tenant index key {key_id} is not loaded")
            }
            Self::Mismatch => formatter.write_str("keyed index value does not verify"),
            Self::MalformedStringForm { purpose } => write!(
                formatter,
                "keyed index value is not `{}.<64 hex>.<64 hex>`",
                purpose.string_prefix()
            ),
            Self::DuplicateKeyId { key_id } => {
                write!(formatter, "tenant index key {key_id} is loaded twice")
            }
            Self::SubkeyDerivation => formatter.write_str("tenant index subkey derivation failed"),
        }
    }
}

impl core::error::Error for TenantBindingError {}

/// One generation of the tenant index key set: its `key_id` and one HKDF subkey per
/// purpose. The set key itself is not retained. Subkeys are zeroized on drop; the transient
/// HKDF pseudorandom key and HMAC pad states inside the `hkdf` and `hmac` crates are not.
pub struct TenantIndexKey {
    key_id: Sha256Digest,
    subkeys: [[u8; 32]; IndexPurpose::ALL.len()],
}

impl TenantIndexKey {
    /// Derives the generation from its 32-byte set key.
    pub fn from_set_key(set_key: &[u8; TENANT_INDEX_KEY_LEN]) -> Result<Self, TenantBindingError> {
        let key_id = Sha256Digest::of_domain(TENANT_INDEX_KEY_ID_DOMAIN, set_key);
        let hkdf = Hkdf::<Sha256>::new(Some(TENANT_INDEX_HKDF_SALT), set_key);
        let mut key = Self {
            key_id,
            subkeys: [[0; 32]; IndexPurpose::ALL.len()],
        };
        for (purpose, subkey) in IndexPurpose::ALL.iter().zip(key.subkeys.iter_mut()) {
            hkdf.expand_multi_info(
                &[
                    TENANT_INDEX_HKDF_SALT,
                    HKDF_INFO_SEPARATOR,
                    purpose.label().as_bytes(),
                ],
                subkey,
            )
            .map_err(|_| TenantBindingError::SubkeyDerivation)?;
        }
        Ok(key)
    }

    #[must_use]
    pub const fn key_id(&self) -> &Sha256Digest {
        &self.key_id
    }

    fn subkey(&self, purpose: IndexPurpose) -> &[u8; 32] {
        let [tenant_binding, tenant_tag, subject_tag, enterprise_subject, active_defense_digest] =
            &self.subkeys;
        match purpose {
            IndexPurpose::TenantBinding => tenant_binding,
            IndexPurpose::TenantTag => tenant_tag,
            IndexPurpose::SubjectTag => subject_tag,
            IndexPurpose::EnterpriseSubject => enterprise_subject,
            IndexPurpose::ActiveDefenseDigest => active_defense_digest,
        }
    }

    fn derive(&self, domain: IndexDomain, preimage: &[u8]) -> KeyedIndexValue {
        // HMAC zero-pads a key shorter than its block, so the padded block key is the subkey.
        let mut block_key = hmac::digest::Key::<HmacSha256>::default();
        for (slot, byte) in block_key
            .iter_mut()
            .zip(self.subkey(domain.purpose()).iter())
        {
            *slot = *byte;
        }
        let mut mac = <HmacSha256 as Mac>::new(&block_key);
        block_key.as_mut_slice().zeroize();
        mac.update(domain.as_bytes());
        mac.update(preimage);
        let value: [u8; 32] = mac.finalize().into_bytes().into();
        KeyedIndexValue {
            key_id: self.key_id,
            value: Sha256Digest::from_bytes(value),
        }
    }
}

impl Zeroize for TenantIndexKey {
    fn zeroize(&mut self) {
        for subkey in &mut self.subkeys {
            subkey.zeroize();
        }
    }
}

impl Drop for TenantIndexKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TenantIndexKey {}

impl fmt::Debug for TenantIndexKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantIndexKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// A deployment's tenant index key set: one active generation that derives, and retired
/// generations that only verify. `key_id`s are distinct across the set.
#[derive(Debug)]
pub struct TenantIndexKeySet {
    active: TenantIndexKey,
    /// Sorted by `key_id`.
    retired: Vec<TenantIndexKey>,
}

impl TenantIndexKeySet {
    /// Refuses a `key_id` that appears more than once.
    pub fn new(
        active: TenantIndexKey,
        mut retired: Vec<TenantIndexKey>,
    ) -> Result<Self, TenantBindingError> {
        retired.sort_by_key(|key| key.key_id);
        for pair in retired.windows(2) {
            if let [left, right] = pair {
                if left.key_id == right.key_id {
                    return Err(TenantBindingError::DuplicateKeyId {
                        key_id: left.key_id,
                    });
                }
            }
        }
        if retired.iter().any(|key| key.key_id == active.key_id) {
            return Err(TenantBindingError::DuplicateKeyId {
                key_id: active.key_id,
            });
        }
        Ok(Self { active, retired })
    }

    #[must_use]
    pub const fn active_key_id(&self) -> &Sha256Digest {
        &self.active.key_id
    }

    /// The loaded generations, active first, then retired in `key_id` order.
    pub fn key_ids(&self) -> impl Iterator<Item = &Sha256Digest> {
        core::iter::once(&self.active.key_id).chain(self.retired.iter().map(|key| &key.key_id))
    }

    fn generation(&self, key_id: &Sha256Digest) -> Result<&TenantIndexKey, TenantBindingError> {
        core::iter::once(&self.active)
            .chain(self.retired.iter())
            .find(|key| key.key_id == *key_id)
            .ok_or(TenantBindingError::TenantIndexKeyUnknown { key_id: *key_id })
    }

    /// Binds `tenant_id` under the active generation.
    #[must_use]
    pub fn bind(&self, tenant_id: &str) -> TenantBinding {
        let keyed = self
            .active
            .derive(IndexDomain::TenantBinding, tenant_id.as_bytes());
        TenantBinding {
            alg: TenantBindingAlg::HkdfHmacSha256,
            key_id: keyed.key_id,
            value: keyed.value,
        }
    }

    /// Verifies `binding` against `tenant_id` under the generation its `key_id` names.
    pub fn verify(
        &self,
        tenant_id: &str,
        binding: &TenantBinding,
    ) -> Result<(), TenantBindingError> {
        self.verify_value(
            IndexDomain::TenantBinding,
            tenant_id.as_bytes(),
            &binding.keyed_value(),
        )
    }

    /// The keyed value of `domain || preimage` under the active generation, keyed by the
    /// subkey of the domain's purpose.
    #[must_use]
    pub fn derive(&self, domain: IndexDomain, preimage: &[u8]) -> KeyedIndexValue {
        self.active.derive(domain, preimage)
    }

    /// The keyed value under the generation named by `key_id`. An unknown `key_id` refuses.
    pub fn derive_in(
        &self,
        key_id: &Sha256Digest,
        domain: IndexDomain,
        preimage: &[u8],
    ) -> Result<KeyedIndexValue, TenantBindingError> {
        Ok(self.generation(key_id)?.derive(domain, preimage))
    }

    /// Selects the generation by the value's `key_id`, derives under `domain` and compares
    /// in constant time. An unknown `key_id` refuses; there is no fallback generation.
    pub fn verify_value(
        &self,
        domain: IndexDomain,
        preimage: &[u8],
        value: &KeyedIndexValue,
    ) -> Result<(), TenantBindingError> {
        let expected = self.derive_in(&value.key_id, domain, preimage)?;
        if bool::from(expected.value.as_bytes().ct_eq(value.value.as_bytes())) {
            Ok(())
        } else {
            Err(TenantBindingError::Mismatch)
        }
    }
}
