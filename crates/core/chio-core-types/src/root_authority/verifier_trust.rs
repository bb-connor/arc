//! `chio.verifier-trust.v1`: the verifier-owned file that pins every key an
//! offline bundle verifier accepts and the report columns that must verify.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use super::jwk::Jwk;
use super::wire::{Identifier, Uri};
use super::RootAuthorityShapeError;
use crate::canonical::{UntrustedJsonError, UntrustedJsonText};
use crate::crypto::PublicKey;
use crate::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding;

pub const CHIO_VERIFIER_TRUST_SCHEMA: &str = "chio.verifier-trust.v1";

/// Largest trust file a verifier reads.
pub const MAX_VERIFIER_TRUST_BYTES: usize = 4 * 1024 * 1024;

const MAX_KEYS_PER_ROLE: usize = 64;
const MAX_IDP_ISSUERS: usize = 64;
const MAX_PEP_KEYS: usize = 256;
const MAX_ANCHOR_MEMBER_BYTES: usize = 2048;

/// A report column a trust file can require to be `verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportColumn {
    IdentityRoot,
    DelegationChain,
    Decision,
    Content,
    Settlement,
}

impl ReportColumn {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityRoot => "identity_root",
            Self::DelegationChain => "delegation_chain",
            Self::Decision => "decision",
            Self::Content => "content",
            Self::Settlement => "settlement",
        }
    }
}

/// A verifier-owned trust file. Unsigned; the verifying party writes it.
///
/// Key bounds: `kernel_keys` holds 1 to 64 keys. `exchange_keys` and
/// `root_policy_keys` hold 0 to 64, because a bundle without anchored roots
/// needs neither; a verifier that meets an anchored root while the role it
/// needs is empty refuses the bundle as missing trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierTrust {
    pub schema: String,
    pub kernel_keys: Vec<PublicKey>,
    pub exchange_keys: Vec<PublicKey>,
    pub root_policy_keys: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub idp_keys: BTreeMap<Uri, Vec<Jwk>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pep_keys: BTreeMap<Identifier, PublicKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoint_keys: Vec<PublicKey>,
    /// The checkpoint publication binding the verifier accepts as a trust
    /// anchor. Absent: publication claims stay transparency previews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_trust_anchor: Option<CheckpointPublicationTrustAnchorBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_columns: Vec<ReportColumn>,
}

/// Why a trust file is refused.
#[derive(Debug)]
pub enum VerifierTrustError {
    /// The bytes are not admissible JSON or do not decode as a trust file.
    Decode(UntrustedJsonError),
    /// A member the typed form would drop or rewrite.
    DroppedInput,
    /// A schema rule the typed form does not enforce.
    Shape(RootAuthorityShapeError),
    /// A key that cannot be trusted.
    WeakKey { field: &'static str },
    /// One key pinned in two roles.
    KeyInTwoRoles,
    /// The checkpoint trust anchor binding is incomplete.
    TrustAnchor(String),
}

impl fmt::Display for VerifierTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "verifier trust file: {error}"),
            Self::DroppedInput => {
                formatter.write_str("verifier trust file: decoded value drops input fields")
            }
            Self::Shape(error) => write!(formatter, "verifier trust file: {error}"),
            Self::WeakKey { field } => {
                write!(
                    formatter,
                    "verifier trust file: `{field}` pins a weak Ed25519 key"
                )
            }
            Self::KeyInTwoRoles => {
                formatter.write_str("verifier trust file: a key is pinned in two roles")
            }
            Self::TrustAnchor(reason) => write!(
                formatter,
                "verifier trust file: `checkpoint_trust_anchor` is invalid: {reason}"
            ),
        }
    }
}

impl core::error::Error for VerifierTrustError {}

impl From<UntrustedJsonError> for VerifierTrustError {
    fn from(error: UntrustedJsonError) -> Self {
        Self::Decode(error)
    }
}

impl From<RootAuthorityShapeError> for VerifierTrustError {
    fn from(error: RootAuthorityShapeError) -> Self {
        Self::Shape(error)
    }
}

impl VerifierTrust {
    /// Strict decode (unknown members refuse at every level, including inside
    /// the checkpoint trust anchor) plus every schema rule the typed form
    /// does not enforce:
    /// the `schema` const, per-role key bounds, uniqueness, no weak Ed25519
    /// key and no key in two roles.
    pub fn load(bytes: &[u8]) -> Result<Self, VerifierTrustError> {
        let input = UntrustedJsonText::from_wire(bytes, MAX_VERIFIER_TRUST_BYTES)?;
        let value: serde_json::Value = input.decode_signed()?;
        let trust: Self = input.decode_signed()?;
        if let (Some(anchor), Some(decoded)) = (
            value.get("checkpoint_trust_anchor"),
            trust.checkpoint_trust_anchor.as_ref(),
        ) {
            if serde_json::to_value(decoded).ok().as_ref() != Some(anchor) {
                return Err(VerifierTrustError::DroppedInput);
            }
        }
        trust.validate()?;
        Ok(trust)
    }

    /// The rules [`VerifierTrust::load`] applies after decoding.
    pub fn validate(&self) -> Result<(), VerifierTrustError> {
        if self.schema != CHIO_VERIFIER_TRUST_SCHEMA {
            return Err(RootAuthorityShapeError::Const {
                field: "schema",
                expected: CHIO_VERIFIER_TRUST_SCHEMA,
            }
            .into());
        }
        check_keys("kernel_keys", &self.kernel_keys, 1)?;
        check_keys("exchange_keys", &self.exchange_keys, 0)?;
        check_keys("root_policy_keys", &self.root_policy_keys, 0)?;
        check_keys("checkpoint_keys", &self.checkpoint_keys, 0)?;
        check_count("idp_keys", self.idp_keys.len(), 0, MAX_IDP_ISSUERS)?;
        for keys in self.idp_keys.values() {
            check_count("idp_keys", keys.len(), 0, MAX_KEYS_PER_ROLE)?;
        }
        check_count("pep_keys", self.pep_keys.len(), 0, MAX_PEP_KEYS)?;
        if self.pep_keys.values().any(PublicKey::is_weak_ed25519) {
            return Err(VerifierTrustError::WeakKey { field: "pep_keys" });
        }
        check_count("required_columns", self.required_columns.len(), 0, 5)?;
        let columns: BTreeSet<_> = self.required_columns.iter().collect();
        if columns.len() != self.required_columns.len() {
            return Err(RootAuthorityShapeError::Duplicate {
                field: "required_columns",
            }
            .into());
        }

        let mut seen = BTreeSet::new();
        let roles = [
            &self.kernel_keys,
            &self.exchange_keys,
            &self.root_policy_keys,
            &self.checkpoint_keys,
        ];
        for key in roles.into_iter().flatten().chain(self.pep_keys.values()) {
            if !seen.insert(key.to_hex()) {
                return Err(VerifierTrustError::KeyInTwoRoles);
            }
        }

        if let Some(anchor) = &self.checkpoint_trust_anchor {
            anchor
                .validate()
                .map_err(|error| VerifierTrustError::TrustAnchor(alloc::format!("{error}")))?;
            let members = [
                anchor.publication_identity.identity.as_str(),
                anchor.trust_anchor_identity.identity.as_str(),
                anchor.trust_anchor_ref.as_str(),
                anchor.signer_cert_ref.as_str(),
                anchor.publication_profile_version.as_str(),
            ];
            if members
                .iter()
                .any(|member| member.len() > MAX_ANCHOR_MEMBER_BYTES)
            {
                return Err(VerifierTrustError::TrustAnchor(alloc::format!(
                    "a member exceeds {MAX_ANCHOR_MEMBER_BYTES} bytes"
                )));
            }
        }
        Ok(())
    }

    /// Whether `key` may sign receipts, checkpoints and the export envelope.
    #[must_use]
    pub fn is_kernel_key(&self, key: &PublicKey) -> bool {
        self.kernel_keys.contains(key)
    }

    /// Whether `key` may sign a checkpoint statement.
    #[must_use]
    pub fn is_checkpoint_key(&self, key: &PublicKey) -> bool {
        self.kernel_keys.contains(key) || self.checkpoint_keys.contains(key)
    }
}

fn check_count(
    field: &'static str,
    actual: usize,
    min: usize,
    max: usize,
) -> Result<(), RootAuthorityShapeError> {
    if actual < min || actual > max {
        return Err(RootAuthorityShapeError::Items {
            field,
            min,
            max,
            actual,
        });
    }
    Ok(())
}

fn check_keys(
    field: &'static str,
    keys: &[PublicKey],
    min: usize,
) -> Result<(), VerifierTrustError> {
    check_count(field, keys.len(), min, MAX_KEYS_PER_ROLE)?;
    let unique: BTreeSet<String> = keys.iter().map(PublicKey::to_hex).collect();
    if unique.len() != keys.len() {
        return Err(RootAuthorityShapeError::Duplicate { field }.into());
    }
    if keys.iter().any(PublicKey::is_weak_ed25519) {
        return Err(VerifierTrustError::WeakKey { field });
    }
    Ok(())
}
