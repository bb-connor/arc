//! `chio.revocation-entry.v1`: one revocation target, recorded once under an
//! id derived from the target alone.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hashing::Sha256State;

use super::wire::{check_nul_free, check_schema, Sha256Digest};
use super::RootAuthorityShapeError;

pub const CHIO_REVOCATION_ENTRY_SCHEMA: &str = "chio.revocation-entry.v1";

/// Hash domain of [`RevocationTarget::id`].
pub const REVOCATION_ENTRY_ID_DOMAIN: &[u8] = b"chio.revocation-entry-id.v1\0";

const ENTRY_ID_PREFIX: &str = "rev_";
const MAX_TARGET_VALUE_CHARS: usize = 512;
const MAX_REVOKED_AT: u64 = i64::MAX.unsigned_abs();

/// What a revocation entry names. Closed: an unknown kind rejects at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTargetKind {
    CapabilityId,
    RootPolicyRule,
    AnchorSubject,
    TenantTag,
    ReplayKey,
}

impl RevocationTargetKind {
    /// The serde name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityId => "capability_id",
            Self::RootPolicyRule => "root_policy_rule",
            Self::AnchorSubject => "anchor_subject",
            Self::TenantTag => "tenant_tag",
            Self::ReplayKey => "replay_key",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RootAuthorityShapeError> {
        match value {
            "capability_id" => Ok(Self::CapabilityId),
            "root_policy_rule" => Ok(Self::RootPolicyRule),
            "anchor_subject" => Ok(Self::AnchorSubject),
            "tenant_tag" => Ok(Self::TenantTag),
            "replay_key" => Ok(Self::ReplayKey),
            _ => Err(RootAuthorityShapeError::Pattern {
                field: "target_kind",
                expected: "a revocation target kind",
            }),
        }
    }

    /// Whether the value is a 64-character lowercase hex digest.
    const fn is_digest(self) -> bool {
        matches!(
            self,
            Self::AnchorSubject | Self::TenantTag | Self::ReplayKey
        )
    }
}

/// Why a target was revoked. Closed, so no free text reaches a store or an
/// export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    OperatorRequest,
    CredentialCompromise,
    PrincipalOffboarded,
    TenantOffboarded,
    PolicyWithdrawn,
    IncidentResponse,
}

impl RevocationReason {
    /// The serde name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorRequest => "operator_request",
            Self::CredentialCompromise => "credential_compromise",
            Self::PrincipalOffboarded => "principal_offboarded",
            Self::TenantOffboarded => "tenant_offboarded",
            Self::PolicyWithdrawn => "policy_withdrawn",
            Self::IncidentResponse => "incident_response",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RootAuthorityShapeError> {
        match value {
            "operator_request" => Ok(Self::OperatorRequest),
            "credential_compromise" => Ok(Self::CredentialCompromise),
            "principal_offboarded" => Ok(Self::PrincipalOffboarded),
            "tenant_offboarded" => Ok(Self::TenantOffboarded),
            "policy_withdrawn" => Ok(Self::PolicyWithdrawn),
            "incident_response" => Ok(Self::IncidentResponse),
            _ => Err(RootAuthorityShapeError::Pattern {
                field: "reason",
                expected: "a revocation reason",
            }),
        }
    }
}

/// `rev_` followed by 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevocationEntryId(String);

impl RevocationEntryId {
    pub fn parse(value: &str) -> Result<Self, RootAuthorityShapeError> {
        let well_formed = value
            .strip_prefix(ENTRY_ID_PREFIX)
            .is_some_and(is_lowercase_hex_digest);
        if !well_formed {
            return Err(RootAuthorityShapeError::Pattern {
                field: "entry_id",
                expected: "rev_<64 lowercase hex>",
            });
        }
        Ok(Self(value.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RevocationEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for RevocationEntryId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RevocationEntryId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A revocation target in its stored form. `value` is the capability id, the
/// root policy rule id, or 64 lowercase hex (subject tag, tenant tag, replay
/// key digest).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevocationTarget {
    kind: RevocationTargetKind,
    value: String,
}

impl RevocationTarget {
    pub fn capability(capability_id: &str) -> Result<Self, RootAuthorityShapeError> {
        Self::from_parts(RevocationTargetKind::CapabilityId, capability_id)
    }

    pub fn root_policy_rule(rule_id: &str) -> Result<Self, RootAuthorityShapeError> {
        Self::from_parts(RevocationTargetKind::RootPolicyRule, rule_id)
    }

    #[must_use]
    pub fn subject_tag(tag: Sha256Digest) -> Self {
        Self::digest(RevocationTargetKind::AnchorSubject, tag)
    }

    #[must_use]
    pub fn tenant_tag(tag: Sha256Digest) -> Self {
        Self::digest(RevocationTargetKind::TenantTag, tag)
    }

    #[must_use]
    pub fn replay_key(digest: Sha256Digest) -> Self {
        Self::digest(RevocationTargetKind::ReplayKey, digest)
    }

    fn digest(kind: RevocationTargetKind, digest: Sha256Digest) -> Self {
        Self {
            kind,
            value: digest.to_bare_hex(),
        }
    }

    /// Validate a stored `(kind, value)` pair: identifiers are 1 to 512
    /// NUL-free characters, digests are 64 lowercase hex characters.
    pub fn from_parts(
        kind: RevocationTargetKind,
        value: &str,
    ) -> Result<Self, RootAuthorityShapeError> {
        if kind.is_digest() {
            if !is_lowercase_hex_digest(value) {
                return Err(RootAuthorityShapeError::Pattern {
                    field: "target_value",
                    expected: "64 lowercase hex",
                });
            }
        } else {
            check_nul_free("target_value", value, MAX_TARGET_VALUE_CHARS)?;
        }
        Ok(Self {
            kind,
            value: value.to_string(),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> RevocationTargetKind {
        self.kind
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// `"rev_"` and the lowercase hex of
    /// `SHA-256(REVOCATION_ENTRY_ID_DOMAIN || kind || 0x00 || value)`. Kind
    /// names and values are NUL-free, so the preimage is injective. The id
    /// names the target only; the reason is not part of it.
    #[must_use]
    pub fn id(&self) -> RevocationEntryId {
        let mut state = Sha256State::new();
        state.update(REVOCATION_ENTRY_ID_DOMAIN);
        state.update(self.kind.as_str().as_bytes());
        state.update(&[0]);
        state.update(self.value.as_bytes());
        let mut id = String::from(ENTRY_ID_PREFIX);
        id.push_str(&hex::encode(state.finalize().as_bytes()));
        RevocationEntryId(id)
    }
}

/// `chio.revocation-entry.v1`, unsigned. Every decoded entry carries the id
/// its target derives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationEntry {
    pub schema: String,
    pub entry_id: RevocationEntryId,
    pub target_kind: RevocationTargetKind,
    pub target_value: String,
    pub revoked_at: u64,
    pub reason: RevocationReason,
}

impl RevocationEntry {
    pub fn new(
        target: &RevocationTarget,
        revoked_at: u64,
        reason: RevocationReason,
    ) -> Result<Self, RootAuthorityShapeError> {
        check_revoked_at(revoked_at)?;
        Ok(Self {
            schema: CHIO_REVOCATION_ENTRY_SCHEMA.to_string(),
            entry_id: target.id(),
            target_kind: target.kind,
            target_value: target.value.clone(),
            revoked_at,
            reason,
        })
    }

    pub fn target(&self) -> Result<RevocationTarget, RootAuthorityShapeError> {
        RevocationTarget::from_parts(self.target_kind, &self.target_value)
    }

    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_REVOCATION_ENTRY_SCHEMA)?;
        if self.target()?.id() != self.entry_id {
            return Err(RootAuthorityShapeError::Pattern {
                field: "entry_id",
                expected: "the id derived from target_kind and target_value",
            });
        }
        check_revoked_at(self.revoked_at)
    }
}

/// One anchored root an export carries and the capability ids under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCoverageRoot {
    pub root_capability_id: String,
    pub capability_ids: Vec<String>,
}

/// An entry that covers an exported root or capability ids under it.
/// `covered_capability_ids` is sorted and holds each id once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCoverage {
    pub entry: RevocationEntry,
    pub covered_capability_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationEntryWire {
    schema: String,
    entry_id: RevocationEntryId,
    target_kind: RevocationTargetKind,
    target_value: String,
    revoked_at: u64,
    reason: RevocationReason,
}

impl<'de> Deserialize<'de> for RevocationEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RevocationEntryWire::deserialize(deserializer)?;
        let entry = Self {
            schema: wire.schema,
            entry_id: wire.entry_id,
            target_kind: wire.target_kind,
            target_value: wire.target_value,
            revoked_at: wire.revoked_at,
            reason: wire.reason,
        };
        entry.validate().map_err(serde::de::Error::custom)?;
        Ok(entry)
    }
}

fn check_revoked_at(revoked_at: u64) -> Result<(), RootAuthorityShapeError> {
    if revoked_at == 0 || revoked_at > MAX_REVOKED_AT {
        return Err(RootAuthorityShapeError::Range {
            field: "revoked_at",
            min: 1,
            max: MAX_REVOKED_AT,
            actual: revoked_at,
        });
    }
    Ok(())
}

fn is_lowercase_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
