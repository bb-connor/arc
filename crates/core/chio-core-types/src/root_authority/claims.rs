//! The closed identity-provider claim set a root policy rule may match or record.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::wire::{check_items, SaltRef, Sha256Digest, Text};
use super::RootAuthorityShapeError;

/// A salted commitment whose salt is held in the disclosure store under `salt_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaltedCommitment {
    pub commit: Sha256Digest,
    pub salt_ref: SaltRef,
}

chio_security_types::lossless_serde! {
    /// A recorded claim: a plain string, a plain list of strings, or a committed value.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    #[serde(untagged)]
    pub enum ClaimValue {
        Plain(Text),
        List(Vec<Text>),
        Committed(SaltedCommitment),
    }
}

impl ClaimValue {
    #[must_use]
    pub const fn mode(&self) -> ClaimMode {
        match self {
            Self::Plain(_) | Self::List(_) => ClaimMode::Plain,
            Self::Committed(_) => ClaimMode::Committed,
        }
    }
}

/// How a rule records a claim in the delegation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimMode {
    Plain,
    Committed,
}

/// One value per claim name of the closed set. Unknown names reject at decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>")
)]
pub struct ClaimSet<T> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<T>,
}

impl<T> Default for ClaimSet<T> {
    fn default() -> Self {
        Self {
            client_id: None,
            scope: None,
            sub: None,
            aud: None,
            resource: None,
            azp: None,
            appid: None,
            oid: None,
            tid: None,
        }
    }
}

impl<T> ClaimSet<T> {
    /// Every claim name with its value slot, in a fixed order.
    pub fn entries(&self) -> [(&'static str, Option<&T>); 9] {
        [
            ("client_id", self.client_id.as_ref()),
            ("scope", self.scope.as_ref()),
            ("sub", self.sub.as_ref()),
            ("aud", self.aud.as_ref()),
            ("resource", self.resource.as_ref()),
            ("azp", self.azp.as_ref()),
            ("appid", self.appid.as_ref()),
            ("oid", self.oid.as_ref()),
            ("tid", self.tid.as_ref()),
        ]
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries().iter().all(|(_, value)| value.is_none())
    }

    /// The first present claim that only Entra tokens carry.
    #[must_use]
    pub fn entra_only_claim(&self) -> Option<&'static str> {
        [
            ("azp", self.azp.is_some()),
            ("appid", self.appid.is_some()),
            ("oid", self.oid.is_some()),
            ("tid", self.tid.is_some()),
        ]
        .into_iter()
        .find_map(|(name, present)| present.then_some(name))
    }
}

/// Claims recorded in a delegation context.
pub type RecordedClaims = ClaimSet<ClaimValue>;

/// Claims a root policy rule records, each plain or committed.
pub type RecordedClaimModes = ClaimSet<ClaimMode>;

impl RecordedClaims {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        for (_, value) in self.entries() {
            if let Some(ClaimValue::List(values)) = value {
                check_items("claims", values.len(), 0, 64)?;
            }
        }
        Ok(())
    }
}

/// Claim name to the values a token must carry for a rule to match.
/// Audience is never matched here; it comes from the provider record.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<Vec<Text>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<Vec<Text>>,
}

impl MatchClaims {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        for values in [
            &self.client_id,
            &self.scope,
            &self.sub,
            &self.resource,
            &self.azp,
            &self.appid,
            &self.oid,
            &self.tid,
        ]
        .into_iter()
        .flatten()
        {
            check_items("match.claims", values.len(), 1, 64)?;
        }
        Ok(())
    }

    /// The first present claim that only Entra tokens carry.
    #[must_use]
    pub fn entra_only_claim(&self) -> Option<&'static str> {
        [
            ("azp", self.azp.is_some()),
            ("appid", self.appid.is_some()),
            ("oid", self.oid.is_some()),
            ("tid", self.tid.is_some()),
        ]
        .into_iter()
        .find_map(|(name, present)| present.then_some(name))
    }
}
