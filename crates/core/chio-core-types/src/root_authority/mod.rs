//! Root-authority artifacts: the delegation context an exchange records for
//! each anchored root, the provider-signed root policy, provider identity
//! projections, identity-provider key snapshots, and offline consistency
//! checks between a root capability and that evidence.
//!
//! Decoding is strict: unknown members, out-of-range values and every
//! per-kind presence rule of the `root_authority` wire schemas reject at
//! decode. No function reads a clock; time is a parameter.

use core::fmt;

pub mod claims;
pub mod consistency;
pub mod delegation_context;
pub mod idp_key_snapshot;
pub mod jwk;
pub mod provider_identity;
pub mod root_policy;
pub mod wire;

pub use claims::{
    ClaimMode, ClaimSet, ClaimValue, MatchClaims, RecordedClaimModes, RecordedClaims,
    SaltedCommitment,
};
pub use consistency::{check_root_consistency, RootConsistencyError, RootConsistencyInput};
pub use delegation_context::{
    DelegationAnchor, DelegationContext, DelegationExchange, HolderClass,
    CHIO_DELEGATION_CONTEXT_SCHEMA,
};
pub use idp_key_snapshot::{
    IdpKeySnapshot, IdpKeySnapshotSignatureError, KeySnapshotSource, CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};
pub use jwk::{Jwk, JwkCurve, JwkKeyType, JwkUse, JwsAlgorithm};
pub use provider_identity::{
    EnterpriseProviderIdentity, InlineJwks, ProviderRecordKind, SubjectMapping,
    CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA,
};
pub use root_policy::{
    DisclosureDefault, InlineFields, LoadedRootPolicy, RootPolicy, RootPolicyDisclosure,
    RootPolicyLoadError, RootPolicyMatch, RootPolicyRule, ToolDisclosure, CHIO_ROOT_POLICY_SCHEMA,
};
pub use wire::{HttpsUrl, Identifier, SaltRef, Sha256Digest, Text, Uri};

/// Why a root-authority artifact is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootAuthorityShapeError {
    Length {
        field: &'static str,
        min: usize,
        max: usize,
        actual: usize,
    },
    Nul {
        field: &'static str,
    },
    Pattern {
        field: &'static str,
        expected: &'static str,
    },
    NonCanonicalEncoding {
        field: &'static str,
    },
    Const {
        field: &'static str,
        expected: &'static str,
    },
    Items {
        field: &'static str,
        min: usize,
        max: usize,
        actual: usize,
    },
    Duplicate {
        field: &'static str,
    },
    Range {
        field: &'static str,
        min: u64,
        max: u64,
        actual: u64,
    },
    RequiredFor {
        field: &'static str,
        kind: &'static str,
    },
    ForbiddenFor {
        field: &'static str,
        kind: &'static str,
    },
    NotAdmittedFor {
        field: &'static str,
        kind: &'static str,
    },
    ExactlyOne {
        fields: &'static str,
    },
}

impl fmt::Display for RootAuthorityShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length {
                field,
                min,
                max,
                actual,
            } => write!(
                formatter,
                "`{field}` has {actual} characters, outside {min}..={max}"
            ),
            Self::Nul { field } => write!(formatter, "`{field}` contains a NUL character"),
            Self::Pattern { field, expected } => {
                write!(formatter, "`{field}` is not {expected}")
            }
            Self::NonCanonicalEncoding { field } => {
                write!(formatter, "`{field}` is not in its canonical encoding")
            }
            Self::Const { field, expected } => {
                write!(formatter, "`{field}` must be `{expected}`")
            }
            Self::Items {
                field,
                min,
                max,
                actual,
            } => write!(
                formatter,
                "`{field}` has {actual} items, outside {min}..={max}"
            ),
            Self::Duplicate { field } => write!(formatter, "`{field}` repeats an item"),
            Self::Range {
                field,
                min,
                max,
                actual,
            } => write!(formatter, "`{field}` is {actual}, outside {min}..={max}"),
            Self::RequiredFor { field, kind } => {
                write!(formatter, "`{field}` is required for {kind}")
            }
            Self::ForbiddenFor { field, kind } => {
                write!(formatter, "`{field}` is not allowed for {kind}")
            }
            Self::NotAdmittedFor { field, kind } => {
                write!(formatter, "`{field}` has a value not admitted for {kind}")
            }
            Self::ExactlyOne { fields } => {
                write!(formatter, "exactly one of `{fields}` is required")
            }
        }
    }
}

impl core::error::Error for RootAuthorityShapeError {}
