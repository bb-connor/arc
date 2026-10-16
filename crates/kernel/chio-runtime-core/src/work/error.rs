//! Stable rejection codes for `chio.work.v1`. No parser or source text is
//! ever serialized into a rejection.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Closed rejection categories. The stable string form is `work.<code>`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkRejectionCodeV1 {
    Schema,
    Malformed,
    DuplicateKey,
    UnsafeInteger,
    Bounds,
    Identifier,
    BindingMismatch,
    Conflict,
    StaleVersion,
    StaleCatalog,
    Expired,
    Revoked,
    Audience,
    Role,
    CrossTenant,
    UnsupportedProfile,
    Busy,
}

impl WorkRejectionCodeV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "work.schema",
            Self::Malformed => "work.malformed",
            Self::DuplicateKey => "work.duplicate_key",
            Self::UnsafeInteger => "work.unsafe_integer",
            Self::Bounds => "work.bounds",
            Self::Identifier => "work.identifier",
            Self::BindingMismatch => "work.binding_mismatch",
            Self::Conflict => "work.conflict",
            Self::StaleVersion => "work.stale_version",
            Self::StaleCatalog => "work.stale_catalog",
            Self::Expired => "work.expired",
            Self::Revoked => "work.revoked",
            Self::Audience => "work.audience",
            Self::Role => "work.role",
            Self::CrossTenant => "work.cross_tenant",
            Self::UnsupportedProfile => "work.unsupported_profile",
            Self::Busy => "work.busy",
        }
    }
}

impl fmt::Display for WorkRejectionCodeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The binding a `work.binding_mismatch` rejection names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkBindingFieldV1 {
    ProgramId,
    CommandId,
    SlotId,
    AllocationHash,
    ReceiverKernelId,
    RequestId,
    CapabilityHash,
    ProfileRef,
    GraphSha256,
    DraftRef,
    Permit,
    InvocationRef,
}

/// A local decode or construction failure. It converts into the wire
/// rejection and keeps no input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkContractError {
    code: WorkRejectionCodeV1,
    field: Option<WorkBindingFieldV1>,
}

impl WorkContractError {
    #[must_use]
    pub const fn new(code: WorkRejectionCodeV1) -> Self {
        Self { code, field: None }
    }

    #[must_use]
    pub const fn binding(field: WorkBindingFieldV1) -> Self {
        Self {
            code: WorkRejectionCodeV1::BindingMismatch,
            field: Some(field),
        }
    }

    #[must_use]
    pub const fn code(&self) -> WorkRejectionCodeV1 {
        self.code
    }

    #[must_use]
    pub const fn field(&self) -> Option<WorkBindingFieldV1> {
        self.field
    }
}

impl fmt::Display for WorkContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl core::error::Error for WorkContractError {}
