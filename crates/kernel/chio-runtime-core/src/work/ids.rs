//! Work identifier and digest newtypes. Each meaning has its own type, so a
//! value cannot be passed where a different identity is expected.
//!
//! ```
//! use chio_runtime_core::work::{WorkContractError, WorkProgramId};
//! fn program(id: WorkProgramId) -> WorkProgramId { id }
//! # fn main() -> Result<(), WorkContractError> {
//! program(WorkProgramId::new("program-a")?);
//! # Ok(()) }
//! ```
//!
//! ```compile_fail
//! use chio_runtime_core::work::{WorkContractError, WorkProgramId, WorkTaskId};
//! fn program(id: WorkProgramId) -> WorkProgramId { id }
//! # fn main() -> Result<(), WorkContractError> {
//! program(WorkTaskId::new("program-a")?);
//! # Ok(()) }
//! ```
//!
//! ```compile_fail
//! use chio_runtime_core::work::{WorkAllocationDigest, WorkContractError, WorkGraphDigest};
//! fn allocation(digest: WorkAllocationDigest) -> WorkAllocationDigest { digest }
//! # fn main() -> Result<(), WorkContractError> {
//! allocation(WorkGraphDigest::new("0".repeat(64))?);
//! # Ok(()) }
//! ```

use core::fmt;
use serde::{de, Deserialize, Deserializer, Serialize};

use super::error::{WorkContractError, WorkRejectionCodeV1};

/// Work-native identifiers use the recovery identifier grammar.
pub const MAX_WORK_IDENTIFIER_BYTES: usize = 128;
/// Identifiers that name a D1 record keep the D1 grammar verbatim.
pub const MAX_DELEGATION_IDENTIFIER_BYTES: usize = 256;

fn work_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORK_IDENTIFIER_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn delegation_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DELEGATION_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

macro_rules! checked_string {
    ($check:ident; $($name:ident),+ $(,)?) => { $(
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, WorkContractError> {
                let value = value.into();
                if !$check(&value) {
                    return Err(WorkContractError::new(WorkRejectionCodeV1::Identifier));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    )+ };
}

checked_string!(
    work_identifier;
    WorkProgramId,
    WorkCommandId,
    WorkPreparationId,
    WorkTaskId,
    WorkJoinId,
    WorkDraftId,
    WorkOwnerId,
    WorkCatalogId,
    WorkCatalogEntryId,
    WorkReceiverKernelId,
    WorkServerId,
    WorkToolName,
    WorkFundingProfileId,
    WorkTermsReference,
    WorkRailId,
    WorkReserveRef,
    WorkReceiptId,
    WorkSourceId
);

checked_string!(delegation_identifier; WorkSlotId);

checked_string!(
    lowercase_sha256;
    WorkAllocationDigest,
    WorkGraphDigest,
    WorkBundleDigest,
    WorkInvocationDigest,
    WorkCommandDigest,
    WorkCapabilityDigest,
    WorkAgreementDigest,
    WorkArtifactDigest,
    WorkProcedureDigest,
    WorkEvidenceDigest,
    WorkEnvelopeDigest,
    WorkCursorDigest
);
