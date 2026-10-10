//! Bounded recovery contracts. Every decoded value is untrusted historical data.
//!
//! These types provide neither a live owner nor permission to execute or release.
//! New recovery protocols use the bounded canonical reader in `chio-core-types`.

#![forbid(unsafe_code)]

mod authorization;
mod bounds;
mod commands;
mod explanation;
mod identifiers;
mod observation;
mod product;
mod profile;
mod provider;
mod trajectory;

pub use authorization::*;
pub use bounds::{
    BoundedList, ContractError, NonEmptyBoundedList, ProtectedText, SafeInteger, VersionV1,
};
pub use commands::*;
pub use explanation::*;
pub use identifiers::*;
pub use observation::*;
pub use product::*;
pub use profile::*;
pub use provider::*;
pub use trajectory::*;

/// Transport ceiling checked before parsing any recovery JSON.
pub const MAX_RECOVERY_WIRE_BYTES: usize = 64 * 1024;
/// Maximum JSON container nesting, including the root.
pub const MAX_RECOVERY_DEPTH: usize = 16;
/// Maximum aggregate JSON values and object keys per input.
pub const MAX_RECOVERY_NODES: usize = 4096;
/// Maximum aggregate encoded string-content bytes, including object keys.
pub const MAX_RECOVERY_STRING_BYTES: usize = 32 * 1024;
/// Maximum entries in any individual JSON container.
pub const MAX_RECOVERY_CONTAINER_ENTRIES: usize = 256;
/// Maximum evidence/dependency checks per pure evaluation.
pub const MAX_RECOVERY_VERIFICATION_WORK: u32 = 4096;
