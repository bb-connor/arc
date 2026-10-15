//! Bounded durable knowledge descriptions. Decoding grants no storage or release authority.
#![forbid(unsafe_code)]

mod artifact;
mod checkpoint;
mod release;
pub use artifact::*;
pub use checkpoint::*;
pub use release::*;

pub const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACT_DEPENDENCIES: usize = 16;
pub const MAX_ARTIFACT_TRAVERSAL: usize = 64;
pub const MAX_ARCHIVE_VERSIONS: usize = 16;
pub const MAX_CHECKPOINT_ENVELOPE_BYTES: usize = 64 * 1024;

macro_rules! protected_debug {
    ($($name:ident),+ $(,)?) => { $(
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    )+ };
}
pub(crate) use protected_debug;
