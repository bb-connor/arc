#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![forbid(unsafe_code)]

//! Private file and directory custody for Unix hosts.
//!
//! A [`PrivateDirectory`] is validated once, from the filesystem root down,
//! and then pinned by a descriptor. Every later operation is relative to that
//! descriptor, never follows a symlink in a final component, and checks the
//! object it opened against an explicit [`OwnerPolicy`]. There is no default
//! policy: each call site states the owner, the forbidden permission bits, the
//! hard-link rule and the ACL rule it relies on.
//!
//! A refusal is an [`std::io::Error`] whose inner error is a [`Refused`].
//! [`refusal`] names the rule that fired, so callers can translate it and tests
//! can assert it exactly. Operating-system failures pass through unchanged.

#[cfg(unix)]
mod directory;
#[cfg(unix)]
mod error;
#[cfg(unix)]
mod file;
#[cfg(unix)]
mod policy;
#[cfg(unix)]
mod publish;
#[cfg(unix)]
mod walk;

#[cfg(unix)]
pub use directory::PrivateDirectory;
#[cfg(unix)]
pub use error::{refusal, Refusal, Refused};
#[cfg(unix)]
pub use file::{
    entry_metadata, private_file_identity, read_private_file, FileIdentity, PrivateFile,
};
#[cfg(unix)]
pub use policy::{effective_uid, Owner, OwnerPolicy};
#[cfg(unix)]
pub use publish::{open_directory_nofollow, publish_at, Expect};

#[cfg(all(test, unix))]
#[path = "tests/mod.rs"]
mod tests;
