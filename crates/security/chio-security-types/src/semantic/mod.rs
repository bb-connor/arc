//! Closed semantic contracts. These values carry claims, never live authority.
#![forbid(unsafe_code)]
macro_rules! protected_debug {
    ($($name:ident),+ $(,)?) => { $(impl core::fmt::Debug for $name {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(concat!(stringify!($name), "([redacted])")) }
    })+ };
}
pub(super) use protected_debug;
mod action;
mod evidence;
mod package;
mod plan;
use crate::recovery::{ContractError, SafeInteger};
pub use action::*;
pub use evidence::*;
pub use package::*;
pub use plan::*;

/// Short-lived observations and authority are checked again at native capture.
pub fn validate_semantic_interval(
    issued: SafeInteger,
    until: SafeInteger,
) -> Result<(), ContractError> {
    if issued.get() == 0 || until.get() <= issued.get() || until.get() - issued.get() > 60_000 {
        return Err(ContractError::InvalidState);
    }
    Ok(())
}
