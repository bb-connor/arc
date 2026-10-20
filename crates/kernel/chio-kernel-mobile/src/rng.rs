//! CSPRNG adapter for mobile hosts.
//!
//! The `getrandom` crate picks the right entropy source for each
//! mobile target:
//!
//!  - iOS: `SecRandomCopyBytes` via the Security framework.
//!  - Android: `/dev/urandom` (via the libc fallback) or the `getrandom(2)`
//!    syscall on API level 28+.
//!
//! A failed OS call returns [`RngError`]; callers refuse the operation that
//! needed the bytes.

#![forbid(unsafe_code)]

use chio_core_types::rng::{Rng, RngError};

/// Mobile-suitable `Rng` delegating to the `getrandom` crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct MobileRng;

impl MobileRng {
    /// Construct a new mobile RNG.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Rng for MobileRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        fill_from_source(dest, getrandom::getrandom)
    }
}

fn fill_from_source(
    dest: &mut [u8],
    source: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<(), RngError> {
    source(dest).map_err(|_| RngError("mobile operating system entropy source failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_rng_fills_buffer() {
        let rng = MobileRng::new();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert_eq!(rng.fill_bytes(&mut first), Ok(()));
        assert_eq!(rng.fill_bytes(&mut second), Ok(()));
        assert_ne!(first, second);
    }

    #[test]
    fn fill_failure_returns_error() {
        let mut dest = [0xaa_u8; 32];
        let result = fill_from_source(&mut dest, |_| Err(getrandom::Error::UNSUPPORTED));
        assert_eq!(
            result,
            Err(RngError("mobile operating system entropy source failed"))
        );
    }
}
