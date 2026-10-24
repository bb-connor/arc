//! Entropy seam for every Chio signing process.
//!
//! Receipt identifiers, nonces and seeds are drawn through [`Rng`] so each
//! platform supplies its own CSPRNG. A failed draw is an error the caller
//! must refuse on; no implementation substitutes deterministic bytes.

use core::fmt;

/// Source of cryptographically secure random bytes.
pub trait Rng {
    /// Fills `dest` with cryptographically secure random bytes or fails. No implementation
    /// zero-fills on failure. After an `Err`, the contents of `dest` are unspecified and must
    /// not be used.
    fn fill_bytes(&self, dest: &mut [u8]) -> core::result::Result<(), RngError>;
}

/// An entropy source could not produce the requested bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RngError(pub &'static str);

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy source failed: {}", self.0)
    }
}

impl core::error::Error for RngError {}

impl<T: Rng + ?Sized> Rng for &T {
    fn fill_bytes(&self, dest: &mut [u8]) -> core::result::Result<(), RngError> {
        (**self).fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::{Rng, RngError};

    struct FailingRng;

    impl Rng for FailingRng {
        fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
            Err(RngError("source offline"))
        }
    }

    struct CountingRng;

    impl Rng for CountingRng {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
            for (index, byte) in dest.iter_mut().enumerate() {
                *byte = u8::try_from(index % 251).map_err(|_| RngError("index"))?;
            }
            Ok(())
        }
    }

    fn draw(rng: &dyn Rng) -> Result<[u8; 4], RngError> {
        let mut bytes = [0xaa; 4];
        rng.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn reference_forwards_fill() {
        let rng = CountingRng;
        let by_ref = &rng;
        assert_eq!(draw(&by_ref), Ok([0, 1, 2, 3]));
    }

    #[test]
    fn fill_failure_propagates_through_reference() {
        let rng = FailingRng;
        let by_ref = &rng;
        assert_eq!(draw(&by_ref), Err(RngError("source offline")));
    }

    #[test]
    fn error_display_names_the_source() {
        let rendered = RngError("source offline").to_string();
        assert_eq!(rendered, "entropy source failed: source offline");
    }
}
