//! Operating-system entropy for std producers.

use chio_core_types::rng::{Rng, RngError};
use rand::rngs::OsRng;
use rand::RngCore;

/// OS CSPRNG through `getrandom`. The `Rng` every std producer injects in release code.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropyRng;

impl Rng for OsEntropyRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        fill_from_source(dest, |buffer| OsRng.try_fill_bytes(buffer))
    }
}

fn fill_from_source<E>(
    dest: &mut [u8],
    source: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<(), RngError> {
    source(dest).map_err(|_| RngError("operating system entropy source failed"))
}

#[cfg(test)]
mod tests {
    use super::{fill_from_source, OsEntropyRng};
    use chio_core_types::rng::{Rng, RngError};

    #[test]
    fn os_entropy_rng_fills() {
        let rng = OsEntropyRng;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert_eq!(rng.fill_bytes(&mut first), Ok(()));
        assert_eq!(rng.fill_bytes(&mut second), Ok(()));
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn os_entropy_rng_fills_empty_buffer() {
        assert_eq!(OsEntropyRng.fill_bytes(&mut []), Ok(()));
    }

    #[test]
    fn fill_failure_returns_error() {
        let mut dest = [0xaa_u8; 16];
        let result = fill_from_source(&mut dest, |_| Err(()));
        assert_eq!(
            result,
            Err(RngError("operating system entropy source failed"))
        );
    }
}
