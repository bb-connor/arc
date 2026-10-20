//! Deterministic [`Rng`] for generated fixtures and tests.
//!
//! Output is fixture material only. This crate is never a dependency of a
//! release build: production producers draw from an operating-system or
//! platform CSPRNG.

#![forbid(unsafe_code)]

use std::sync::Mutex;

use chio_core_types::rng::{Rng, RngError};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// Domain prefix of every fixture seed derivation.
pub const FIXTURE_RNG_DOMAIN: &[u8] = b"chio.fixture-rng.v1\0";

/// Deterministic ChaCha20 stream from a 32-byte seed. Output is fixture material only.
///
/// Successive `fill_bytes` calls continue one keystream, so a fixture that draws the same
/// lengths in the same order reproduces the same bytes.
#[derive(Debug)]
pub struct FixtureRng {
    stream: Mutex<ChaCha20Rng>,
}

impl FixtureRng {
    /// `seed = SHA-256("chio.fixture-rng.v1\0" || label || 0x00 || fixture_id)`.
    ///
    /// Refuses a `label` that contains a NUL byte, which would make the
    /// `(label, fixture_id)` encoding ambiguous.
    pub fn for_fixture(label: &str, fixture_id: &str) -> Result<Self, RngError> {
        if label.as_bytes().contains(&0) {
            return Err(RngError("fixture rng label contains a NUL byte"));
        }
        let mut hasher = Sha256::new();
        hasher.update(FIXTURE_RNG_DOMAIN);
        hasher.update(label.as_bytes());
        hasher.update([0u8]);
        hasher.update(fixture_id.as_bytes());
        Ok(Self {
            stream: Mutex::new(ChaCha20Rng::from_seed(hasher.finalize().into())),
        })
    }
}

impl Rng for FixtureRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| RngError("fixture rng stream lock poisoned"))?;
        stream.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FixtureRng;
    use chio_core_types::rng::{Rng, RngError};

    fn fixture(label: &str, fixture_id: &str) -> FixtureRng {
        match FixtureRng::for_fixture(label, fixture_id) {
            Ok(rng) => rng,
            Err(error) => panic!("fixture rng must build: {error}"),
        }
    }

    fn draw<const N: usize>(rng: &dyn Rng) -> [u8; N] {
        let mut bytes = [0u8; N];
        if let Err(error) = rng.fill_bytes(&mut bytes) {
            panic!("fixture rng must fill: {error}");
        }
        bytes
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn fixture_rng_is_deterministic_per_fixture() {
        let first = draw::<32>(&fixture("receipt-salt", "fixture-a"));
        let again = draw::<32>(&fixture("receipt-salt", "fixture-a"));
        let other_fixture = draw::<32>(&fixture("receipt-salt", "fixture-b"));
        let other_label = draw::<32>(&fixture("receipt-id", "fixture-a"));
        assert_eq!(first, again);
        assert_ne!(first, other_fixture);
        assert_ne!(first, other_label);
    }

    #[test]
    fn fixture_rng_matches_chacha20_reference_stream() {
        let rng = fixture("receipt-salt", "fixture-a");
        assert_eq!(
            hex(&draw::<32>(&rng)),
            "93323cf8117f01058dbef70d68adf030937eccf52affcf6c2427f7bd061b0bb1"
        );
        assert_eq!(
            hex(&draw::<48>(&rng)),
            "1b17b490aa0f256c2841879ca449abc105ef45882d6b87f99f947e4cb560f30a\
             01205f7daffea4974bf99009d25f6c7c"
        );
        assert_eq!(
            hex(&draw::<32>(&fixture("receipt-salt", "fixture-b"))),
            "fcf06844daa5adbebbddc3f65ac51824914015b60c37717669bf8559720b9c73"
        );
    }

    #[test]
    fn fixture_rng_refuses_nul_in_label() {
        match FixtureRng::for_fixture("receipt\0salt", "fixture-a") {
            Err(error) => assert_eq!(error, RngError("fixture rng label contains a NUL byte")),
            Ok(_) => panic!("a NUL in the label must be refused"),
        }
    }
}
