//! Unpredictable identifiers drawn directly from the operating system.

use chio_security_types::ports::PortError;
use rand_core::{OsRng, RngCore as _};

/// Thirty-two bytes from the operating system's random source, hex-encoded.
/// An unavailable source is a port outage.
pub(crate) fn hex_256() -> Result<String, PortError> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PortError::unavailable())?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;

    #[test]
    fn identifiers_are_256_bit_lowercase_hex_and_distinct() {
        let first = super::hex_256().test_unwrap();
        let second = super::hex_256().test_unwrap();
        for value in [&first, &second] {
            assert_eq!(value.len(), 64);
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
        assert_ne!(first, second);
    }
}
