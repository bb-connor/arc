//! Lowercase hex encoding for public cryptographic material.

#[cfg(not(kani))]
use alloc::format;
use alloc::string::String;

/// Fill one owned typed ASCII buffer, then transfer it into a string.
/// Non-ASCII prefixes use the established general rendering fallback.
pub(super) fn prefixed_hex(prefix: &str, bytes: &[u8]) -> String {
    let encoded = try_prefixed_hex(prefix, bytes);
    // Prove that the real checked encoder covers every bounded proof input.
    // Refusal is a failing property. Keep the unrelated compatibility fallback
    // out of symbolic expansion even on an infeasible error branch.
    #[cfg(kani)]
    {
        match encoded {
            Some(text) => text,
            None => panic!("bounded hex encoding must succeed"),
        }
    }
    // Preserve the established wire rendering if a checked codec operation
    // refuses. Never emit a partial, empty or lossy encoding on that path.
    #[cfg(not(kani))]
    {
        encoded.unwrap_or_else(|| format!("{prefix}{}", hex::encode(bytes)))
    }
}

fn try_prefixed_hex(prefix: &str, bytes: &[u8]) -> Option<String> {
    let len = bytes
        .len()
        .checked_mul(2)
        .and_then(|len| len.checked_add(prefix.len()))?;
    let mut encoded = alloc::vec![ascii::AsciiChar::Null; len];
    fill_prefixed_hex(prefix, bytes, &mut encoded)?;
    Some(String::from(ascii::AsciiString::from(encoded)))
}

/// Fill an exactly sized typed ASCII buffer with the established wire bytes.
pub(super) fn fill_prefixed_hex(
    prefix: &str,
    bytes: &[u8],
    encoded: &mut [ascii::AsciiChar],
) -> Option<()> {
    const DIGITS: [ascii::AsciiChar; 16] = [
        ascii::AsciiChar::_0,
        ascii::AsciiChar::_1,
        ascii::AsciiChar::_2,
        ascii::AsciiChar::_3,
        ascii::AsciiChar::_4,
        ascii::AsciiChar::_5,
        ascii::AsciiChar::_6,
        ascii::AsciiChar::_7,
        ascii::AsciiChar::_8,
        ascii::AsciiChar::_9,
        ascii::AsciiChar::a,
        ascii::AsciiChar::b,
        ascii::AsciiChar::c,
        ascii::AsciiChar::d,
        ascii::AsciiChar::e,
        ascii::AsciiChar::f,
    ];
    let (prefix_chars, hex_chars) = encoded.split_at_mut_checked(prefix.len())?;
    if hex_chars.len() != bytes.len().checked_mul(2)? {
        return None;
    }
    for (output, byte) in prefix_chars.iter_mut().zip(prefix.bytes()) {
        *output = ascii::AsciiChar::from_ascii(byte).ok()?;
    }
    for (output, byte) in hex_chars.chunks_exact_mut(2).zip(bytes) {
        let [high, low] = output else {
            return None;
        };
        *high = *DIGITS.get(usize::from(byte >> 4))?;
        *low = *DIGITS.get(usize::from(byte & 0x0f))?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::prefixed_hex;
    use alloc::format;
    use alloc::vec::Vec;

    #[test]
    fn all_bytes_and_prefixes_match_the_established_wire_encoding() {
        let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        for prefix in ["", "p256:", "p384:", "\u{3bb}:"] {
            for len in [0, 1, 31, 32, 64, 65, 97, 127, 128, 255, 256] {
                assert_eq!(
                    prefixed_hex(prefix, &bytes[..len]),
                    format!("{prefix}{}", hex::encode(&bytes[..len]))
                );
            }
        }
    }
}
