//! Lowercase hex encoding for public cryptographic material.

#[cfg(not(kani))]
use alloc::format;
use alloc::string::String;

/// Fill one owned byte buffer, then validate and transfer it into a string.
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
    let mut encoded = alloc::vec![0; len];
    fill_prefixed_hex(prefix, bytes, &mut encoded)?;
    String::from_utf8(encoded).ok()
}

/// Fill an exactly sized byte buffer with the established ASCII wire bytes.
pub(super) fn fill_prefixed_hex(prefix: &str, bytes: &[u8], encoded: &mut [u8]) -> Option<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let (prefix_chars, hex_chars) = encoded.split_at_mut_checked(prefix.len())?;
    if hex_chars.len() != bytes.len().checked_mul(2)? || !prefix.is_ascii() {
        return None;
    }
    prefix_chars.copy_from_slice(prefix.as_bytes());
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
