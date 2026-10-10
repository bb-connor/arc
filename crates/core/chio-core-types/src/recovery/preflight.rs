//! Allocation-free resource accounting, not a replacement JSON parser. The
//! existing lossless signed reader validates syntax, duplicates and canonicality.
use super::RecoveryDecodeLimits;
use chio_security_types::recovery::{ContractError, SafeInteger, MAX_RECOVERY_DEPTH};

pub(super) fn check(input: &[u8], limits: RecoveryDecodeLimits) -> Result<(), ContractError> {
    if input.is_empty() || input.len() > limits.bytes {
        return Err(ContractError::LimitExceeded);
    }
    let mut entries = [0usize; MAX_RECOVERY_DEPTH];
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut strings = 0usize;
    let mut cursor = 0usize;
    while cursor < input.len() {
        match input[cursor] {
            b' ' | b'\n' | b'\r' | b'\t' | b':' => {
                cursor += 1;
            }
            b'{' | b'[' => {
                charge(&mut nodes, 1, limits.nodes)?;
                if depth >= limits.depth {
                    return Err(ContractError::LimitExceeded);
                }
                entries[depth] = 1; // Empty containers are conservatively one entry.
                depth += 1;
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(ContractError::Malformed)?;
                cursor += 1;
            }
            b',' => {
                let frame = depth.checked_sub(1).ok_or(ContractError::Malformed)?;
                charge(&mut entries[frame], 1, limits.container_entries)?;
                cursor += 1;
            }
            b'"' => {
                charge(&mut nodes, 1, limits.nodes)?;
                cursor += 1;
                let start = cursor;
                loop {
                    match input.get(cursor) {
                        Some(b'"') => break,
                        Some(b'\\') => {
                            cursor += 2;
                        }
                        Some(_) => {
                            cursor += 1;
                        }
                        None => return Err(ContractError::Malformed),
                    }
                    if cursor - start > limits.string_bytes.saturating_sub(strings) {
                        return Err(ContractError::LimitExceeded);
                    }
                }
                charge(&mut strings, cursor - start, limits.string_bytes)?;
                cursor += 1;
            }
            _ => {
                charge(&mut nodes, 1, limits.nodes)?;
                let start = cursor;
                while input.get(cursor).is_some_and(|byte| {
                    !matches!(byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t')
                }) {
                    cursor += 1;
                }
                let token = &input[start..cursor];
                if !matches!(token, b"true" | b"false" | b"null") {
                    // foundation recovery metadata uses unsigned interoperable integers.
                    // Arbitrary tool payloads retain their existing owning parser.
                    let mut integer = 0u64;
                    if token.is_empty() {
                        return Err(ContractError::Malformed);
                    }
                    for byte in token {
                        if !byte.is_ascii_digit() {
                            return Err(ContractError::UnsafeInteger);
                        }
                        integer = integer
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                            .filter(|n| *n <= SafeInteger::MAX)
                            .ok_or(ContractError::UnsafeInteger)?;
                    }
                }
            }
        }
    }
    if depth != 0 {
        return Err(ContractError::Malformed);
    }
    Ok(())
}

fn charge(used: &mut usize, amount: usize, ceiling: usize) -> Result<(), ContractError> {
    *used = used
        .checked_add(amount)
        .filter(|value| *value <= ceiling)
        .ok_or(ContractError::LimitExceeded)?;
    Ok(())
}
