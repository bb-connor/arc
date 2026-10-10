//! Count decoded JSON string bytes without constructing a JSON tree.
use super::*;

pub(crate) fn decoded_json_text_bytes(raw: &str) -> Result<u64, ReceiptStoreError> {
    let invalid =
        || ReceiptStoreError::Conflict("report source has invalid JSON string encoding".into());
    let mut input = raw.bytes();
    let mut in_string = false;
    let mut total = 0_u64;
    while let Some(byte) = input.next() {
        if byte == b'"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            continue;
        }
        let decoded = if byte == b'\\' {
            match input.next().ok_or_else(invalid)? {
                b'u' => {
                    let high = code_unit(&mut input).ok_or_else(invalid)?;
                    let code = if (0xd800..=0xdbff).contains(&high) {
                        if input.next() != Some(b'\\') || input.next() != Some(b'u') {
                            return Err(invalid());
                        }
                        let low = code_unit(&mut input).ok_or_else(invalid)?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(invalid());
                        }
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
                    } else {
                        u32::from(high)
                    };
                    u64::try_from(char::from_u32(code).ok_or_else(invalid)?.len_utf8())
                        .map_err(|_| invalid())?
                }
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => 1,
                _ => return Err(invalid()),
            }
        } else {
            1
        };
        total = total.checked_add(decoded).ok_or_else(invalid)?;
    }
    if in_string {
        return Err(invalid());
    }
    Ok(total)
}

fn code_unit(input: &mut impl Iterator<Item = u8>) -> Option<u16> {
    let mut value = 0_u16;
    for _ in 0..4 {
        let digit = char::from(input.next()?).to_digit(16)?;
        value = value
            .checked_mul(16)?
            .checked_add(u16::try_from(digit).ok()?)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_text_counts_keys_and_unicode_escapes_without_raw_expansion() {
        for (source, expected) in [
            (r#"{"key":"value"}"#, 8),
            (r#"["\u0061","\u00e9","\ud83d\ude00"]"#, 7),
            (r#"["\\","\"","\n"]"#, 3),
            (r#"{"é":"😀"}"#, 6),
        ] {
            assert_eq!(
                decoded_json_text_bytes(source).unwrap_or_else(|error| panic!("counter: {error}")),
                expected
            );
        }
        for source in [r#""\ud83d""#, r#""\ude00""#, r#""\q""#, "\"unterminated"] {
            assert!(decoded_json_text_bytes(source).is_err());
        }
    }
}
